package action

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/rand"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func spec() *Spec {
	return &Spec{
		ID: "aws-creds", Description: "AWS credentials", Command: "/usr/bin/granted",
		Args: []string{"credential-process", "--profile", "{profile}", "--region={region}"},
		Params: map[string]*Param{
			"profile": {Allowed: []string{"dev-admin", "staging-readonly"}},
			"region":  {Pattern: "[a-z]{2}-[a-z]+-[0-9]"},
		},
	}
}

func checked(t *testing.T, s *Spec) *Spec {
	t.Helper()
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCheckDefaults(t *testing.T) {
	s := checked(t, spec())
	if s.Timeout != DefaultTimeout || s.MaxBytes != DefaultMaxBytes || s.Format != FormatNone {
		t.Fatalf("defaults: %s %d %q", s.Timeout, s.MaxBytes, s.Format)
	}
}

func TestCheckRejections(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*Spec)
		want string
	}{
		"relative command":          {func(s *Spec) { s.Command = "granted" }, "absolute path"},
		"unclean command":           {func(s *Spec) { s.Command = "/usr/bin/../bin/granted" }, "absolute path"},
		"undeclared placeholder":    {func(s *Spec) { s.Args = append(s.Args, "{account}") }, "{account} is not declared"},
		"unused param":              {func(s *Spec) { s.Args = s.Args[:3] }, "params.region is declared but no argument uses it"},
		"unclosed brace":            {func(s *Spec) { s.Args = append(s.Args, "{profile") }, "unclosed {"},
		"stray close brace":         {func(s *Spec) { s.Args = append(s.Args, "a}b") }, "unmatched }"},
		"non-name placeholder":      {func(s *Spec) { s.Args = append(s.Args, "{a b}") }, "not a parameter name"},
		"both constraints":          {func(s *Spec) { s.Params["profile"].Pattern = ".*" }, "not both"},
		"no constraint":             {func(s *Spec) { s.Params["profile"].Allowed = nil }, "exactly one of allowed and pattern"},
		"empty allowed":             {func(s *Spec) { s.Params["profile"].Allowed = []string{} }, "must not be empty"},
		"dash in allowed":           {func(s *Spec) { s.Params["profile"].Allowed = []string{"-x"} }, "allow_leading_dash"},
		"control in allowed":        {func(s *Spec) { s.Params["profile"].Allowed = []string{"a\nb"} }, "control"},
		"bad pattern":               {func(s *Spec) { s.Params["region"].Pattern = "(" }, "pattern"},
		"unbalanced pattern":        {func(s *Spec) { s.Params["region"].Pattern = "[a-z]+)|(.*" }, "pattern"},
		"bad param name":            {func(s *Spec) { s.Params["Bad"] = &Param{Allowed: []string{"x"}} }, "params.Bad: name must match"},
		"timeout too long":          {func(s *Spec) { s.Timeout = time.Hour }, "timeout"},
		"max_bytes too large":       {func(s *Spec) { s.MaxBytes = MaxMaxBytes + 1 }, "max_bytes"},
		"unknown format":            {func(s *Spec) { s.Format = "yaml" }, "output.format"},
		"env sets FOCA_ACTION":      {func(s *Spec) { s.Env = map[string]string{"FOCA_ACTION": "x"} }, "FOCA_ACTION is set by foca"},
		"bad env name":              {func(s *Spec) { s.Env = map[string]string{"A=B": "x"} }, "not a valid variable name"},
		"NUL in env":                {func(s *Spec) { s.Env = map[string]string{"A": "x\x00"} }, "NUL"},
		"env_secrets clashes":       {func(s *Spec) { s.Env = map[string]string{"T": "x"}; s.EnvSecrets = map[string]string{"T": "v:tok"} }, "also set in env"},
		"env_secrets bad id":        {func(s *Spec) { s.EnvSecrets = map[string]string{"T": "a b"} }, "is not a secret name"},
		"env_secrets without vault": {func(s *Spec) { s.EnvSecrets = map[string]string{"T": "tok"} }, "is not a secret name"},
		"control in description":    {func(s *Spec) { s.Description = "AWS‮creds" }, "control or format"},
		"description too long":      {func(s *Spec) { s.Description = strings.Repeat("x", 81) }, "longer than"},
		"NUL in literal":            {func(s *Spec) { s.Args = append(s.Args, "a\x00b") }, "NUL"},
		"bad id":                    {func(s *Spec) { s.ID = "AWS" }, "id"},
		"param description control": {func(s *Spec) { s.Params["profile"].Description = "a\tb" }, "control"},
	} {
		t.Run(name, func(t *testing.T) {
			s := spec()
			tc.edit(s)
			err := s.Check()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestArgvKeepsOneElementPerTemplateElement(t *testing.T) {
	s := spec()
	s.Params["region"].Pattern = "[a-z0-9 ;$()`'\"*-]+"
	s.Args = append(s.Args, "{{literal}}", "")
	checked(t, s)
	p, err := s.Validate(map[string]string{"profile": "dev-admin", "region": "eu west 1; $(id) `id` '*'"})
	if err != nil {
		t.Fatal(err)
	}
	got := s.Argv(p)
	want := []string{"/usr/bin/granted", "credential-process", "--profile", "dev-admin", "--region=eu west 1; $(id) `id` '*'", "{literal}", ""}
	if !slices.Equal(got, want) {
		t.Fatalf("argv\n got %q\nwant %q", got, want)
	}
}

func TestValidateRefusesInjectionAttempts(t *testing.T) {
	s := spec()
	s.Params["free"] = &Param{Pattern: ".*"}
	s.Args = append(s.Args, "{free}")
	checked(t, s)
	ok := map[string]string{"profile": "dev-admin", "region": "eu-west-1", "free": "x"}
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range ok {
			m[a] = b
		}
		m[k] = v
		return m
	}
	if _, err := s.Validate(ok); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Validate(with("free", "a plain space")); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		params map[string]string
		want   string
	}{
		"unknown param":           {with("account", "1"), "unknown params: \"account\""},
		"missing param":           {map[string]string{"profile": "dev-admin", "region": "eu-west-1"}, "param free: missing"},
		"value not allowed":       {with("profile", "prod-admin"), "not one of the allowed values"},
		"allowed with suffix":     {with("profile", "dev-admin --debug"), "not one of the allowed values"},
		"option injection":        {with("free", "--exec=/bin/sh"), "starts with \"-\""},
		"short option":            {with("free", "-x"), "starts with \"-\""},
		"pattern partial match":   {with("region", "eu-west-1x"), "doesn't match"},
		"pattern prefix match":    {with("region", "xeu-west-1"), "doesn't match"},
		"pattern across lines":    {with("region", "eu-west-1\neu-west-2"), "control"},
		"newline":                 {with("free", "a\nb"), "control"},
		"NUL":                     {with("free", "a\x00b"), "control"},
		"escape sequence":         {with("free", "\x1b[2J"), "control"},
		"bidi override":           {with("free", "abc‮def"), "format"},
		"zero width":              {with("free", "a​b"), "format"},
		"line separator":          {with("free", "a\u2028b"), "separator"},
		"paragraph separator":     {with("free", "a\u2029b"), "separator"},
		"no-break space":          {with("free", "a\u00a0b"), "separator"},
		"ideographic space":       {with("free", "a\u3000b"), "separator"},
		"invalid UTF-8":           {with("free", "a\xffb"), "UTF-8"},
		"empty":                   {with("free", ""), "empty"},
		"too long":                {with("free", strings.Repeat("a", MaxParamValue+1)), "longer than"},
		"shell metachar allowed?": {with("profile", "dev-admin;id"), "not one of the allowed values"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.Validate(tc.params)
			var pe *ParamError
			if !errors.As(err, &pe) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	// A dash is allowed only where the host says so.
	s.Params["free"].AllowLeadingDash = true
	if _, err := s.Validate(with("free", "--verbose")); err != nil {
		t.Fatal(err)
	}
}

func TestValidateQuotesRejectedValues(t *testing.T) {
	s := checked(t, spec())
	_, err := s.Validate(map[string]string{"profile": "x\x1b]0;evil\x07" + strings.Repeat("a", 100), "region": "eu-west-1"})
	if err == nil || strings.ContainsAny(err.Error(), "\x1b\x07") || len(err.Error()) > 200 {
		t.Fatalf("rejected value must be escaped and short: %q", err)
	}
}

func TestEnvironIsOnlyConfig(t *testing.T) {
	s := spec()
	s.Env = map[string]string{"PATH": "/usr/bin", "HOME": "/home/u"}
	checked(t, s)
	got := s.Environ()
	want := []string{"HOME=/home/u", "PATH=/usr/bin", "FOCA_ACTION=aws-creds"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}
}

func TestDescribeAndCanonicalParams(t *testing.T) {
	got := DescribeParams(map[string]string{"repo": "foca/foca", "q": "a b. Approve"})
	if got != `q="a b. Approve", repo=foca/foca` {
		t.Fatalf("got %s", got)
	}
	a := CanonicalParams(map[string]string{"a": "b;c", "d": ""})
	b := CanonicalParams(map[string]string{"a": "b", "c\";d": ""})
	if a == b || CanonicalParams(nil) != "" {
		t.Fatalf("canonical forms must not collide: %s %s", a, b)
	}
}

func TestValidateOutput(t *testing.T) {
	good := `{"Version":1,"AccessKeyId":"AKIA","SecretAccessKey":"s","SessionToken":"t","Expiration":"2026-10-07T12:00:00Z"}`
	for _, tc := range []struct {
		format, out string
		ok          bool
	}{
		{FormatNone, "\x00anything", true},
		{FormatText, "line one\n\tline two\r\n", true},
		{FormatText, "bell\x07", false},
		{FormatText, "\xff", false},
		{FormatJSON, `{"a":[1,2]}`, true},
		{FormatJSON, `{"a":`, false},
		{FormatAWSCredProc, good, true},
		{FormatAWSCredProc, `{"Version":1,"AccessKeyId":"AKIA","SecretAccessKey":"s"}`, true},
		{FormatAWSCredProc, `{"Version":2,"AccessKeyId":"AKIA","SecretAccessKey":"s"}`, false},
		{FormatAWSCredProc, `{"Version":1,"SecretAccessKey":"s"}`, false},
		{FormatAWSCredProc, `{"Version":1,"AccessKeyId":"AKIA","SecretAccessKey":""}`, false},
		{FormatAWSCredProc, `{"Version":1,"AccessKeyId":"AKIA","SecretAccessKey":"s","Expiration":"tomorrow"}`, false},
		{FormatAWSCredProc, good + good, false},
		{FormatAWSCredProc, "AKIA s", false},
	} {
		err := ValidateOutput(tc.format, []byte(tc.out))
		if (err == nil) != tc.ok {
			t.Errorf("%s %q: %v", tc.format, tc.out, err)
		}
	}
}

func allEncodings(v []byte) []string {
	h := hex.EncodeToString(v)
	return []string{string(v), base64.StdEncoding.EncodeToString(v), base64.URLEncoding.EncodeToString(v),
		base64.RawStdEncoding.EncodeToString(v), base64.RawURLEncoding.EncodeToString(v), h, strings.ToUpper(h),
		url.QueryEscape(string(v)), url.PathEscape(string(v))}
}

func TestMaskedOutputContainsNoSecretEncoding(t *testing.T) {
	secrets := map[string][]byte{
		"github-pat": []byte("ghp_S3cr3t/with+chars=and spaces?&"),
		"npm-token":  []byte("npm_\x00\xffbinary"),
	}
	m := NewMasker(secrets)
	var out strings.Builder
	for id, v := range secrets {
		for _, enc := range allEncodings(v) {
			out.WriteString("before " + enc + " after\n" + enc + enc + "\n")
		}
		_ = id
	}
	masked := string(m.Mask([]byte(out.String())))
	for id, v := range secrets {
		for _, enc := range allEncodings(v) {
			if strings.Contains(masked, enc) {
				t.Errorf("%s: %q survived masking", id, enc)
			}
		}
		if !strings.Contains(masked, "[hidden:"+id+"]") {
			t.Errorf("no mark for %s", id)
		}
	}
	if !strings.Contains(masked, "before [hidden:") || !strings.Contains(masked, "] after") {
		t.Fatalf("text around values must stay: %q", masked)
	}
	m.Zero()
	if m.Active() {
		t.Fatal("zeroed masker still active")
	}
}

// Two secrets can overlap in the output. Both are hidden whole, under the
// mark of the one that starts first, whichever is replaced first.
func TestOverlappingSecretsAreMaskedTogether(t *testing.T) {
	m := NewMasker(map[string][]byte{"a": []byte("zzAB"), "b": []byte("ABCDEFGHIJKLMNOP")})
	if got := string(m.Mask([]byte("<zzABCDEFGHIJKLMNOP>"))); got != "<[hidden:a]>" {
		t.Fatalf("stdout masked to %q", got)
	}
	// In the stderr tail too, wherever the cut falls.
	stream := []byte(strings.Repeat("x", 40) + "zzABCDEFGHIJKLMNOP" + strings.Repeat("y", 10))
	for keep := 1; keep <= 30; keep++ {
		window := stream[max(0, len(stream)-(keep+m.Window())):]
		tail := string(m.MaskTail(window, keep))
		if strings.ContainsAny(strings.ReplaceAll(tail, "[hidden:a]", ""), "zABCDEFGHIJKLMNOP") {
			t.Fatalf("keep %d: tail %q shows part of a secret", keep, tail)
		}
	}
}

// A command that prints a secret inside a JSON string escapes it. The
// escaped forms common encoders write are masked like the raw value.
func TestMaskedOutputContainsNoJSONEscapedSecret(t *testing.T) {
	v := []byte("p/w<&>\"q\\\n\tz")
	m := NewMasker(map[string][]byte{"t": v})
	for _, enc := range []string{
		`p/w\u003c\u0026\u003e\"q\\\n\tz`,  // Go, escaping HTML
		`p/w<&>\"q\\\n\tz`,                 // most encoders
		`p\/w\u003c\u0026\u003e\"q\\\n\tz`, // escaping / as well
		`p\/w<&>\"q\\\n\tz`,
	} {
		out := string(m.Mask([]byte(`{"token":"` + enc + `"}`)))
		if out != `{"token":"[hidden:t]"}` {
			t.Errorf("%s: masked to %s", enc, out)
		}
	}
}

// A secret may straddle the start of the stderr tail. Whatever the cut, the
// tail must hold none of its encodings, not even part of the value.
func TestMaskTailNeverShowsAPartialSecret(t *testing.T) {
	v := []byte("tok_0123456789abcdef0123456789")
	m := NewMasker(map[string][]byte{"t": v})
	r := rand.New(rand.NewSource(1))
	const keep = 64
	for i := 0; i < 2000; i++ {
		encs := allEncodings(v)
		enc := encs[r.Intn(len(encs))]
		stream := strings.Repeat("x", r.Intn(200)) + enc + strings.Repeat("y", r.Intn(100))
		window := stream[max(0, len(stream)-(keep+m.Window())):]
		tail := string(m.MaskTail([]byte(window), keep))
		// No suffix of the value's encoding longer than 3 bytes may show.
		for n := 4; n <= len(enc); n++ {
			if strings.Contains(tail, enc[len(enc)-n:]) {
				t.Fatalf("tail %q shows %q of %q", tail, enc[len(enc)-n:], enc)
			}
		}
		if len(tail) > keep+len("[hidden:t]") {
			t.Fatalf("tail too long: %d", len(tail))
		}
	}
}
