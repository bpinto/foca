// Package action is what a host-declared action is (design §11, D14): its
// spec from config, how a caller's parameters are checked against it, how
// they fill the argument template, how its output is validated and how
// secrets are masked out of that output. It does no I/O; the command
// provider runs the action.
//
// Callers send only a name and parameter values. Everything else, the
// command, its arguments, its environment and the secrets it uses, comes
// from host config.
package action

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bpinto/foca/internal/secretname"
)

// Limits. The timeout and output bounds apply to config values; the others
// to what a caller may send.
const (
	DefaultTimeout = 60 * time.Second
	MinTimeout     = time.Second
	MaxTimeout     = 30 * time.Minute

	DefaultMaxBytes = 64 << 10
	// MaxMaxBytes keeps a result inside one protocol message (1 MiB) after
	// base64.
	MaxMaxBytes = 512 << 10

	// StderrTail is how much of the end of stderr a caller gets back.
	StderrTail = 4 << 10

	MaxParams     = 16
	MaxParamValue = 256
	maxDesc       = 80
)

// Output formats an action's stdout can be checked against.
const (
	FormatNone        = ""
	FormatText        = "text"
	FormatJSON        = "json"
	FormatAWSCredProc = "aws-credential-process"
)

var (
	idPattern    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	paramPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	envPattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// ValidID reports whether s can name an action.
func ValidID(s string) bool { return idPattern.MatchString(s) }

// Param is one parameter a caller must supply. Exactly one of Allowed and
// Pattern is set.
type Param struct {
	Description string
	// Allowed values, matched exactly.
	Allowed []string
	// Pattern is an RE2 expression the whole value must match.
	Pattern string
	// AllowLeadingDash lets a value start with "-". Off by default, so a
	// value can't turn into an option of the command.
	AllowLeadingDash bool

	re *regexp.Regexp
}

// Spec is one [actions.<id>] table.
type Spec struct {
	ID          string
	Description string
	// Command is an absolute path, run with execve, never through a shell.
	Command string
	// Args may hold {param} placeholders; {{ and }} are literal braces.
	Args   []string
	Params map[string]*Param
	// Env is the child's whole environment, with FOCA_ACTION added.
	Env map[string]string
	// EnvSecrets maps a variable to a secret's full name, "<vault>:<id>",
	// which the calling instance must be able to read. Values go only into
	// the child's environment.
	EnvSecrets map[string]string
	// Mask replaces the secrets in EnvSecrets, and their common encodings,
	// in stdout and stderr.
	Mask            bool
	Timeout         time.Duration
	MaxBytes        int
	Format          string
	ReturnOnFailure bool

	args [][]part
}

// part is a literal piece of an argument, or a placeholder.
type part struct {
	lit   string
	param string
}

// Display is the action's name on prompts: its description, else its id.
func (s *Spec) Display() string {
	if s.Description != "" {
		return s.Description
	}
	return s.ID
}

// SecretIDs lists the secrets the action uses, sorted, without repeats.
func (s *Spec) SecretIDs() []string {
	var ids []string
	for _, id := range s.EnvSecrets {
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// ParamNames lists the parameters, sorted.
func (s *Spec) ParamNames() []string {
	names := make([]string, 0, len(s.Params))
	for n := range s.Params {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Check validates the spec and prepares it for use. Config loading calls it;
// a spec that fails is never used.
func (s *Spec) Check() error {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if !ValidID(s.ID) {
		fail("id %q must match %s", s.ID, idPattern)
	}
	if err := plainText(s.Description, maxDesc); err != nil {
		fail("description: %v", err)
	}
	if !filepath.IsAbs(s.Command) || filepath.Clean(s.Command) != s.Command {
		fail("command %q must be a clean absolute path; PATH is never searched", s.Command)
	}
	if s.Timeout == 0 {
		s.Timeout = DefaultTimeout
	}
	if s.Timeout < MinTimeout || s.Timeout > MaxTimeout {
		fail("timeout %s is outside %s..%s", s.Timeout, MinTimeout, MaxTimeout)
	}
	if s.MaxBytes == 0 {
		s.MaxBytes = DefaultMaxBytes
	}
	if s.MaxBytes < 1 || s.MaxBytes > MaxMaxBytes {
		fail("output.max_bytes %d is outside 1..%d", s.MaxBytes, MaxMaxBytes)
	}
	switch s.Format {
	case FormatNone, FormatText, FormatJSON, FormatAWSCredProc:
	default:
		fail("output.format %q is not one of %s, %s, %s", s.Format, FormatText, FormatJSON, FormatAWSCredProc)
	}

	for name, p := range s.Params {
		if !paramPattern.MatchString(name) {
			fail("params.%s: name must match %s", name, paramPattern)
			continue
		}
		if err := p.check(); err != nil {
			fail("params.%s: %v", name, err)
		}
	}
	if len(s.Params) > MaxParams {
		fail("at most %d params", MaxParams)
	}

	used := map[string]bool{}
	s.args = make([][]part, len(s.Args))
	for i, a := range s.Args {
		parts, err := parseTemplate(a)
		if err != nil {
			fail("args[%d] %q: %v", i, a, err)
			continue
		}
		for _, p := range parts {
			if p.param == "" {
				continue
			}
			if s.Params[p.param] == nil {
				fail("args[%d] %q: placeholder {%s} is not declared in params", i, a, p.param)
			}
			used[p.param] = true
		}
		s.args[i] = parts
	}
	for _, name := range s.ParamNames() {
		if !used[name] {
			// A parameter no argument uses would be on the prompt and do
			// nothing, which misleads whoever approves it.
			fail("params.%s is declared but no argument uses it", name)
		}
	}

	for k, v := range s.Env {
		if !envPattern.MatchString(k) {
			fail("env: %q is not a valid variable name", k)
		}
		if strings.IndexByte(v, 0) >= 0 {
			fail("env.%s: value contains a NUL byte", k)
		}
	}
	if _, ok := s.Env["FOCA_ACTION"]; ok {
		fail("env: FOCA_ACTION is set by foca")
	}
	for k, id := range s.EnvSecrets {
		if !envPattern.MatchString(k) {
			fail("env_secrets: %q is not a valid variable name", k)
		}
		if k == "FOCA_ACTION" {
			fail("env_secrets: FOCA_ACTION is set by foca")
		}
		if _, ok := s.Env[k]; ok {
			fail("env_secrets.%s is also set in env", k)
		}
		if _, _, ok := secretname.Split(id); !ok {
			fail("env_secrets.%s: %q is not a secret name, <vault>:<secret>", k, id)
		}
	}
	return errors.Join(errs...)
}

func (p *Param) check() error {
	if err := plainText(p.Description, maxDesc); err != nil {
		return fmt.Errorf("description: %v", err)
	}
	switch {
	case p.Allowed != nil && p.Pattern != "":
		return errors.New("set exactly one of allowed and pattern, not both")
	case p.Allowed == nil && p.Pattern == "":
		return errors.New("set exactly one of allowed and pattern")
	case p.Allowed != nil:
		if len(p.Allowed) == 0 {
			return errors.New("allowed must not be empty")
		}
		for _, v := range p.Allowed {
			if err := p.plain(v); err != nil {
				return fmt.Errorf("allowed value %q: %v", v, err)
			}
		}
	default:
		// Compiled alone first: wrapped, an unbalanced pattern such as
		// "[a-z]+)|(.*" still compiles, and matches anything.
		if _, err := regexp.Compile(p.Pattern); err != nil {
			return fmt.Errorf("pattern: %v", err)
		}
		// Fully matched whatever the pattern says, so a missing anchor
		// can't let anything through around the part that matched.
		re, err := regexp.Compile(`^(?:` + p.Pattern + `)$`)
		if err != nil {
			return fmt.Errorf("pattern: %v", err)
		}
		p.re = re
	}
	return nil
}

// plain checks the rules every value obeys, whatever its constraint.
func (p *Param) plain(v string) error {
	switch {
	case v == "":
		return errors.New("empty")
	case len(v) > MaxParamValue:
		return fmt.Errorf("longer than %d bytes", MaxParamValue)
	case !utf8.ValidString(v):
		return errors.New("not valid UTF-8")
	case strings.HasPrefix(v, "-") && !p.AllowLeadingDash:
		return errors.New("starts with \"-\" (set allow_leading_dash to allow it)")
	}
	for _, r := range v {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return errors.New("contains a control or format character")
		}
		// Line and paragraph separators break a prompt like a newline, and
		// other spaces pass for a plain one there.
		if r != ' ' && unicode.Is(unicode.Z, r) {
			return errors.New("contains a separator character other than a plain space")
		}
	}
	return nil
}

// plainText checks host-written text that ends up on a prompt.
func plainText(s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("longer than %d bytes", max)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			return errors.New("contains a control or format character")
		}
	}
	return nil
}

// parseTemplate splits an argument into literals and {param} placeholders.
// {{ and }} stand for literal braces; any other brace is an error.
func parseTemplate(s string) ([]part, error) {
	var parts []part
	var lit strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '{' && i+1 < len(s) && s[i+1] == '{':
			lit.WriteByte('{')
			i++
		case c == '}' && i+1 < len(s) && s[i+1] == '}':
			lit.WriteByte('}')
			i++
		case c == '{':
			end := strings.IndexByte(s[i:], '}')
			if end < 0 {
				return nil, errors.New("unclosed {")
			}
			name := s[i+1 : i+end]
			if !paramPattern.MatchString(name) {
				return nil, fmt.Errorf("{%s} is not a parameter name (write {{ for a literal brace)", name)
			}
			if lit.Len() > 0 {
				parts = append(parts, part{lit: lit.String()})
				lit.Reset()
			}
			parts = append(parts, part{param: name})
			i += end
		case c == '}':
			return nil, errors.New("unmatched } (write }} for a literal brace)")
		case c == 0:
			return nil, errors.New("contains a NUL byte")
		default:
			lit.WriteByte(c)
		}
	}
	if lit.Len() > 0 || len(parts) == 0 {
		parts = append(parts, part{lit: lit.String()})
	}
	return parts, nil
}

// ParamError is a caller's parameter that the spec refuses.
type ParamError struct {
	Param string
	Msg   string
}

func (e *ParamError) Error() string {
	if e.Param == "" {
		return e.Msg
	}
	return "param " + e.Param + ": " + e.Msg
}

// Validate checks a caller's parameters: every declared one is present,
// nothing else is, and each value meets its constraint. The result is a
// fresh map the caller may trust.
func (s *Spec) Validate(params map[string]string) (map[string]string, error) {
	var unknown []string
	for name := range params {
		if s.Params[name] == nil {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		for i, n := range unknown {
			unknown[i] = quoteShort(n)
		}
		return nil, &ParamError{Msg: "unknown params: " + strings.Join(unknown, ", ")}
	}
	out := make(map[string]string, len(s.Params))
	for _, name := range s.ParamNames() {
		p := s.Params[name]
		v, ok := params[name]
		if !ok {
			return nil, &ParamError{Param: name, Msg: "missing"}
		}
		if err := p.plain(v); err != nil {
			return nil, &ParamError{Param: name, Msg: fmt.Sprintf("%s: %v", quoteShort(v), err)}
		}
		switch {
		case p.Allowed != nil:
			if !slices.Contains(p.Allowed, v) {
				return nil, &ParamError{Param: name, Msg: fmt.Sprintf("%s is not one of the allowed values", quoteShort(v))}
			}
		case !p.re.MatchString(v):
			return nil, &ParamError{Param: name, Msg: fmt.Sprintf("%s doesn't match the required pattern", quoteShort(v))}
		}
		out[name] = v
	}
	return out, nil
}

// quoteShort quotes caller data for an error or the audit log: escaped,
// and cut to 64 bytes first.
func quoteShort(s string) string {
	if len(s) > 64 {
		s = s[:64] + "…"
	}
	return strconv.Quote(s)
}

// Argv fills the argument template with validated params. A placeholder
// never splits or joins arguments: each template element is one argument.
// argv[0] is the configured command path.
func (s *Spec) Argv(params map[string]string) []string {
	argv := []string{s.Command}
	for _, parts := range s.args {
		var b strings.Builder
		for _, p := range parts {
			if p.param != "" {
				b.WriteString(params[p.param])
			} else {
				b.WriteString(p.lit)
			}
		}
		argv = append(argv, b.String())
	}
	return argv
}

// Environ is the child's whole environment, without the secret values,
// which the provider adds itself: env from config plus FOCA_ACTION.
func (s *Spec) Environ() []string {
	keys := make([]string, 0, len(s.Env))
	for k := range s.Env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys)+1)
	for _, k := range keys {
		out = append(out, k+"="+s.Env[k])
	}
	return append(out, "FOCA_ACTION="+s.ID)
}

// DescribeParams writes validated params for a prompt: name=value, sorted
// by name. A value with characters other than plain word characters is
// quoted, so it can't blur into the sentence around it.
func DescribeParams(params map[string]string) string {
	names := make([]string, 0, len(params))
	for n := range params {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, len(names))
	for i, n := range names {
		v := params[n]
		if !plainWord(v) {
			v = strconv.Quote(v)
		}
		parts[i] = n + "=" + v
	}
	return strings.Join(parts, ", ")
}

func plainWord(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._/:@+-", r)) {
			return false
		}
	}
	return s != ""
}

// CanonicalParams is params in one stable form, for grant keys: a grant for
// one set of values never covers another.
func CanonicalParams(params map[string]string) string {
	names := make([]string, 0, len(params))
	for n := range params {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(strconv.Quote(n))
		b.WriteByte('=')
		b.WriteString(strconv.Quote(params[n]))
		b.WriteByte(';')
	}
	return b.String()
}
