package command

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/action"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/provider/static"
	"github.com/bpinto/foca/internal/plugins/store/memory"
)

const token = "ghp_S3cr3t/with+chars=and spaces?&"

// script writes an executable sh script and returns its path.
func script(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "action.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func secrets(t *testing.T) plugin.Provider {
	t.Helper()
	store := memory.New()
	ctx := context.Background()
	store.Put(ctx, nil, plugin.SecretMeta{ID: "github-pat", DisplayName: "GitHub PAT"}, plugin.SecretValue{Bytes: []byte(token)})
	store.Put(ctx, nil, plugin.SecretMeta{ID: "hidden"}, plugin.SecretValue{Bytes: []byte("h")})
	store.Put(ctx, nil, plugin.SecretMeta{ID: "nul"}, plugin.SecretValue{Bytes: []byte("a\x00b")})
	store.Put(ctx, nil, plugin.SecretMeta{ID: "short"}, plugin.SecretValue{Bytes: []byte("x")})
	return static.NewVaults(static.New("v", store, static.Exposure{IDs: []string{"github-pat", "nul", "short"}}, nil))
}

func provider(t *testing.T, specs ...*action.Spec) *Provider {
	t.Helper()
	for _, s := range specs {
		if s.Env == nil {
			// The environment is only what config gives; scripts need a PATH.
			s.Env = map[string]string{"PATH": os.Getenv("PATH")}
		}
		if err := s.Check(); err != nil {
			t.Fatal(err)
		}
	}
	return New(specs, secrets(t)).WithGrace(200 * time.Millisecond)
}

func run(t *testing.T, p *Provider, id string, params map[string]string) (plugin.Result, error) {
	t.Helper()
	ctx := context.Background()
	rs, errs, err := p.Resolve(ctx, []string{id})
	if err != nil || errs[0] != nil {
		t.Fatalf("resolve: %v %v", err, errs)
	}
	v, err := p.Validate(ctx, rs[0], params)
	if err != nil {
		t.Fatal(err)
	}
	return p.Serve(ctx, rs[0], v)
}

func reason(err error) string {
	var re *plugin.RunError
	if errors.As(err, &re) {
		return re.Reason
	}
	return ""
}

func TestEnvironmentIsExactlyConfig(t *testing.T) {
	os.Setenv("FOCA_PROBE", "leak")
	defer os.Unsetenv("FOCA_PROBE")
	p := provider(t, &action.Spec{ID: "env", Command: "/usr/bin/env",
		Env: map[string]string{"LANG": "C", "PATH": "/nowhere"}, EnvSecrets: map[string]string{"GH_TOKEN": "v:github-pat"}, Mask: false})
	res, err := run(t, p, "env", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(res.Value)), "\n")
	slices.Sort(got)
	want := []string{"FOCA_ACTION=env", "GH_TOKEN=" + token, "LANG=C", "PATH=/nowhere"}
	if !slices.Equal(got, want) {
		t.Fatalf("environment\n got %q\nwant %q", got, want)
	}
}

func TestStdinIsDevNullAndCwdIsRoot(t *testing.T) {
	p := provider(t, &action.Spec{ID: "io", Command: script(t, `cat; pwd; readlink /proc/self/fd/0 2>/dev/null || echo /dev/null`)})
	res, err := run(t, p, "io", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Value) != "/\n/dev/null\n" {
		t.Fatalf("got %q", res.Value)
	}
}

func TestParamsReachArgvWithoutAShell(t *testing.T) {
	sh := script(t, `for a in "$@"; do printf '[%s]\n' "$a"; done`)
	p := provider(t, &action.Spec{ID: "args", Command: sh,
		Args:   []string{"--repo={repo}", "{repo}", "lit{{x}}"},
		Params: map[string]*action.Param{"repo": {Pattern: `[^/]+/.+`}}})
	res, err := run(t, p, "args", map[string]string{"repo": "a/b; touch /tmp/pwned $(id) `id` *"})
	if err != nil {
		t.Fatal(err)
	}
	want := "[--repo=a/b; touch /tmp/pwned $(id) `id` *]\n[a/b; touch /tmp/pwned $(id) `id` *]\n[lit{x}]\n"
	if string(res.Value) != want {
		t.Fatalf("argv\n got %q\nwant %q", res.Value, want)
	}
	if _, err := os.Stat("/tmp/pwned"); err == nil {
		t.Fatal("a param reached a shell")
	}
}

// pidAlive reports whether pid still runs (a zombie counts as gone).
func pidAlive(pid int) bool {
	if syscall.Kill(pid, 0) != nil {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true // no procfs: trust kill
	}
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+1:]))
	return len(f) > 0 && f[0] != "Z"
}

func waitGone(pid int) bool {
	for i := 0; i < 50; i++ {
		if !pidAlive(pid) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestTimeoutKillsTheProcessGroup(t *testing.T) {
	for name, body := range map[string]string{
		"children":             `sleep 30 & echo $! > "$1"; sleep 30`,
		"children ignore TERM": `(trap '' TERM; sleep 30) & echo $! > "$1"; trap '' TERM; sleep 30`,
		"leader exits on TERM": `(trap '' TERM; exec sleep 30) & echo $! > "$1"; wait`,
	} {
		t.Run(name, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "pid")
			p := provider(t, &action.Spec{ID: "slow", Command: script(t, body), Args: []string{pidFile}, Timeout: time.Second})
			start := time.Now()
			res, err := run(t, p, "slow", nil)
			if reason(err) != plugin.RunTimeout || !res.Run.TimedOut {
				t.Fatalf("got %v %+v", err, res.Run)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("took %s", d)
			}
			b, _ := os.ReadFile(pidFile)
			pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
			if pid == 0 || !waitGone(pid) {
				t.Fatalf("child %d of the group outlived the timeout", pid)
			}
		})
	}
}

func TestCancelKillsTheProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	p := provider(t, &action.Spec{ID: "slow", Command: script(t, `sleep 30 & echo $! > "$1"; wait`), Args: []string{pidFile}})
	ctx, cancel := context.WithCancel(context.Background())
	rs, _, _ := p.Resolve(ctx, []string{"slow"})
	time.AfterFunc(300*time.Millisecond, cancel)
	_, err := p.Serve(ctx, rs[0], nil)
	if reason(err) != plugin.RunCancelled {
		t.Fatalf("got %v", err)
	}
	b, _ := os.ReadFile(pidFile)
	if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid == 0 || !waitGone(pid) {
		t.Fatalf("child %d outlived the cancel", pid)
	}
}

func TestOutputLimitsAndExitCodes(t *testing.T) {
	p := provider(t,
		&action.Spec{ID: "big", Command: script(t, `head -c 100000 /dev/zero; sleep 30`), MaxBytes: 1000},
		&action.Spec{ID: "fail", Command: script(t, `echo out; echo err >&2; exit 3`)},
		&action.Spec{ID: "fail-out", Command: script(t, `echo out; exit 3`), ReturnOnFailure: true},
	)
	start := time.Now()
	if _, err := run(t, p, "big", nil); reason(err) != plugin.RunOutputTooLarge || time.Since(start) > 5*time.Second {
		t.Fatalf("big: %v after %s", err, time.Since(start))
	}
	res, err := run(t, p, "fail", nil)
	if err != nil || res.Run.ExitCode != 3 || res.Value != nil || res.Run.StdoutReturned || string(res.Run.StderrTail) != "err\n" {
		t.Fatalf("fail: %v %+v %q", err, res.Run, res.Value)
	}
	if res.Run.StderrSHA256 == "" || res.Run.StderrBytes != 4 || res.Run.StdoutBytes != 4 {
		t.Fatalf("fail: stderr is logged as length and hash: %+v", res.Run)
	}
	res, err = run(t, p, "fail-out", nil)
	if err != nil || res.Run.ExitCode != 3 || string(res.Value) != "out\n" || !res.Run.StdoutReturned {
		t.Fatalf("fail-out: %v %+v %q", err, res.Run, res.Value)
	}
}

func TestOutputValidation(t *testing.T) {
	good := `{"Version":1,"AccessKeyId":"AKIA","SecretAccessKey":"s"}`
	p := provider(t,
		&action.Spec{ID: "good", Command: script(t, "printf '%s' '"+good+"'"), Format: action.FormatAWSCredProc},
		&action.Spec{ID: "bad", Command: script(t, `echo '{"Version":1}'`), Format: action.FormatAWSCredProc},
		&action.Spec{ID: "badtext", Command: script(t, `printf 'a\033[2Jb'`), Format: action.FormatText},
	)
	if res, err := run(t, p, "good", nil); err != nil || string(res.Value) != good {
		t.Fatalf("good: %v %q", err, res.Value)
	}
	for _, id := range []string{"bad", "badtext"} {
		res, err := run(t, p, id, nil)
		if reason(err) != plugin.RunOutputInvalid || res.Value != nil {
			t.Fatalf("%s: %v %q", id, err, res.Value)
		}
	}
}

func TestMaskedOutputContainsNoSecretEncoding(t *testing.T) {
	v := []byte(token)
	h := hex.EncodeToString(v)
	encs := []string{token, base64.StdEncoding.EncodeToString(v), base64.URLEncoding.EncodeToString(v),
		base64.RawStdEncoding.EncodeToString(v), base64.RawURLEncoding.EncodeToString(v), h, strings.ToUpper(h),
		url.QueryEscape(token), url.PathEscape(token)}
	env := map[string]string{"PATH": os.Getenv("PATH")}
	body := ""
	for i, e := range encs {
		k := "E" + strconv.Itoa(i)
		env[k] = e
		body += `printf 'out %s.\n' "$` + k + `"; printf 'err %s.\n' "$` + k + `" >&2` + "\n"
	}
	// Push part of the token across the start of the stderr tail.
	body += `head -c 4090 /dev/zero | tr '\0' x >&2; printf '%s' "$GH_TOKEN" >&2` + "\n"
	body += `printf '%s' "$GH_TOKEN" | head -c 20 >&2; head -c 4093 /dev/zero | tr '\0' y >&2` + "\n"
	p := provider(t, &action.Spec{ID: "leaky", Command: script(t, body), Env: env,
		EnvSecrets: map[string]string{"GH_TOKEN": "v:github-pat"}, Mask: true})
	res, err := run(t, p, "leaky", nil)
	if err != nil {
		t.Fatal(err)
	}
	out, tail := string(res.Value), string(res.Run.StderrTail)
	for _, e := range encs {
		if strings.Contains(out, e) || strings.Contains(tail, e) {
			t.Errorf("%q survived masking", e)
		}
	}
	if strings.Contains(tail, token[len(token)-8:]) {
		t.Errorf("part of the token shows in the tail")
	}
	if strings.Count(out, "[hidden:v:github-pat]") != len(encs) || !res.Run.Masked {
		t.Fatalf("stdout: %q", out)
	}
	if len(tail) > action.StderrTail+len("[hidden:v:github-pat]") {
		t.Fatalf("tail is %d bytes", len(tail))
	}
	// Output that may hold a secret isn't hashed into the audit log.
	if res.Run.StderrSHA256 != "" {
		t.Fatal("stderr of an action using secrets must not be hashed")
	}
}

func TestSecretsResolveUnderTheInstancesExposure(t *testing.T) {
	p := provider(t,
		&action.Spec{ID: "uses-hidden", Command: "/usr/bin/env", EnvSecrets: map[string]string{"T": "v:hidden"}},
		&action.Spec{ID: "uses-missing", Command: "/usr/bin/env", EnvSecrets: map[string]string{"T": "v:nope"}},
		&action.Spec{ID: "uses-nul", Command: "/usr/bin/env", EnvSecrets: map[string]string{"T": "v:nul"}},
		&action.Spec{ID: "uses-pat", Command: "/usr/bin/env", EnvSecrets: map[string]string{"T": "v:github-pat"}},
	)
	rs, errs, err := p.Resolve(context.Background(), []string{"uses-hidden", "uses-missing", "nope", "uses-pat"})
	if err != nil {
		t.Fatal(err)
	}
	var use *plugin.UseError
	if !errors.As(errs[0], &use) || use.Secret != "v:hidden" || !errors.Is(errs[0], plugin.ErrNotExposed) {
		t.Fatalf("hidden: %v", errs[0])
	}
	if !errors.As(errs[1], &use) || errors.Is(errs[1], plugin.ErrNotExposed) || !errors.Is(errs[1], plugin.ErrNotFound) {
		t.Fatalf("missing: %v", errs[1])
	}
	if !errors.Is(errs[2], plugin.ErrNotFound) || errs[3] != nil {
		t.Fatalf("errs %v", errs)
	}
	if len(rs[3].Uses) != 1 || rs[3].Uses[0].Display != "GitHub PAT" {
		t.Fatalf("uses %+v", rs[3].Uses)
	}
	if _, err := run(t, p, "uses-nul", nil); reason(err) != plugin.RunSecretUnreadable {
		t.Fatalf("NUL: %v", err)
	}
}

func TestUntrustedCommandIsRefused(t *testing.T) {
	sh := script(t, "echo hi")
	p := provider(t, &action.Spec{ID: "a", Command: sh}, &action.Spec{ID: "missing", Command: "/nonexistent/cmd"})
	if _, err := run(t, p, "a", nil); err != nil {
		t.Fatal(err)
	}
	// Replaced after start-up by something others can write: refused at run time.
	os.Chmod(sh, 0o722)
	if _, err := run(t, p, "a", nil); reason(err) != plugin.RunCommandUntrusted {
		t.Fatalf("group-writable: %v", err)
	}
	os.Chmod(sh, 0o600)
	if _, err := run(t, p, "a", nil); reason(err) != plugin.RunCommandUntrusted {
		t.Fatalf("not executable: %v", err)
	}
	if _, err := run(t, p, "missing", nil); reason(err) != plugin.RunCommandUntrusted {
		t.Fatalf("missing: %v", err)
	}
}

func TestListShowsParamSchemas(t *testing.T) {
	p := provider(t, &action.Spec{ID: "b", Command: "/usr/bin/env", Description: "B",
		Args: []string{"{x}"}, Params: map[string]*action.Param{"x": {Allowed: []string{"1", "2"}, Description: "an x"}}},
		&action.Spec{ID: "a", Command: "/usr/bin/env"})
	rs, _ := p.List(context.Background())
	if len(rs) != 2 || rs[0].Ref.ID != "a" || rs[1].Ref.Display != "B" || len(rs[1].Params) != 1 ||
		rs[1].Params[0].Description != "an x" || !slices.Equal(rs[1].Params[0].Allowed, []string{"1", "2"}) {
		t.Fatalf("list %+v", rs)
	}
}

// Marks are longer than a one-byte secret, so masking can make the output
// grow past what one message carries. That is refused, not sent.
func TestMaskedOutputStaysWithinTheLimit(t *testing.T) {
	p := provider(t, &action.Spec{ID: "grow", Command: script(t, `head -c 100000 /dev/zero | tr '\0' x; head -c 100000 /dev/zero | tr '\0' x >&2`),
		MaxBytes: 100000, EnvSecrets: map[string]string{"S": "v:short"}, Mask: true})
	res, err := run(t, p, "grow", nil)
	if reason(err) != plugin.RunOutputTooLarge || res.Value != nil {
		t.Fatalf("got %v", err)
	}
	if len(res.Run.StderrTail) > action.StderrTail || strings.Contains(string(res.Run.StderrTail), "x") {
		t.Fatalf("tail %d bytes", len(res.Run.StderrTail))
	}
}

// An action names each secret with its vault, so the same id from two vaults
// is two secrets, each read from its own vault.
func TestSecretsComeFromTheVaultTheyName(t *testing.T) {
	ctx := context.Background()
	a, b := memory.New(), memory.New()
	a.Put(ctx, nil, plugin.SecretMeta{ID: "tok"}, plugin.SecretValue{Bytes: []byte("from-a")})
	b.Put(ctx, nil, plugin.SecretMeta{ID: "tok"}, plugin.SecretValue{Bytes: []byte("from-b")})
	vaults := static.NewVaults(
		static.New("a", a, static.Exposure{All: true}, nil),
		static.New("b", b, static.Exposure{All: true}, nil),
	)
	s := &action.Spec{ID: "env", Command: "/usr/bin/env", Mask: false,
		Env: map[string]string{"PATH": "/nowhere"}, EnvSecrets: map[string]string{"ONE": "a:tok", "TWO": "b:tok"}}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	p := New([]*action.Spec{s}, vaults)
	rs, errs, err := p.Resolve(ctx, []string{"env"})
	if err != nil || errs[0] != nil {
		t.Fatalf("resolve: %v %v", err, errs)
	}
	if len(rs[0].Uses) != 2 || rs[0].Uses[0].ID != "a:tok" || rs[0].Uses[1].ID != "b:tok" {
		t.Fatalf("uses %+v", rs[0].Uses)
	}
	res, err := p.Serve(ctx, rs[0], nil)
	if err != nil || !strings.Contains(string(res.Value), "ONE=from-a\n") || !strings.Contains(string(res.Value), "TWO=from-b\n") {
		t.Fatalf("serve: %q %v", res.Value, err)
	}
}

// A child an action with secrets leaves running would keep them in its
// environment. It goes with the command, and the result doesn't wait for
// the pipes it holds.
func TestSecretsActionLeavesNoChildBehind(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	p := provider(t, &action.Spec{ID: "bg", Command: script(t, `sleep 30 & echo $! > "$1"`), Args: []string{pidFile},
		EnvSecrets: map[string]string{"T": "v:github-pat"}}).WithGrace(5 * time.Second)
	start := time.Now()
	if _, err := run(t, p, "bg", nil); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s: the result waited for the child's pipes", d)
	}
	b, _ := os.ReadFile(pidFile)
	if pid, _ := strconv.Atoi(strings.TrimSpace(string(b))); pid == 0 || !waitGone(pid) {
		t.Fatalf("child %d of an action with secrets outlived it", pid)
	}
}

// An action without secrets may start something meant to outlive it, such
// as a browser for a login, so its group is left alone after a normal exit.
func TestActionWithoutSecretsLeavesItsChildrenAlone(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	p := provider(t, &action.Spec{ID: "bg", Command: script(t, `sleep 30 >/dev/null 2>&1 & echo $! > "$1"`), Args: []string{pidFile}})
	if _, err := run(t, p, "bg", nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(pidFile)
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if pid == 0 {
		t.Fatal("no child pid")
	}
	defer syscall.Kill(pid, syscall.SIGKILL)
	time.Sleep(200 * time.Millisecond)
	if !pidAlive(pid) {
		t.Fatalf("child %d of an action without secrets was killed", pid)
	}
}
