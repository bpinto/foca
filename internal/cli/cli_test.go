package cli

import (
	"bytes"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

// testEnv is a non-interactive environment with captured output.
func testEnv(t *testing.T, vars map[string]string) (*Env, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	var out, errb bytes.Buffer
	return &Env{
		Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb,
		Getenv: func(k string) string { return vars[k] },
		ReadPassword: func() ([]byte, error) {
			t.Fatal("prompted in a non-interactive test")
			return nil, nil
		},
		Exec: func(string, []string, []string) error {
			t.Fatal("exec in a test that doesn't expect it")
			return nil
		},
	}, &out, &errb
}

// No flag or argument can carry a secret value: values come only from a
// hidden prompt, stdin or a file (design D21).
func TestNoSecretInArgv(t *testing.T) {
	env, _, _ := testEnv(t, nil)
	k, err := Parser(&CLI{}, env)
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"value", "secret", "password", "passphrase", "token", "recovery-passphrase", "key", "data"}
	var walk func(n *kong.Node)
	walk = func(n *kong.Node) {
		for _, f := range n.Flags {
			for _, b := range banned {
				if f.Name == b && !f.IsBool() {
					t.Errorf("%s: flag --%s takes a value that could be a secret", n.Path(), f.Name)
				}
			}
		}
		for _, p := range n.Positional {
			for _, b := range banned {
				if strings.Contains(strings.ToLower(p.Name), b) {
					t.Errorf("%s: positional %s could carry a secret", n.Path(), p.Name)
				}
			}
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(k.Model.Node)

	// The host commands take exactly one positional, the name. A value typed
	// after it is a usage error, not a secret.
	for _, args := range [][]string{
		{"add", "github-pat", "ghp_value"},
		{"edit", "github-pat", "ghp_value"},
		{"remove", "github-pat", "ghp_value"},
		{"init", "passphrase"},
	} {
		env, _, errb := testEnv(t, nil)
		if code := Main(args, env, "test"); code != 2 {
			t.Errorf("%v: exit %d, want a usage error", args, code)
		}
		if strings.Contains(errb.String(), "ghp_value") && !strings.Contains(errb.String(), "unexpected argument") {
			t.Errorf("%v: %s", args, errb.String())
		}
	}
}

// get refuses a terminal before contacting the service, so nobody is asked
// to approve a read that would only be thrown away.
func TestGetRefusesTerminalBeforeAsking(t *testing.T) {
	env, out, errb := testEnv(t, nil)
	env.StdoutTTY = true
	code := Main([]string{"get", "--socket", "/nonexistent/sock", "common:github-pat"}, env, "test")
	if code != 1 || !strings.Contains(errb.String(), "refusing to write a secret to a terminal") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatal("wrote to the terminal")
	}
	// With --output the terminal doesn't matter (the dial fails instead).
	env, _, errb = testEnv(t, nil)
	env.StdoutTTY = true
	Main([]string{"get", "--socket", "/nonexistent/sock", "-o", filepath.Join(t.TempDir(), "f"), "common:github-pat"}, env, "test")
	if strings.Contains(errb.String(), "terminal") {
		t.Fatalf("--output still refused: %s", errb.String())
	}
}

// A shell redirect makes the file under the umask: a value written to a
// file others can read gets a warning, a private file none.
func TestGetWarnsWhenStdoutIsAFileOthersCanRead(t *testing.T) {
	for mode, warn := range map[os.FileMode]bool{0o644: true, 0o640: true, 0o600: false} {
		path := filepath.Join(t.TempDir(), "out")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, mode)
		if err != nil {
			t.Fatal(err)
		}
		os.Chmod(path, mode) // whatever the test's umask
		env, _, errb := testEnv(t, nil)
		env.Stdout = f
		Main([]string{"get", "--socket", "/nonexistent/sock", "common:github-pat"}, env, "test")
		f.Close()
		if got := strings.Contains(errb.String(), "warning: stdout is a file others may read"); got != warn {
			t.Errorf("mode %04o: %s", mode, errb.String())
		}
	}
}

func TestGetArgumentRules(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"get", "v:a", "v:b"}, "exactly one secret"},
		{[]string{"get", "X=v:a"}, "only applies to --format env"},
		{[]string{"get", "-f", "env", "1x=v:a"}, "not a valid variable name"},
		{[]string{"get", "-f", "env", "X=v:a", "X=v:b"}, "variable X is set twice"},
		{[]string{"get", "-f", "env", "v:npm-token", "w:npm-token"}, "variable NPM_TOKEN is set twice"},
		{[]string{"get", "../etc"}, "invalid secret name"},
		{[]string{"get", "github-pat"}, "name secrets <vault>:<secret>"},
		{[]string{"run", "-e", "GH=github-pat", "--", "true"}, "name secrets <vault>:<secret>"},
		{[]string{"get", "-f", "yaml", "v:a"}, "must be one of"},
	} {
		env, _, errb := testEnv(t, nil)
		Main(append(tc.args, "--socket", "/nonexistent"), env, "test")
		if !strings.Contains(errb.String(), tc.want) {
			t.Errorf("%v: %s", tc.args, errb.String())
		}
	}
}

func TestReadValueSources(t *testing.T) {
	// stdin: one trailing line break dropped.
	env, _, _ := testEnv(t, nil)
	env.Stdin = strings.NewReader("ghp_x\r\n")
	if b, err := readValue(env, "v", ""); err != nil || string(b) != "ghp_x" {
		t.Fatalf("stdin: %q %v", b, err)
	}
	// file: byte for byte.
	path := filepath.Join(t.TempDir(), "v")
	os.WriteFile(path, []byte("line\n"), 0o600)
	if b, err := readValue(env, "v", path); err != nil || string(b) != "line\n" {
		t.Fatalf("file: %q %v", b, err)
	}
	// hidden prompt, only with stdin and stderr on a terminal.
	env, _, errb := testEnv(t, nil)
	env.StdinTTY, env.StderrTTY = true, true
	env.ReadPassword = func() ([]byte, error) { return []byte("typed"), nil }
	if b, err := readValue(env, "Value for x", ""); err != nil || string(b) != "typed" {
		t.Fatalf("prompt: %q %v", b, err)
	}
	if !strings.Contains(errb.String(), "Value for x (input hidden)") || strings.Contains(errb.String(), "typed") {
		t.Fatalf("prompt text %q", errb.String())
	}
	// stdin is a terminal but stderr isn't: no prompt, and the error names
	// the alternatives instead of hanging.
	env, _, _ = testEnv(t, nil)
	env.StdinTTY = true
	if _, err := readValue(env, "v", ""); err == nil || !strings.Contains(err.Error(), "--from-file") || !strings.Contains(err.Error(), "stdin") {
		t.Fatalf("no tty: %v", err)
	}
	env, _, _ = testEnv(t, nil)
	env.Stdin = strings.NewReader("\n")
	if _, err := readValue(env, "v", ""); err == nil {
		t.Fatal("empty value accepted")
	}
	env.Stdin = bytes.NewReader(make([]byte, maxValue+1))
	if _, err := readValue(env, "v", ""); err == nil {
		t.Fatal("oversized value accepted")
	}
}

func TestReadPassphraseConfirms(t *testing.T) {
	env, _, _ := testEnv(t, nil)
	env.StdinTTY, env.StderrTTY = true, true
	answers := [][]byte{[]byte("one"), []byte("two")}
	env.ReadPassword = func() ([]byte, error) { a := answers[0]; answers = answers[1:]; return a, nil }
	if _, err := readPassphrase(env, "recovery passphrase"); err == nil || !strings.Contains(err.Error(), "don't match") {
		t.Fatalf("mismatch: %v", err)
	}
	env, _, _ = testEnv(t, nil)
	env.Stdin = strings.NewReader("pass phrase\nrest")
	if b, err := readPassphrase(env, "p"); err != nil || string(b) != "pass phrase" {
		t.Fatalf("stdin: %q %v", b, err)
	}
}

func TestOutputFileIsPrivateAndNoSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out")
	os.WriteFile(path, []byte("old content that is longer"), 0o644)
	// A reader that opened the file earlier, and a hard link to it, keep
	// the old file: the secret goes into a new one.
	reader, _ := os.Open(path)
	defer reader.Close()
	hard := filepath.Join(dir, "hard")
	os.Link(path, hard)
	if err := writeOutput(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	b, _ := os.ReadFile(path)
	if fi.Mode().Perm() != 0o600 || string(b) != "new" {
		t.Fatalf("mode %o content %q", fi.Mode().Perm(), b)
	}
	if b, _ := os.ReadFile(hard); string(b) != "old content that is longer" {
		t.Fatalf("written through a hard link: %q", b)
	}
	if b, _ := io.ReadAll(reader); string(b) != "old content that is longer" {
		t.Fatalf("an earlier reader saw %q", b)
	}

	link := filepath.Join(dir, "link")
	os.Symlink(path, link)
	for _, bad := range []string{link, dir, "/dev/null", filepath.Join(dir, "missing", "out"), filepath.Join(path, "x")} {
		if err := writeOutput(bad, []byte("x")); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if b, _ := os.ReadFile(path); string(b) != "new" {
		t.Fatalf("symlink followed: %q", b)
	}
}

// A destination that can't take the secret is refused before the service
// is asked, so nobody approves a read that would only be thrown away.
func TestGetRefusesABadOutputBeforeAsking(t *testing.T) {
	// Under /tmp: macOS limits socket paths to 104 bytes, and t.TempDir()
	// there is longer.
	sockDir, err := os.MkdirTemp("/tmp", "foca")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	sock := filepath.Join(sockDir, "s.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// Every connection is closed at once, so a client that did dial fails
	// fast instead of waiting for an answer.
	dialled := make(chan struct{}, 1)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
			select {
			case dialled <- struct{}{}:
			default:
			}
		}
	}()
	dir := t.TempDir()
	link := filepath.Join(dir, "link")
	os.Symlink(filepath.Join(dir, "target"), link)
	for _, bad := range []string{dir, link, "/dev/tty", filepath.Join(dir, "missing", "out")} {
		env, _, errb := testEnv(t, nil)
		if code := Main([]string{"get", "--socket", sock, "-o", bad, "github-pat"}, env, "test"); code != 1 {
			t.Fatalf("%s: exit %d: %s", bad, code, errb.String())
		}
	}
	select {
	case <-dialled:
		t.Fatal("the service was contacted")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestSocketDiscoveryOrder(t *testing.T) {
	home := t.TempDir()
	vars := map[string]string{"HOME": home, "FOCA_RUNTIME_DIR": "/run/f", "FOCA_CONFIG": "/nonexistent"}
	g := &Globals{}
	env, _, _ := testEnv(t, vars)
	if _, err := g.socketPath(env); err == nil || !strings.Contains(err.Error(), "FOCA_SOCK") {
		t.Fatalf("nothing configured: %v", err)
	}
	// Only a socket found in the runtime directory must be served by this
	// user; one given or forwarded is taken as is.
	os.WriteFile(filepath.Join(home, ".foca.sock"), nil, 0o600)
	if p, own, _ := g.findSocket(env); p != filepath.Join(home, ".foca.sock") || own {
		t.Fatalf("forwarded socket: %s own=%v", p, own)
	}
	vars["FOCA_INSTANCE"] = "dev"
	if p, own, _ := g.findSocket(env); p != "/run/f/dev/client.sock" || !own {
		t.Fatalf("instance: %s own=%v", p, own)
	}
	vars["FOCA_SOCK"] = "/x.sock"
	if p, own, _ := g.findSocket(env); p != "/x.sock" || own {
		t.Fatalf("FOCA_SOCK: %s own=%v", p, own)
	}
	g.Socket = "/flag.sock"
	if p, own, _ := g.findSocket(env); p != "/flag.sock" || own {
		t.Fatalf("--socket: %s own=%v", p, own)
	}
	vars["FOCA_SOCK"], g.Socket, vars["FOCA_INSTANCE"] = "", "", "../x"
	if _, err := g.socketPath(env); err == nil {
		t.Fatal("path in instance name accepted")
	}
}

// huh and its terminal UI stack are for the CLI only; the service never
// links them (design §15).
func TestServiceDoesNotImportCLIUI(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/bpinto/foca/internal/server/...").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, banned := range []string{"github.com/charmbracelet/", "github.com/alecthomas/kong", "/internal/cli"} {
			if strings.Contains(dep, banned) {
				t.Errorf("internal/server depends on %s", dep)
			}
		}
	}
}

func TestVersion(t *testing.T) {
	env, out, _ := testEnv(t, nil)
	if Main([]string{"version"}, env, "1.2.3") != 0 || out.String() != "foca 1.2.3\n" {
		t.Fatalf("%q", out.String())
	}
	env, out, _ = testEnv(t, nil)
	if code := Main([]string{"--help"}, env, "x"); code != 0 || !strings.Contains(out.String(), "Usage: foca") {
		t.Fatalf("help: %d %q", code, out.String())
	}
}

func TestPolicyExplain(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.toml")
	os.WriteFile(cfg, []byte(`version = 1
[plugins]
authenticator = "fake"
platform_events = "none"
[vaults.common]
[vaults.common.policy]
approval = "reuse"
window = "2h"
[instances.dev]
realm = { kind = "vm" }
expose = ["common:github-pat"]
[instances.work]
realm = { kind = "vm" }
expose = ["common:*"]
[instances.work.policy]
approval = "reuse"
window = "30m"
scope = "connection"
`), 0o600)
	env, out, errb := testEnv(t, map[string]string{"FOCA_CONFIG": cfg, "FOCA_DATA_DIR": dir, "FOCA_RUNTIME_DIR": dir})
	if code := Main([]string{"policy", "explain"}, env, "test"); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(out.String(), "Platform events: none. Grants can't be wiped") ||
		strings.Contains(out.String(), "reuse for") {
		t.Fatalf("without platform events, explain promised reuse:\n%s", out)
	}

	os.WriteFile(cfg, bytes.Replace(mustRead(t, cfg), []byte(`platform_events = "none"`), []byte(`platform_events = "logind"`), 1), 0o600)
	env, out, _ = testEnv(t, map[string]string{"FOCA_CONFIG": cfg, "FOCA_DATA_DIR": dir, "FOCA_RUNTIME_DIR": dir})
	if code := Main([]string{"policy", "explain", "common:github-pat", "common:npm-token"}, env, "test"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	want := `Platform events: logind. Reuse applies only while it reports sleep and screen lock; otherwise every access asks.

Instance dev (VM dev), vault common
  common:github-pat  one approval allows reuse for 2h by anything in VM dev
  common:npm-token   not exposed to this instance

Instance work (VM work), vault common
  common:github-pat  one approval allows reuse for 30m on the same connection
  common:npm-token   one approval allows reuse for 30m on the same connection
`
	if out.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
