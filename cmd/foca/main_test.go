//go:build foca_testing && linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// These tests run the real binary, built with the test tag, as separate
// processes: serve, signals, the pid file and a real terminal.

const config = `version = 1
[plugins]
authenticator = "fake"
secret_store = "vault-file"
key_protector = "file"
insecure_file_protector = true
[instances.dev]
realm = { kind = "host" }
`

type proc struct {
	t    *testing.T
	bin  string
	base string
	env  []string
}

func setup(t *testing.T) *proc {
	t.Helper()
	base, err := os.MkdirTemp("", "fbin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	os.Chmod(base, 0o700)
	bin := filepath.Join(base, "foca")
	build := exec.Command("go", "build", "-tags", "foca_testing", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("can't build foca: %v\n%s", err, out)
	}
	cfg := filepath.Join(base, "config.toml")
	os.WriteFile(cfg, []byte(config), 0o600)
	return &proc{t: t, bin: bin, base: base, env: append(os.Environ(),
		"FOCA_CONFIG="+cfg, "FOCA_DATA_DIR="+filepath.Join(base, "d"), "FOCA_RUNTIME_DIR="+filepath.Join(base, "r"),
		"FOCA_SOCK=", "FOCA_INSTANCE=")}
}

func (p *proc) cmd(stdin string, args ...string) *exec.Cmd {
	c := exec.Command(p.bin, args...)
	c.Env = p.env
	c.Stdin = strings.NewReader(stdin)
	return c
}

func (p *proc) run(stdin string, args ...string) (string, string, error) {
	c := p.cmd(stdin, args...)
	var out, errb bytes.Buffer
	c.Stdout, c.Stderr = &out, &errb
	err := c.Run()
	return out.String(), errb.String(), err
}

func (p *proc) ok(stdin string, args ...string) string {
	p.t.Helper()
	out, errs, err := p.run(stdin, args...)
	if err != nil {
		p.t.Fatalf("foca %v: %v\n%s", args, err, errs)
	}
	return out
}

func (p *proc) serve() *exec.Cmd {
	p.t.Helper()
	c := p.cmd("", "serve")
	if testing.Verbose() {
		c.Stderr = os.Stderr
	}
	if err := c.Start(); err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	pidfile := filepath.Join(p.base, "r", "serve.pid")
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if b, err := os.ReadFile(pidfile); err == nil && strings.HasPrefix(string(b), fmt.Sprint(c.Process.Pid)+" ") {
			return c
		}
		if time.Now().After(deadline) {
			p.t.Fatal("serve never wrote its pid file")
		}
	}
}

func (p *proc) auditTypes() string {
	b, _ := os.ReadFile(filepath.Join(p.base, "d", "audit.jsonl"))
	return string(b)
}

// openPTY returns a new pseudo-terminal pair.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no /dev/ptmx: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("unlockpt: %v", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skipf("ptsname: %v", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open pts: %v", err)
	}
	t.Cleanup(func() { m.Close(); s.Close() })
	return m, s
}

func TestBinaryServeGetReloadStop(t *testing.T) {
	p := setup(t)
	p.ok("", "init")
	p.ok("ghp_123\n", "add", "dev:github-pat")
	srv := p.serve()

	if out := p.ok("", "get", "dev:github-pat"); out != "ghp_123" {
		t.Fatalf("get: %q", out)
	}

	// A real terminal on stdout is refused, before any approval is asked.
	before := strings.Count(p.auditTypes(), `"approval.granted"`)
	_, slave := openPTY(t)
	c := p.cmd("", "get", "dev:github-pat")
	var errb bytes.Buffer
	c.Stdout, c.Stderr = slave, &errb
	if err := c.Run(); err == nil || !strings.Contains(errb.String(), "refusing to write a secret to a terminal") {
		t.Fatalf("pty: %v %s", err, errb.String())
	}
	if after := strings.Count(p.auditTypes(), `"approval.granted"`); after != before {
		t.Fatal("an approval was asked for a read that was refused")
	}

	// reload refuses a broken config without signalling.
	cfgPath := filepath.Join(p.base, "config.toml")
	good, _ := os.ReadFile(cfgPath)
	os.WriteFile(cfgPath, append(append([]byte(nil), good...), "\nbogus = 1\n"...), 0o600)
	if _, errs, err := p.run("", "reload"); err == nil || !strings.Contains(errs, "not reloading") {
		t.Fatalf("reload of a bad config: %v %s", err, errs)
	}
	// Signalled directly anyway, the service keeps the running config.
	srv.Process.Signal(syscall.SIGHUP)
	waitFor(t, func() bool { return strings.Contains(p.auditTypes(), `"type":"config.reload","outcome":"error"`) })
	// (The client names the instance: with no --instance it reads the
	// config, which is broken on purpose.)
	if out := p.ok("", "get", "-i", "dev", "dev:github-pat"); out != "ghp_123" {
		t.Fatalf("after rejected reload: %q", out)
	}

	// A good config is applied: the instance is now named work.
	os.WriteFile(cfgPath, bytes.Replace(good, []byte("[instances.dev]"), []byte("[instances.work]\nexpose = [\"dev:*\"]\n[vaults.dev]\n[instances.dev]\nexpose = [\"dev:*\"]"), 1), 0o600)
	if _, errs, err := p.run("", "reload"); err != nil {
		t.Fatalf("reload: %v %s", err, errs)
	}
	waitFor(t, func() bool { return strings.Contains(p.auditTypes(), `"type":"config.reload","outcome":"ok"`) })
	if out := p.ok("", "get", "-i", "work", "dev:github-pat"); out != "ghp_123" {
		t.Fatalf("after reload: %q", out)
	}

	if _, errs, err := p.run("", "stop"); err != nil || !strings.Contains(errs, "stopped") {
		t.Fatalf("stop: %v %s", err, errs)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve exited with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve still running after stop")
	}
	if _, errs, err := p.run("", "stop"); err == nil || !strings.Contains(errs, "not running") {
		t.Fatalf("stop when stopped: %v %s", err, errs)
	}
}

// A second serve refuses to start while one is running.
func TestBinarySecondServeRefused(t *testing.T) {
	p := setup(t)
	p.serve()
	_, errs, err := p.run("", "serve")
	if err == nil || !strings.Contains(errs, "in use by another running service") {
		t.Fatalf("second serve: %v %s", err, errs)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
	}
}

// Reuse across separate client processes in one session, then `foca lock`
// ends it; `foca policy explain` describes the same policy.
func TestBinaryReuseLockAndExplain(t *testing.T) {
	p := setup(t)
	cfgPath := filepath.Join(p.base, "config.toml")
	cfg := strings.Replace(config, "[plugins]\n", "[plugins]\nplatform_events = \"fake\"\n", 1) +
		"[instances.dev.policy]\napproval = \"reuse\"\nwindow = \"15m\"\nscope = \"peer-session\"\n" +
		"[secrets.\"dev:prod-db\".policy]\napproval = \"every-time\"\n"
	os.WriteFile(cfgPath, []byte(cfg), 0o600)

	out := p.ok("", "policy", "explain")
	for _, want := range []string{
		"Platform events: fake.",
		"Instance dev (host dev), vault dev",
		"any other secret in dev  one approval allows reuse for 15m by anything in the same session",
		"dev:prod-db              asks every time",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("explain output lacks %q:\n%s", want, out)
		}
	}

	p.ok("", "init")
	p.ok("ghp_123\n", "add", "dev:github-pat")
	srv := p.serve()
	count := func(s string) int { return strings.Count(p.auditTypes(), s) }
	// The fake source reports ready at once, but give the service a moment.
	time.Sleep(100 * time.Millisecond)

	base := count(`"type":"approval.granted"`) // init and add
	p.ok("", "get", "dev:github-pat")
	p.ok("", "get", "dev:github-pat")
	if g, r := count(`"type":"approval.granted"`)-base, count(`"type":"approval.reused"`); g != 1 || r != 1 {
		t.Fatalf("granted %d, reused %d", g, r)
	}
	if out := p.ok("", "grants"); !strings.Contains(out, "github-pat") || !strings.Contains(out, "peer-session") {
		t.Fatalf("grants: %q", out)
	}

	if _, errs, err := p.run("", "lock"); err != nil || !strings.Contains(errs, "lock requested") {
		t.Fatalf("lock: %v %s", err, errs)
	}
	waitFor(t, func() bool { return count(`"type":"lock","outcome":"ok","reason":"manual"`) == 1 })
	p.ok("", "get", "dev:github-pat")
	if g := count(`"type":"approval.granted"`) - base; g != 2 {
		t.Fatalf("after lock: %d grants", g)
	}

	p.ok("", "stop")
	srv.Wait()
	if !strings.Contains(p.auditTypes(), `"type":"lock","outcome":"ok","reason":"shutdown","count":1`) {
		t.Fatalf("no shutdown wipe in:\n%s", p.auditTypes())
	}
}
