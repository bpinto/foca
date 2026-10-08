//go:build foca_testing && linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Three host instances: dev and work share vault common, web reads only its
// own.
const multiConfig = `version = 1
[plugins]
authenticator = "fake"
secret_store = "vault-file"
key_protector = "file"
platform_events = "fake"
[vaults.common]
[instances.dev]
realm = { kind = "host" }
expose = ["dev:*", "common:*"]
[instances.work]
realm = { kind = "host" }
expose = ["common:*"]
[instances.web]
realm = { kind = "host" }
`

// serveOnly starts `foca serve --only …` and waits until it has written the
// pid file of the first instance.
func (p *proc) serveOnly(instances ...string) *exec.Cmd {
	p.t.Helper()
	args := []string{"serve"}
	for _, i := range instances {
		args = append(args, "--only", i)
	}
	c := p.cmd("", args...)
	if err := c.Start(); err != nil {
		p.t.Fatal(err)
	}
	p.t.Cleanup(func() { c.Process.Kill(); c.Wait() })
	pidfile := filepath.Join(p.base, "r", instances[0], "serve.pid")
	waitFor(p.t, func() bool {
		b, err := os.ReadFile(pidfile)
		return err == nil && strings.HasPrefix(string(b), fmt.Sprint(c.Process.Pid)+" ")
	})
	return c
}

// One process per group of instances: a process never serves part of a
// vault's readers, two processes never serve one instance, and lock, reload
// and stop reach every process, or the one -i names.
func TestBinaryOneProcessPerInstanceGroup(t *testing.T) {
	p := setup(t)
	os.WriteFile(filepath.Join(p.base, "config.toml"), []byte(multiConfig), 0o600)
	for _, v := range []string{"common", "dev", "web"} {
		p.ok("", "init", "--vault", v)
	}
	p.ok("c", "add", "common:tok")
	p.ok("w", "add", "web:tok")

	if _, errs, err := p.run("", "serve", "--only", "dev"); err == nil || !strings.Contains(errs, "vault common is read by dev and work, so they must be served by one process: add --only work") {
		t.Fatalf("split vault: %v %s", err, errs)
	}
	shared := p.serveOnly("dev", "work")
	web := p.serveOnly("web")
	if out := p.ok("", "get", "-i", "work", "common:tok"); out != "c" {
		t.Fatalf("work: %q", out)
	}
	if out := p.ok("", "get", "-i", "web", "web:tok"); out != "w" {
		t.Fatalf("web: %q", out)
	}
	// The other process's vaults are out of reach here, as in one process.
	if _, errs, err := p.run("", "get", "-i", "web", "common:tok"); err == nil || !strings.Contains(errs, "not_found") {
		t.Fatalf("web reading common: %v %s", err, errs)
	}
	if _, errs, err := p.run("", "serve", "--only", "web"); err == nil {
		t.Fatalf("a second process served web: %s", errs)
	}

	// A reload keeps the process to its --only instances.
	if _, errs, err := p.run("", "reload", "-i", "web"); err != nil || !strings.Contains(errs, fmt.Sprintf("reload requested (pid %d)", web.Process.Pid)) {
		t.Fatalf("reload web: %v %s", err, errs)
	}
	waitFor(t, func() bool { return strings.Count(p.auditTypes(), `"type":"config.reload","outcome":"ok"`) == 1 })
	if out := p.ok("", "get", "-i", "web", "web:tok"); out != "w" {
		t.Fatalf("web after reload: %q", out)
	}

	_, errs, err := p.run("", "lock")
	if err != nil || !strings.Contains(errs, fmt.Sprint(shared.Process.Pid)) || !strings.Contains(errs, fmt.Sprint(web.Process.Pid)) {
		t.Fatalf("lock reaches both processes: %v %s", err, errs)
	}
	if _, errs, err := p.run("", "stop", "-i", "web"); err != nil || !strings.Contains(errs, fmt.Sprintf("stopped (pid %d)", web.Process.Pid)) {
		t.Fatalf("stop web: %v %s", err, errs)
	}
	if out := p.ok("", "get", "-i", "dev", "common:tok"); out != "c" {
		t.Fatalf("dev after web stopped: %q", out)
	}
	if _, errs, err := p.run("", "stop"); err != nil || !strings.Contains(errs, fmt.Sprintf("stopped (pid %d)", shared.Process.Pid)) {
		t.Fatalf("stop: %v %s", err, errs)
	}
	done := make(chan error, 1)
	go func() { done <- shared.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("dev and work's process still running after stop")
	}
	if _, errs, err := p.run("", "stop"); err == nil || !strings.Contains(errs, "not running") {
		t.Fatalf("stop with nothing running: %v %s", err, errs)
	}
}
