//go:build foca_testing

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/audit"
)

func actionsWorld(t *testing.T) *world {
	return newWorldWith(t, func(base string) string {
		hello := filepath.Join(base, "hello.sh")
		os.WriteFile(hello, []byte("#!/bin/sh\nprintf 'hello %s\\n' \"$1\"\necho \"to stderr $GH_TOKEN\" >&2\n"), 0o700)
		fails := filepath.Join(base, "fails.sh")
		os.WriteFile(fails, []byte("#!/bin/sh\necho partial\necho 'it broke' >&2\nexit 7\n"), 0o700)
		return fmt.Sprintf(`version = 1
[plugins]
authenticator = "fake"
platform_events = "none"
secret_store = "vault-file"
key_protector = "file"
[instances.dev]
realm = { kind = "host" }
actions = ["hello", "fails"]
[instances.work]
realm = { kind = "host" }

[actions.hello]
description = "Say hello"
command = %q
args = ["{who}"]
env_secrets = { GH_TOKEN = "dev:github-pat" }
  [actions.hello.params.who]
  description = "whom to greet"
  pattern = "[a-z]{1,16}"

[actions.fails]
command = %q
`, hello, fails)
	})
}

func TestExecEndToEnd(t *testing.T) {
	w := actionsWorld(t)
	w.ok("", "init", "--vault", "dev")
	w.ok("ghp_123", "add", "dev:github-pat")
	stop := w.serve()
	defer func() { stop() }()

	if out := string(w.ok("", "actions", "-i", "dev")); !strings.Contains(out, "hello  Say hello    who=/[a-z]{1,16}/") ||
		!strings.Contains(out, "fails") {
		t.Fatalf("actions:\n%s", out)
	}
	out, errs, code := w.run("", "exec", "-i", "dev", "hello", "-p", "who=world")
	if code != 0 || string(out) != "hello world\n" || errs != "to stderr [hidden:dev:github-pat]\n" {
		t.Fatalf("exec: %d %q %q", code, out, errs)
	}
	// The action's exit code is passed on; stdout is withheld.
	out, errs, code = w.run("", "exec", "-i", "dev", "fails")
	if code != 7 || len(out) != 0 || errs != "it broke\n" {
		t.Fatalf("fails: %d %q %q", code, out, errs)
	}
	for _, args := range [][]string{
		{"exec", "-i", "dev", "hello", "-p", "who=--help"},
		{"exec", "-i", "dev", "hello", "-p", "who=world", "-p", "shell=sh"},
		{"exec", "-i", "dev", "hello"},
	} {
		if _, errs, code := w.run("", args...); code != 1 || !strings.Contains(errs, "param_rejected") {
			t.Fatalf("%v: %d %s", args, code, errs)
		}
	}
	// Not offered to work: it looks like no action at all.
	if _, errs, code := w.run("", "exec", "-i", "work", "hello", "-p", "who=world"); code != 1 || !strings.Contains(errs, "not_found") {
		t.Fatalf("work: %d %s", code, errs)
	}
	if _, errs, _ := w.run("", "actions", "-i", "work"); !strings.Contains(errs, "no actions offered here") {
		t.Fatalf("work actions: %s", errs)
	}

	stop()
	stop = func() {}
	var runs []audit.Event
	for _, e := range w.events() {
		if e.Type == audit.TypeActionRun && e.Outcome != audit.OutcomeRejected && e.Outcome != audit.OutcomeNotFound {
			runs = append(runs, e)
		}
	}
	if len(runs) != 2 || runs[0].Params["who"] != "world" || runs[0].Uses[0].ID != "dev:github-pat" ||
		runs[1].Run.ExitCode != 7 || runs[1].Reason != "exit_status" {
		t.Fatalf("runs %+v", runs)
	}
	log, _ := os.ReadFile(w.paths.AuditLog())
	if strings.Contains(string(log), "ghp_123") || strings.Contains(string(log), "hello world") || strings.Contains(string(log), "it broke") {
		t.Fatal("the audit log holds a secret or action output")
	}
}

func TestPolicyExplainShowsActions(t *testing.T) {
	w := actionsWorld(t)
	squash := func(b []byte) string { return strings.Join(strings.Fields(string(b)), " ") }
	out := squash(w.ok("", "policy", "explain"))
	if !strings.Contains(out, "action hello asks every time") || !strings.Contains(out, "action fails asks every time") {
		t.Fatalf("explain:\n%s", out)
	}
	out = squash(w.ok("", "policy", "explain", "-i", "work", "hello"))
	if !strings.Contains(out, "action hello not offered to this instance") {
		t.Fatalf("explain work:\n%s", out)
	}
}
