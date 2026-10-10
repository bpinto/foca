//go:build foca_testing

package cli

import (
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/server/wiring"
	"github.com/bpinto/foca/internal/svcctl"
)

const grantsConfig = `version = 1
[plugins]
authenticator = "fake"
platform_events = "fake"
secret_store = "vault-file"
key_protector = "file"
[vaults.common]
[instances.dev]
realm = { kind = "host" }
expose = ["common:*"]
[instances.dev.policy]
approval = "reuse"
window = "30m"
scope = "connection"
`

// foca grants --host shows every live grant from the service's snapshot,
// and trusts a snapshot only while a verified service holds the instance's
// pid file: one a crashed service left behind names grants that are gone
// (design §8.6).
func TestHostGrantsTrustsOnlyALiveService(t *testing.T) {
	w := newWorldWith(t, func(string) string { return grantsConfig })
	w.ok("", "init", "--vault", "common")
	w.ok("ghp_123", "add", "common:github-pat")

	// No service: nothing to read.
	if _, errs, code := w.run("", "grants", "--host"); code != 1 || !strings.Contains(errs, "service not running") {
		t.Fatalf("without a service: %d %s", code, errs)
	}

	stop := w.serve()
	defer func() { stop() }()
	// serve writes the pid file after Start; this test process stands in
	// for it.
	remove, err := svcctl.WritePIDFile(w.paths.PIDFile("dev"))
	if err != nil {
		t.Fatal(err)
	}
	defer remove()

	host := func() hostGrants {
		t.Helper()
		out, errs, code := w.run("", "grants", "--host", "-f", "json")
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		if len(lines) != 1 {
			t.Fatalf("grants --host: exit %d, %q, %s", code, out, errs)
		}
		var h hostGrants
		if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	// A connection-scoped grant: one get makes it, and it lives as long as
	// the service.
	waitFor := func(what string, ok func(hostGrants) bool) hostGrants {
		t.Helper()
		var h hostGrants
		for range 500 {
			if h = host(); ok(h) {
				return h
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("%s: %+v", what, h)
		return h
	}
	waitFor("reuse on", func(h hostGrants) bool { return h.Running && h.Reuse && len(h.Grants) == 0 })
	w.ok("", "get", "-i", "dev", "-o", t.TempDir()+"/v", "common:github-pat")
	h := waitFor("a grant", func(h hostGrants) bool { return len(h.Grants) == 1 })
	if g := h.Grants[0]; h.Instance != "dev" || g.Name != "common:github-pat" || g.Scope != "connection" || g.ApprovalID == "" {
		t.Fatalf("grant %+v", h)
	}
	out := w.ok("", "grants", "--host")
	if !strings.Contains(string(out), "common:github-pat") || !strings.Contains(string(out), "connection ") {
		t.Fatalf("table: %s", out)
	}
	if strings.Contains(string(out), "ghp_123") {
		t.Fatal("grants --host printed a value")
	}

	// Another instance name: refused before reading anything.
	if _, errs, code := w.run("", "grants", "--host", "-i", "../dev"); code == 0 || !strings.Contains(errs, "not an instance name") {
		t.Fatalf("bad instance: %d %s", code, errs)
	}

	// A snapshot whose service is gone isn't trusted, even though the file
	// still names a grant.
	b, err := os.ReadFile(w.paths.GrantsFile("dev"))
	if err != nil {
		t.Fatal(err)
	}
	remove()
	if _, errs, code := w.run("", "grants", "--host"); code != 1 || !strings.Contains(errs, "service not running") {
		t.Fatalf("no pid file: %d %s", code, errs)
	}
	out, _, _ = w.run("", "grants", "--host", "-i", "dev", "-f", "json")
	var gone hostGrants
	if err := json.Unmarshal(out, &gone); err != nil || gone.Running || len(gone.Grants) != 0 || !strings.Contains(gone.Error, "service not running") {
		t.Fatalf("snapshot trusted without a service: %s %v", out, err)
	}
	stop()
	stop = func() {}
	if _, err := os.Stat(w.paths.GrantsFile("dev")); !os.IsNotExist(err) {
		t.Fatalf("snapshot outlived the service: %v", err)
	}
	// A leftover from a crash, with a pid file naming a process that isn't
	// foca's service any more, is refused too.
	os.WriteFile(w.paths.GrantsFile("dev"), b, 0o600)
	os.WriteFile(w.paths.PIDFile("dev"), []byte("999999 1\n"), 0o600)
	if _, errs, code := w.run("", "grants", "--host"); code != 1 || !strings.Contains(errs, "service not running") || strings.Contains(errs, "github-pat") {
		t.Fatalf("crash leftover: %d %s", code, errs)
	}
}

// foca grants --host --drop drops one grant of a running service, named by
// its approval, leaves the others, is recorded from the host, and says so
// only once the service's snapshot shows it (design §8.6).
func TestHostDropDropsOneGrant(t *testing.T) {
	w := newWorldWith(t, func(string) string { return grantsConfig })
	w.ok("", "init", "--vault", "common")
	w.ok("ghp_123", "add", "common:github-pat")
	w.ok("npm_123", "add", "common:npm-token")

	cfg, err := config.Load(w.vars["FOCA_CONFIG"])
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	b, err := wiring.Build(cfg, w.paths, "test", log)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { b.Server.Shutdown("test"); b.Audit.Close() }()
	remove, err := svcctl.WritePIDFile(w.paths.PIDFile("dev"))
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	// This process stands in for serve: the CLI signals it, and it does
	// what serve does on SIGUSR2.
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGUSR2)
	defer signal.Stop(sig)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-sig:
				takeDrops(b, cfg, w.paths, log)
			case <-done:
				return
			}
		}
	}()

	snapshot := func() []svcctl.Grant {
		t.Helper()
		s, err := svcctl.ReadGrants(w.paths.PIDFile("dev"), w.paths.GrantsFile("dev"), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return s.Grants
	}
	dir := t.TempDir()
	w.ok("", "get", "-i", "dev", "-o", dir+"/a", "common:github-pat")
	w.ok("", "get", "-i", "dev", "-o", dir+"/b", "common:npm-token")
	var gs []svcctl.Grant
	for range 500 {
		if gs = snapshot(); len(gs) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(gs) != 2 {
		t.Fatalf("grants %+v", gs)
	}
	pat := gs[0]
	if pat.Name != "common:github-pat" {
		pat = gs[1]
	}

	for _, bad := range [][]string{{}, {"not-an-id"}, {pat.ApprovalID + "/a b"}} {
		if _, errs, code := w.run("", append([]string{"grants", "--host", "--drop"}, bad...)...); code == 0 {
			t.Fatalf("drop %q accepted: %s", bad, errs)
		}
	}
	if _, errs, code := w.run("", "grants", "--host", "--drop", "01J9Z8K3J0000000000000000Z"); code == 0 || !strings.Contains(errs, "no live grant") {
		t.Fatalf("unknown approval: %d %s", code, errs)
	}

	if _, errs, code := w.run("", "grants", "--host", "--drop", pat.ApprovalID+"/common:github-pat"); code != 0 || !strings.Contains(errs, "dropped 1 grant") {
		t.Fatalf("drop: %d %s", code, errs)
	}
	if gs := snapshot(); len(gs) != 1 || gs[0].Name != "common:npm-token" {
		t.Fatalf("after the drop: %+v", gs)
	}
	var drop *audit.Event
	for _, e := range w.events() {
		if e.Type == audit.TypeGrantsDrop {
			drop = &e
		}
	}
	if drop == nil || drop.Origin != audit.OriginHostCLI || drop.Instance != "dev" || drop.Count != 1 ||
		len(drop.Resources) != 1 || drop.Resources[0].ID != "common:github-pat" {
		t.Fatalf("drop event %+v", drop)
	}
	if entries, _ := os.ReadDir(w.paths.DropDir("dev")); len(entries) != 0 {
		t.Fatalf("requests left behind: %v", entries)
	}
}

// A grant made under notify = false reaches the host's view marked quiet,
// which is what the menu-bar app reads to show it (design §8.6, §8.7); any
// other grant isn't.
func TestHostGrantsShowQuietGrants(t *testing.T) {
	for _, quiet := range []bool{true, false} {
		cfg := grantsConfig
		if quiet {
			cfg += "notify = false\n"
		}
		w := newWorldWith(t, func(string) string { return cfg })
		w.ok("", "init", "--vault", "common")
		w.ok("ghp_123", "add", "common:github-pat")
		stop := w.serve()
		remove, err := svcctl.WritePIDFile(w.paths.PIDFile("dev"))
		if err != nil {
			t.Fatal(err)
		}
		w.ok("", "get", "-i", "dev", "-o", t.TempDir()+"/v", "common:github-pat")
		var h hostGrants
		for range 500 {
			out, _, _ := w.run("", "grants", "--host", "-f", "json")
			if json.Unmarshal(out, &h) == nil && len(h.Grants) == 1 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if len(h.Grants) != 1 || h.Grants[0].Quiet != quiet {
			t.Fatalf("notify = %v: %+v", !quiet, h)
		}
		out, _, _ := w.run("", "grants", "--host", "-f", "json")
		if got := strings.Contains(string(out), `"quiet":true`); got != quiet {
			t.Fatalf("notify = %v: json %s", !quiet, out)
		}
		if got := strings.Contains(string(w.ok("", "grants", "--host")), "(quiet)"); got != quiet {
			t.Fatalf("notify = %v: table doesn't say so", !quiet)
		}
		remove()
		stop()
	}
}
