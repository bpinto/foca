//go:build foca_testing && linux

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/plugins/authn/polkit"
	"github.com/bpinto/foca/internal/plugins/authn/polkit/polkittest"
)

const polkitConfig = `version = 1
[plugins]
authenticator   = "polkit"
secret_store    = "vault-file"
key_protector   = "file"
platform_events = "none"
[instances.dev]
realm = { kind = "host" }
`

// The real binary with authenticator = "polkit": the host CLI and the
// service both ask polkit on the system bus, first a fake authority that
// can approve, then the real polkitd, which can't (it takes an agent's
// answer only from uid 0) but shows the real prompt to an agent.
func TestBinaryPolkit(t *testing.T) {
	p := setup(t)
	os.WriteFile(filepath.Join(p.base, "config.toml"), []byte(polkitConfig), 0o600)
	uid := strconv.Itoa(os.Getuid())
	bus := polkittest.Bus(t)
	f := polkittest.StartFake(t, bus, polkit.Message, "unix-user:"+uid)
	f.Set(func(f *polkittest.Fake) { f.Default = polkittest.Approve })
	env := p.env
	p.env = append(env, "FOCA_SYSTEM_BUS="+bus)

	p.ok("", "init")
	p.ok("ghp_123\n", "add", "dev:github-pat")
	srv := p.serve()
	if out := p.ok("", "get", "dev:github-pat"); out != "ghp_123" {
		t.Fatalf("get: %q", out)
	}
	var reasons []string
	for _, c := range f.Checks() {
		if c.Flags != 0 {
			reasons = append(reasons, c.Details["reason"])
		}
	}
	if len(reasons) != 3 || !strings.HasPrefix(reasons[0], "create vault dev") ||
		!strings.HasPrefix(reasons[1], "add github-pat") || !strings.Contains(reasons[2], "use dev:github-pat") {
		t.Fatalf("prompts %q", reasons)
	}
	if !strings.Contains(p.auditTypes(), `"authenticator":"polkit","method":"polkit-auth_self"`) {
		t.Fatalf("approval not recorded as polkit:\n%s", p.auditTypes())
	}

	f.Script(polkittest.NoAgent)
	if _, errs, err := p.run("", "get", "dev:github-pat"); err == nil || !strings.Contains(errs, "auth_unavailable") {
		t.Fatalf("get with no agent: %v %s", err, errs)
	}
	f.Script(polkittest.Dismiss)
	if _, errs, err := p.run("", "get", "dev:github-pat"); err == nil || !strings.Contains(errs, "denied") {
		t.Fatalf("dismissed get: %v %s", err, errs)
	}
	// No prompt was shown, so the refusal is a coalesced rejection.
	if !hasLine(p.auditTypes(), `"type":"request.rejected"`, `"reason":"auth_unavailable"`) {
		t.Fatalf("no auth_unavailable rejection in:\n%s", p.auditTypes())
	}
	p.ok("", "stop")
	srv.Wait()

	t.Run("RealPolkitd", func(t *testing.T) {
		bus := polkittest.Bus(t)
		pol, _ := polkit.PolicyFile(uid)
		p.env = append(env, "FOCA_SYSTEM_BUS="+bus)
		// The service first: polkitd must see it as a service of this user.
		srv := p.serve()
		polkittest.StartPolkitd(t, bus, pol, nil, polkittest.Session{Active: true, Services: []int{srv.Process.Pid}})
		agent := polkittest.RegisterAgent(t, bus, srv.Process.Pid)
		if _, errs, err := p.run("", "get", "dev:github-pat"); err == nil || !strings.Contains(errs, "denied") {
			t.Fatalf("dismissed get: %v %s", err, errs)
		}
		b := agent.Begun()
		if len(b) != 1 || b[0].ActionID != polkit.ActionID ||
			!strings.HasPrefix(b[0].Message, "foca is trying to let ") || !strings.Contains(b[0].Message, " use dev:github-pat") {
			t.Fatalf("agent shown %+v", b)
		}
		p.ok("", "stop")
		srv.Wait()
	})
}
