package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/identity"
)

const minimal = `
version = 1
[plugins]
authenticator = "fake"
[instances.dev]
realm = { kind = "vm" }
`

func TestMinimalDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	inst, ok := c.Instance("dev")
	if !ok {
		t.Fatal("instance missing")
	}
	want := identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"}
	if inst.Realm != want {
		t.Fatalf("realm %+v", inst.Realm)
	}
	if inst.Vault != "dev" || !inst.Expose.All || inst.SharedVault {
		t.Fatalf("private vault defaults wrong: %+v", inst)
	}
	if c.Approval.PromptTimeout != time.Minute || c.Approval.MaxQueue != 4 || !c.Approval.PromptShowClient {
		t.Fatalf("approval defaults %+v", c.Approval)
	}
	if c.Limits.MaxConnections != DefaultMaxConnections || c.Limits.IdleTimeout != DefaultIdleTimeout {
		t.Fatalf("limit defaults %+v", c.Limits)
	}
	if c.Plugins.SecretStore != "memory" || c.Plugins.AuditSink != "jsonl" {
		t.Fatalf("plugin defaults %+v", c.Plugins)
	}
}

func TestRejections(t *testing.T) {
	cases := map[string]struct{ cfg, want string }{
		"unknown key": {minimal + "\n[approval]\npromt_timeout = \"30s\"\n", "unknown keys: approval.promt_timeout"},
		"no version":  {strings.Replace(minimal, "version = 1", "", 1), "version must be 1"},
		"no authenticator": {`version = 1
[instances.dev]`, "plugins.authenticator is required"},
		"no instances": {`version = 1
[plugins]
authenticator = "fake"`, "at least one"},
		"bad instance name":       {strings.Replace(minimal, "instances.dev", "instances.Dev", 1), "instance name"},
		"timeout too long":        {minimal + "\n[approval]\nprompt_timeout = \"2h\"\n", "outside"},
		"timeout typo":            {minimal + "\n[approval]\nprompt_timeout = \"30\"\n", "missing unit"},
		"queue too big":           {minimal + "\n[approval]\nmax_queue = 1000\n", "max_queue"},
		"vm claims direct":        {strings.Replace(minimal, `{ kind = "vm" }`, `{ kind = "vm", peers = "direct" }`, 1), "always opaque"},
		"container without peers": {strings.Replace(minimal, `{ kind = "vm" }`, `{ kind = "container" }`, 1), "must set peers"},
		"unknown realm kind":      {strings.Replace(minimal, `{ kind = "vm" }`, `{ kind = "jail" }`, 1), "unknown kind"},
		"undeclared vault":        {minimal + "vault = \"common\"\n", "not declared"},
		"expose star in list":     {minimal + "expose = [\"*\"]\n", `use expose = "*"`},
		"expose bad id":           {minimal + "expose = [\"../etc\"]\n", "invalid secret id"},
		"no connections":          {minimal + "\n[limits]\nmax_connections = 0\n", "max_connections"},
		"too many connections":    {minimal + "\n[limits]\nmax_connections = 5000\n", "max_connections"},
		"idle timeout too short":  {minimal + "\n[limits]\nidle_timeout = \"1s\"\n", "idle_timeout"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.cfg))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

func TestSharedVaultRequiresExplicitExposeOnEveryUser(t *testing.T) {
	base := `
version = 1
[plugins]
authenticator = "fake"
[vaults.common]
[instances.dev]
realm = { kind = "vm" }
vault = "common"
expose = ["github-pat", "tag:npm"]
[instances.work]
realm = { kind = "vm" }
vault = "common"
`
	_, err := Parse([]byte(base))
	if err == nil || !strings.Contains(err.Error(), "instances.work: vault \"common\" is shared with dev") {
		t.Fatalf("missing expose on shared vault not rejected: %v", err)
	}

	c, err := Parse([]byte(base + "expose = \"*\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := c.Instance("dev")
	work, _ := c.Instance("work")
	if !dev.SharedVault || dev.Expose.All || len(dev.Expose.IDs) != 1 || dev.Expose.Tags[0] != "npm" {
		t.Fatalf("dev %+v", dev)
	}
	if !work.Expose.All {
		t.Fatalf("work %+v", work)
	}
}

func TestImplicitPrivateVaultCollisionCountsAsSharing(t *testing.T) {
	// "work" points at the vault "dev" gets implicitly; dev never opted in.
	cfg := `
version = 1
[plugins]
authenticator = "fake"
[vaults.dev]
[instances.dev]
realm = { kind = "vm" }
[instances.work]
realm = { kind = "vm" }
vault = "dev"
expose = "*"
`
	_, err := Parse([]byte(cfg))
	if err == nil || !strings.Contains(err.Error(), "instances.dev: vault \"dev\" is shared") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadChecksFileTrust(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")
	os.WriteFile(p, []byte(minimal), 0o600)
	if _, err := Load(p); err != nil {
		t.Fatal(err)
	}
	os.Chmod(p, 0o666)
	if _, err := Load(p); err == nil {
		t.Fatal("world-writable config loaded")
	}
}

// The TOML decoder matches field names regardless of case, so a second table
// spelled differently could quietly override the first. Only exact names load.
func TestKeysDifferingOnlyInCaseAreRefused(t *testing.T) {
	cases := map[string]struct{ cfg, want string }{
		"upper-case version":     {strings.Replace(minimal, "version", "VERSION", 1), "VERSION"},
		"capitalised table":      {strings.Replace(minimal, "[plugins]", "[Plugins]", 1), "Plugins"},
		"capitalised plugin key": {strings.Replace(minimal, "authenticator =", "Authenticator =", 1), "plugins.Authenticator"},
		"inline table key":       {strings.Replace(minimal, `{ kind = "vm" }`, `{ Kind = "vm" }`, 1), "instances.dev.realm.Kind"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.cfg))
			if err == nil || !strings.Contains(err.Error(), "unknown keys") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want unknown key %q", err, tc.want)
			}
		})
	}
}

func TestResolvePaths(t *testing.T) {
	env := map[string]string{"HOME": "/home/u", "XDG_RUNTIME_DIR": "/run/user/1000"}
	get := func(k string) string { return env[k] }
	p, err := ResolvePaths(Overrides{}, get)
	if err != nil {
		t.Fatal(err)
	}
	if p.Config != "/home/u/.config/foca/config.toml" || p.DataDir != "/home/u/.local/share/foca" ||
		p.RuntimeDir != "/run/user/1000/foca" {
		t.Fatalf("defaults %+v", p)
	}
	if p.ClientSocket("dev") != "/run/user/1000/foca/dev/client.sock" {
		t.Fatal(p.ClientSocket("dev"))
	}
	env["FOCA_DATA_DIR"] = "/data"
	p, _ = ResolvePaths(Overrides{RuntimeDir: "/r"}, get)
	if p.DataDir != "/data" || p.RuntimeDir != "/r" {
		t.Fatalf("overrides %+v", p)
	}
	if err := CheckSocketPath("/" + strings.Repeat("x", 200)); err == nil {
		t.Fatal("long socket path accepted")
	}
}

func TestDefaultOpaquePeersIncludeKnownRelays(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ssh", "sshd", "sshd-session", "socat", "nc", "ncat", "systemd-socket-proxyd"} {
		found := false
		for _, n := range c.OpaquePeers {
			found = found || n == want
		}
		if !found {
			t.Errorf("%s missing from default opaque_peers %v", want, c.OpaquePeers)
		}
	}
}

// Peers are matched by their shown name, so an entry written as a path, a
// Nix wrapper's name or with stray characters would silently never match.
func TestOpaquePeersMustBeShownNames(t *testing.T) {
	with := func(list string) string {
		return strings.Replace(minimal, "version = 1", "version = 1\nopaque_peers = "+list, 1)
	}
	for _, bad := range []string{`["/usr/bin/ssh"]`, `[".ssh-wrapped"]`, `["ssh "]`, `[""]`, `["ssh", "my proxy"]`} {
		if _, err := Parse([]byte(with(bad))); err == nil || !strings.Contains(err.Error(), "never matches") {
			t.Errorf("opaque_peers = %s: %v", bad, err)
		}
	}
	c, err := Parse([]byte(with(`["ssh", "systemd-socket-proxyd", "vpnkit-bridge"]`)))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.OpaquePeers) != 3 {
		t.Fatalf("opaque_peers %v", c.OpaquePeers)
	}
}

func TestDirectContainerRefusedOnMacOS(t *testing.T) {
	cfg := strings.Replace(minimal, `{ kind = "vm" }`, `{ kind = "container", peers = "direct" }`, 1)
	defer func(old string) { goos = old }(goos)
	goos = "linux"
	if _, err := Parse([]byte(cfg)); err != nil {
		t.Fatalf("linux: %v", err)
	}
	goos = "darwin"
	if _, err := Parse([]byte(cfg)); err == nil || !strings.Contains(err.Error(), "always opaque") {
		t.Fatalf("darwin: got %v", err)
	}
}
