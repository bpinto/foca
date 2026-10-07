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
	if strings.Join(inst.Vaults(), ",") != "dev" || !inst.Expose["dev"].All {
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
		"bad instance name":            {strings.Replace(minimal, "instances.dev", "instances.Dev", 1), "instance name"},
		"timeout too long":             {minimal + "\n[approval]\nprompt_timeout = \"2h\"\n", "outside"},
		"timeout typo":                 {minimal + "\n[approval]\nprompt_timeout = \"30\"\n", "missing unit"},
		"queue too big":                {minimal + "\n[approval]\nmax_queue = 1000\n", "max_queue"},
		"vm claims direct":             {strings.Replace(minimal, `{ kind = "vm" }`, `{ kind = "vm", peers = "direct" }`, 1), "always opaque"},
		"container without peers":      {strings.Replace(minimal, `{ kind = "vm" }`, `{ kind = "container" }`, 1), "must set peers"},
		"unknown realm kind":           {strings.Replace(minimal, `{ kind = "vm" }`, `{ kind = "jail" }`, 1), "unknown kind"},
		"no connections":               {minimal + "\n[limits]\nmax_connections = 0\n", "max_connections"},
		"too many connections":         {minimal + "\n[limits]\nmax_connections = 5000\n", "max_connections"},
		"idle timeout too short":       {minimal + "\n[limits]\nidle_timeout = \"1s\"\n", "idle_timeout"},
		"vault-file without protector": {strings.Replace(minimal, "[plugins]", "[plugins]\nsecret_store = \"vault-file\"", 1), "key_protector is required"},
		"file protector not opted in":  {strings.Replace(minimal, "[plugins]", "[plugins]\nsecret_store = \"vault-file\"\nkey_protector = \"file\"", 1), "insecure_file_protector = true"},
		"opt-in without file":          {strings.Replace(minimal, "[plugins]", "[plugins]\nsecret_store = \"vault-file\"\nkey_protector = \"keychain\"\ninsecure_file_protector = true", 1), "not \"file\""},
		"protector without vault-file": {strings.Replace(minimal, "[plugins]", "[plugins]\nkey_protector = \"file\"", 1), "only used with"},
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

func TestExposeNamesTheVaultsAnInstanceReads(t *testing.T) {
	c, err := Parse([]byte(`
version = 1
[plugins]
authenticator = "fake"
secret_store = "memory"
[vaults.common]
[vaults.team]
[instances.dev]
realm = { kind = "vm" }
expose = ["dev:*", "common:github-pat", "common:npm-token", "team:*"]
[instances.work]
realm = { kind = "vm" }
expose = ["common:*"]
`))
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := c.Instance("dev")
	work, _ := c.Instance("work")
	if got := dev.Vaults(); strings.Join(got, ",") != "common,dev,team" {
		t.Fatalf("dev reads %v", got)
	}
	if !dev.Exposes("common", "github-pat") || dev.Exposes("common", "prod-db") || !dev.Exposes("dev", "x") || dev.Exposes("work", "x") {
		t.Fatalf("dev exposes %+v", dev.Expose)
	}
	if got := work.Vaults(); strings.Join(got, ",") != "common" {
		t.Fatalf("work reads %v", got)
	}
	if strings.Join(c.Vaults, ",") != "common,dev,team" {
		t.Fatalf("vaults %v", c.Vaults)
	}
}

func TestExposeRejections(t *testing.T) {
	head := "version = 1\n[plugins]\nauthenticator = \"fake\"\nsecret_store = \"memory\"\n[vaults.common]\n[instances.dev]\nrealm = { kind = \"vm\" }\n"
	for name, tc := range map[string]struct{ expose, want string }{
		"undeclared vault":  {`["work:*"]`, `instances.dev.expose: vault "work" is not declared in [vaults]`},
		"not a list":        {`"*"`, `expose must be a list of "<vault>:*" and "<vault>:<secret>"`},
		"empty":             {`[]`, "expose is empty"},
		"no vault":          {`["github-pat"]`, `"github-pat" must be "<vault>:*" or "<vault>:<secret>"`},
		"bad vault name":    {`["Common:*"]`, `invalid vault name "Common"`},
		"bad secret name":   {`["common:../etc"]`, `invalid secret name "../etc"`},
		"tag selector":      {`["common:tag:npm"]`, `invalid secret name "tag:npm"`},
		"star and a name":   {`["common:*", "common:a"]`, `"common:a" overlaps`},
		"name and a star":   {`["common:a", "common:*"]`, `"common:*" overlaps`},
		"listed twice":      {`["common:a", "common:a"]`, `"common:a" is listed twice`},
		"star twice":        {`["common:*", "common:*"]`, `"common:*" overlaps`},
		"not strings":       {`[1]`, "expose entries must be strings"},
		"old vault key set": {`["common:*"]` + "\nvault = \"common\"", "unknown keys: instances.dev.vault"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(head + "expose = " + tc.expose + "\n"))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestImplicitPrivateVaultCollisionCountsAsSharing(t *testing.T) {
	// "work" reads the vault "dev" gets implicitly; dev never opted in.
	cfg := `
version = 1
[plugins]
authenticator = "fake"
secret_store = "memory"
[vaults.dev]
[instances.dev]
realm = { kind = "vm" }
[instances.work]
realm = { kind = "vm" }
expose = ["dev:*"]
`
	_, err := Parse([]byte(cfg))
	if err == nil || !strings.Contains(err.Error(), "instances.dev: vault \"dev\" is shared with work") {
		t.Fatalf("got %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(cfg, "[instances.dev]\nrealm = { kind = \"vm\" }\n", "[instances.dev]\nrealm = { kind = \"vm\" }\nexpose = [\"dev:*\"]\n", 1))); err != nil {
		t.Fatalf("explicit expose on the shared private vault: %v", err)
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

func TestFileProtectorWhenOptedIn(t *testing.T) {
	c, err := Parse([]byte(strings.Replace(minimal, "[plugins]", "[plugins]\nsecret_store = \"vault-file\"\nkey_protector = \"file\"\ninsecure_file_protector = true", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Plugins.KeyProtector != "file" || !c.Plugins.InsecureFileProtector {
		t.Fatalf("%+v", c.Plugins)
	}
}
