package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/policy"
)

const minimal = `
version = 1
[plugins]
authenticator = "fake"
secret_store = "memory"
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
	if c.Audit.MaxFileSize != 16<<20 || c.Audit.KeepFiles != 16 {
		t.Fatalf("audit defaults %+v", c.Audit)
	}
	if c.Plugins.AuditSink != "jsonl" {
		t.Fatalf("plugin defaults %+v", c.Plugins)
	}
}

// The store defaults to the vault file the host CLI writes, so a config
// that leaves it out can't serve an empty in-memory store by mistake. The
// vault file still needs its key protector named.
func TestSecretStoreDefaultsToVaultFile(t *testing.T) {
	noStore := strings.Replace(minimal, "secret_store = \"memory\"\n", "", 1)
	if _, err := Parse([]byte(noStore)); err == nil || !strings.Contains(err.Error(), "key_protector is required") {
		t.Fatalf("no store and no protector: %v", err)
	}
	c, err := Parse([]byte(strings.Replace(noStore, "[plugins]", "[plugins]\nkey_protector = \"file\"", 1)))
	if err != nil || c.Plugins.SecretStore != "vault-file" {
		t.Fatalf("store %q, %v", c.Plugins.SecretStore, err)
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
authenticator = "fake"
secret_store = "memory"`, "at least one"},
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
		"audit file size zero":         {minimal + "\n[audit]\nmax_file_size_mib = 0\n", "audit.max_file_size_mib 0 is outside 1..1024"},
		"audit file size too big":      {minimal + "\n[audit]\nmax_file_size_mib = 2048\n", "audit.max_file_size_mib"},
		"audit keeps no files":         {minimal + "\n[audit]\nkeep_files = 0\n", "audit.keep_files 0 is outside 1..1000"},
		"audit unknown key":            {minimal + "\n[audit]\nrotate = true\n", "unknown keys: audit.rotate"},
		"vault-file without protector": {strings.Replace(minimal, "secret_store = \"memory\"", "secret_store = \"vault-file\"", 1), "key_protector is required"},
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
		"policy repeated in another case": {minimal + `
[instances.dev.policy]
approval = "every-time"
[instances.dev.Policy]
Approval = "reuse"
Window = "8h"
`, "instances.dev.Policy"},
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

func TestKeyProtectorOptions(t *testing.T) {
	defer func(old string) { goos = old }(goos)
	goos = "linux"
	tpm := strings.Replace(minimal, "secret_store = \"memory\"", "secret_store = \"vault-file\"\nkey_protector = \"tpm\"", 1)
	c, err := Parse([]byte(tpm))
	if err != nil {
		t.Fatal(err)
	}
	if c.TPM.Device != "/dev/tpmrm0" || len(c.TPM.PCRs) != 1 || c.TPM.PCRs[0] != 7 {
		t.Fatalf("defaults %+v", c.TPM)
	}
	c, err = Parse([]byte(tpm + "[key_protectors.tpm]\ndevice = \"/dev/tpm0\"\npcrs = [7, 0]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.TPM.Device != "/dev/tpm0" || len(c.TPM.PCRs) != 2 || c.TPM.PCRs[0] != 0 {
		t.Fatalf("options %+v", c.TPM)
	}
	if c, err = Parse([]byte(tpm + "[key_protectors.tpm]\npcrs = []\n")); err != nil || len(c.TPM.PCRs) != 0 {
		t.Fatalf("no pcrs: %+v %v", c.TPM, err)
	}
	for name, tc := range map[string]struct{ cfg, want string }{
		"pcr out of range":  {tpm + "[key_protectors.tpm]\npcrs = [24]\n", "PCR 24 is outside 0..23"},
		"pcr twice":         {tpm + "[key_protectors.tpm]\npcrs = [7, 7]\n", "PCR 7 is listed twice"},
		"relative device":   {tpm + "[key_protectors.tpm]\ndevice = \"tpmrm0\"\n", "clean absolute path"},
		"other protector":   {tpm + "[key_protectors.keychain]\n", "only tpm takes options"},
		"unknown option":    {tpm + "[key_protectors.tpm]\nsrk = 1\n", "unknown keys"},
		"old insecure flag": {strings.Replace(tpm, "key_protector = \"tpm\"", "key_protector = \"file\"\ninsecure_file_protector = true", 1), "unknown keys: plugins.insecure_file_protector"},
	} {
		if _, err := Parse([]byte(tc.cfg)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
	goos = "darwin"
	if _, err := Parse([]byte(tpm)); err == nil || !strings.Contains(err.Error(), "key_protector = \"tpm\" only works on Linux") {
		t.Fatalf("tpm on darwin: %v", err)
	}
}

func TestPolicyRejections(t *testing.T) {
	pol := func(table, body string) string { return minimal + "\n[" + table + "]\n" + body + "\n" }
	cases := map[string]struct{ cfg, want string }{
		"window over the 8h cap":   {pol("instances.dev.policy", "approval = \"reuse\"\nwindow = \"8h1s\""), "window 8h0m1s is outside 1s..8h0m0s"},
		"window under 1s":          {pol("vaults.dev.policy", "approval = \"reuse\"\nwindow = \"500ms\""), "outside"},
		"secret without its vault": {pol("secrets.x.policy", "approval = \"every-time\""), `secrets: "x" is not a secret name`},
		"secret in no vault":       {pol(`secrets."nope:x".policy`, "approval = \"every-time\""), `secrets.nope:x: vault "nope" is not in the config`},
		"every-time with a window": {pol(`secrets."dev:x".policy`, "approval = \"every-time\"\nwindow = \"1m\""), "takes no window"},
		"every-time with a scope":  {pol(`secrets."dev:x".policy`, "approval = \"every-time\"\nscope = \"connection\""), "takes no window"},
		"reuse without a window":   {pol("instances.dev.policy", "approval = \"reuse\""), "needs a window"},
		"no approval key":          {pol("instances.dev.policy", "window = \"1m\""), "approval is required"},
		"unknown approval":         {pol("instances.dev.policy", "approval = \"sometimes\""), "must be"},
		"unknown scope":            {pol("instances.dev.policy", "approval = \"reuse\"\nwindow = \"1m\"\nscope = \"vm\""), "unknown scope"},
		"unknown policy key":       {pol("instances.dev.policy", "approval = \"reuse\"\nwindow = \"1m\"\nwidth = 3"), "unknown keys"},
		"unknown authenticator":    {pol("authenticators.faceid.policy", "approval = \"every-time\""), "unknown authenticator"},
		"bad secret id":            {pol("secrets.\"common:a/b\".policy", "approval = \"every-time\""), "is not a secret name"},
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

// The design's example config (§7.1) folds to the results it states.
func TestPolicyFoldsLikeTheDesignExample(t *testing.T) {
	defer func(old string) { goos = old }(goos)
	goos = "darwin" // the example is a Mac host
	cfg := `
version = 1
[plugins]
authenticator = "touchid"
key_protector = "keychain"
[vaults.common]
[vaults.common.policy]
approval = "reuse"
window   = "2h"
[instances.dev]
realm  = { kind = "vm" }
expose = ["common:github-pat"]
[instances.dev.policy]
approval = "reuse"
window   = "30m"
scope    = "peer-session"
[instances.work]
realm  = { kind = "vm" }
expose = ["common:*"]
[authenticators.touchid.policy]
approval = "reuse"
window   = "1h"
[authenticators.polkit.policy]
approval = "reuse"
window   = "8h"
[secrets."common:prod-db-password".policy]
approval = "every-time"
`
	c, err := Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := c.Instance("dev")
	work, _ := c.Instance("work")
	want := policy.Policy{Kind: policy.Reuse, Window: 30 * time.Minute, Scope: policy.ScopePeerSession}
	if got := c.SecretPolicy(dev, "common:github-pat"); got != want {
		t.Errorf("dev github-pat = %v, want %v", got, want)
	}
	if got := c.SecretPolicy(work, "common:prod-db-password"); got.Kind != policy.EveryTime {
		t.Errorf("work prod-db-password = %v, want every-time", got)
	}
	// work has no instance policy: vault 2h and authenticator 1h fold to 1h,
	// and the floor caps the scope. The unused polkit entry plays no part.
	want = policy.Policy{Kind: policy.Reuse, Window: time.Hour, Scope: policy.ScopePeerSession}
	if got := c.SecretPolicy(work, "common:github-pat"); got != want {
		t.Errorf("work github-pat = %v, want %v", got, want)
	}
	if c.Plugins.PlatformEvents != "auto" {
		t.Errorf("platform_events default %q", c.Plugins.PlatformEvents)
	}
}

func TestNoPolicyMeansEveryTime(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := c.Instance("dev")
	if got := c.SecretPolicy(dev, "common:anything"); got.Kind != policy.EveryTime {
		t.Fatalf("got %v", got)
	}
}

func TestPlatformEventsAuto(t *testing.T) {
	defer func(old string) { goos = old }(goos)
	for os, want := range map[string]string{"linux": "logind", "darwin": "darwin", "freebsd": "none"} {
		goos = os
		c, err := Parse([]byte(minimal))
		if err != nil || c.PlatformEventsName() != want {
			t.Errorf("%s: auto is %q (%v), want %q", os, c.PlatformEventsName(), err, want)
		}
	}
	c, _ := Parse([]byte(strings.Replace(minimal, "[plugins]", "[plugins]\nplatform_events = \"none\"", 1)))
	if c.PlatformEventsName() != "none" {
		t.Fatal("explicit none not kept")
	}
}

func TestTouchIDPasswordFallback(t *testing.T) {
	defer func(old string) { goos = old }(goos)
	goos = "darwin"
	base := "version = 1\n[instances.dev]\n[plugins]\nauthenticator = \"touchid\"\nkey_protector = \"keychain\"\n"
	c, err := Parse([]byte(base))
	if err != nil || c.TouchID.AllowPasswordFallback {
		t.Fatalf("password fallback on by default (%v)", err)
	}
	c, err = Parse([]byte(base + "[authenticators.touchid]\nallow_password_fallback = true\n"))
	if err != nil || !c.TouchID.AllowPasswordFallback {
		t.Fatalf("fallback: %v", err)
	}
	_, err = Parse([]byte(base + "[authenticators.polkit]\nallow_password_fallback = true\n"))
	if err == nil || !strings.Contains(err.Error(), "only touchid") {
		t.Fatalf("fallback on polkit: %v", err)
	}
	// The helper's location isn't configurable.
	if _, err := Parse([]byte(base + "[helpers.darwin]\npath = \"/x\"\n")); err == nil || !strings.Contains(err.Error(), "unknown keys") {
		t.Fatalf("helpers table accepted: %v", err)
	}
}

// Touch ID, the Keychain and macOS events are refused on other systems with
// a clear message, rather than failing later over a missing helper.
func TestDarwinPluginsOnlyOnMacOS(t *testing.T) {
	defer func(os string, anywhere bool) { goos, darwinPluginsAnywhere = os, anywhere }(goos, darwinPluginsAnywhere)
	darwinPluginsAnywhere = false
	base := "version = 1\n[instances.dev]\n[plugins]\n"
	for _, plugins := range []string{
		"authenticator = \"touchid\"\nsecret_store = \"memory\"",
		"authenticator = \"fake\"\nkey_protector = \"keychain\"",
		"authenticator = \"fake\"\nsecret_store = \"memory\"\nplatform_events = \"darwin\"",
	} {
		goos = "linux"
		_, err := Parse([]byte(base + plugins))
		if err == nil || !strings.Contains(err.Error(), "only work on macOS") {
			t.Errorf("%s on linux: %v", plugins, err)
		}
		goos = "darwin"
		if _, err := Parse([]byte(base + plugins)); err != nil {
			t.Errorf("%s on macOS: %v", plugins, err)
		}
	}
	// Test builds allow them anywhere, for the fake helper.
	goos, darwinPluginsAnywhere = "linux", true
	if _, err := Parse([]byte(base + "authenticator = \"touchid\"\nkey_protector = \"keychain\"")); err != nil {
		t.Fatalf("test build: %v", err)
	}
}

func TestPolkitOnlyOnLinux(t *testing.T) {
	defer func(os string) { goos = os }(goos)
	conf := "version = 1\n[instances.dev]\n[plugins]\nauthenticator = \"polkit\"\nsecret_store = \"memory\"\n"
	goos = "linux"
	if _, err := Parse([]byte(conf)); err != nil {
		t.Fatalf("on linux: %v", err)
	}
	for _, os := range []string{"darwin", "freebsd"} {
		goos = os
		if _, err := Parse([]byte(conf)); err == nil || !strings.Contains(err.Error(), "only works on Linux") {
			t.Errorf("on %s: %v", os, err)
		}
	}
}

func TestAuditRotationSettings(t *testing.T) {
	c, err := Parse([]byte(minimal + "\n[audit]\nmax_file_size_mib = 4\nkeep_files = 3\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Audit.MaxFileSize != 4<<20 || c.Audit.KeepFiles != 3 {
		t.Fatalf("audit %+v", c.Audit)
	}
}

// One process may serve some instances, but never part of a vault's readers.
func TestOnlyNeverSplitsAVault(t *testing.T) {
	c, err := Parse([]byte(`
version = 1
[plugins]
authenticator = "fake"
secret_store = "memory"
[vaults.common]
[instances.dev]
realm = { kind = "vm" }
expose = ["dev:*", "common:github-pat"]
[instances.work]
realm = { kind = "vm" }
expose = ["common:*"]
[instances.web]
realm = { kind = "container", peers = "opaque" }
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Only([]string{"dev"}); err == nil || !strings.Contains(err.Error(), "vault common is read by dev and work, so they must be served by one process: add --only work") {
		t.Fatalf("split vault: %v", err)
	}
	both, err := c.Only([]string{"work", "dev"})
	if err != nil || len(both.Instances) != 2 || len(c.Instances) != 3 {
		t.Fatalf("dev and work: %v %+v", err, both)
	}
	if web, err := c.Only([]string{"web"}); err != nil || len(web.Instances) != 1 || web.Instances[0].Name != "web" {
		t.Fatalf("web: %v", err)
	}
	if _, err := c.Only([]string{"nope"}); err == nil || !strings.Contains(err.Error(), "no such instance") {
		t.Fatalf("unknown: %v", err)
	}
}
