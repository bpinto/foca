//go:build foca_testing

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugins/store/vaultfile"
	"github.com/bpinto/foca/internal/server/wiring"
)

const e2eConfig = `version = 1
[plugins]
authenticator = "fake"
platform_events = "none"
secret_store = "vault-file"
key_protector = "file"
[vaults.common]
[instances.dev]
realm = { kind = "host" }
expose = ["common:github-pat", "common:cert", "dev:*"]
[instances.work]
realm = { kind = "host" }
expose = ["common:*"]
`

type world struct {
	t     *testing.T
	vars  map[string]string
	paths config.Paths
}

func newWorld(t *testing.T) *world { return newWorldWith(t, func(string) string { return e2eConfig }) }

// newWorldWith writes the config cfg returns for the world's base directory.
func newWorldWith(t *testing.T, cfg func(base string) string) *world {
	// Short base dir: socket paths must fit in sun_path.
	base, err := os.MkdirTemp("", "fe2e")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	os.Chmod(base, 0o700)
	cfgPath := filepath.Join(base, "config.toml")
	os.WriteFile(cfgPath, []byte(cfg(base)), 0o600)
	w := &world{t: t, vars: map[string]string{
		"FOCA_CONFIG": cfgPath, "FOCA_DATA_DIR": filepath.Join(base, "d"), "FOCA_RUNTIME_DIR": filepath.Join(base, "r"),
		"HOME": base,
	}}
	w.paths, _ = config.ResolvePaths(config.Overrides{}, func(k string) string { return w.vars[k] })
	return w
}

// run runs the CLI in-process with stdin as given (not a terminal).
func (w *world) run(stdin string, args ...string) (stdout []byte, stderr string, code int) {
	w.t.Helper()
	var out, errb bytes.Buffer
	env := &Env{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb,
		Getenv: func(k string) string { return w.vars[k] },
		Exec: func(string, []string, []string) error {
			w.t.Fatal("unexpected exec")
			return nil
		}}
	code = Main(args, env, "test")
	return out.Bytes(), errb.String(), code
}

func (w *world) ok(stdin string, args ...string) []byte {
	w.t.Helper()
	out, errs, code := w.run(stdin, args...)
	if code != 0 {
		w.t.Fatalf("foca %v: exit %d: %s", args, code, errs)
	}
	return out
}

// serve starts the service in-process, as `foca serve` builds it.
func (w *world) serve() func() {
	w.t.Helper()
	cfg, err := config.Load(w.vars["FOCA_CONFIG"])
	if err != nil {
		w.t.Fatal(err)
	}
	b, err := wiring.Build(cfg, w.paths, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		w.t.Fatal(err)
	}
	if err := b.Server.Start(); err != nil {
		w.t.Fatal(err)
	}
	return func() { b.Server.Shutdown("test"); b.Audit.Close() }
}

func (w *world) events() []audit.Event {
	b, _ := os.ReadFile(w.paths.AuditLog())
	var out []audit.Event
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var e audit.Event
		json.Unmarshal([]byte(l), &e)
		out = append(out, e)
	}
	return out
}

func TestHostCLIAndClientEndToEnd(t *testing.T) {
	w := newWorld(t)

	// Before init, the service says the vault isn't initialized.
	stop := w.serve()
	if _, errs, code := w.run("", "get", "-i", "dev", "common:github-pat"); code != 1 || !strings.Contains(errs, "not_initialized") {
		t.Fatalf("before init: %d %s", code, errs)
	}
	stop()

	w.ok("", "init", "--vault", "common")
	if _, errs, code := w.run("", "init", "--vault", "common"); code != 1 || !strings.Contains(errs, "already exists") {
		t.Fatalf("second init: %s", errs)
	}
	fi, _ := os.Stat(w.paths.VaultFile("common"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("vault mode %o", fi.Mode().Perm())
	}
	w.ok("", "init", "--vault", "dev")

	_, errs, _ := w.run("ghp_123\n", "add", "common:github-pat", "--description", "GitHub")
	if !strings.Contains(errs, "added common:github-pat, visible to dev, work") {
		t.Fatalf("add output: %s", errs)
	}
	// A binary value goes in from a file, byte for byte.
	cert := []byte{0x30, 0x82, 0x00, 0xff, '\n'}
	certFile := filepath.Join(t.TempDir(), "cert.der")
	os.WriteFile(certFile, cert, 0o600)
	w.ok("", "add", "common:cert", "--from-file", certFile)
	w.ok("npm_456", "add", "common:npm-token")

	// A secret is always named with its vault, and two vaults can hold the
	// same id.
	if _, errs, code := w.run("k", "add", "dev-key"); code != 1 || !strings.Contains(errs, "name secrets <vault>:<secret>") {
		t.Fatalf("add without a vault: %s", errs)
	}
	w.ok("dev_pat", "add", "dev:github-pat")
	_, errs, _ = w.run("dev_789", "add", "dev:dev-key")
	if !strings.Contains(errs, "added dev:dev-key, visible to dev\n") {
		t.Fatalf("add to dev: %s", errs)
	}

	stop = w.serve()
	defer func() { stop() }()

	// raw: exactly the stored bytes; the stdin newline was dropped.
	if out := w.ok("", "get", "-i", "dev", "common:github-pat"); string(out) != "ghp_123" {
		t.Fatalf("raw: %q", out)
	}
	// Binary values cross the socket as base64 and come out unchanged.
	if out := w.ok("", "get", "-i", "dev", "common:cert"); !bytes.Equal(out, cert) {
		t.Fatalf("binary raw: %x", out)
	}
	if out := w.ok("", "get", "-i", "dev", "-f", "json", "common:github-pat", "common:cert"); string(out) != `{"common:github-pat":"ghp_123","common:cert":{"base64":"MIIA/wo="}}`+"\n" {
		t.Fatalf("json: %s", out)
	}
	if out := w.ok("", "get", "-i", "dev", "-f", "env", "GH=common:github-pat"); string(out) != "GH=ghp_123\n" {
		t.Fatalf("env: %q", out)
	}
	if _, errs, _ := w.run("", "get", "-i", "dev", "-f", "env", "common:cert"); !strings.Contains(errs, "can't hold") {
		t.Fatalf("binary in env: %s", errs)
	}
	outFile := filepath.Join(t.TempDir(), "tok")
	w.ok("", "get", "-i", "dev", "-o", outFile, "common:github-pat")
	if b, _ := os.ReadFile(outFile); string(b) != "ghp_123" {
		t.Fatalf("output file %q", b)
	}

	// One request reads from both of dev's vaults, the same id from each, and
	// each read names its own.
	if out := w.ok("", "get", "-i", "dev", "-f", "env", "common:github-pat", "B=dev:github-pat", "dev:dev-key"); string(out) != "GITHUB_PAT=ghp_123\nB=dev_pat\nDEV_KEY=dev_789\n" {
		t.Fatalf("two vaults: %q", out)
	}
	vaultOf := map[string]string{}
	for _, e := range w.events() {
		if e.Type == audit.TypeSecretRead && e.Outcome == audit.OutcomeOK {
			vaultOf[e.Resource.ID] = e.Vault
		}
	}
	if vaultOf["common:github-pat"] != "common" || vaultOf["dev:github-pat"] != "dev" || vaultOf["dev:dev-key"] != "dev" {
		t.Fatalf("read events name vaults %v", vaultOf)
	}

	// npm-token isn't exposed to dev: it looks missing, and the attempt is
	// audited with the reason.
	if _, errs, _ := w.run("", "get", "-i", "dev", "common:npm-token"); !strings.Contains(errs, "not_found") {
		t.Fatalf("unexposed: %s", errs)
	}
	if out := w.ok("", "list", "-i", "dev"); strings.Contains(string(out), "npm-token") || !strings.Contains(string(out), "common:github-pat") {
		t.Fatalf("list dev:\n%s", out)
	}
	notExposed := false
	for _, e := range w.events() {
		if e.Type == audit.TypeSecretRead && e.Outcome == audit.OutcomeNotFound && e.Reason == "not_exposed" && e.Resource.ID == "common:npm-token" {
			notExposed = true
		}
	}
	if !notExposed {
		t.Fatal("unexposed read not audited with reason not_exposed")
	}

	// run puts values only in the child's environment.
	var gotEnv []string
	var gotArgv []string
	var errb bytes.Buffer
	env := &Env{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: &errb,
		Getenv: func(k string) string { return w.vars[k] },
		Exec: func(path string, argv, envv []string) error {
			gotArgv, gotEnv = argv, envv
			return nil
		}}
	if code := Main([]string{"run", "-i", "work", "-e", "TOKEN=common:github-pat", "-e", "common:npm-token", "--", "sh", "-c", "true"}, env, "test"); code != 0 {
		t.Fatalf("run: %s", errb.String())
	}
	if strings.Join(gotArgv, " ") != "sh -c true" || !contains(gotEnv, "TOKEN=ghp_123") || !contains(gotEnv, "NPM_TOKEN=npm_456") {
		t.Fatalf("run argv %v env has token: %v", gotArgv, contains(gotEnv, "TOKEN=ghp_123"))
	}
	// The read claims the command it was for: its path and name, never its
	// arguments.
	var target *identity.Target
	for _, e := range w.events() {
		if e.Type == audit.TypeSecretRead && e.Instance == "work" {
			target = e.Client.Reported.Target
		}
	}
	if sh, _ := exec.LookPath("sh"); target == nil || *target != (identity.Target{Exe: sh, Argv0: "sh"}) {
		t.Fatalf("run target %+v", target)
	}

	// Edits apply to the running service on its next request, and the CLI
	// names every realm that reads the secret.
	_, errs, _ = w.run("", "edit", "common:github-pat", "--description", "GitHub token")
	if !strings.Contains(errs, "changed common:github-pat, visible to dev, work") {
		t.Fatalf("edit output: %s", errs)
	}
	w.ok("ghp_new\n", "edit", "common:github-pat", "--value")
	if out := w.ok("", "get", "-i", "work", "common:github-pat"); string(out) != "ghp_new" {
		t.Fatalf("after value edit: %q", out)
	}
	_, errs, _ = w.run("", "remove", "common:github-pat")
	if !strings.Contains(errs, "no longer visible to dev, work") {
		t.Fatalf("remove output: %s", errs)
	}
	if _, errs, _ := w.run("", "get", "-i", "work", "common:github-pat"); !strings.Contains(errs, "not_found") {
		t.Fatalf("after remove: %s", errs)
	}
	if out := w.ok("", "get", "-i", "dev", "dev:github-pat"); string(out) != "dev_pat" {
		t.Fatalf("the other vault's github-pat after remove: %q", out)
	}

	// Every change is in the audit log, from both processes' points of view,
	// with unique seqs and no values.
	log, _ := os.ReadFile(w.paths.AuditLog())
	for _, v := range []string{"ghp_123", "ghp_new", "npm_456"} {
		if strings.Contains(string(log), v) {
			t.Fatalf("value %s in the audit log", v)
		}
	}
	seen := map[uint64]bool{}
	var kinds []string
	for _, e := range w.events() {
		if seen[e.Seq] {
			t.Fatalf("duplicate seq %d", e.Seq)
		}
		seen[e.Seq] = true
		if e.Origin == audit.OriginHostCLI && e.Outcome == audit.OutcomeOK && e.Type != audit.TypeApprovalGranted {
			kinds = append(kinds, e.Type)
		}
	}
	want := "vault.init vault.init secret.add secret.add secret.add secret.add secret.add secret.update secret.update secret.remove"
	if strings.Join(kinds, " ") != want {
		t.Fatalf("host events %v", kinds)
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// init --recovery makes the recovery key and writes it once, to stdout:
// never to stderr, the vault file or the audit log. It opens the vault.
func TestInitWritesTheRecoveryKeyOnce(t *testing.T) {
	w := newWorld(t)
	out, errs, code := w.run("", "init", "--vault", "common", "--recovery")
	if code != 0 {
		t.Fatalf("init: %d %s", code, errs)
	}
	written := strings.TrimSuffix(string(out), "\n")
	key, err := vaultfile.ParseRecoveryKey([]byte(written))
	if err != nil || len(written) != 39 || strings.Count(string(out), "\n") != 1 {
		t.Fatalf("stdout %q: %v", out, err)
	}
	b, _ := os.ReadFile(w.paths.VaultFile("common"))
	if !strings.Contains(string(b), `"type": "recovery-key"`) || strings.Contains(string(b), written) {
		t.Fatalf("vault file:\n%s", b)
	}
	log, _ := os.ReadFile(w.paths.AuditLog())
	if strings.Contains(errs, written) || strings.Contains(string(log), written) {
		t.Fatal("the recovery key was written somewhere other than stdout")
	}
	if dek, err := vaultfile.New(w.paths.VaultFile("common"), "common").UnsealRecovery(key); err != nil || len(dek) != 32 {
		t.Fatalf("the key doesn't open the vault: %v", err)
	}
}

func TestHostCLIRefusesMemoryStore(t *testing.T) {
	w := newWorld(t)
	cfg := strings.Replace(e2eConfig, `secret_store = "vault-file"
key_protector = "file"`, "", 1)
	os.WriteFile(w.vars["FOCA_CONFIG"], []byte(cfg), 0o600)
	if _, errs, code := w.run("", "init", "--vault", "common"); code != 1 || !strings.Contains(errs, "vault-file") {
		t.Fatalf("%d %s", code, errs)
	}
}

// rekey encrypts the vault again under a new key after approval, records
// vault.rekey with both vault ids, removes the old protector entry, and
// writes a new recovery key once; the old recovery key no longer opens it,
// and the service reads the secrets as before.
func TestRekeyEndToEnd(t *testing.T) {
	w := newWorld(t)
	oldKey := string(w.ok("", "init", "--vault", "common", "--recovery"))
	w.ok("ghp_123", "add", "common:github-pat")
	oldKeys, _ := filepath.Glob(filepath.Join(w.paths.KeysDir(), "common-*"))

	out, errs, code := w.run("", "rekey", "--vault", "common")
	if code != 0 || !strings.Contains(errs, "encrypted vault common again under a new key") {
		t.Fatalf("rekey: %d %s", code, errs)
	}
	newKey := strings.TrimSuffix(string(out), "\n")
	if _, err := vaultfile.ParseRecoveryKey([]byte(newKey)); err != nil || newKey == strings.TrimSuffix(oldKey, "\n") {
		t.Fatalf("new recovery key %q: %v", out, err)
	}
	keys, _ := filepath.Glob(filepath.Join(w.paths.KeysDir(), "common-*"))
	if len(oldKeys) != 1 || len(keys) != 1 || keys[0] == oldKeys[0] {
		t.Fatalf("protector entries before %v, after %v", oldKeys, keys)
	}
	var e audit.Event
	for _, ev := range w.events() {
		if ev.Type == audit.TypeVaultRekey {
			e = ev
		}
	}
	if e.Outcome != audit.OutcomeOK || e.Approval == nil || e.Params["protector"] != "file" || e.Params["recovery_key"] != "true" ||
		e.Params["old_vault_id"] == "" || e.Params["vault_id"] == e.Params["old_vault_id"] ||
		!strings.HasSuffix(keys[0], e.Params["vault_id"]+".key") {
		t.Fatalf("rekey event %+v", e)
	}
	log, _ := os.ReadFile(w.paths.AuditLog())
	if strings.Contains(errs, newKey) || strings.Contains(string(log), newKey) {
		t.Fatal("the recovery key was written somewhere other than stdout")
	}

	if _, errs, code := w.run(oldKey, "recover", "--vault", "common"); code != 1 || !strings.Contains(errs, "wrong recovery key") {
		t.Fatalf("recover with the old key: %d %s", code, errs)
	}
	stop := w.serve()
	defer stop()
	if got := w.ok("", "get", "-i", "work", "common:github-pat"); string(got) != "ghp_123" {
		t.Fatalf("get after rekey: %q", got)
	}

	// A vault without a recovery key gets none, unless asked.
	w.ok("", "init", "--vault", "dev")
	if out := w.ok("", "rekey", "--vault", "dev"); len(out) != 0 {
		t.Fatalf("rekey of a vault without recovery wrote %q", out)
	}
	if out := w.ok("", "rekey", "--vault", "dev", "--recovery"); len(out) != 40 {
		t.Fatalf("rekey --recovery wrote %q", out)
	}
}

// The commands that hold vault keys or values make their process private
// before they read anything, and refuse to run if they can't.
func TestKeyHoldingCommandsArePrivate(t *testing.T) {
	w := newWorld(t)
	for _, args := range [][]string{{"init"}, {"add", "common:x"}, {"edit", "common:x", "--value"}, {"remove", "common:x"}, {"recover"}, {"rekey"}} {
		var errb bytes.Buffer
		env := &Env{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: &errb,
			Getenv: func(k string) string { return w.vars[k] },
			Harden: func() error { return errors.New("no prctl") }}
		if code := Main(args, env, "test"); code != 1 || !strings.Contains(errb.String(), "can't keep this process private") {
			t.Errorf("%v: %d %s", args, code, errb.String())
		}
	}
}
