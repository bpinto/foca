// Package wiring turns a validated config into running plugins. It is the
// only place plugin names from config are mapped to implementations.
package wiring

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"

	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bpinto/foca/internal/action"
	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugin/helper"
	"github.com/bpinto/foca/internal/plugins/authn/polkit"
	"github.com/bpinto/foca/internal/plugins/keyprot/tpm"
	"github.com/bpinto/foca/internal/plugins/provider/command"
	"github.com/bpinto/foca/internal/plugins/provider/static"
	"github.com/bpinto/foca/internal/plugins/store/memory"
	"github.com/bpinto/foca/internal/plugins/store/vaultfile"
	"github.com/bpinto/foca/internal/policy"
	"github.com/bpinto/foca/internal/server"
	"github.com/bpinto/foca/internal/server/core"
)

// env is what plugin constructors may need. The darwin helper is opened
// (trust-checked and asked for its kinds) once, on first use.
type env struct {
	cfg    *config.Config
	log    *slog.Logger
	darwin *helper.Helper
}

// The helper is fixed when foca is built, never configured or searched for
// (design §5). The build pins its sha256, which is required: a foca built
// without one runs no helper. scripts/build-darwin.sh sets it; packaging may
// also set the path:
//
//	-ldflags "-X …/wiring.builtinHelperSHA256=<hex>
//	          -X …/wiring.builtinHelperPath=/nix/store/…/bin/foca-darwin"
//
// Without a path, foca-darwin is expected next to the foca binary.
var (
	builtinHelperPath   string
	builtinHelperSHA256 string
)

// darwinHelperPath is the built-in path, else foca-darwin in the directory
// of the running binary, symlinks resolved.
func darwinHelperPath() (string, error) {
	if builtinHelperPath != "" {
		return builtinHelperPath, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "foca-darwin"), nil
}

func (e *env) darwinHelper() (*helper.Helper, error) {
	if e.darwin != nil {
		return e.darwin, nil
	}
	need, uses := e.darwinKinds()
	if builtinHelperSHA256 == "" {
		return nil, fmt.Errorf("%s needs foca-darwin, but this foca was built without its sha256 pin, so it runs no helper; build with scripts/build-darwin.sh", strings.Join(uses, ", "))
	}
	path, err := darwinHelperPath()
	if err != nil {
		return nil, fmt.Errorf("can't locate foca-darwin: %w", err)
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		where := "this build expects it there"
		if builtinHelperPath == "" {
			where = "install it next to foca"
		}
		return nil, fmt.Errorf("%s needs foca-darwin, which is not at %s; %s", strings.Join(uses, ", "), path, where)
	}
	h, err := helper.Open(context.Background(), helper.Config{Path: path, SHA256: builtinHelperSHA256, Log: e.log}, need...)
	if err != nil {
		return nil, err
	}
	e.darwin = h
	return h, nil
}

// darwinKinds lists the helper kinds the config uses, and the settings that
// use them.
func (e *env) darwinKinds() (kinds, uses []string) {
	if e.cfg.Plugins.Authenticator == "touchid" {
		kinds, uses = append(kinds, helper.KindAuthenticator), append(uses, `authenticator = "touchid"`)
	}
	if e.cfg.Plugins.KeyProtector == "keychain" {
		kinds, uses = append(kinds, helper.KindKeyProtector), append(uses, `key_protector = "keychain"`)
	}
	if e.cfg.PlatformEventsName() == "darwin" {
		kinds, uses = append(kinds, helper.KindEvents), append(uses, `platform_events = "darwin"`)
	}
	return kinds, uses
}

// authenticators maps config names to constructors. Test-only entries are
// added by files built with the foca_testing tag.
var authenticators = map[string]func(*env) (plugin.Authenticator, error){
	"polkit": func(*env) (plugin.Authenticator, error) { return polkit.New(), nil },
	"touchid": func(e *env) (plugin.Authenticator, error) {
		h, err := e.darwinHelper()
		if err != nil {
			return nil, err
		}
		return helper.NewAuthenticator(h, "touchid", e.cfg.TouchID.AllowPasswordFallback), nil
	},
}

// testOnly lists names that exist only in test builds, for a clear error.
var testOnly = map[string]bool{"fake": true}

// TestBuild is true in binaries built with -tags foca_testing.
var TestBuild = false

func authenticator(e *env, name string) (plugin.Authenticator, error) {
	if mk, ok := authenticators[name]; ok {
		return mk(e)
	}
	if testOnly[name] {
		return nil, fmt.Errorf("authenticator %q is only available in test builds (built with -tags foca_testing)", name)
	}
	return nil, fmt.Errorf("unknown authenticator %q", name)
}

// plannedProtectors are key protectors the design names but foca doesn't
// have yet.
var plannedProtectors = map[string]bool{"secure-enclave": true, "libsecret": true, "keyring": true}

// protectors are key protectors only test builds add (the file protector).
var protectors = map[string]func(e *env, paths config.Paths) (plugin.KeyProtector, error){}

// openTPM opens the TPM device; test builds may point it at a software TPM.
var openTPM = func(device string) (transport.TPMCloser, error) { return linuxtpm.Open(device) }

// efiVars is where the TPM protector reads whether Secure Boot is on; test
// builds may point it elsewhere.
var efiVars = func() string { return tpm.EFIVars }

func keyProtector(e *env, paths config.Paths) (plugin.KeyProtector, error) {
	if mk, ok := protectors[e.cfg.Plugins.KeyProtector]; ok {
		return mk(e, paths)
	}
	switch name := e.cfg.Plugins.KeyProtector; name {
	case "tpm":
		device := e.cfg.TPM.Device
		return tpm.New(func() (transport.TPMCloser, error) { return openTPM(device) }, e.cfg.TPM.PCRs, efiVars()), nil
	case "keychain":
		h, err := e.darwinHelper()
		if err != nil {
			return nil, err
		}
		return helper.NewKeyProtector(h, "keychain"), nil
	default:
		if name == "file" {
			return nil, fmt.Errorf("key_protector %q is only available in test builds (built with -tags foca_testing): it keeps the vault key in a plain file", name)
		}
		if plannedProtectors[name] {
			return nil, fmt.Errorf("key_protector %q is not implemented yet", name)
		}
		return nil, fmt.Errorf("unknown key_protector %q", name)
	}
}

// vaults is every configured vault's store and key.
type vaults struct {
	stores    map[string]plugin.SecretStore
	keys      map[string]plugin.DEKFunc
	files     map[string]*vaultfile.Store // only with secret_store = "vault-file"
	protector plugin.KeyProtector
}

func openVaults(e *env, paths config.Paths) (*vaults, error) {
	cfg, log := e.cfg, e.log
	v := &vaults{stores: map[string]plugin.SecretStore{}, keys: map[string]plugin.DEKFunc{}, files: map[string]*vaultfile.Store{}}
	switch cfg.Plugins.SecretStore {
	case "memory":
		log.Warn("secret_store is memory: secrets are lost when the service stops")
		for _, name := range cfg.Vaults {
			v.stores[name] = memory.New()
		}
	case "vault-file":
		p, err := keyProtector(e, paths)
		if err != nil {
			return nil, err
		}
		if p.Name() == "file" {
			log.Warn("key_protector is file: the vault key is in a plain file; anyone who can read " + paths.KeysDir() + " can decrypt the vaults")
		}
		v.protector = p
		for _, name := range cfg.Vaults {
			s := vaultfile.New(paths.VaultFile(name), name)
			v.stores[name], v.files[name], v.keys[name] = s, s, s.DEKFunc(p)
		}
	default:
		return nil, fmt.Errorf("unknown secret_store %q", cfg.Plugins.SecretStore)
	}
	return v, nil
}

func openAudit(cfg *config.Config, paths config.Paths) (plugin.AuditSink, error) {
	switch cfg.Plugins.AuditSink {
	case "jsonl":
		if err := fsutil.EnsurePrivateDir(paths.DataDir); err != nil {
			return nil, fmt.Errorf("data dir: %w", err)
		}
		return audit.OpenJSONL(paths.AuditLog(), audit.Rotation{MaxSize: cfg.Audit.MaxFileSize, Keep: cfg.Audit.KeepFiles})
	default:
		return nil, fmt.Errorf("unknown audit_sink %q", cfg.Plugins.AuditSink)
	}
}

func newCore(cfg *config.Config, paths config.Paths, auth plugin.Authenticator, sink plugin.AuditSink, v *vaults) *core.Service {
	var instances []*core.Instance
	for _, ic := range cfg.Instances {
		var vaults []*static.Provider
		for _, name := range ic.Vaults() {
			e := ic.Expose[name]
			vaults = append(vaults, static.New(name, v.stores[name], static.Exposure{All: e.All, IDs: e.IDs}, v.keys[name]))
		}
		secrets := static.NewVaults(vaults...)
		inst := &core.Instance{
			Name: ic.Name, Realm: ic.Realm, Vaults: ic.Vaults(), GuestRelay: ic.GuestRelay,
			Secrets: secrets,
			Exposes: ic.Exposes,
			Policy:  func(name string) policy.Policy { return cfg.SecretPolicy(ic, name) },
		}
		if len(ic.Actions) > 0 {
			specs := make([]*action.Spec, len(ic.Actions))
			for i, id := range ic.Actions {
				specs[i] = cfg.Actions[id]
			}
			inst.Actions = command.New(specs, secrets)
			inst.ActionPolicy = func(id string) policy.Policy { return cfg.ActionPolicy(ic, id) }
		}
		instances = append(instances, inst)
	}
	return core.New(core.Options{
		Authenticator: auth, Audit: sink, Keys: v.keys,
		PromptTimeout: cfg.Approval.PromptTimeout, MaxQueue: cfg.Approval.MaxQueue,
		ShowClient: cfg.Approval.PromptShowClient, SkipAncestors: cfg.Approval.SkipAncestors,
		// The service and the host CLI share it, so foca shows one prompt
		// at a time across processes. The CLI may create the directory.
		PromptLock: fsutil.PrivateLock(paths.RuntimeDir, "prompt.lock"),
	}, instances, v.stores)
}

// Built is everything a running service needs.
type Built struct {
	Server *server.Server
	Core   *core.Service
	Audit  plugin.AuditSink
	Stores map[string]plugin.SecretStore
}

// Build wires the service. It binds nothing; Server.Start does.
func Build(cfg *config.Config, paths config.Paths, version string, log *slog.Logger) (*Built, error) {
	e := &env{cfg: cfg, log: log}
	auth, err := authenticator(e, cfg.Plugins.Authenticator)
	if err != nil {
		return nil, err
	}
	if TestBuild {
		log.Warn("TEST BUILD: test-only plugins are available; never use this binary for real secrets")
	}
	if err := checkActions(cfg); err != nil {
		return nil, err
	}
	v, err := openVaults(e, paths)
	if err != nil {
		return nil, err
	}
	peers, err := peerIdentifier(cfg.Plugins.PeerIdentifier)
	if err != nil {
		return nil, err
	}
	events, err := platformEvents(e)
	if err != nil {
		return nil, err
	}
	if events == nil {
		log.Warn("platform_events is none: grants can't be wiped on sleep or lock, so every access asks")
	}
	sink, err := openAudit(cfg, paths)
	if err != nil {
		return nil, err
	}
	svc := newCore(cfg, paths, auth, sink, v)
	srv := server.New(server.Options{
		Paths: paths, Instances: cfg.Instances, OpaquePeers: cfg.OpaquePeers,
		Core: svc, Peers: peers, Version: version, Log: log,
		Events:         events,
		MaxConnections: cfg.Limits.MaxConnections, IdleTimeout: cfg.Limits.IdleTimeout,
	})
	return &Built{Server: srv, Core: svc, Audit: sink, Stores: v.stores}, nil
}

// Host is what the host CLI needs to manage vaults in its own process: the
// same authenticator, vault files and audit log as the service, and no
// sockets.
type Host struct {
	Core      *core.Service
	Audit     plugin.AuditSink
	Vaults    map[string]*vaultfile.Store
	Protector plugin.KeyProtector
}

func BuildHost(cfg *config.Config, paths config.Paths, log *slog.Logger) (*Host, error) {
	if cfg.Plugins.SecretStore != "vault-file" {
		return nil, fmt.Errorf("the host CLI manages vault files; secret_store is %q (set secret_store = \"vault-file\")", cfg.Plugins.SecretStore)
	}
	e := &env{cfg: cfg, log: log}
	auth, err := authenticator(e, cfg.Plugins.Authenticator)
	if err != nil {
		return nil, err
	}
	if TestBuild {
		log.Warn("TEST BUILD: test-only plugins are available; never use this binary for real secrets")
	}
	v, err := openVaults(e, paths)
	if err != nil {
		return nil, err
	}
	sink, err := openAudit(cfg, paths)
	if err != nil {
		return nil, err
	}
	return &Host{Core: newCore(cfg, paths, auth, sink, v), Audit: sink, Vaults: v.files, Protector: v.protector}, nil
}

// checkActions runs the command trust checks for every action an instance
// is offered, at start-up as for helpers (design §5). They run again before
// every run, so a command replaced later is refused then.
func checkActions(cfg *config.Config) error {
	var errs []error
	for _, id := range sortedActionIDs(cfg) {
		if _, err := command.CheckCommand(cfg.Actions[id].Command); err != nil {
			errs = append(errs, fmt.Errorf("actions.%s: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

func sortedActionIDs(cfg *config.Config) []string {
	seen := map[string]bool{}
	var ids []string
	for _, inst := range cfg.Instances {
		for _, id := range inst.Actions {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Strings(ids)
	return ids
}
