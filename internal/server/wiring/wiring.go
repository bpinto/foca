// Package wiring turns a validated config into running plugins. It is the
// only place plugin names from config are mapped to implementations.
package wiring

import (
	"fmt"
	"log/slog"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/plugin"
	keyfile "github.com/bpinto/foca/internal/plugins/keyprot/file"
	"github.com/bpinto/foca/internal/plugins/provider/static"
	"github.com/bpinto/foca/internal/plugins/store/memory"
	"github.com/bpinto/foca/internal/plugins/store/vaultfile"
	"github.com/bpinto/foca/internal/policy"
	"github.com/bpinto/foca/internal/server"
	"github.com/bpinto/foca/internal/server/core"
)

// authenticators maps config names to constructors. Test-only entries are
// added by files built with the foca_testing tag.
var authenticators = map[string]func() (plugin.Authenticator, error){}

// testOnly lists names that exist only in test builds, for a clear error.
var testOnly = map[string]bool{"fake": true}

// TestBuild is true in binaries built with -tags foca_testing.
var TestBuild = false

// planned lists names that are part of the design but not built yet.
var planned = map[string]bool{"touchid": true, "polkit": true, "fido2": true, "pinentry": true}

func authenticator(name string) (plugin.Authenticator, error) {
	if mk, ok := authenticators[name]; ok {
		return mk()
	}
	if testOnly[name] {
		return nil, fmt.Errorf("authenticator %q is only available in test builds (built with -tags foca_testing)", name)
	}
	if planned[name] {
		return nil, fmt.Errorf("authenticator %q is not implemented yet", name)
	}
	return nil, fmt.Errorf("unknown authenticator %q", name)
}

// plannedProtectors are key protectors the design names but foca doesn't
// have yet.
var plannedProtectors = map[string]bool{"keychain": true, "secure-enclave": true, "tpm": true, "libsecret": true, "keyring": true}

func keyProtector(cfg *config.Config, paths config.Paths) (plugin.KeyProtector, error) {
	switch name := cfg.Plugins.KeyProtector; name {
	case "file":
		// config.validate has already required insecure_file_protector.
		return keyfile.New(paths.KeysDir()), nil
	default:
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

func openVaults(cfg *config.Config, paths config.Paths, log *slog.Logger) (*vaults, error) {
	v := &vaults{stores: map[string]plugin.SecretStore{}, keys: map[string]plugin.DEKFunc{}, files: map[string]*vaultfile.Store{}}
	switch cfg.Plugins.SecretStore {
	case "memory":
		log.Warn("secret_store is memory: secrets are lost when the service stops")
		for _, name := range cfg.Vaults {
			v.stores[name] = memory.New()
		}
	case "vault-file":
		p, err := keyProtector(cfg, paths)
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
		return audit.OpenJSONL(paths.AuditLog())
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
		instances = append(instances, &core.Instance{
			Name: ic.Name, Realm: ic.Realm, Vaults: ic.Vaults(),
			Secrets: static.NewVaults(vaults...),
			Exposes: ic.Exposes,
			Policy:  func(name string) policy.Policy { return cfg.SecretPolicy(ic, name) },
		})
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
	auth, err := authenticator(cfg.Plugins.Authenticator)
	if err != nil {
		return nil, err
	}
	if TestBuild {
		log.Warn("TEST BUILD: test-only plugins are available; never use this binary for real secrets")
	}
	v, err := openVaults(cfg, paths, log)
	if err != nil {
		return nil, err
	}
	peers, err := peerIdentifier(cfg.Plugins.PeerIdentifier)
	if err != nil {
		return nil, err
	}
	events, err := platformEvents(cfg)
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
	auth, err := authenticator(cfg.Plugins.Authenticator)
	if err != nil {
		return nil, err
	}
	if TestBuild {
		log.Warn("TEST BUILD: test-only plugins are available; never use this binary for real secrets")
	}
	v, err := openVaults(cfg, paths, log)
	if err != nil {
		return nil, err
	}
	sink, err := openAudit(cfg, paths)
	if err != nil {
		return nil, err
	}
	return &Host{Core: newCore(cfg, paths, auth, sink, v), Audit: sink, Vaults: v.files, Protector: v.protector}, nil
}
