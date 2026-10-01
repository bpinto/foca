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
	"github.com/bpinto/foca/internal/plugins/provider/static"
	"github.com/bpinto/foca/internal/plugins/store/memory"
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

// Built is everything a running service needs.
type Built struct {
	Server *server.Server
	Core   *core.Service
	Audit  plugin.AuditSink
	Stores map[string]plugin.SecretStore
}

func Build(cfg *config.Config, paths config.Paths, version string, log *slog.Logger) (*Built, error) {
	auth, err := authenticator(cfg.Plugins.Authenticator)
	if err != nil {
		return nil, err
	}
	if TestBuild {
		log.Warn("TEST BUILD: test-only plugins are available; never use this binary for real secrets")
	}

	stores := map[string]plugin.SecretStore{}
	for _, v := range cfg.Vaults {
		switch cfg.Plugins.SecretStore {
		case "memory":
			stores[v] = memory.New()
		case "vault-file":
			return nil, fmt.Errorf("secret_store %q is not implemented yet", cfg.Plugins.SecretStore)
		default:
			return nil, fmt.Errorf("unknown secret_store %q", cfg.Plugins.SecretStore)
		}
	}
	if cfg.Plugins.SecretStore == "memory" {
		log.Warn("secret_store is memory: secrets are lost when the service stops")
	}

	peers, err := peerIdentifier(cfg.Plugins.PeerIdentifier)
	if err != nil {
		return nil, err
	}

	var sink plugin.AuditSink
	switch cfg.Plugins.AuditSink {
	case "jsonl":
		if err := fsutil.EnsurePrivateDir(paths.DataDir); err != nil {
			return nil, fmt.Errorf("data dir: %w", err)
		}
		sink, err = audit.OpenJSONL(paths.AuditLog())
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unknown audit_sink %q", cfg.Plugins.AuditSink)
	}

	var instances []*core.Instance
	for _, ic := range cfg.Instances {
		exp := static.Exposure{All: ic.Expose.All, IDs: ic.Expose.IDs, Tags: ic.Expose.Tags}
		instances = append(instances, &core.Instance{
			Name: ic.Name, Realm: ic.Realm, Vault: ic.Vault,
			Secrets: static.New(ic.Vault, stores[ic.Vault], exp, nil),
			Exposes: exp.Allows,
		})
	}
	svc := core.New(core.Options{
		Authenticator: auth, Audit: sink,
		PromptTimeout: cfg.Approval.PromptTimeout, MaxQueue: cfg.Approval.MaxQueue,
		ShowClient: cfg.Approval.PromptShowClient, SkipAncestors: cfg.Approval.SkipAncestors,
	}, instances, stores)
	srv := server.New(server.Options{
		Paths: paths, Instances: cfg.Instances, OpaquePeers: cfg.OpaquePeers,
		Core: svc, Peers: peers, Version: version, Log: log,
		MaxConnections: cfg.Limits.MaxConnections, IdleTimeout: cfg.Limits.IdleTimeout,
	})
	return &Built{Server: srv, Core: svc, Audit: sink, Stores: stores}, nil
}
