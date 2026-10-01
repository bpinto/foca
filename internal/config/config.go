// Package config loads and validates the host-owned TOML config.
//
// Validation is strict on purpose: unknown keys, out-of-range values and
// ambiguous sharing are errors, never silently corrected.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/identity"
)

// Config is the validated result of loading a config file.
type Config struct {
	Path        string
	OpaquePeers []string
	Plugins     Plugins
	Approval    Approval
	Limits      Limits
	Vaults      []string
	Instances   []Instance
}

type Plugins struct {
	Authenticator  string
	SecretStore    string
	PeerIdentifier string
	AuditSink      string
}

type Approval struct {
	PromptTimeout    time.Duration
	MaxQueue         int
	PromptShowClient bool
	SkipAncestors    []string
}

// Limits bound what one realm can make the service hold, so a misbehaving
// realm can't exhaust it for the others.
type Limits struct {
	// MaxConnections is per instance. Further connections are closed at once.
	MaxConnections int
	// IdleTimeout closes a connection that sends no complete request for
	// this long. It doesn't apply while a request is being handled.
	IdleTimeout time.Duration
}

type Instance struct {
	Name   string
	Realm  identity.Realm
	Vault  string
	Expose Expose
	// SharedVault is true when another instance uses the same vault.
	SharedVault bool
}

// Expose lists what an instance may see in its vault.
type Expose struct {
	All  bool
	IDs  []string
	Tags []string
}

// Limits.
const (
	MinPromptTimeout = 5 * time.Second
	MaxPromptTimeout = 10 * time.Minute
	MaxQueueLimit    = 64

	DefaultMaxConnections = 32
	MaxConnectionsLimit   = 1024
	DefaultIdleTimeout    = 2 * time.Minute
	MinIdleTimeout        = 5 * time.Second
	MaxIdleTimeout        = time.Hour
)

var (
	namePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	secretIDPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	tagPattern       = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	realmNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)
)

// ValidName reports whether s is a valid instance or vault name.
func ValidName(s string) bool { return namePattern.MatchString(s) }

// ValidSecretID reports whether s is a valid secret id.
func ValidSecretID(s string) bool { return secretIDPattern.MatchString(s) }

// DefaultOpaquePeers are programs that relay a socket for someone else. On a
// direct realm they are refused; on an opaque realm the peer must be one.
// macOS container runtimes' proxies are added once checked on a Mac;
// until then such a realm must list its runtime's proxy, and fails closed.
var DefaultOpaquePeers = []string{"ssh", "sshd", "sshd-session", "socat", "nc", "ncat", "systemd-socket-proxyd"}

// goos is the OS the config is validated for; tests override it.
var goos = runtime.GOOS

var defaultSkipAncestors = []string{
	"sh", "bash", "zsh", "fish", "nu", "dash", "ksh", "tmux", "screen",
	"sshd", "sshd-session", "login", "su", "sudo", "env", "nix", "direnv", "foca",
}

// ---- raw file shape ----

type rawFile struct {
	Version     int                    `toml:"version"`
	OpaquePeers []string               `toml:"opaque_peers"`
	Plugins     rawPlugins             `toml:"plugins"`
	Approval    rawApproval            `toml:"approval"`
	Limits      rawLimits              `toml:"limits"`
	Vaults      map[string]rawVault    `toml:"vaults"`
	Instances   map[string]rawInstance `toml:"instances"`
}

type rawPlugins struct {
	Authenticator  string `toml:"authenticator"`
	SecretStore    string `toml:"secret_store"`
	PeerIdentifier string `toml:"peer_identifier"`
	AuditSink      string `toml:"audit_sink"`
}

type rawApproval struct {
	PromptTimeout    *duration `toml:"prompt_timeout"`
	MaxQueue         *int      `toml:"max_queue"`
	PromptShowClient *bool     `toml:"prompt_show_client"`
	SkipAncestors    []string  `toml:"skip_ancestors"`
}

type rawLimits struct {
	MaxConnections *int      `toml:"max_connections"`
	IdleTimeout    *duration `toml:"idle_timeout"`
}

type rawVault struct{}

type rawInstance struct {
	Realm  *rawRealm  `toml:"realm"`
	Vault  string     `toml:"vault"`
	Expose *rawExpose `toml:"expose"`
}

type rawRealm struct {
	Kind  string `toml:"kind"`
	Name  string `toml:"name"`
	Peers string `toml:"peers"`
}

type duration struct{ time.Duration }

func (d *duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// rawExpose accepts either the string "*" or a list of ids and "tag:" selectors.
type rawExpose struct{ Expose }

func (e *rawExpose) UnmarshalTOML(v any) error {
	switch x := v.(type) {
	case string:
		if x != "*" {
			return fmt.Errorf(`expose must be "*" or a list, got %q`, x)
		}
		e.All = true
		return nil
	case []any:
		for _, item := range x {
			s, ok := item.(string)
			if !ok {
				return fmt.Errorf("expose entries must be strings, got %T", item)
			}
			switch {
			case s == "*":
				return errors.New(`expose: use expose = "*" instead of a list containing "*"`)
			case strings.HasPrefix(s, "tag:"):
				tag := strings.TrimPrefix(s, "tag:")
				if !tagPattern.MatchString(tag) {
					return fmt.Errorf("expose: invalid tag %q", tag)
				}
				e.Tags = append(e.Tags, tag)
			default:
				if !secretIDPattern.MatchString(s) {
					return fmt.Errorf("expose: invalid secret id %q", s)
				}
				e.IDs = append(e.IDs, s)
			}
		}
		return nil
	default:
		return fmt.Errorf(`expose must be "*" or a list, got %T`, v)
	}
}

// ---- loading ----

// Load reads, trust-checks and validates the config file at path.
func Load(path string) (*Config, error) {
	resolved, err := fsutil.CheckTrustedFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	b, err := os.ReadFile(resolved)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c.Path = path
	return c, nil
}

// Parse validates config bytes. It does no file checks.
func Parse(b []byte) (*Config, error) {
	var raw rawFile
	md, err := toml.Decode(string(b), &raw)
	if err != nil {
		return nil, err
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("unknown keys: %s", strings.Join(keys, ", "))
	}
	if keys := miscasedKeys(md, &raw); len(keys) > 0 {
		return nil, fmt.Errorf("unknown keys: %s (key names are matched exactly)", strings.Join(keys, ", "))
	}
	return validate(&raw)
}

func validate(raw *rawFile) (*Config, error) {
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if raw.Version != 1 {
		fail("version must be 1 (got %d)", raw.Version)
	}
	c := &Config{}

	// plugins
	c.Plugins = Plugins{
		Authenticator:  raw.Plugins.Authenticator,
		SecretStore:    orDefault(raw.Plugins.SecretStore, "memory"),
		PeerIdentifier: orDefault(raw.Plugins.PeerIdentifier, "auto"),
		AuditSink:      orDefault(raw.Plugins.AuditSink, "jsonl"),
	}
	if c.Plugins.Authenticator == "" {
		fail("plugins.authenticator is required")
	}

	// approval
	a := Approval{PromptTimeout: 60 * time.Second, MaxQueue: 4, PromptShowClient: true,
		SkipAncestors: defaultSkipAncestors}
	if raw.Approval.PromptTimeout != nil {
		a.PromptTimeout = raw.Approval.PromptTimeout.Duration
		if a.PromptTimeout < MinPromptTimeout || a.PromptTimeout > MaxPromptTimeout {
			fail("approval.prompt_timeout %s is outside %s..%s", a.PromptTimeout, MinPromptTimeout, MaxPromptTimeout)
		}
	}
	if raw.Approval.MaxQueue != nil {
		a.MaxQueue = *raw.Approval.MaxQueue
		if a.MaxQueue < 0 || a.MaxQueue > MaxQueueLimit {
			fail("approval.max_queue %d is outside 0..%d", a.MaxQueue, MaxQueueLimit)
		}
	}
	if raw.Approval.PromptShowClient != nil {
		a.PromptShowClient = *raw.Approval.PromptShowClient
	}
	if raw.Approval.SkipAncestors != nil {
		a.SkipAncestors = raw.Approval.SkipAncestors
	}
	c.Approval = a

	// limits
	l := Limits{MaxConnections: DefaultMaxConnections, IdleTimeout: DefaultIdleTimeout}
	if raw.Limits.MaxConnections != nil {
		l.MaxConnections = *raw.Limits.MaxConnections
		if l.MaxConnections < 1 || l.MaxConnections > MaxConnectionsLimit {
			fail("limits.max_connections %d is outside 1..%d", l.MaxConnections, MaxConnectionsLimit)
		}
	}
	if raw.Limits.IdleTimeout != nil {
		l.IdleTimeout = raw.Limits.IdleTimeout.Duration
		if l.IdleTimeout < MinIdleTimeout || l.IdleTimeout > MaxIdleTimeout {
			fail("limits.idle_timeout %s is outside %s..%s", l.IdleTimeout, MinIdleTimeout, MaxIdleTimeout)
		}
	}
	c.Limits = l

	c.OpaquePeers = raw.OpaquePeers
	if c.OpaquePeers == nil {
		c.OpaquePeers = append([]string(nil), DefaultOpaquePeers...)
	}
	// Peers are matched by the name foca shows for them, so an entry
	// written any other way ("/usr/bin/ssh", ".ssh-wrapped") would never
	// match.
	for _, n := range c.OpaquePeers {
		if shown := identity.DisplayName(n, 64); shown != n || n == "" {
			fail("opaque_peers: %q never matches; entries are bare program names as foca shows them (%q)", n, shown)
		}
	}

	// vaults
	declared := map[string]bool{}
	for name := range raw.Vaults {
		if !namePattern.MatchString(name) {
			fail("vault name %q must match %s", name, namePattern)
		}
		declared[name] = true
	}

	// instances
	if len(raw.Instances) == 0 {
		fail("at least one [instances.<name>] is required")
	}
	names := make([]string, 0, len(raw.Instances))
	for n := range raw.Instances {
		names = append(names, n)
	}
	sort.Strings(names)

	users := map[string][]string{} // vault -> instances using it
	explicitExpose := map[string]bool{}
	for _, name := range names {
		ri := raw.Instances[name]
		if !namePattern.MatchString(name) {
			fail("instance name %q must match %s", name, namePattern)
			continue
		}
		inst := Instance{Name: name}

		realm, err := validateRealm(name, ri.Realm)
		if err != nil {
			fail("instances.%s.realm: %v", name, err)
		}
		inst.Realm = realm

		inst.Vault = ri.Vault
		if inst.Vault == "" {
			// No vault key: a private vault named after the instance.
			inst.Vault = name
		} else if !declared[inst.Vault] {
			fail("instances.%s.vault: vault %q is not declared in [vaults]", name, inst.Vault)
		}
		if ri.Expose != nil {
			inst.Expose = ri.Expose.Expose
			explicitExpose[name] = true
		}
		users[inst.Vault] = append(users[inst.Vault], name)
		c.Instances = append(c.Instances, inst)
	}

	// Sharing is never implicit: every instance using a shared vault must say
	// what it exposes.
	for i := range c.Instances {
		inst := &c.Instances[i]
		shared := len(users[inst.Vault]) > 1
		inst.SharedVault = shared
		switch {
		case shared && !explicitExpose[inst.Name]:
			fail("instances.%s: vault %q is shared with %s, so expose must be set explicitly (use expose = \"*\" to share everything)",
				inst.Name, inst.Vault, strings.Join(others(users[inst.Vault], inst.Name), ", "))
		case !shared && !explicitExpose[inst.Name]:
			inst.Expose = Expose{All: true}
		}
	}

	vaultSet := map[string]bool{}
	for v := range declared {
		vaultSet[v] = true
	}
	for v := range users {
		vaultSet[v] = true
	}
	for v := range vaultSet {
		c.Vaults = append(c.Vaults, v)
	}
	sort.Strings(c.Vaults)

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

func validateRealm(instance string, r *rawRealm) (identity.Realm, error) {
	if r == nil {
		return identity.Realm{Kind: identity.RealmHost, Name: instance, Peers: identity.PeersDirect}, nil
	}
	out := identity.Realm{Kind: r.Kind, Name: orDefault(r.Name, instance), Peers: r.Peers}
	if !realmNamePattern.MatchString(out.Name) {
		return out, fmt.Errorf("name %q must match %s", out.Name, realmNamePattern)
	}
	switch r.Kind {
	case identity.RealmHost:
		if out.Peers == "" {
			out.Peers = identity.PeersDirect
		}
	case identity.RealmVM, identity.RealmRemote:
		// The host kernel can never see a process inside a VM or on another
		// machine, so these realms can't claim direct peers.
		if out.Peers == "" {
			out.Peers = identity.PeersOpaque
		}
		if out.Peers != identity.PeersOpaque {
			return out, fmt.Errorf("a %s realm's peers are always opaque", r.Kind)
		}
	case identity.RealmContainer:
		// Depends on the host: direct for Linux containers on a Linux host,
		// opaque for containers inside a macOS runtime VM. Must be stated.
		if out.Peers == "" {
			return out, errors.New(`container realms must set peers = "direct" or "opaque"`)
		}
		if out.Peers == identity.PeersDirect && goos == "darwin" {
			// On macOS containers run inside the runtime's Linux VM; the
			// host only ever sees the runtime's proxy.
			return out, errors.New(`containers on macOS run in a VM, so their peers are always opaque`)
		}
	case "":
		return out, errors.New("kind is required (host | vm | container | remote)")
	default:
		return out, fmt.Errorf("unknown kind %q (host | vm | container | remote)", r.Kind)
	}
	if out.Peers != identity.PeersDirect && out.Peers != identity.PeersOpaque {
		return out, fmt.Errorf("peers must be %q or %q", identity.PeersDirect, identity.PeersOpaque)
	}
	return out, nil
}

func others(all []string, self string) []string {
	var out []string
	for _, n := range all {
		if n != self {
			out = append(out, n)
		}
	}
	return out
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Instance returns the named instance.
func (c *Config) Instance(name string) (Instance, bool) {
	for _, i := range c.Instances {
		if i.Name == name {
			return i, true
		}
	}
	return Instance{}, false
}
