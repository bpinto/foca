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
	KeyProtector   string
	PeerIdentifier string
	AuditSink      string
	// InsecureFileProtector allows key_protector = "file", which keeps the
	// key that unlocks the vault in a plain file next to it.
	InsecureFileProtector bool
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
	Name  string
	Realm identity.Realm
	// Expose is what the instance may read, by vault (design §7.1). Its keys
	// are exactly the vaults the instance reads.
	Expose map[string]Expose
}

// Expose is what an instance may read in one vault: all of it, or the
// secrets it names.
type Expose struct {
	All bool
	IDs []string
}

// Vaults returns the vaults the instance reads, sorted.
func (i Instance) Vaults() []string {
	out := make([]string, 0, len(i.Expose))
	for v := range i.Expose {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// Exposes reports whether the instance may read secret id in vault.
func (i Instance) Exposes(vault, id string) bool {
	e, ok := i.Expose[vault]
	if !ok {
		return false
	}
	for _, x := range e.IDs {
		if x == id {
			return true
		}
	}
	return e.All
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
	Authenticator         string `toml:"authenticator"`
	SecretStore           string `toml:"secret_store"`
	KeyProtector          string `toml:"key_protector"`
	PeerIdentifier        string `toml:"peer_identifier"`
	AuditSink             string `toml:"audit_sink"`
	InsecureFileProtector bool   `toml:"insecure_file_protector"`
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

// rawExpose is a list of "<vault>:*" and "<vault>:<secret>" selectors.
type rawExpose struct{ m map[string]Expose }

func (e *rawExpose) UnmarshalTOML(v any) error {
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf(`expose must be a list of "<vault>:*" and "<vault>:<secret>", got %T`, v)
	}
	if len(list) == 0 {
		return errors.New("expose is empty; leave it out for the instance's own vault")
	}
	e.m = map[string]Expose{}
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return fmt.Errorf("expose entries must be strings, got %T", item)
		}
		vault, sel, ok := strings.Cut(s, ":")
		switch {
		case !ok:
			return fmt.Errorf(`expose: %q must be "<vault>:*" or "<vault>:<secret>"`, s)
		case !namePattern.MatchString(vault):
			return fmt.Errorf("expose: %q: invalid vault name %q", s, vault)
		case sel != "*" && !secretIDPattern.MatchString(sel):
			return fmt.Errorf("expose: %q: invalid secret name %q", s, sel)
		}
		x := e.m[vault]
		listed := false
		for _, id := range x.IDs {
			listed = listed || id == sel
		}
		switch {
		case sel == "*" && (x.All || len(x.IDs) > 0), sel != "*" && x.All:
			return fmt.Errorf("expose: %q overlaps another entry for vault %s; %s:* already names all of it", s, vault, vault)
		case listed:
			return fmt.Errorf("expose: %q is listed twice", s)
		case sel == "*":
			x.All = true
		default:
			x.IDs = append(x.IDs, sel)
		}
		e.m[vault] = x
	}
	return nil
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
		KeyProtector:   raw.Plugins.KeyProtector,

		InsecureFileProtector: raw.Plugins.InsecureFileProtector,
	}
	if c.Plugins.Authenticator == "" {
		fail("plugins.authenticator is required")
	}
	switch {
	case c.Plugins.SecretStore == "vault-file" && c.Plugins.KeyProtector == "":
		fail("plugins.key_protector is required with secret_store = \"vault-file\"")
	case c.Plugins.SecretStore != "vault-file" && c.Plugins.KeyProtector != "":
		fail("plugins.key_protector is only used with secret_store = \"vault-file\"")
	case c.Plugins.KeyProtector == "file" && !c.Plugins.InsecureFileProtector:
		// The file protector keeps the key next to the vault, so anyone who
		// can read the data dir can decrypt it. It must be asked for by name.
		fail("plugins.key_protector = \"file\" keeps the vault key in a plain file; set insecure_file_protector = true to allow it")
	case c.Plugins.InsecureFileProtector && c.Plugins.KeyProtector != "file":
		fail("plugins.insecure_file_protector is set but key_protector is not \"file\"")
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

		if ri.Expose != nil {
			inst.Expose = ri.Expose.m
			explicitExpose[name] = true
		} else {
			// No expose: all of a private vault named after the instance.
			inst.Expose = map[string]Expose{name: {All: true}}
		}
		for _, v := range inst.Vaults() {
			// An undeclared vault is the instance's own; any other must be
			// declared, so sharing is never implied by a name.
			if v != name && !declared[v] {
				fail("instances.%s.expose: vault %q is not declared in [vaults]", name, v)
			}
			users[v] = append(users[v], name)
		}
		c.Instances = append(c.Instances, inst)
	}

	// Sharing is never implicit: an instance whose own vault is shared must
	// say what it reads.
	for i := range c.Instances {
		inst := &c.Instances[i]
		if users := users[inst.Name]; len(users) > 1 && !explicitExpose[inst.Name] {
			fail("instances.%s: vault %q is shared with %s, so expose must be set explicitly (use \"%s:*\" to read all of it)",
				inst.Name, inst.Name, strings.Join(others(users, inst.Name), ", "), inst.Name)
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
