// Package core is the request pipeline: resolve → approve → audit → serve →
// audit → respond. It is pure Go behind plugin interfaces and has no
// knowledge of sockets.
package core

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/policy"
	"github.com/bpinto/foca/internal/protocol"
	"github.com/bpinto/foca/internal/secretname"
)

type Options struct {
	Authenticator plugin.Authenticator
	Audit         plugin.AuditSink
	PromptTimeout time.Duration
	MaxQueue      int
	ShowClient    bool
	SkipAncestors []string
	// Keys unseals each vault's data key, by vault name. A vault without
	// one is a store that doesn't encrypt (the in-memory test store).
	Keys map[string]plugin.DEKFunc
	// Now is the wall clock; grants expire by it (design D11). Mono is
	// time elapsed on a clock that stops during sleep. The watchdog compares
	// the two every WatchEvery.
	Now        func() time.Time
	Mono       func() time.Duration
	WatchEvery time.Duration
	// PromptPause is how long the prompt slot stays held after a prompt
	// ends by timeout or cancel, so a queued prompt can't appear under a
	// finger that was reaching for the one that just closed.
	PromptPause time.Duration
	// PromptLock, if set, is held while a prompt is on screen and through
	// the pause after it. The service and the host CLI share it, so foca
	// never shows two prompts at once. nil means no lock.
	PromptLock func(ctx context.Context) (release func(), err error)
}

// Instance is one realm's view of the service.
type Instance struct {
	Name  string
	Realm identity.Realm
	// Vault is the vault a host operation changes; prompts and events name
	// it. A realm's instance leaves it empty: each read names its own.
	Vault   string
	Secrets plugin.Provider
	// Vaults are the vaults the instance reads, and Exposes says which of
	// their secrets it may see (design §7.1). Host operations name the
	// realms a change reaches with them.
	Vaults  []string
	Exposes func(vault, secretID string) bool
	// Policy is the folded config policy for reading a secret, by its full
	// name (design §9.2). nil means every-time.
	Policy func(name string) policy.Policy
}

// visibleTo lists the realms of every instance that may read secret id in
// vault.
func (s *Service) visibleTo(vault, id string) (realms []identity.Realm, names []string) {
	for _, inst := range s.instances {
		if inst.Exposes != nil && inst.Exposes(vault, id) {
			realms = append(realms, inst.Realm)
			names = append(names, inst.Name)
		}
	}
	sort.Strings(names)
	sort.Slice(realms, func(i, j int) bool { return realms[i].Kind+realms[i].Name < realms[j].Kind+realms[j].Name })
	return realms, names
}

type Service struct {
	opts      Options
	instances map[string]*Instance
	stores    map[string]plugin.SecretStore
	queue     *promptQueue
	rej       rejections
	lim       limiter

	// mu guards grants, denial backoff and platform-event health.
	mu      sync.Mutex
	grants  map[grantKey]*grant
	denials map[denialKey]*denial
	strikes map[string][]strike // per instance, oldest first
	// healthy: platform events are reporting, so grants can be wiped on
	// sleep and lock. Reuse is off while it is false (design D13).
	healthy bool
	// wipes counts wipes, so an approval that was pending during one
	// creates no grant.
	wipes uint64
	// clock is the wall-clock and monotonic time at the last clock check.
	clock struct {
		mu   sync.Mutex
		wall time.Time
		mono time.Duration
	}
	// pauses counts the prompt pauses still running (Settle).
	pauses sync.WaitGroup

	// grantMu orders grant decisions against wipes. An approval holds it
	// for reading from deciding on a grant until the grant exists, and Wipe
	// holds it for writing, so approval.granted never claims a grant that a
	// wipe kept from being made. Take it before mu.
	grantMu sync.RWMutex

	// auditFailed: the last append to the audit sink failed. Coalesced
	// events are then written, not counted, so a sink that stopped refuses
	// them too (design D10).
	auditFailed atomic.Bool
}

func New(opts Options, instances []*Instance, stores map[string]plugin.SecretStore) *Service {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Mono == nil {
		start := time.Now()
		opts.Mono = func() time.Duration { return time.Since(start) }
	}
	if opts.WatchEvery == 0 {
		opts.WatchEvery = 5 * time.Second
	}
	if opts.PromptPause == 0 {
		opts.PromptPause = 1500 * time.Millisecond
	}
	s := &Service{opts: opts, instances: map[string]*Instance{}, stores: stores, queue: newPromptQueue(opts.MaxQueue, len(instances)),
		rej: rejections{windows: map[string]*rejWindow{}}, grants: map[grantKey]*grant{}, denials: map[denialKey]*denial{},
		strikes: map[string][]strike{}}
	for _, i := range instances {
		s.instances[i.Name] = i
	}
	return s
}

func (s *Service) Instance(name string) (*Instance, bool) {
	i, ok := s.instances[name]
	return i, ok
}

func (s *Service) Audit() plugin.AuditSink { return s.opts.Audit }

// Call describes one request: where it came from and who sent it.
type Call struct {
	RequestID string
	Origin    string // audit.OriginClientSocket | audit.OriginHostCLI
	// Conn identifies the socket connection, for connection-scoped grants.
	Conn     string
	Instance *Instance
	Peer     identity.VerifiedPeer
	Reported *identity.ClientInfo
}

func (c Call) requester() plugin.Requester {
	return plugin.Requester{Peer: c.Peer, Reported: c.Reported}
}

// Event returns an audit event pre-filled with the call's context. Verified
// and reported identity go into separate blocks.
func (s *Service) Event(c Call, typ, outcome string) *audit.Event {
	peer := c.Peer
	e := &audit.Event{
		Type: typ, Outcome: outcome, RequestID: c.RequestID, Origin: c.Origin,
		Peer: &audit.Peer{Verified: &peer},
	}
	if c.Instance != nil {
		e.Instance = c.Instance.Name
		e.Vault = c.Instance.Vault
	}
	if c.Reported != nil {
		r := *c.Reported
		e.Client = &audit.Client{Reported: &r}
	}
	return e
}

// record appends an event. A failure becomes an audit_failed error that the
// caller must return instead of whatever it was about to do. The write is not
// cancelled with the request: a client that hangs up mid-request is still
// recorded.
func (s *Service) record(ctx context.Context, c Call, e *audit.Event) (uint64, *protocol.Error) {
	seq, err := s.appendEvent(ctx, e)
	if err != nil {
		return 0, s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
	}
	return seq, nil
}

// appendEvent writes e to the audit sink, and remembers whether that worked.
func (s *Service) appendEvent(ctx context.Context, e *audit.Event) (uint64, error) {
	seq, err := s.opts.Audit.Append(context.WithoutCancel(ctx), e)
	s.auditFailed.Store(err != nil)
	return seq, err
}

func (s *Service) fail(c Call, code int, seq uint64, format string, a ...any) *protocol.Error {
	e := protocol.NewError(code, format, a...)
	e.Data.RequestID = c.RequestID
	e.Data.EventSeq = seq
	return e
}

// ---- secret.list ----

func (s *Service) ListSecrets(ctx context.Context, c Call) ([]plugin.Resource, error) {
	if err := s.limit(ctx, c, protocol.MethodSecretList); err != nil {
		return nil, err
	}
	rs, err := c.Instance.Secrets.List(ctx)
	if err != nil {
		return nil, s.internal(ctx, c, audit.TypeSecretList, "", err)
	}
	e := s.Event(c, audit.TypeSecretList, audit.OutcomeOK)
	e.Approval = &audit.Approval{Mode: audit.ModeNone}
	e.Count = len(rs)
	if _, aerr := s.recordCoalesced(ctx, c, e); aerr != nil {
		return nil, aerr
	}
	return rs, nil
}

// ---- secret.read ----

// Secret is one served value. The caller must zero Value after use.
type Secret struct {
	Name  string
	Value []byte
}

const maxBatch = 32

func ZeroSecrets(ss []Secret) {
	for i := range ss {
		for j := range ss[i].Value {
			ss[i].Value[j] = 0
		}
		ss[i].Value = nil
	}
}

func (s *Service) ReadSecrets(ctx context.Context, c Call, names []string) ([]Secret, error) {
	if err := s.limit(ctx, c, protocol.MethodSecretRead); err != nil {
		return nil, err
	}
	names, perr := s.checkNames(c, names)
	if perr != nil {
		return nil, perr
	}

	// Resolve every name before prompting; never prompt for a partial batch.
	resolved, errs, err := c.Instance.Secrets.Resolve(ctx, names)
	if err != nil {
		return nil, s.internal(ctx, c, audit.TypeSecretRead, "", err)
	}
	var resources []plugin.Resource
	var missing []string
	for i, n := range names {
		if errs[i] == nil {
			resources = append(resources, resolved[i])
			continue
		}
		if !errors.Is(errs[i], plugin.ErrNotFound) {
			return nil, s.internal(ctx, c, audit.TypeSecretRead, n, errs[i])
		}
		reason := "unknown"
		if errors.Is(errs[i], plugin.ErrNotExposed) {
			reason = "not_exposed"
		}
		e := s.Event(c, audit.TypeSecretRead, audit.OutcomeNotFound)
		e.Resource = &audit.Resource{Kind: "secret", ID: n}
		e.Reason = reason
		if _, aerr := s.recordCoalesced(ctx, c, e); aerr != nil {
			return nil, aerr
		}
		missing = append(missing, n)
	}
	if len(missing) > 0 {
		// Same message whether unknown or not exposed.
		return nil, s.fail(c, protocol.CodeNotFound, 0, "secret not found: %s", strings.Join(missing, ", "))
	}

	approvals, err := s.approveRead(ctx, c, resources)
	if err != nil {
		return nil, err
	}

	if ctx.Err() != nil {
		// Approved, but the client is gone: don't decrypt anything.
		for _, r := range resources {
			e := s.Event(c, audit.TypeSecretRead, audit.OutcomeError)
			e.Resource = &audit.Resource{Kind: "secret", ID: r.Ref.ID}
			setVault(e, r.Ref)
			e.Approval = approvals[r.Ref.ID]
			e.Reason = "cancelled"
			if _, aerr := s.record(ctx, c, e); aerr != nil {
				return nil, aerr
			}
		}
		return nil, s.fail(c, protocol.CodeTimeout, 0, "request cancelled")
	}

	out := make([]Secret, 0, len(resources))
	for _, r := range resources {
		res, err := c.Instance.Secrets.Serve(ctx, r, nil)
		if err != nil {
			ZeroSecrets(out)
			return nil, s.internal(ctx, c, audit.TypeSecretRead, r.Ref.ID, err)
		}
		out = append(out, Secret{Name: r.Ref.ID, Value: res.Value})
	}
	if !fitsOneMessage(out) {
		// The client could never read the answer: nothing is served, and
		// nothing recorded as served.
		ZeroSecrets(out)
		var seq uint64
		for _, r := range resources {
			e := s.Event(c, audit.TypeSecretRead, audit.OutcomeError)
			e.Resource = &audit.Resource{Kind: "secret", ID: r.Ref.ID}
			setVault(e, r.Ref)
			e.Approval = approvals[r.Ref.ID]
			e.Reason = "response_too_large"
			var aerr *protocol.Error
			if seq, aerr = s.record(ctx, c, e); aerr != nil {
				return nil, aerr
			}
		}
		return nil, s.fail(c, protocol.CodeInvalidParams, seq, "the values don't fit in one answer (%d bytes); read fewer at a time", protocol.MaxMessage)
	}
	// Record every read before releasing any value.
	for _, r := range resources {
		e := s.Event(c, audit.TypeSecretRead, audit.OutcomeOK)
		e.Resource = &audit.Resource{Kind: "secret", ID: r.Ref.ID}
		setVault(e, r.Ref)
		e.Approval = approvals[r.Ref.ID]
		if _, aerr := s.record(ctx, c, e); aerr != nil {
			ZeroSecrets(out)
			return nil, aerr
		}
	}
	return out, nil
}

// fitsOneMessage: the secret.read answer for out, whatever its id, fits in
// one protocol message.
func fitsOneMessage(out []Secret) bool {
	names := make([]string, len(out))
	values := make([][]byte, len(out))
	for i, sec := range out {
		names[i], values[i] = sec.Name, sec.Value
	}
	return protocol.SecretReadLen(names, values) <= protocol.MaxResult
}

func (s *Service) checkNames(c Call, names []string) ([]string, *protocol.Error) {
	if len(names) == 0 {
		return nil, s.fail(c, protocol.CodeInvalidParams, 0, "names must not be empty")
	}
	if len(names) > maxBatch {
		return nil, s.fail(c, protocol.CodeInvalidParams, 0, "at most %d names per request", maxBatch)
	}
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if _, _, ok := secretname.Split(n); !ok {
			return nil, s.fail(c, protocol.CodeInvalidParams, 0, "invalid secret name %q: name secrets <vault>:<secret>", n)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

func (s *Service) internal(ctx context.Context, c Call, typ, id string, err error) error {
	e := s.Event(c, typ, audit.OutcomeError)
	if id != "" {
		e.Resource = &audit.Resource{Kind: "secret", ID: id}
	}
	if errors.Is(err, plugin.ErrNotInitialized) {
		e.Error = &audit.ErrorInfo{Code: protocol.CodeName(protocol.CodeNotInitialized), Message: err.Error()}
		seq, aerr := s.record(ctx, c, e)
		if aerr != nil {
			return aerr
		}
		return s.fail(c, protocol.CodeNotInitialized, seq, "%s", notInitialized(err))
	}
	e.Error = &audit.ErrorInfo{Code: "internal", Message: err.Error()}
	seq, aerr := s.record(ctx, c, e)
	if aerr != nil {
		return aerr
	}
	return s.fail(c, protocol.CodeInternal, seq, "internal error")
}

func validSecretID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r == '-' || r == '_' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	return true
}

func validLabel(field, s string, max int) error {
	if len(s) > max {
		return fmt.Errorf("%s must be at most %d bytes", field, max)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return fmt.Errorf("%s must not contain control or format characters", field)
		}
	}
	return nil
}

// notInitialized says which vault isn't initialized, when the error names it.
func notInitialized(err error) string {
	var ni plugin.NotInitialized
	if errors.As(err, &ni) {
		return ni.Error()
	}
	return "a vault is not initialized"
}

// setVault names the vault of refs on e, when they are all in one; events
// about several vaults name none.
func setVault(e *audit.Event, refs ...plugin.ResourceRef) {
	vault := ""
	for i, r := range refs {
		if r.Vault == "" || i > 0 && r.Vault != vault {
			return
		}
		vault = r.Vault
	}
	if vault != "" {
		e.Vault = vault
	}
}
