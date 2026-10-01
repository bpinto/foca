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
	"time"
	"unicode"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/ids"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/protocol"
)

type Options struct {
	Authenticator plugin.Authenticator
	Audit         plugin.AuditSink
	PromptTimeout time.Duration
	MaxQueue      int
	ShowClient    bool
	SkipAncestors []string
	Now           func() time.Time
}

// Instance is one realm's view of the service.
type Instance struct {
	Name    string
	Realm   identity.Realm
	Vault   string
	Secrets plugin.Provider
	// Exposes reports whether this instance can see a secret with this
	// metadata. Tag selectors make this depend on vault metadata, so the
	// host CLI shows it when a secret is added (design §7.1).
	Exposes func(plugin.SecretMeta) bool
}

// visibleTo lists the realms of every instance that would see meta in vault.
func (s *Service) visibleTo(vault string, meta plugin.SecretMeta) (realms []identity.Realm, names []string) {
	for _, inst := range s.instances {
		if inst.Vault == vault && inst.Exposes != nil && inst.Exposes(meta) {
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
}

func New(opts Options, instances []*Instance, stores map[string]plugin.SecretStore) *Service {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &Service{opts: opts, instances: map[string]*Instance{}, stores: stores, queue: newPromptQueue(opts.MaxQueue, len(instances)),
		rej: rejections{windows: map[string]*rejWindow{}}}
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
	Instance  *Instance
	Peer      identity.VerifiedPeer
	Reported  *identity.ClientInfo
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
	seq, err := s.opts.Audit.Append(context.WithoutCancel(ctx), e)
	if err != nil {
		return 0, s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
	}
	return seq, nil
}

func (s *Service) fail(c Call, code int, seq uint64, format string, a ...any) *protocol.Error {
	e := protocol.NewError(code, format, a...)
	e.Data.RequestID = c.RequestID
	e.Data.EventSeq = seq
	return e
}

// ---- secret.list ----

func (s *Service) ListSecrets(ctx context.Context, c Call) ([]plugin.Resource, error) {
	rs, err := c.Instance.Secrets.List(ctx)
	if err != nil {
		e := s.Event(c, audit.TypeSecretList, audit.OutcomeError)
		e.Error = &audit.ErrorInfo{Code: "internal", Message: err.Error()}
		seq, aerr := s.record(ctx, c, e)
		if aerr != nil {
			return nil, aerr
		}
		return nil, s.fail(c, protocol.CodeInternal, seq, "listing failed")
	}
	e := s.Event(c, audit.TypeSecretList, audit.OutcomeOK)
	e.Approval = &audit.Approval{Mode: audit.ModeNone}
	e.Count = len(rs)
	if _, aerr := s.record(ctx, c, e); aerr != nil {
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
	names, perr := s.checkNames(c, names)
	if perr != nil {
		return nil, perr
	}

	// Resolve every name before prompting; never prompt for a partial batch.
	var resources []plugin.Resource
	var missing []string
	for _, n := range names {
		r, err := c.Instance.Secrets.Resolve(ctx, n)
		if err == nil {
			resources = append(resources, r)
			continue
		}
		if !errors.Is(err, plugin.ErrNotFound) {
			return nil, s.internal(ctx, c, audit.TypeSecretRead, n, err)
		}
		reason := "unknown"
		if errors.Is(err, plugin.ErrNotExposed) {
			reason = "not_exposed"
		}
		e := s.Event(c, audit.TypeSecretRead, audit.OutcomeNotFound)
		e.Resource = &audit.Resource{Kind: "secret", ID: n}
		e.Reason = reason
		if _, aerr := s.record(ctx, c, e); aerr != nil {
			return nil, aerr
		}
		missing = append(missing, n)
	}
	if len(missing) > 0 {
		// Same message whether unknown or not exposed.
		return nil, s.fail(c, protocol.CodeNotFound, 0, "secret not found: %s", strings.Join(missing, ", "))
	}

	refs := make([]plugin.ResourceRef, len(resources))
	for i, r := range resources {
		refs[i] = r.Ref
	}
	appr, err := s.approve(ctx, c, "secret.read", refs, audit.TypeSecretRead)
	if err != nil {
		return nil, err
	}

	if ctx.Err() != nil {
		// Approved, but the client is gone: don't decrypt anything.
		for _, r := range resources {
			e := s.Event(c, audit.TypeSecretRead, audit.OutcomeError)
			e.Resource = &audit.Resource{Kind: "secret", ID: r.Ref.ID}
			e.Approval = appr
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
	// Record every read before releasing any value.
	for _, r := range resources {
		e := s.Event(c, audit.TypeSecretRead, audit.OutcomeOK)
		e.Resource = &audit.Resource{Kind: "secret", ID: r.Ref.ID}
		e.Approval = appr
		if _, aerr := s.record(ctx, c, e); aerr != nil {
			ZeroSecrets(out)
			return nil, aerr
		}
	}
	return out, nil
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
		if !validSecretID(n) {
			return nil, s.fail(c, protocol.CodeInvalidParams, 0, "invalid secret name %q", n)
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
	e.Error = &audit.ErrorInfo{Code: "internal", Message: err.Error()}
	seq, aerr := s.record(ctx, c, e)
	if aerr != nil {
		return aerr
	}
	return s.fail(c, protocol.CodeInternal, seq, "internal error")
}

// ---- approval ----

// approve asks the authenticator, records the decision, and on denial also
// records one access event per resource so a UI can show what was attempted.
// There is no reuse yet: every call is a fresh approval.
func (s *Service) approve(ctx context.Context, c Call, op string, refs []plugin.ResourceRef, accessType string) (*audit.Approval, error) {
	return s.approveVisible(ctx, c, op, refs, accessType, nil)
}

// approveVisible is approve with the list of realms an added secret becomes
// visible to, which the add prompt must state.
func (s *Service) approveVisible(ctx context.Context, c Call, op string, refs []plugin.ResourceRef, accessType string, visible []identity.Realm) (*audit.Approval, error) {
	auth := s.opts.Authenticator
	approvalID := ids.New()
	resources := make([]audit.Resource, len(refs))
	for i, r := range refs {
		resources[i] = audit.Resource{Kind: r.Kind, ID: r.ID}
	}
	prompt, fits := BuildPrompt(PromptInput{
		Operation: op, Realm: c.Instance.Realm, Vault: c.Instance.Vault, Resources: refs,
		Requester: c.requester(), ShowClient: s.opts.ShowClient, Skip: s.opts.SkipAncestors,
		VisibleTo: visible,
	})
	if !fits {
		// Every name must be on screen; refuse rather than elide any.
		e := s.Event(c, audit.TypeRequestRejected, audit.OutcomeRejected)
		e.Resources = resources
		e.Reason = "prompt_too_long"
		seq, err := s.RecordRejection(ctx, e)
		if err != nil {
			return nil, s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
		}
		return nil, s.fail(c, protocol.CodeInvalidParams, seq,
			"these names don't fit in one approval prompt; split the request")
	}
	base := audit.Approval{ID: approvalID, Mode: audit.ModeFresh, Authenticator: auth.Name(), Scope: "request", PromptText: prompt}

	deny := func(typ, outcome, reason string, code int, msg string) error {
		e := s.Event(c, typ, outcome)
		e.Resources = resources
		e.Reason = reason
		a := base
		e.Approval = &a
		seq, aerr := s.record(ctx, c, e)
		if aerr != nil {
			return aerr
		}
		for _, r := range resources {
			ae := s.Event(c, accessType, audit.OutcomeDenied)
			r := r
			ae.Resource = &r
			ae.Reason = reason
			a := base
			ae.Approval = &a
			if _, aerr := s.record(ctx, c, ae); aerr != nil {
				return aerr
			}
		}
		return s.fail(c, code, seq, "%s", msg)
	}

	if ok, why := auth.Available(ctx); !ok {
		return nil, deny(audit.TypeApprovalDenied, audit.OutcomeError, "auth_unavailable",
			protocol.CodeAuthUnavailable, "no approval prompt can be shown here: "+why)
	}

	release, err := s.queue.acquire(ctx, c.Instance.Name)
	if err != nil {
		if errors.Is(err, errBusy) {
			e := s.Event(c, audit.TypeRequestRejected, audit.OutcomeRejected)
			e.Resources = resources
			e.Reason = "busy"
			seq, err := s.RecordRejection(ctx, e)
			if err != nil {
				return nil, s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
			}
			return nil, s.fail(c, protocol.CodeBusy, seq, "too many approvals pending; try again")
		}
		return nil, deny(audit.TypeApprovalTimeout, audit.OutcomeDenied, "cancelled", protocol.CodeTimeout, "request cancelled while waiting")
	}
	pctx, cancel := context.WithTimeout(ctx, s.opts.PromptTimeout)
	res, err := auth.Approve(pctx, plugin.ApprovalRequest{
		ID: approvalID, Instance: c.Instance.Name, Realm: c.Instance.Realm, Operation: op,
		Resources: refs, Requester: c.requester(), Prompt: prompt, Timeout: s.opts.PromptTimeout,
	})
	timedOut := pctx.Err() != nil
	cancel()
	release()

	switch {
	case err == nil && res.Approved:
		now := s.opts.Now().UTC().Truncate(time.Millisecond)
		a := base
		a.Method = res.Method
		a.GrantedAt = &now
		e := s.Event(c, audit.TypeApprovalGranted, audit.OutcomeOK)
		e.Resources = resources
		e.Approval = &a
		if _, aerr := s.record(ctx, c, e); aerr != nil {
			// Not recorded means not approved.
			return nil, aerr
		}
		return &a, nil
	case err == nil:
		base.Method = res.Method
		return nil, deny(audit.TypeApprovalDenied, audit.OutcomeDenied, "user_denied", protocol.CodeDenied, "access denied")
	case ctx.Err() != nil:
		// The client hung up or the service is stopping.
		return nil, deny(audit.TypeApprovalTimeout, audit.OutcomeDenied, "cancelled", protocol.CodeTimeout, "request cancelled")
	case errors.Is(err, plugin.ErrUnavailable):
		return nil, deny(audit.TypeApprovalDenied, audit.OutcomeError, "auth_unavailable", protocol.CodeAuthUnavailable, "no approval prompt can be shown here")
	case timedOut || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		return nil, deny(audit.TypeApprovalTimeout, audit.OutcomeDenied, "timeout", protocol.CodeTimeout, "approval timed out")
	default:
		return nil, deny(audit.TypeApprovalDenied, audit.OutcomeError, "authenticator_error", protocol.CodeDenied, "approval failed")
	}
}

// ---- secret.add (host CLI) ----

// AddSecret runs in the host CLI process, not behind a socket: the CLI builds
// its own Service over the same authenticator, store and audit sink.

type NewSecret struct {
	Vault       string
	ID          string
	DisplayName string
	Description string
	Tags        []string
	Value       []byte
}

func (s *Service) AddSecret(ctx context.Context, c Call, ns NewSecret) error {
	if ns.Vault == "" {
		ns.Vault = c.Instance.Vault
	}
	store, ok := s.stores[ns.Vault]
	if !ok {
		return s.fail(c, protocol.CodeInvalidParams, 0, "unknown vault %q", ns.Vault)
	}
	if !validSecretID(ns.ID) {
		return s.fail(c, protocol.CodeInvalidParams, 0, "invalid secret name %q", ns.ID)
	}
	if err := validLabel("display_name", ns.DisplayName, 64); err != nil {
		return s.fail(c, protocol.CodeInvalidParams, 0, "%v", err)
	}
	if err := validLabel("description", ns.Description, 512); err != nil {
		return s.fail(c, protocol.CodeInvalidParams, 0, "%v", err)
	}
	for _, t := range ns.Tags {
		if err := validLabel("tag", t, 64); err != nil || t == "" || strings.ContainsAny(t, " ,:") {
			return s.fail(c, protocol.CodeInvalidParams, 0, "invalid tag %q", t)
		}
	}
	if len(ns.Value) == 0 {
		return s.fail(c, protocol.CodeInvalidParams, 0, "value must not be empty")
	}
	existing, err := store.List(ctx, nil)
	if err != nil {
		// Without the list we can't rule out overwriting a secret.
		return s.internal(ctx, c, audit.TypeSecretAdd, ns.ID, err)
	}
	for _, m := range existing {
		if m.ID == ns.ID {
			return s.fail(c, protocol.CodeInvalidParams, 0, "secret %q already exists in vault %q", ns.ID, ns.Vault)
		}
	}

	ref := plugin.ResourceRef{Kind: "secret", ID: ns.ID, Display: displayOr(ns.DisplayName, ns.ID)}
	addCall := c
	inst := *c.Instance
	inst.Vault = ns.Vault
	addCall.Instance = &inst
	meta := plugin.SecretMeta{ID: ns.ID, DisplayName: ns.DisplayName, Description: ns.Description, Tags: ns.Tags}
	// Tag selectors mean metadata decides who sees the secret, so the prompt
	// names every realm it becomes visible to before anyone approves.
	visible, visibleNames := s.visibleTo(ns.Vault, meta)
	appr, err := s.approveVisible(ctx, addCall, "secret.add", []plugin.ResourceRef{ref}, audit.TypeSecretAdd, visible)
	if err != nil {
		return err
	}
	if err := store.Put(ctx, nil, meta, plugin.SecretValue{Bytes: ns.Value}); err != nil {
		return s.internal(ctx, addCall, audit.TypeSecretAdd, ns.ID, err)
	}
	e := s.Event(addCall, audit.TypeSecretAdd, audit.OutcomeOK)
	e.Resource = &audit.Resource{Kind: "secret", ID: ns.ID}
	e.Params = map[string]string{"visible_to": strings.Join(visibleNames, ",")}
	e.Approval = appr
	if _, aerr := s.record(ctx, addCall, e); aerr != nil {
		// The value is stored but unrecorded: remove it again so nothing
		// exists that the audit log doesn't know about.
		if derr := store.Delete(context.WithoutCancel(ctx), nil, ns.ID); derr != nil {
			// Nothing more can be recorded. Say plainly what was left
			// behind, so the operator can remove it.
			return s.fail(addCall, protocol.CodeAuditFailed, 0,
				"could not record the add, and could not undo it (%v): secret %q is stored in vault %q without an audit record; remove it",
				derr, ns.ID, ns.Vault)
		}
		return aerr
	}
	return nil
}

func displayOr(d, id string) string {
	if d != "" {
		return d
	}
	return id
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
