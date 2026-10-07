package core

import (
	"context"
	"errors"
	"time"

	"github.com/bpinto/foca/internal/action"
	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/ids"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/policy"
	"github.com/bpinto/foca/internal/protocol"
)

// ask is one approval to request.
type ask struct {
	op         string // prompt template: "secret.read", "secret.add", …
	accessType string // per-resource event type recorded on denial
	refs       []plugin.ResourceRef
	// uses are the secrets an action reads on the host, and params its
	// validated params. Both are on the prompt and in every event.
	uses   []plugin.ResourceRef
	params map[string]string
	// visible and hidden name the realms a host operation affects.
	visible, hidden []identity.Realm
	// policy, when Reuse, makes approving create grants under key.
	policy  policy.Policy
	key     ScopeKey
	denials int
	// unanswered is how many of the instance's recent prompts timed out or
	// were cancelled.
	unanswered int
}

func (a ask) resources() []audit.Resource {
	out := make([]audit.Resource, len(a.refs))
	for i, r := range a.refs {
		out[i] = audit.Resource{Kind: r.Kind, ID: r.ID}
	}
	return out
}

func (s *Service) promptFor(c Call, a ask) (string, bool) {
	return BuildPrompt(PromptInput{
		Operation: a.op, Realm: c.Instance.Realm, Vault: c.Instance.Vault, Resources: a.refs,
		Requester: c.requester(), ShowClient: s.opts.ShowClient, Skip: s.opts.SkipAncestors,
		VisibleTo: a.visible, Hidden: a.hidden, Uses: a.uses, Params: a.params,
		Reach: policy.Reach(a.policy, c.Instance.Realm), Denials: a.denials, Unanswered: a.unanswered,
	})
}

// refuseTooLong refuses a request whose prompt can't show every name.
func (s *Service) refuseTooLong(ctx context.Context, c Call, a ask) error {
	e := s.Event(c, audit.TypeRequestRejected, audit.OutcomeRejected)
	e.Resources = a.resources()
	e.Reason = "prompt_too_long"
	seq, err := s.RecordRejection(ctx, e)
	if err != nil {
		return s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
	}
	if a.op == "action.run" {
		// Every value must be on screen, so long ones are refused.
		return s.fail(c, protocol.CodeParamRejected, seq, "the action's params don't fit in its approval prompt; use shorter values")
	}
	return s.fail(c, protocol.CodeInvalidParams, seq, "these names don't fit in one approval prompt; split the request")
}

// base is the approval record shared by every event about one prompt.
func (s *Service) base(a ask, text string) audit.Approval {
	b := audit.Approval{ID: ids.New(), Mode: audit.ModeFresh, Authenticator: s.opts.Authenticator.Name(), Scope: "request", PromptText: text}
	if a.policy.Kind == policy.Reuse {
		b.Scope = a.policy.Scope.String()
		b.ScopeKey = a.key.audit()
	}
	return b
}

// deny records a refused approval, and one access event per resource so a
// UI can show what was attempted.
func (s *Service) deny(ctx context.Context, c Call, a ask, base audit.Approval, typ, outcome, reason string, code int, msg string) error {
	resources := a.resources()
	e := s.Event(c, typ, outcome)
	setVault(e, a.refs...)
	e.Resources = resources
	e.Uses = refsToAudit(a.uses)
	e.Params = copyParams(a.params)
	e.Reason = reason
	ap := base
	e.Approval = &ap
	seq, aerr := s.record(ctx, c, e)
	if aerr != nil {
		return aerr
	}
	for i, r := range resources {
		ae := s.Event(c, a.accessType, audit.OutcomeDenied)
		setVault(ae, a.refs[i])
		r := r
		ae.Resource = &r
		ae.Uses = refsToAudit(a.uses)
		ae.Params = copyParams(a.params)
		ae.Reason = reason
		ap := base
		ae.Approval = &ap
		if _, aerr := s.record(ctx, c, ae); aerr != nil {
			return aerr
		}
	}
	return s.fail(c, code, seq, "%s", msg)
}

// admit runs the checks before a request may wait for the prompt: the text
// fits, an authenticator can show it, and a queue slot is free. On success
// the caller holds the slot and must pass release on to ask.
func (s *Service) admit(ctx context.Context, c Call, a ask) (release func(), err error) {
	if _, ok := s.promptFor(c, a); !ok {
		// Every name must be on screen; refuse rather than elide any.
		return nil, s.refuseTooLong(ctx, c, a)
	}
	if ok, why := s.opts.Authenticator.Available(ctx); !ok {
		return nil, s.unshown(ctx, c, a, "auth_unavailable", protocol.CodeAuthUnavailable, "no approval prompt can be shown here: "+why)
	}
	release, err = s.queue.acquire(ctx, c.Instance.Name)
	if err == nil {
		return release, nil
	}
	if errors.Is(err, errBusy) {
		e := s.Event(c, audit.TypeRequestRejected, audit.OutcomeRejected)
		e.Resources = a.resources()
		e.Reason = "busy"
		seq, err := s.RecordRejection(ctx, e)
		if err != nil {
			return nil, s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
		}
		return nil, s.fail(c, protocol.CodeBusy, seq, "too many approvals pending; try again")
	}
	return nil, s.unshown(ctx, c, a, "cancelled", protocol.CodeTimeout, "request cancelled while waiting")
}

// unshown refuses a request for which no prompt was ever shown: none can be
// shown here, or the client left while it waited. A realm can cause that as
// often as it likes, so it is one coalesced request.rejected, not an
// approval event and one per name (design §9.6).
func (s *Service) unshown(ctx context.Context, c Call, a ask, reason string, code int, msg string) error {
	e := s.Event(c, audit.TypeRequestRejected, audit.OutcomeRejected)
	e.Resources = a.resources()
	e.Reason = reason
	seq, err := s.RecordRejection(ctx, e)
	if err != nil {
		return s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
	}
	return s.fail(c, code, seq, "%s", msg)
}

// ask shows the prompt while the caller holds the queue slot, records the
// decision, then releases the slot. A grant is created only once the approval is
// recorded, and only if no wipe happened while the prompt was open.
func (s *Service) ask(ctx context.Context, c Call, a ask, release func()) (*audit.Approval, error) {
	// The slot is held until the decision is recorded and any grant or
	// denial count is in place, so the next request in the queue sees it.
	// After a timeout or cancel it is held a little longer (PromptPause),
	// without keeping the caller waiting.
	pause := false
	defer func() {
		if pause {
			s.pauses.Add(1)
			time.AfterFunc(s.opts.PromptPause, func() {
				release()
				s.pauses.Done()
			})
		} else {
			release()
		}
	}()
	text, ok := s.promptFor(c, a)
	if !ok {
		return nil, s.refuseTooLong(ctx, c, a)
	}
	base := s.base(a, text)
	if s.opts.PromptLock != nil {
		unlock, err := s.opts.PromptLock(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil, s.unshown(ctx, c, a, "cancelled", protocol.CodeTimeout, "request cancelled while waiting")
			}
			return nil, s.deny(ctx, c, a, base, audit.TypeApprovalDenied, audit.OutcomeError, "authenticator_error", protocol.CodeDenied, "approval failed")
		}
		slot := release
		release = func() { unlock(); slot() }
	}
	gen := s.generation()
	pctx, cancel := context.WithTimeout(ctx, s.opts.PromptTimeout)
	res, err := s.opts.Authenticator.Approve(pctx, plugin.ApprovalRequest{
		ID: base.ID, Instance: c.Instance.Name, Realm: c.Instance.Realm, Operation: a.op,
		Resources: a.refs, Params: copyParams(a.params), Requester: c.requester(), Prompt: text, Timeout: s.opts.PromptTimeout,
	})
	timedOut := pctx.Err() != nil
	cancel()

	switch {
	case err == nil && res.Approved:
		// No wipe may come between deciding on a grant and making it, or
		// approval.granted would claim a grant that never existed.
		s.grantMu.RLock()
		defer s.grantMu.RUnlock()
		now := s.wall().Truncate(time.Millisecond)
		ap := base
		ap.Method = res.Method
		ap.GrantedAt = &now
		grants := a.policy.Kind == policy.Reuse && s.canGrant(gen)
		if grants {
			exp := now.Add(a.policy.Window)
			ap.ExpiresAt = &exp
		} else if a.policy.Kind == policy.Reuse {
			// A wipe, or unhealthy events, while the prompt was open:
			// this request is served, but nothing is reused.
			ap.Scope, ap.ScopeKey = "request", nil
		}
		e := s.Event(c, audit.TypeApprovalGranted, audit.OutcomeOK)
		setVault(e, a.refs...)
		e.Resources = a.resources()
		e.Uses = refsToAudit(a.uses)
		e.Params = copyParams(a.params)
		e.Approval = &ap
		if _, aerr := s.record(ctx, c, e); aerr != nil {
			// Not recorded means not approved.
			return nil, aerr
		}
		s.approved(c, a, &ap, grants)
		return &ap, nil
	case err == nil:
		base.Method = res.Method
		s.denied(c, a.refs)
		s.struck(c, false)
		return nil, s.deny(ctx, c, a, base, audit.TypeApprovalDenied, audit.OutcomeDenied, "user_denied", protocol.CodeDenied, "access denied")
	case ctx.Err() != nil:
		// The client hung up or the service is stopping.
		s.struck(c, true)
		pause = true
		return nil, s.deny(ctx, c, a, base, audit.TypeApprovalTimeout, audit.OutcomeDenied, "cancelled", protocol.CodeTimeout, "request cancelled")
	case errors.Is(err, plugin.ErrUnavailable):
		return nil, s.unshown(ctx, c, a, "auth_unavailable", protocol.CodeAuthUnavailable, "no approval prompt can be shown here")
	case timedOut || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
		s.struck(c, true)
		pause = true
		return nil, s.deny(ctx, c, a, base, audit.TypeApprovalTimeout, audit.OutcomeDenied, "timeout", protocol.CodeTimeout, "approval timed out")
	default:
		return nil, s.deny(ctx, c, a, base, audit.TypeApprovalDenied, audit.OutcomeError, "authenticator_error", protocol.CodeDenied, "approval failed")
	}
}

// Settle waits until every pause after a timed-out or cancelled prompt has
// ended. The host CLI calls it before exiting: its prompt lock would
// otherwise drop with the process, and a queued prompt could open at once.
func (s *Service) Settle() { s.pauses.Wait() }

// approveVisible is the approval for host operations. They never create or
// reuse grants. Their prompts state every realm that will see the secret
// (visible) and every realm that will stop seeing it (hidden).
func (s *Service) approveVisible(ctx context.Context, c Call, op string, refs []plugin.ResourceRef, accessType string, visible, hidden []identity.Realm) (*audit.Approval, error) {
	a := ask{op: op, accessType: accessType, refs: refs, visible: visible, hidden: hidden}
	release, err := s.admit(ctx, c, a)
	if err != nil {
		return nil, err
	}
	return s.ask(ctx, c, a, release)
}

// ---- accesses: reuse ----

// access is what a request asks to have approved: reads of secrets, or one
// run of an action with its validated params.
type access struct {
	op         string // prompt template and per-resource event type
	accessType string
	params     map[string]string
}

var readAccess = access{op: "secret.read", accessType: audit.TypeSecretRead}

// planned is one resource of a request and how it will be approved.
type planned struct {
	res    plugin.Resource
	policy policy.Policy
	grant  *grant // a copy of the live grant that covers it, if any
}

// policyFor is the policy an access to r runs under right now. It is
// every-time while platform events aren't healthy, and when the caller has
// no key for the scope (no wider scope is used instead). Caller holds s.mu.
func (s *Service) policyFor(c Call, r plugin.Resource) policy.Policy {
	every := policy.Policy{Kind: policy.EveryTime}
	fn := c.Instance.Policy
	if r.Ref.Kind == "action" {
		fn = c.Instance.ActionPolicy
	}
	if fn == nil || !s.healthy {
		return every
	}
	p := fn(r.Ref.ID)
	if p.Kind != policy.Reuse {
		return every
	}
	if _, ok := keyFor(p.Scope, c); !ok {
		return every
	}
	return p
}

// plan splits a request into resources live grants cover and those that
// need a prompt. It checks the clock first, as the watchdog does, so a
// grant is never reused after a missed sleep while the next tick is due.
func (s *Service) plan(ctx context.Context, c Call, acc access, rs []plugin.Resource) (covered, todo []planned, err error) {
	if _, err := s.checkClock(ctx); err != nil {
		return nil, nil, s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
	}
	now := s.wall()
	params := action.CanonicalParams(acc.params)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range rs {
		p := s.policyFor(c, r)
		if g := s.findGrant(c, audit.Resource{Kind: r.Ref.Kind, ID: r.Ref.ID}, params, p, now); g != nil {
			cp := *g
			covered = append(covered, planned{res: r, policy: p, grant: &cp})
		} else {
			todo = append(todo, planned{res: r, policy: p})
		}
	}
	return covered, todo, nil
}

// accessAsk is the one prompt for the resources no grant covers. A batch is
// one approval, so it runs under the meet of their policies: the prompt's
// reach sentence is then true for every name on it.
func (s *Service) accessAsk(c Call, acc access, todo []planned) ask {
	a := ask{op: acc.op, accessType: acc.accessType, params: acc.params}
	p := policy.Policy{}
	for _, t := range todo {
		a.refs = append(a.refs, t.res.Ref)
		a.uses = append(a.uses, t.res.Uses...)
		p = policy.Meet(p, t.policy)
	}
	if p.Kind == policy.Reuse {
		if k, ok := keyFor(p.Scope, c); ok {
			a.policy, a.key = p, k
		}
	}
	a.denials = s.denialCount(c, a.refs)
	a.unanswered = s.unanswered(c)
	return a
}

// unapproved is the resources of rs that have no approval in out yet.
func unapproved(rs []plugin.Resource, out map[string]*audit.Approval) []plugin.Resource {
	var left []plugin.Resource
	for _, r := range rs {
		if out[r.Ref.ID] == nil {
			left = append(left, r)
		}
	}
	return left
}

func (s *Service) approveRead(ctx context.Context, c Call, rs []plugin.Resource) (map[string]*audit.Approval, error) {
	return s.approve(ctx, c, readAccess, rs)
}

// approve decides a request: resources covered by live grants are reused,
// the rest get one prompt. It returns each resource's approval by id.
//
// The queue wait and the prompt can each take minutes, and grants are made,
// wiped and expire meanwhile. So whatever isn't approved yet is planned again
// after each: once the request reaches the front of the queue, so concurrent
// requests coalesce after one approval, and once the prompt closes, so a
// grant that ended while it was open is never reused. Its names are asked
// for in a new prompt.
func (s *Service) approve(ctx context.Context, c Call, acc access, rs []plugin.Resource) (map[string]*audit.Approval, error) {
	out := map[string]*audit.Approval{}
	covered, todo, err := s.plan(ctx, c, acc, rs)
	if err != nil {
		return nil, err
	}
	for len(todo) > 0 {
		a := s.accessAsk(c, acc, todo)
		if err := s.mayPrompt(ctx, c, a); err != nil {
			return nil, err
		}
		release, err := s.admit(ctx, c, a)
		if err != nil {
			return nil, err
		}
		covered, todo, err = s.plan(ctx, c, acc, unapproved(rs, out))
		if err != nil {
			release()
			return nil, err
		}
		if len(todo) == 0 {
			release()
			break
		}
		a = s.accessAsk(c, acc, todo)
		if err := s.mayPrompt(ctx, c, a); err != nil {
			release()
			return nil, err
		}
		ap, err := s.ask(ctx, c, a, release)
		if err != nil {
			return nil, err
		}
		for _, t := range todo {
			out[t.res.Ref.ID] = ap
		}
		if covered, todo, err = s.plan(ctx, c, acc, unapproved(rs, out)); err != nil {
			return nil, err
		}
	}
	for _, p := range covered {
		ap := p.grant.approval(s.opts.Authenticator.Name())
		e := s.Event(c, audit.TypeApprovalReused, audit.OutcomeOK)
		setVault(e, p.res.Ref)
		e.Resource = &p.grant.resource
		e.Uses = refsToAudit(p.res.Uses)
		e.Params = copyParams(acc.params)
		e.Approval = ap
		if _, aerr := s.record(ctx, c, e); aerr != nil {
			return nil, aerr
		}
		out[p.res.Ref.ID] = ap
	}
	return out, nil
}

func refsToAudit(refs []plugin.ResourceRef) []audit.Resource {
	if len(refs) == 0 {
		return nil
	}
	out := make([]audit.Resource, len(refs))
	for i, r := range refs {
		out[i] = audit.Resource{Kind: r.Kind, ID: r.ID}
	}
	return out
}

func copyParams(p map[string]string) map[string]string {
	if len(p) == 0 {
		return nil
	}
	out := make(map[string]string, len(p))
	for k, v := range p {
		out[k] = v
	}
	return out
}

// ---- grants and wipes ----

func (s *Service) generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wipes
}

// canGrant reports whether an approval asked for at generation gen may
// still create grants: events are healthy and no wipe happened since.
func (s *Service) canGrant(gen uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.healthy && s.wipes == gen
}

// approved creates the grants an approval allows and clears denial backoff
// and the instance's strikes. The caller holds grantMu for reading since it
// decided on grants, so no wipe has happened in between. Events may have
// turned unhealthy meanwhile; the wipe that follows then drops the grants.
func (s *Service) approved(c Call, a ask, ap *audit.Approval, grants bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range a.refs {
		delete(s.denials, denialKeyFor(c, r))
	}
	delete(s.strikes, c.Instance.Name)
	if !grants {
		return
	}
	params := action.CanonicalParams(a.params)
	for _, r := range a.refs {
		res := audit.Resource{Kind: r.Kind, ID: r.ID}
		s.grants[grantKey{resource: res, params: params, scope: a.policy.Scope, key: a.key}] = &grant{
			approvalID: ap.ID, resource: res, params: copyParams(a.params), scope: a.policy.Scope, key: a.key,
			grantedAt: *ap.GrantedAt, expiresAt: *ap.ExpiresAt,
		}
	}
}
