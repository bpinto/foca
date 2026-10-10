package core

import (
	"context"
	"sort"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/policy"
	"github.com/bpinto/foca/internal/protocol"
)

// ScopeKey is what a grant is matched on. Every component comes from the
// host kernel or the service itself, never from the client (design §9.1). A key is only built
// when every component its scope needs is present, so a missing component
// can never match another missing one.
type ScopeKey struct {
	Instance    string
	Connection  string // one socket connection
	PeerSession string // durable session of a pinned peer
}

// keyFor builds the caller's key for scope. ok=false means no grant can be
// made or reused for this caller under that scope, and the request is
// treated as every-time; a scope is never replaced by a wider one.
func keyFor(scope policy.Scope, c Call) (ScopeKey, bool) {
	if c.Origin != audit.OriginClientSocket || c.Instance == nil {
		return ScopeKey{}, false
	}
	k := ScopeKey{Instance: c.Instance.Name}
	// Without a pinned pid, the session may belong to a process that
	// reused the pid (design §4.6).
	peerSession := c.Peer.PIDStable && c.Peer.Session != ""
	switch scope {
	case policy.ScopeConnection:
		if c.Conn == "" {
			return ScopeKey{}, false
		}
		k.Connection = c.Conn
	case policy.ScopePeerSession:
		if !peerSession {
			return ScopeKey{}, false
		}
		k.PeerSession = c.Peer.Session
	default:
		// request never reuses; instance is capped at peer-session by the
		// floor.
		return ScopeKey{}, false
	}
	return k, true
}

func (k ScopeKey) audit() *audit.ScopeKey {
	out := &audit.ScopeKey{Instance: k.Instance}
	part := func(v, by string) *audit.KeyPart {
		if v == "" {
			return nil
		}
		return &audit.KeyPart{Value: v, By: by}
	}
	out.Connection = part(k.Connection, "host")
	out.PeerSession = part(k.PeerSession, "host")
	return out
}

// grant lets later reads of one resource skip the prompt. Times are wall
// clock (design D11): the monotonic clock stops during sleep.
type grant struct {
	approvalID string
	resource   audit.Resource
	// params are the validated params an action grant was approved with.
	params    map[string]string
	scope     policy.Scope
	key       ScopeKey
	grantedAt time.Time
	expiresAt time.Time
}

func (g *grant) approval(authenticator string) *audit.Approval {
	granted, expires := g.grantedAt, g.expiresAt
	return &audit.Approval{
		ID: g.approvalID, Mode: audit.ModeReused, Authenticator: authenticator,
		Scope: g.scope.String(), ScopeKey: g.key.audit(), GrantedAt: &granted, ExpiresAt: &expires,
	}
}

// grantKey identifies the one live grant per resource and scope key; a newer
// approval replaces an older one.
type grantKey struct {
	resource audit.Resource
	// params is an action's params in canonical form: approving one set of
	// values never covers another.
	params string
	scope  policy.Scope
	key    ScopeKey
}

// GrantInfo describes a live grant to the caller it belongs to.
type GrantInfo struct {
	Resource   audit.Resource
	Params     map[string]string
	Scope      string
	ApprovalID string
	ExpiresAt  time.Time
}

// wall is the current wall-clock time in UTC, with the monotonic reading
// stripped so comparisons can't fall back to a clock that stops during sleep.
// UTC because grant times are recorded and returned as they are.
func (s *Service) wall() time.Time { return s.opts.Now().UTC().Round(0) }

// findGrant returns a live grant that covers resource for the caller under p.
// Caller holds s.mu.
func (s *Service) findGrant(c Call, r audit.Resource, params string, p policy.Policy, now time.Time) *grant {
	if p.Kind != policy.Reuse || !s.healthy {
		return nil
	}
	k, ok := keyFor(p.Scope, c)
	if !ok {
		return nil
	}
	g := s.grants[grantKey{resource: r, params: params, scope: p.Scope, key: k}]
	if g == nil || !now.Before(g.expiresAt) {
		return nil
	}
	return g
}

// Grants lists the caller's live grants: those a request from it would reuse.
// It needs no approval and isn't recorded, but it costs a token like a
// listing.
func (s *Service) Grants(ctx context.Context, c Call) ([]GrantInfo, error) {
	if err := s.limit(ctx, c, protocol.MethodGrantsStatus); err != nil {
		return nil, err
	}
	if _, err := s.checkClock(ctx); err != nil {
		return nil, s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
	}
	now := s.wall()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []GrantInfo
	for gk, g := range s.grants {
		if k, ok := keyFor(gk.scope, c); ok && k == gk.key && now.Before(g.expiresAt) {
			out = append(out, GrantInfo{Resource: g.resource, Params: g.params, Scope: g.scope.String(), ApprovalID: g.approvalID, ExpiresAt: g.expiresAt})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource.ID < out[j].Resource.ID })
	return out, nil
}
