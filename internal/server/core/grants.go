package core

import (
	"sort"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/policy"
)

// ScopeKey is what a grant is matched on. Every component comes from the
// host kernel or the service itself, never from the client (design §9.1).
// A key is only built when every component its scope needs is present, so
// a missing component can never match another missing one.
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
	switch scope {
	case policy.ScopeConnection:
		if c.Conn == "" {
			return ScopeKey{}, false
		}
		k.Connection = c.Conn
	case policy.ScopePeerSession:
		// Without a pinned pid, the session may belong to a process that
		// reused the pid (design §4.6).
		if !c.Peer.PIDStable || c.Peer.Session == "" {
			return ScopeKey{}, false
		}
		k.PeerSession = c.Peer.Session
	default:
		// request never reuses; guest-* scopes need the relay;
		// instance is capped at peer-session by the floor.
		return ScopeKey{}, false
	}
	return k, true
}

func (k ScopeKey) audit() *audit.ScopeKey {
	out := &audit.ScopeKey{Instance: k.Instance}
	if k.Connection != "" {
		out.Connection = &audit.KeyPart{Value: k.Connection, By: "host"}
	}
	if k.PeerSession != "" {
		out.PeerSession = &audit.KeyPart{Value: k.PeerSession, By: "host"}
	}
	return out
}

// grant lets later reads of one resource skip the prompt. Times are wall
// clock (design D11): the monotonic clock stops during sleep.
type grant struct {
	approvalID string
	resource   audit.Resource
	scope      policy.Scope
	key        ScopeKey
	grantedAt  time.Time
	expiresAt  time.Time
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
	scope    policy.Scope
	key      ScopeKey
}

// GrantInfo describes a live grant to the caller it belongs to.
type GrantInfo struct {
	Resource   audit.Resource
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
func (s *Service) findGrant(c Call, r audit.Resource, p policy.Policy, now time.Time) *grant {
	if p.Kind != policy.Reuse || !s.healthy {
		return nil
	}
	k, ok := keyFor(p.Scope, c)
	if !ok {
		return nil
	}
	g := s.grants[grantKey{resource: r, scope: p.Scope, key: k}]
	if g == nil || !now.Before(g.expiresAt) {
		return nil
	}
	return g
}

// Grants lists the caller's live grants: those a request from it would reuse.
func (s *Service) Grants(c Call) []GrantInfo {
	now := s.wall()
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []GrantInfo
	for gk, g := range s.grants {
		if k, ok := keyFor(gk.scope, c); ok && k == gk.key && now.Before(g.expiresAt) {
			out = append(out, GrantInfo{Resource: g.resource, Scope: g.scope.String(), ApprovalID: g.approvalID, ExpiresAt: g.expiresAt})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource.ID < out[j].Resource.ID })
	return out
}
