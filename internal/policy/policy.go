// Package policy is the approval-policy lattice (design §9). Each config
// level holds one Policy, or none; levels fold with Meet, "stricter wins",
// and the result is capped by a floor fixed in code. Meet is commutative,
// associative and idempotent, and Meet(x, y) is never looser than x, so no
// setting at any level can loosen what another level asks for.
package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/bpinto/foca/internal/identity"
)

// Limits on reuse windows. Config values outside them are rejected; the
// evaluator clamps as well, as defence in depth.
const (
	MinReuseWindow = time.Second
	MaxReuseWindow = 8 * time.Hour
)

// Scope says how far a grant reaches, narrowest first. Each name says who
// vouches for the key it is matched on.
type Scope int

const (
	// ScopeUnset is a Reuse level that has no opinion on scope. It folds
	// like the widest scope and is then capped by the floor.
	ScopeUnset Scope = iota
	ScopeRequest
	ScopeConnection
	ScopeGuestProgram
	ScopeGuestSession
	ScopePeerSession
	ScopeInstance
)

var scopeNames = map[Scope]string{
	ScopeRequest:      "request",
	ScopeConnection:   "connection",
	ScopeGuestProgram: "guest-program",
	ScopeGuestSession: "guest-session",
	ScopePeerSession:  "peer-session",
	ScopeInstance:     "instance",
}

// Scopes lists every named scope, narrowest first.
var Scopes = []Scope{ScopeRequest, ScopeConnection, ScopeGuestProgram, ScopeGuestSession, ScopePeerSession, ScopeInstance}

func (s Scope) String() string {
	if n, ok := scopeNames[s]; ok {
		return n
	}
	return ""
}

// ParseScope reads a scope name from config.
func ParseScope(name string) (Scope, error) {
	for s, n := range scopeNames {
		if n == name {
			return s, nil
		}
	}
	return ScopeUnset, fmt.Errorf("unknown scope %q (%s)", name, strings.Join(scopeList(), " | "))
}

func scopeList() []string {
	out := make([]string, len(Scopes))
	for i, s := range Scopes {
		out[i] = s.String()
	}
	return out
}

// NeedsRelay reports whether the scope's key comes from the guest relay.
func (s Scope) NeedsRelay() bool { return s == ScopeGuestProgram || s == ScopeGuestSession }

// width orders scopes for folding: unset counts as the widest.
func (s Scope) width() Scope {
	if s == ScopeUnset {
		return ScopeInstance + 1
	}
	return s
}

func narrower(a, b Scope) Scope {
	if a.width() <= b.width() {
		return a
	}
	return b
}

// Kind is the shape of a Policy.
type Kind int

const (
	// Unset is "no opinion": the level's table was left out.
	Unset Kind = iota
	// EveryTime asks for a fresh approval on each access.
	EveryTime
	// Reuse lets one approval cover later accesses within Window and Scope.
	Reuse
)

// Policy is one level's setting, or the folded result.
type Policy struct {
	Kind   Kind
	Window time.Duration // Reuse only
	Scope  Scope         // Reuse only
}

// Floor is the hard cap in code (design §9.2). Not configurable.
var Floor = Policy{Kind: Reuse, Window: MaxReuseWindow, Scope: ScopePeerSession}

// Meet returns the stricter of a and b.
func Meet(a, b Policy) Policy {
	switch {
	case a.Kind == Unset:
		return b
	case b.Kind == Unset:
		return a
	case a.Kind == EveryTime || b.Kind == EveryTime:
		return Policy{Kind: EveryTime}
	}
	return Policy{Kind: Reuse, Window: min(a.Window, b.Window), Scope: narrower(a.Scope, b.Scope)}
}

// Effective folds the configured levels, in any order. Nothing configured
// means EveryTime. The result is then capped by the floor, and a window
// outside the limits is clamped down or turned into EveryTime, never
// widened.
func Effective(levels ...Policy) Policy {
	p := Policy{}
	for _, l := range levels {
		p = Meet(p, l)
	}
	if p.Kind == Unset {
		return Policy{Kind: EveryTime}
	}
	p = Meet(p, Floor)
	if p.Kind == Reuse && (p.Window < MinReuseWindow || p.Scope == ScopeRequest) {
		// Too short to mean anything, or a grant nothing can ever reuse.
		return Policy{Kind: EveryTime}
	}
	return p
}

// AtMost reports whether a is at least as strict as b (a ⊑ b): b permits
// everything a permits. Unset is the top: it permits anything.
func AtMost(a, b Policy) bool {
	switch {
	case b.Kind == Unset:
		return true
	case a.Kind == Unset:
		return false
	case a.Kind == EveryTime:
		return true
	case b.Kind == EveryTime:
		return false
	}
	return a.Window <= b.Window && a.Scope.width() <= b.Scope.width()
}

// String is the config-like form, for logs and tests.
func (p Policy) String() string {
	switch p.Kind {
	case Unset:
		return "unset"
	case EveryTime:
		return "every-time"
	}
	s := "reuse " + FormatWindow(p.Window)
	if p.Scope != ScopeUnset {
		s += " " + p.Scope.String()
	}
	return s
}

// FormatWindow writes a duration without trailing zero units: 15m, 2h, 1h30m.
func FormatWindow(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// Reach says in plain words who an approval under p also covers, or "" if
// approving creates no grant. The prompt (design §4.1.1) and
// `foca policy explain` both use it, so they always agree.
func Reach(p Policy, realm identity.Realm) string {
	if p.Kind != Reuse {
		return ""
	}
	return fmt.Sprintf("Approving allows reuse for %s %s.", FormatWindow(p.Window), who(p.Scope, realm))
}

// Describe is the whole policy in plain words, for `foca policy explain`.
func Describe(p Policy, realm identity.Realm) string {
	if p.Kind != Reuse {
		return "asks every time"
	}
	return fmt.Sprintf("one approval allows reuse for %s %s", FormatWindow(p.Window), who(p.Scope, realm))
}

func who(s Scope, realm identity.Realm) string {
	in := ""
	if n := realm.Noun(); n != "" {
		in = " in " + n + " " + realm.Name
	}
	switch s {
	case ScopeConnection:
		return "on the same connection"
	case ScopeGuestProgram:
		return "by the same program in the same session" + in
	case ScopeGuestSession:
		return "by anything in the same session" + in
	case ScopePeerSession:
		if realm.Peers == identity.PeersOpaque {
			// The host sees only the proxy, so the session is the whole realm.
			return "by anything" + in
		}
		return "by anything in the same session" + in
	default:
		return "by anything" + in
	}
}
