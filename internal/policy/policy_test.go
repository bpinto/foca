package policy

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/identity"
)

// domain is every shape a level can take, over a few windows that straddle
// the limits.
func domain() []Policy {
	out := []Policy{{Kind: Unset}, {Kind: EveryTime}}
	scopes := append([]Scope{ScopeUnset}, Scopes...)
	for _, w := range []time.Duration{time.Second, 15 * time.Minute, 30 * time.Minute, 8 * time.Hour, 9 * time.Hour} {
		for _, s := range scopes {
			for _, n := range notifies {
				out = append(out, Policy{Kind: Reuse, Window: w, Scope: s, Notify: n})
			}
		}
	}
	return out
}

var notifies = []Notify{NotifyUnset, NotifyOn, NotifyOff}

func random(r *rand.Rand) Policy {
	switch r.IntN(4) {
	case 0:
		return Policy{Kind: Unset}
	case 1:
		return Policy{Kind: EveryTime}
	}
	scopes := append([]Scope{ScopeUnset}, Scopes...)
	return Policy{Kind: Reuse, Window: time.Duration(r.Int64N(int64(10 * time.Hour))), Scope: scopes[r.IntN(len(scopes))], Notify: notifies[r.IntN(len(notifies))]}
}

// The lattice laws (design §9.3), checked over every combination of the
// finite domain and then over random windows.
func TestLatticeLaws(t *testing.T) {
	check := func(x, y, z Policy) {
		t.Helper()
		if Meet(x, y) != Meet(y, x) {
			t.Fatalf("not commutative: %v, %v", x, y)
		}
		if Meet(Meet(x, y), z) != Meet(x, Meet(y, z)) {
			t.Fatalf("not associative: %v, %v, %v", x, y, z)
		}
		if Meet(x, x) != x {
			t.Fatalf("not idempotent: %v", x)
		}
		if !AtMost(Meet(x, y), x) {
			t.Fatalf("meet(%v, %v) = %v is looser than %v", x, y, Meet(x, y), x)
		}
		if Meet(x, Policy{}) != x {
			t.Fatalf("unset is not the identity for %v", x)
		}
		if Meet(x, Policy{Kind: EveryTime}).Kind != EveryTime && x.Kind != Unset {
			t.Fatalf("every-time doesn't absorb %v", x)
		}
	}
	d := domain()
	for _, x := range d {
		for _, y := range d {
			for _, z := range d {
				check(x, y, z)
			}
		}
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 100000 {
		check(random(r), random(r), random(r))
	}
}

// Once any level is set, adding another level or tightening one can never
// loosen the effective policy. Nothing configured at all is EveryTime, so
// reuse is only ever opt-in.
func TestEffectiveNeverLoosens(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4))
	for range 50000 {
		n := 1 + r.IntN(4)
		levels := make([]Policy, n)
		for i := range levels {
			levels[i] = random(r)
		}
		for levels[0].Kind == Unset {
			levels[0] = random(r)
		}
		base := Effective(levels...)
		extra := random(r)
		if got := Effective(append(levels, extra)...); !AtMost(got, base) {
			t.Fatalf("adding %v to %v loosened %v to %v", extra, levels, base, got)
		}
		// Tighten one level to its meet with something else.
		i := r.IntN(n)
		tight := append([]Policy(nil), levels...)
		tight[i] = Meet(tight[i], extra)
		if got := Effective(tight...); !AtMost(got, base) {
			t.Fatalf("tightening level %d of %v with %v loosened %v to %v", i, levels, extra, base, got)
		}
		if !AtMost(base, Floor) {
			t.Fatalf("%v is looser than the floor", base)
		}
	}
	if got := Effective(); got.Kind != EveryTime {
		t.Fatalf("no config = %v, want every-time", got)
	}
	if got := Effective(Policy{}, Policy{}); got.Kind != EveryTime {
		t.Fatalf("all unset = %v, want every-time", got)
	}
}

func reuse(w time.Duration, s Scope) Policy { return Policy{Kind: Reuse, Window: w, Scope: s} }
func quiet(w time.Duration) Policy          { return Policy{Kind: Reuse, Window: w, Notify: NotifyOff} }
func loud(w time.Duration) Policy           { return Policy{Kind: Reuse, Window: w, Notify: NotifyOn} }

func (p Policy) withScope(s Scope) Policy { p.Scope = s; return p }

var every = Policy{Kind: EveryTime}

// Attempts to loosen policy from one level against another.
func TestLooseningAttempts(t *testing.T) {
	cases := []struct {
		name   string
		levels []Policy
		want   Policy
	}{
		{"secret every-time beats an instance window", []Policy{reuse(30*time.Minute, ScopePeerSession), every}, every},
		{"every-time at the authenticator beats everything", []Policy{reuse(time.Hour, ScopePeerSession), reuse(2*time.Hour, ScopeUnset), every}, every},
		{"shortest window wins", []Policy{reuse(30*time.Minute, ScopePeerSession), reuse(2*time.Hour, ScopeUnset), reuse(time.Hour, ScopeUnset)}, reuse(30*time.Minute, ScopePeerSession)},
		{"narrowest scope wins", []Policy{reuse(time.Hour, ScopePeerSession), reuse(time.Hour, ScopeConnection)}, reuse(time.Hour, ScopeConnection)},
		{"instance scope is capped at peer-session", []Policy{reuse(time.Hour, ScopeInstance)}, reuse(time.Hour, ScopePeerSession)},
		{"no scope anywhere is capped at peer-session", []Policy{reuse(time.Hour, ScopeUnset)}, reuse(time.Hour, ScopePeerSession)},
		{"a window over 8h is clamped to the cap", []Policy{reuse(24*time.Hour, ScopeConnection)}, reuse(8*time.Hour, ScopeConnection)},
		{"a window under 1s asks every time", []Policy{reuse(time.Millisecond, ScopeConnection)}, every},
		{"request scope never creates a grant", []Policy{reuse(time.Hour, ScopeRequest)}, every},
		{"an unset level changes nothing", []Policy{{}, reuse(time.Hour, ScopeConnection), {}}, reuse(time.Hour, ScopeConnection)},
		{"a wide level can't undo a narrow one, in either order", []Policy{reuse(time.Minute, ScopeConnection), reuse(8*time.Hour, ScopeInstance)}, reuse(time.Minute, ScopeConnection)},
		{"same, reversed", []Policy{reuse(8*time.Hour, ScopeInstance), reuse(time.Minute, ScopeConnection)}, reuse(time.Minute, ScopeConnection)},
		{"notify = true at any level keeps a grant announced", []Policy{quiet(time.Hour), loud(time.Hour)}, loud(time.Hour).withScope(ScopePeerSession)},
		{"same, reversed", []Policy{loud(time.Hour), quiet(time.Hour)}, loud(time.Hour).withScope(ScopePeerSession)},
		{"one quiet level silences levels with no opinion", []Policy{reuse(time.Hour, ScopeUnset), quiet(2 * time.Hour)}, quiet(time.Hour).withScope(ScopePeerSession)},
		{"every-time leaves nothing to silence", []Policy{quiet(time.Hour), every}, every},
	}
	for _, c := range cases {
		if got := Effective(c.levels...); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestParseScope(t *testing.T) {
	for _, s := range Scopes {
		got, err := ParseScope(s.String())
		if err != nil || got != s {
			t.Errorf("ParseScope(%q) = %v, %v", s, got, err)
		}
	}
	if _, err := ParseScope("session"); err == nil {
		t.Error("unknown scope accepted")
	}
}

func TestReachWording(t *testing.T) {
	vm := identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"}
	host := identity.Realm{Kind: "host", Name: "laptop", Peers: "direct"}
	ctr := identity.Realm{Kind: "container", Name: "web", Peers: "direct"}
	cases := []struct {
		p     Policy
		realm identity.Realm
		want  string
	}{
		{reuse(15*time.Minute, ScopePeerSession), vm, "15m, anything in this VM"},
		{reuse(90*time.Minute, ScopePeerSession), host, "1h30m, this session"},
		{reuse(2*time.Hour, ScopePeerSession), ctr, "2h, this session"},
		{reuse(45*time.Second, ScopeConnection), vm, "45s, this connection"},
		{reuse(time.Hour, ScopeInstance), ctr, "1h, anything in this container"},
		{reuse(time.Hour, ScopeInstance), host, "1h, anything on this host"},
		{every, vm, ""},
	}
	for _, c := range cases {
		if got := Reach(c.p, c.realm); got != c.want {
			t.Errorf("Reach(%v, %s) = %q, want %q", c.p, c.realm.Name, got, c.want)
		}
	}
}

// policy explain says when reuses go unannounced.
func TestDescribeSaysWhenQuiet(t *testing.T) {
	vm := identity.Realm{Kind: "vm", Name: "dev", Peers: identity.PeersOpaque}
	if got := Describe(Policy{Kind: Reuse, Window: 15 * time.Minute, Scope: ScopePeerSession}, vm); got != "one approval allows reuse for 15m by anything in VM dev" {
		t.Errorf("got %q", got)
	}
	if got := Describe(Policy{Kind: Reuse, Window: 15 * time.Minute, Scope: ScopePeerSession, Notify: NotifyOff}, vm); got != "one approval allows reuse for 15m by anything in VM dev, without notifying" {
		t.Errorf("got %q", got)
	}
}
