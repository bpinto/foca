package core

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/policy"
	"github.com/bpinto/foca/internal/protocol"
)

// clock is a wall clock and a monotonic clock that tests move separately.
type clock struct {
	mu   sync.Mutex
	wall time.Time
	mono time.Duration
}

func newClock() *clock { return &clock{wall: time.Date(2026, 10, 7, 9, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wall
}

func (c *clock) Mono() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mono
}

// advance moves both clocks, as time passing while awake does.
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
	c.mono += d
}

// sleep moves only the wall clock, as a suspended machine does.
func (c *clock) sleep(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wall = c.wall.Add(d)
}

var quiet = slog.New(slog.DiscardHandler)

func reuse(w time.Duration, s policy.Scope) policy.Policy {
	return policy.Policy{Kind: policy.Reuse, Window: w, Scope: s}
}

// rig is a harness with policy, a controllable clock and healthy platform
// events.
type rig struct {
	*harness
	clk *clock
}

func newRig(t *testing.T, pol func(id string) policy.Policy, decisions ...fake.Decision) *rig {
	t.Helper()
	h := newHarness(t, decisions...)
	clk := newClock()
	// pol is by id: every secret of the rig is in its one vault, common.
	h.inst.Policy = func(name string) policy.Policy { return pol(strings.TrimPrefix(name, "common:")) }
	h.svc = New(Options{Authenticator: h.auth, Audit: h.sink, PromptTimeout: time.Second, MaxQueue: 4, ShowClient: true,
		Now: clk.Now, Mono: clk.Mono, WatchEvery: 5 * time.Millisecond, PromptPause: time.Millisecond},
		[]*Instance{h.inst}, map[string]plugin.SecretStore{"common": h.store})
	h.svc.setHealthy(context.Background(), true, quiet)
	return &rig{harness: h, clk: clk}
}

func every(string) policy.Policy { return policy.Policy{Kind: policy.EveryTime} }

func all(p policy.Policy) func(string) policy.Policy { return func(string) policy.Policy { return p } }

// from is a socket call from a pinned peer in session, on connection conn.
func (r *rig) from(conn, session string) Call {
	c := r.call()
	c.Conn = conn
	c.Peer.PIDStable = true
	c.Peer.Session = session
	return c
}

// read reads secrets of the harness's vault, common, by id.
func (r *rig) read(t *testing.T, c Call, ids ...string) error {
	t.Helper()
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = "common:" + id
	}
	out, err := r.svc.ReadSecrets(context.Background(), c, names)
	ZeroSecrets(out)
	return err
}

func (r *rig) prompts() int { return len(r.auth.Requests()) }

// grants is grants.status for c.
func (r *rig) grants(t *testing.T, c Call) []GrantInfo {
	t.Helper()
	gs, err := r.svc.Grants(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	return gs
}

func (r *rig) events(typ string) []audit.Event {
	var out []audit.Event
	for _, e := range r.sink.Events() {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// Grant times carry no monotonic reading, so expiry compares wall clocks
// (D11). Go compares by the monotonic clock whenever both times have one,
// and that clock stops during sleep, so a window would stretch across it.
func TestGrantTimesAreWallClockOnly(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve)
	r.svc.opts.Now = time.Now
	if now := r.svc.wall(); strings.Contains(now.String(), "m=") {
		t.Fatalf("wall time %s keeps a monotonic reading", now)
	}
	r.read(t, r.from("c1", "sid:10:100"), "github-pat")
	r.svc.mu.Lock()
	defer r.svc.mu.Unlock()
	for _, g := range r.svc.grants {
		if strings.Contains(g.expiresAt.String(), "m=") || strings.Contains(g.grantedAt.String(), "m=") {
			t.Fatalf("grant times %s .. %s keep a monotonic reading", g.grantedAt, g.expiresAt)
		}
	}
}

// Grant times are UTC whatever the host's zone, in the recorded approval and
// in grants.status.
func TestGrantTimesAreUTC(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve)
	r.clk.wall = r.clk.wall.In(time.FixedZone("WEST", 3600))
	if now := r.svc.wall(); now.Location() != time.UTC {
		t.Fatalf("wall time %s not UTC", now)
	}
	c := r.from("c1", "sid:10:100")
	if err := r.read(t, c, "github-pat"); err != nil {
		t.Fatal(err)
	}
	a := r.events(audit.TypeApprovalGranted)[0].Approval
	if a.GrantedAt.Location() != time.UTC || a.ExpiresAt.Location() != time.UTC {
		t.Fatalf("approval times %s .. %s not UTC", a.GrantedAt, a.ExpiresAt)
	}
	gs := r.grants(t, c)
	if len(gs) != 1 || gs[0].ExpiresAt.Location() != time.UTC {
		t.Fatalf("grants %+v", gs)
	}
}

func TestReuseWithinWindowThenExpiry(t *testing.T) {
	r := newRig(t, all(reuse(15*time.Minute, policy.ScopePeerSession)), fake.Approve, fake.Approve)
	c := r.from("c1", "sid:10:100")
	if err := r.read(t, c, "github-pat"); err != nil {
		t.Fatal(err)
	}
	if got := r.auth.Requests()[0].Prompt; !strings.HasSuffix(got, "\n⏱️ 15m, anything in this VM") {
		t.Fatalf("prompt doesn't state the reach: %q", got)
	}
	// Another connection in the same peer session: reused, no prompt.
	r.clk.advance(14 * time.Minute)
	if err := r.read(t, r.from("c2", "sid:10:100"), "github-pat"); err != nil {
		t.Fatal(err)
	}
	if r.prompts() != 1 {
		t.Fatalf("%d prompts, want 1", r.prompts())
	}
	granted := r.events(audit.TypeApprovalGranted)[0].Approval
	if granted.Scope != "peer-session" || granted.ScopeKey.PeerSession.Value != "sid:10:100" || granted.ScopeKey.PeerSession.By != "host" ||
		granted.ExpiresAt.Sub(*granted.GrantedAt) != 15*time.Minute {
		t.Fatalf("granted approval %+v", granted)
	}
	reused := r.events(audit.TypeApprovalReused)
	if len(reused) != 1 || reused[0].Approval.ID != granted.ID || reused[0].Approval.Mode != audit.ModeReused {
		t.Fatalf("reused events %+v", reused)
	}
	reads := r.events(audit.TypeSecretRead)
	if reads[1].Approval.Mode != audit.ModeReused || reads[1].Approval.ID != granted.ID {
		t.Fatalf("second read approval %+v", reads[1].Approval)
	}

	// The window ends by wall clock, and expiry is recorded.
	r.clk.advance(time.Minute)
	if err := r.svc.expire(context.Background()); err != nil {
		t.Fatal(err)
	}
	if locks := r.events(audit.TypeLock); len(locks) != 1 || locks[0].Reason != "expired" || locks[0].Count != 1 {
		t.Fatalf("lock events %+v", locks)
	}
	if err := r.read(t, c, "github-pat"); err != nil {
		t.Fatal(err)
	}
	if r.prompts() != 2 {
		t.Fatalf("expired grant reused: %d prompts", r.prompts())
	}
}

// A grant is reused only when every component of its key matches; a
// component that is missing never matches.
func TestGrantKeyMismatchNeverReuses(t *testing.T) {
	base := func(r *rig) Call { return r.from("c1", "sid:10:100") }
	cases := []struct {
		name  string
		scope policy.Scope
		next  func(r *rig) Call
		reuse bool
	}{
		{"same session reuses", policy.ScopePeerSession, base, true},
		{"other peer session", policy.ScopePeerSession, func(r *rig) Call { return r.from("c1", "sid:11:100") }, false},
		{"recycled sid, other leader start", policy.ScopePeerSession, func(r *rig) Call { return r.from("c1", "sid:10:101") }, false},
		{"pid not pinned", policy.ScopePeerSession, func(r *rig) Call { c := base(r); c.Peer.PIDStable = false; return c }, false},
		{"no session", policy.ScopePeerSession, func(r *rig) Call { return r.from("c1", "") }, false},
		{"other instance", policy.ScopePeerSession, func(r *rig) Call {
			c := base(r)
			other := *r.inst
			other.Name = "work"
			c.Instance = &other
			return c
		}, false},
		{"host CLI origin", policy.ScopePeerSession, func(r *rig) Call { c := base(r); c.Origin = audit.OriginHostCLI; return c }, false},
		{"same connection reuses", policy.ScopeConnection, base, true},
		{"other connection", policy.ScopeConnection, func(r *rig) Call { return r.from("c2", "sid:10:100") }, false},
		{"no connection", policy.ScopeConnection, func(r *rig) Call { return r.from("", "sid:10:100") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, all(reuse(time.Hour, tc.scope)), fake.Approve, fake.Approve)
			if err := r.read(t, base(r), "github-pat"); err != nil {
				t.Fatal(err)
			}
			if err := r.read(t, tc.next(r), "github-pat"); err != nil {
				t.Fatal(err)
			}
			if reused := r.prompts() == 1; reused != tc.reuse {
				t.Fatalf("reused = %v, want %v", reused, tc.reuse)
			}
		})
	}

	t.Run("other resource", func(t *testing.T) {
		r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve, fake.Approve)
		r.read(t, base(r), "github-pat")
		r.read(t, base(r), "npm-token")
		if r.prompts() != 2 {
			t.Fatalf("a grant for github-pat covered npm-token")
		}
	})
	// A missing component never matches another missing one.
	t.Run("two callers without a session", func(t *testing.T) {
		r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve, fake.Approve)
		r.read(t, r.from("c1", ""), "github-pat")
		r.read(t, r.from("c2", ""), "github-pat")
		if r.prompts() != 2 || r.grantCount() != 0 {
			t.Fatalf("%d prompts, %d grants: callers without a session shared a grant", r.prompts(), r.grantCount())
		}
	})
	t.Run("no key means no grant and no reach on the prompt", func(t *testing.T) {
		r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve)
		c := base(r)
		c.Peer.PIDStable = false
		r.read(t, c, "github-pat")
		if p := r.auth.Requests()[0].Prompt; strings.Contains(p, "reuse") {
			t.Fatalf("prompt promises reuse it can't give: %q", p)
		}
		if a := r.events(audit.TypeApprovalGranted)[0].Approval; a.Scope != "request" || a.ExpiresAt != nil {
			t.Fatalf("approval %+v", a)
		}
	})
}

func TestEveryTimePolicyNeverReuses(t *testing.T) {
	r := newRig(t, every, fake.Approve, fake.Approve)
	c := r.from("c1", "sid:10:100")
	r.read(t, c, "github-pat")
	r.read(t, c, "github-pat")
	if r.prompts() != 2 {
		t.Fatalf("%d prompts", r.prompts())
	}
	if r.events(audit.TypeApprovalGranted)[0].Approval.Scope != "request" {
		t.Fatal("every-time approval has a scope")
	}
}

// One prompt for a batch runs under the meet of its resources' policies, so
// the reach sentence is true for every name on it.
func TestBatchRunsUnderTheStricterPolicy(t *testing.T) {
	pols := map[string]policy.Policy{
		"github-pat": reuse(time.Hour, policy.ScopePeerSession),
		"npm-token":  reuse(15*time.Minute, policy.ScopeConnection),
	}
	r := newRig(t, func(id string) policy.Policy { return pols[id] }, fake.Approve, fake.Approve)
	c := r.from("c1", "sid:10:100")
	if err := r.read(t, c, "github-pat", "npm-token"); err != nil {
		t.Fatal(err)
	}
	if p := r.auth.Requests()[0].Prompt; !strings.HasSuffix(p, "\n⏱️ 15m, this connection") {
		t.Fatalf("prompt %q", p)
	}
	// Both grants are connection-scoped: another connection is prompted.
	r.read(t, r.from("c2", "sid:10:100"), "github-pat")
	if r.prompts() != 2 {
		t.Fatal("batch grant reached wider than its prompt said")
	}

	// An every-time secret in the batch means no grant for any of them.
	pols["github-pat"] = policy.Policy{Kind: policy.EveryTime}
	r = newRig(t, func(id string) policy.Policy { return pols[id] }, fake.Approve, fake.Approve)
	r.read(t, c, "github-pat", "npm-token")
	r.read(t, c, "npm-token")
	if r.prompts() != 2 || strings.Contains(r.auth.Requests()[0].Prompt, "reuse") {
		t.Fatalf("mixed batch: %d prompts, %q", r.prompts(), r.auth.Requests()[0].Prompt)
	}
}

// Names already covered are left out of the prompt; if none remain, there
// is no prompt (design §9.7).
func TestCoveredNamesLeftOutOfTheBatchPrompt(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve, fake.Approve)
	c := r.from("c1", "sid:10:100")
	r.read(t, c, "github-pat")
	if err := r.read(t, c, "github-pat", "npm-token"); err != nil {
		t.Fatal(err)
	}
	if p := r.auth.Requests()[1].Prompt; strings.Contains(p, "GitHub PAT") || !strings.Contains(p, "npm token") {
		t.Fatalf("second prompt %q", p)
	}
	r.read(t, c, "npm-token", "github-pat")
	if r.prompts() != 2 {
		t.Fatalf("%d prompts", r.prompts())
	}
}

// The 8 h cap holds even if a level asks for more.
func TestEightHourCap(t *testing.T) {
	p := policy.Effective(policy.Policy{Kind: policy.Reuse, Window: 24 * time.Hour})
	r := newRig(t, all(p), fake.Approve, fake.Approve)
	c := r.from("c1", "sid:10:100")
	r.read(t, c, "github-pat")
	a := r.events(audit.TypeApprovalGranted)[0].Approval
	if a.ExpiresAt.Sub(*a.GrantedAt) != 8*time.Hour || a.Scope != "peer-session" {
		t.Fatalf("approval %+v", a)
	}
	r.clk.advance(8 * time.Hour)
	r.read(t, c, "github-pat")
	if r.prompts() != 2 {
		t.Fatal("grant outlived the 8h cap")
	}
}

// fakeEvents is a platform-events source the test drives.
type fakeEvents struct {
	out  chan plugin.PlatformEvent
	fail chan error
	runs chan struct{}
}

func newFakeEvents() *fakeEvents {
	return &fakeEvents{out: make(chan plugin.PlatformEvent), fail: make(chan error), runs: make(chan struct{}, 8)}
}

func (f *fakeEvents) Name() string { return "test" }

func (f *fakeEvents) Run(ctx context.Context, out chan<- plugin.PlatformEvent) error {
	f.runs <- struct{}{}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-f.fail:
			return err
		case ev := <-f.out:
			out <- ev
		}
	}
}

func (f *fakeEvents) send(k plugin.EventKind) { f.out <- plugin.PlatformEvent{Kind: k, Source: "test"} }

// waitFor polls until cond holds.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (r *rig) grantCount() int {
	r.svc.mu.Lock()
	defer r.svc.mu.Unlock()
	return len(r.svc.grants)
}

// Every wipe trigger drops every grant and records a lock event with its
// reason.
func TestWipeOnEveryEventKind(t *testing.T) {
	type trigger struct {
		reason string
		fire   func(t *testing.T, r *rig, src *fakeEvents)
	}
	viaEvent := func(k plugin.EventKind) func(*testing.T, *rig, *fakeEvents) {
		return func(_ *testing.T, _ *rig, src *fakeEvents) { src.send(k) }
	}
	direct := func(reason string) func(*testing.T, *rig, *fakeEvents) {
		return func(t *testing.T, r *rig, _ *fakeEvents) {
			if err := r.svc.Wipe(context.Background(), reason, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
	triggers := []trigger{
		{"sleep", viaEvent(plugin.EventSleep)},
		{"screen-lock", viaEvent(plugin.EventScreenLock)},
		{"session-end", viaEvent(plugin.EventSessionEnd)},
		{"events-unhealthy", func(_ *testing.T, _ *rig, src *fakeEvents) { src.fail <- errors.New("bus gone") }},
		{"manual", direct(WipeManual)},
		{"shutdown", direct(WipeShutdown)},
		{"reload", direct(WipeReload)},
	}
	for _, tr := range triggers {
		t.Run(tr.reason, func(t *testing.T) {
			r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve, fake.Approve, fake.Approve)
			r.svc.setHealthy(context.Background(), false, quiet)
			src := newFakeEvents()
			ctx, cancel := context.WithCancel(context.Background())
			done := r.svc.Guard(ctx, src, quiet)
			defer func() { cancel(); <-done }()
			src.send(plugin.EventReady)
			waitFor(t, "healthy", r.svc.Healthy)

			c := r.from("c1", "sid:10:100")
			r.read(t, c, "github-pat")
			r.read(t, c, "npm-token")
			if r.grantCount() != 2 {
				t.Fatalf("%d grants", r.grantCount())
			}
			before := len(r.events(audit.TypeLock))
			tr.fire(t, r, src)
			waitFor(t, "lock event", func() bool { return len(r.events(audit.TypeLock)) > before })
			if r.grantCount() != 0 {
				t.Fatal("grants survived the wipe")
			}
			lock := r.events(audit.TypeLock)[before]
			if lock.Reason != tr.reason || lock.Count != 2 {
				t.Fatalf("lock event %+v", lock)
			}
			r.read(t, c, "github-pat")
			if r.prompts() != 3 {
				t.Fatalf("read after wipe: %d prompts", r.prompts())
			}
		})
	}
}

// While platform events aren't reporting, every access asks; once the
// source is back and ready, reuse returns (design D13).
func TestUnhealthyEventsMeanEveryTime(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve, fake.Approve, fake.Approve, fake.Approve, fake.Approve)
	r.svc.setHealthy(context.Background(), false, quiet)
	c := r.from("c1", "sid:10:100")

	// Never ready yet: every-time, and the prompt promises nothing.
	r.read(t, c, "github-pat")
	r.read(t, c, "github-pat")
	if r.prompts() != 2 || strings.Contains(r.auth.Requests()[0].Prompt, "reuse") {
		t.Fatalf("before ready: %d prompts, %q", r.prompts(), r.auth.Requests()[0].Prompt)
	}

	src := newFakeEvents()
	ctx, cancel := context.WithCancel(context.Background())
	done := r.svc.Guard(ctx, src, quiet)
	defer func() { cancel(); <-done }()
	<-src.runs
	src.send(plugin.EventReady)
	waitFor(t, "healthy", r.svc.Healthy)
	r.read(t, c, "github-pat")
	r.read(t, c, "github-pat")
	if r.prompts() != 3 {
		t.Fatalf("after ready: %d prompts", r.prompts())
	}

	// The source fails: wipe, and every-time until it is ready again.
	src.fail <- errors.New("bus gone")
	waitFor(t, "unhealthy", func() bool { return !r.svc.Healthy() })
	r.read(t, c, "github-pat")
	r.read(t, c, "github-pat")
	if r.prompts() != 5 {
		t.Fatalf("after failure: %d prompts", r.prompts())
	}
	// It is restarted, and reuse returns once it reports ready.
	<-src.runs
	src.send(plugin.EventReady)
	waitFor(t, "healthy again", r.svc.Healthy)
}

func TestNoEventsSourceMeansEveryTime(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve, fake.Approve)
	r.svc.setHealthy(context.Background(), false, quiet)
	ctx, cancel := context.WithCancel(context.Background())
	done := r.svc.Guard(ctx, nil, quiet)
	defer func() { cancel(); <-done }()
	c := r.from("c1", "sid:10:100")
	r.read(t, c, "github-pat")
	r.read(t, c, "github-pat")
	if r.prompts() != 2 {
		t.Fatalf("%d prompts", r.prompts())
	}
}

// The watchdog treats a gap between wall-clock and monotonic time as a
// sleep, in case the sleep event was missed (design D11).
func TestSleepJumpWatchdog(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve, fake.Approve)
	ctx, cancel := context.WithCancel(context.Background())
	done := r.svc.Guard(ctx, nil, quiet)
	defer func() { cancel(); <-done }()
	r.svc.setHealthy(ctx, true, quiet) // no source here; health set by hand
	c := r.from("c1", "sid:10:100")
	r.read(t, c, "github-pat")

	// Time passing while awake, and a small clock step, are not a sleep.
	r.clk.advance(10 * time.Minute)
	r.clk.sleep(20 * time.Second)
	time.Sleep(50 * time.Millisecond)
	if r.grantCount() != 1 || len(r.events(audit.TypeLock)) != 0 {
		t.Fatal("wiped without a sleep")
	}

	// The machine slept 40s: the wall clock moved, the monotonic one didn't.
	r.clk.sleep(40 * time.Second)
	waitFor(t, "lock event", func() bool { return len(r.events(audit.TypeLock)) > 0 })
	lock := r.events(audit.TypeLock)[0]
	if lock.Reason != "sleep" || lock.Count != 1 || lock.Params["clock_jump"] != "40s" || r.grantCount() != 0 {
		t.Fatalf("lock event %+v, %d grants", lock, r.grantCount())
	}
	// A clock set backwards wipes too: early, which is safe.
	r.read(t, c, "github-pat")
	r.clk.sleep(-time.Hour)
	waitFor(t, "second lock", func() bool { return len(r.events(audit.TypeLock)) > 1 })
}

// gate is an authenticator whose prompt stays open until the test answers.
type gate struct {
	*fake.Authenticator
	open   chan plugin.ApprovalRequest
	answer chan bool
}

func newGate() *gate {
	return &gate{Authenticator: fake.New(), open: make(chan plugin.ApprovalRequest), answer: make(chan bool)}
}

func (g *gate) Approve(ctx context.Context, req plugin.ApprovalRequest) (plugin.ApprovalResult, error) {
	g.open <- req
	select {
	case ok := <-g.answer:
		return plugin.ApprovalResult{Approved: ok, Method: "gate"}, nil
	case <-ctx.Done():
		return plugin.ApprovalResult{}, ctx.Err()
	}
}

func gateRig(t *testing.T, pol policy.Policy) (*rig, *gate) {
	r := newRig(t, all(pol))
	g := newGate()
	r.svc.opts.Authenticator = g
	r.svc.opts.PromptTimeout = 5 * time.Second
	return r, g
}

// An approval given while a wipe happened during its prompt serves that
// request but creates no grant.
func TestWipeDuringPromptCreatesNoGrant(t *testing.T) {
	r, g := gateRig(t, reuse(time.Hour, policy.ScopePeerSession))
	c := r.from("c1", "sid:10:100")
	errc := make(chan error)
	go func() { errc <- r.read(t, c, "github-pat") }()
	<-g.open
	r.svc.Wipe(context.Background(), WipeScreenLock, nil)
	g.answer <- true
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if r.grantCount() != 0 {
		t.Fatal("grant created across a wipe")
	}
	if a := r.events(audit.TypeApprovalGranted)[0].Approval; a.Scope != "request" || a.ExpiresAt != nil {
		t.Fatalf("approval claims a grant: %+v", a)
	}
}

// wipeOnGrant starts a wipe while approval.granted is being written: the
// moment a wipe could fall between deciding on a grant and making it.
type wipeOnGrant struct {
	plugin.AuditSink
	svc  *Service
	done chan struct{}
}

func (w *wipeOnGrant) Append(ctx context.Context, e *audit.Event) (uint64, error) {
	if e.Type == audit.TypeApprovalGranted && w.done == nil {
		w.done = make(chan struct{})
		go func() { w.svc.Wipe(context.Background(), WipeScreenLock, nil); close(w.done) }()
		select {
		case <-w.done:
		case <-time.After(100 * time.Millisecond): // the wipe waits for the grant
		}
	}
	return w.AuditSink.Append(ctx, e)
}

// approval.granted never claims a grant that a wipe kept from being made:
// a wipe that comes while the approval is recorded waits for the grant, then
// drops it and counts it.
func TestGrantedEventNeverClaimsAMissingGrant(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve)
	w := &wipeOnGrant{AuditSink: r.sink, svc: r.svc}
	r.svc.opts.Audit = w
	if err := r.read(t, r.from("c1", "sid:10:100"), "github-pat"); err != nil {
		t.Fatal(err)
	}
	<-w.done
	granted := r.events(audit.TypeApprovalGranted)[0].Approval
	locks := r.events(audit.TypeLock)
	if len(locks) != 1 {
		t.Fatalf("%d lock events", len(locks))
	}
	if granted.ExpiresAt != nil && locks[0].Count != 1 {
		t.Fatalf("approval.granted claims a grant until %s, but the wipe dropped %d grants", granted.ExpiresAt, locks[0].Count)
	}
	if r.grantCount() != 0 {
		t.Fatal("a grant outlived the wipe")
	}
}

// A grant that covers part of a batch is checked again once the prompt for
// the rest closes. If a wipe or expiry ended it meanwhile, its names get a
// prompt of their own; nothing is reused across the wipe.
func TestBatchNeverReusesAGrantThatEndedDuringItsPrompt(t *testing.T) {
	for _, end := range []struct {
		name string
		do   func(r *rig)
	}{
		{"wipe", func(r *rig) { r.svc.Wipe(context.Background(), WipeScreenLock, nil) }},
		{"expiry", func(r *rig) { r.clk.advance(2 * time.Minute) }},
	} {
		t.Run(end.name, func(t *testing.T) {
			r, g := gateRig(t, reuse(time.Minute, policy.ScopePeerSession))
			c := r.from("c1", "sid:10:100")
			errc := make(chan error)
			go func() { errc <- r.read(t, c, "github-pat") }()
			<-g.open
			g.answer <- true
			if err := <-errc; err != nil {
				t.Fatal(err)
			}

			go func() { errc <- r.read(t, c, "github-pat", "npm-token") }()
			if req := <-g.open; strings.Contains(req.Prompt, "GitHub PAT") {
				t.Fatalf("covered name prompted: %q", req.Prompt)
			}
			end.do(r)
			g.answer <- true
			var req plugin.ApprovalRequest
			select {
			case req = <-g.open:
			case err := <-errc:
				t.Fatalf("read ended (%v) without asking for the ended grant's name", err)
			}
			if !strings.Contains(req.Prompt, "GitHub PAT") || strings.Contains(req.Prompt, "npm token") {
				t.Fatalf("second prompt %q, want GitHub PAT alone", req.Prompt)
			}
			g.answer <- true
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
			if n := len(r.events(audit.TypeApprovalReused)); n != 0 {
				t.Fatalf("%d reused events after the grant ended", n)
			}
		})
	}
}

// Reads waiting in the queue re-check reuse at the front, so they coalesce
// after one approval (design §9.6).
func TestQueuedReadsCoalesceAfterOneApproval(t *testing.T) {
	r, g := gateRig(t, reuse(time.Hour, policy.ScopePeerSession))
	c := r.from("c1", "sid:10:100")
	errs := make(chan error, 3)
	go func() { errs <- r.read(t, c, "github-pat") }()
	<-g.open
	for range 2 {
		go func() { errs <- r.read(t, c, "github-pat") }()
	}
	waitFor(t, "queued reads", func() bool { return r.svc.queue.pending() == 3 })
	g.answer <- true
	for range 3 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	select {
	case req := <-g.open:
		t.Fatalf("a second prompt opened: %q", req.Prompt)
	default:
	}
	if n := len(r.events(audit.TypeApprovalReused)); n != 2 {
		t.Fatalf("%d reused events, want 2", n)
	}
}

func TestDenialBackoff(t *testing.T) {
	r := newRig(t, every, fake.Deny, fake.Deny, fake.Approve)
	c := r.from("c1", "sid:10:100")
	if err := r.read(t, c, "github-pat"); err == nil {
		t.Fatal("denied read succeeded")
	}
	// Straight away: refused without a prompt, and recorded.
	err := r.read(t, c, "github-pat")
	var pe *protocol.Error
	if !errors.As(err, &pe) || pe.Code != protocol.CodeDenied || !strings.Contains(pe.Message, "ask again in 2s") {
		t.Fatalf("got %v", err)
	}
	if r.prompts() != 1 {
		t.Fatalf("%d prompts", r.prompts())
	}
	rej := r.events(audit.TypeRequestRejected)
	if len(rej) != 1 || rej[0].Reason != "denial_backoff" {
		t.Fatalf("rejections %+v", rej)
	}
	// Another secret, or another session, isn't held back.
	if err := r.read(t, c, "npm-token"); err == nil || r.prompts() != 2 {
		t.Fatalf("npm-token: %v, %d prompts", err, r.prompts())
	}

	r.clk.advance(2 * time.Second)
	if err := r.read(t, c, "github-pat"); err != nil {
		t.Fatal(err)
	}
	if p := r.auth.Requests()[2].Prompt; !strings.HasSuffix(p, "\n🚫 denied once") {
		t.Fatalf("prompt %q", p)
	}
	// Approval resets the count.
	if r.svc.denialCount(c, refs("common:github-pat")) != 0 {
		t.Fatal("approval didn't reset the backoff")
	}
}

// A denial counts for 10 minutes. After that the prompt no longer says
// "🚫 denied …", and the backoff starts again from 2 s.
func TestDenialIsForgottenAfterTenMinutes(t *testing.T) {
	r := newRig(t, every, fake.Deny, fake.Deny, fake.Deny)
	c := r.from("c1", "sid:10:100")
	r.read(t, c, "github-pat")
	r.clk.advance(2 * time.Second)
	r.read(t, c, "github-pat")
	if n := r.svc.denialCount(c, refs("common:github-pat")); n != 2 {
		t.Fatalf("denial count %d, want 2", n)
	}
	r.clk.advance(denialMemory)
	if n := r.svc.denialCount(c, refs("common:github-pat")); n != 0 {
		t.Fatalf("denial count %d after %s, want 0", n, denialMemory)
	}
	r.read(t, c, "github-pat")
	if p := r.auth.Requests()[2].Prompt; strings.Contains(p, "denied") {
		t.Fatalf("prompt still counts old denials: %q", p)
	}
	// Forgotten, so this denial is the first again: 2 s, not 30 s.
	r.clk.advance(2 * time.Second)
	if err := r.read(t, c, "github-pat"); r.prompts() != 4 {
		t.Fatalf("retry after 2s held back as if denied 3 times: %v", err)
	}
}

func TestDenialBackoffGrowsAndWipeResetsIt(t *testing.T) {
	r := newRig(t, every, fake.Deny, fake.Deny, fake.Deny)
	c := r.from("c1", "sid:10:100")
	ref := []plugin.ResourceRef{{Kind: "secret", ID: "github-pat"}}
	for i, wait := range []time.Duration{2 * time.Second, 8 * time.Second} {
		r.read(t, c, "github-pat")
		r.clk.advance(wait - time.Second)
		if err := r.read(t, c, "github-pat"); err == nil || r.prompts() != i+1 {
			t.Fatalf("denial %d: retry before %s was prompted", i+1, wait)
		}
		r.clk.advance(time.Second)
	}
	r.read(t, c, "github-pat")
	if p := r.auth.Requests()[2].Prompt; !strings.HasSuffix(p, "\n🚫 denied 2 times") {
		t.Fatalf("prompt %q", p)
	}
	r.clk.advance(29 * time.Second)
	if err := r.read(t, c, "github-pat"); err == nil || r.prompts() != 3 {
		t.Fatal("third denial didn't back off 30s")
	}
	r.svc.Wipe(context.Background(), WipeManual, nil)
	if r.svc.denialCount(c, ref) != 0 {
		t.Fatal("wipe kept the backoff")
	}
}

func TestGrantsStatusAndDrop(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve, fake.Approve, fake.Approve)
	c := r.from("c1", "sid:10:100")
	other := r.from("c9", "sid:99:1")
	r.read(t, c, "github-pat", "npm-token")
	r.read(t, other, "github-pat")

	got := r.grants(t, c)
	if len(got) != 2 || got[0].Resource.ID != "common:github-pat" || got[1].Resource.ID != "common:npm-token" || got[0].Scope != "peer-session" {
		t.Fatalf("status %+v", got)
	}
	n, err := r.svc.DropGrants(context.Background(), c, []string{"common:npm-token"})
	if err != nil || n != 1 {
		t.Fatalf("drop: %d, %v", n, err)
	}
	if n, _ := r.svc.DropGrants(context.Background(), c, nil); n != 1 {
		t.Fatalf("drop all: %d", n)
	}
	// The other caller's grant is untouched.
	if len(r.grants(t, other)) != 1 || len(r.grants(t, c)) != 0 {
		t.Fatal("drop reached another caller's grants")
	}
	drops := r.events(audit.TypeGrantsDrop)
	if len(drops) != 2 || drops[0].Count != 1 || drops[0].Params["names"] != "common:npm-token" {
		t.Fatalf("drop events %+v", drops)
	}
	if _, err := r.svc.DropGrants(context.Background(), c, []string{"../x"}); err == nil {
		t.Fatal("invalid name accepted")
	}
}

// A read queued behind a prompt the user denies meets the backoff at the
// front of the queue, instead of a second prompt.
func TestQueuedReadAfterDenialBacksOff(t *testing.T) {
	r, g := gateRig(t, policy.Policy{Kind: policy.EveryTime})
	c := r.from("c1", "sid:10:100")
	errs := make(chan error, 2)
	go func() { errs <- r.read(t, c, "github-pat") }()
	<-g.open
	go func() { errs <- r.read(t, c, "github-pat") }()
	waitFor(t, "queued read", func() bool { return r.svc.queue.pending() == 2 })
	g.answer <- false
	for range 2 {
		if err := <-errs; err == nil {
			t.Fatal("read succeeded")
		}
	}
	select {
	case req := <-g.open:
		t.Fatalf("a second prompt opened: %q", req.Prompt)
	default:
	}
	if rej := r.events(audit.TypeRequestRejected); len(rej) != 1 || rej[0].Reason != "denial_backoff" {
		t.Fatalf("rejections %+v", rej)
	}
}

// grants.drop and grants.status need no approval, so they cost a token
// like a listing, and a drop that removed nothing is coalesced: repeating
// one can't fill the audit log. A drop that removed grants is recorded in
// full.
func TestGrantsDropAndStatusCantFloodTheLog(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve)
	ctx := context.Background()
	c := r.from("c1", "sid:10:100")
	r.read(t, c, "github-pat")
	if n, err := r.svc.DropGrants(ctx, c, nil); err != nil || n != 1 {
		t.Fatalf("drop: %d, %v", n, err)
	}
	// The longest request a drop can carry: 32 names of 128 bytes.
	var names []string
	for i := 0; i < maxBatch; i++ {
		names = append(names, "common:"+strings.Repeat("x", 127)+"abcdefghijklmnopqrstuvwxyzABCDEF"[i:i+1])
	}
	busy, dropped := 0, 0
	for i := 0; i < 100; i++ {
		if i%10 == 0 {
			if _, err := r.svc.Grants(ctx, c); code(err) == protocol.CodeBusy {
				busy++
			}
		}
		_, err := r.svc.DropGrants(ctx, c, names)
		switch code(err) {
		case 0:
			dropped++
		case protocol.CodeBusy:
			busy++
		default:
			t.Fatalf("drop %d: %v", i, err)
		}
	}
	if busy == 0 {
		t.Fatal("no drop or status was rate-limited")
	}
	r.svc.FlushRejections(ctx)
	drops := r.events(audit.TypeGrantsDrop)
	if len(drops) != 3 || drops[0].Count != 1 || drops[1].Count != 0 || drops[1].Params["names"] == "" ||
		drops[2].Coalesced == nil || drops[2].Params != nil {
		t.Fatalf("drop events %+v", drops)
	}
	// Every drop that wasn't refused is in the full event or the count.
	if drops[2].Coalesced.Count != dropped-1 {
		t.Fatalf("count %d for %d empty drops", drops[2].Coalesced.Count, dropped)
	}
}

// A sleep whose event was missed is caught by the request that would reuse
// a grant, not only by the watchdog's next tick: up to WatchEvery after
// waking, the grant would otherwise still be reused.
func TestMissedSleepIsCaughtBeforeReuse(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve, fake.Approve)
	c := r.from("c1", "sid:10:100")
	r.read(t, c, "github-pat")
	r.clk.advance(time.Minute)
	r.read(t, c, "github-pat")
	if r.prompts() != 1 {
		t.Fatal("not reused while awake")
	}
	// No watchdog runs here, so nothing ticks between the sleep and the read.
	r.clk.sleep(40 * time.Second)
	if err := r.read(t, c, "github-pat"); err != nil {
		t.Fatal(err)
	}
	if r.prompts() != 2 {
		t.Fatal("a grant was reused after a missed sleep")
	}
	locks := r.events(audit.TypeLock)
	if len(locks) != 1 || locks[0].Reason != WipeSleep || locks[0].Count != 1 || locks[0].Params["clock_jump"] != "40s" {
		t.Fatalf("lock events %+v", locks)
	}
	if gs := r.grants(t, c); len(gs) != 1 {
		t.Fatalf("grants after the new approval: %+v", gs)
	}
	// grants.status checks the clock too.
	r.clk.sleep(40 * time.Second)
	if gs := r.grants(t, c); len(gs) != 0 {
		t.Fatalf("grants listed after a missed sleep: %+v", gs)
	}
}
