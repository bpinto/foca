package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/policy"
)

// A sleep is marked handled only once its wipe is done and recorded, so a
// source that holds sleep back until then never lets the machine suspend
// with grants still live. The lock event's append is held open, so the
// order is checked, not raced.
func TestSleepIsHandledOnlyAfterTheWipe(t *testing.T) {
	r := newRig(t, all(reuse(time.Hour, policy.ScopePeerSession)), fake.Approve)
	held := &holdLock{AuditSink: r.svc.opts.Audit, reached: make(chan struct{}), release: make(chan struct{})}
	r.svc.opts.Audit = held
	src := newFakeEvents()
	ctx, cancel := context.WithCancel(context.Background())
	done := r.svc.Guard(ctx, src, quiet)
	defer func() { cancel(); <-done }()
	src.send(plugin.EventReady)
	waitFor(t, "healthy", r.svc.Healthy)
	r.read(t, r.from("c1", "sid:10:100"), "github-pat")
	if r.grantCount() != 1 {
		t.Fatalf("%d grants", r.grantCount())
	}

	ev := plugin.PlatformEvent{Kind: plugin.EventSleep, Source: "test", Done: make(chan struct{})}
	src.out <- ev
	<-held.reached
	select {
	case <-ev.Done:
		close(held.release)
		t.Fatal("sleep marked handled before its lock event was recorded")
	case <-time.After(100 * time.Millisecond):
	}
	close(held.release)
	select {
	case <-ev.Done:
	case <-time.After(5 * time.Second):
		t.Fatal("sleep never marked handled")
	}
	if r.grantCount() != 0 || len(r.events(audit.TypeLock)) == 0 {
		t.Fatalf("handled before the wipe: %d grants, %d lock events", r.grantCount(), len(r.events(audit.TypeLock)))
	}
}

// holdLock is an audit sink whose first lock append waits for release.
type holdLock struct {
	plugin.AuditSink
	once             sync.Once
	reached, release chan struct{}
}

func (h *holdLock) Append(ctx context.Context, e *audit.Event) (uint64, error) {
	if e.Type == audit.TypeLock {
		h.once.Do(func() {
			close(h.reached)
			<-h.release
		})
	}
	return h.AuditSink.Append(ctx, e)
}

// A source waits for the core at most the given time.
func TestWaitHandledIsBounded(t *testing.T) {
	ev := plugin.PlatformEvent{Kind: plugin.EventSleep, Done: make(chan struct{})}
	start := time.Now()
	ev.WaitHandled(context.Background(), 50*time.Millisecond)
	if d := time.Since(start); d < 50*time.Millisecond || d > 2*time.Second {
		t.Fatalf("waited %s", d)
	}
	plugin.PlatformEvent{}.WaitHandled(context.Background(), time.Hour) // no Done: returns at once
	ev.Handled()
	ev.WaitHandled(context.Background(), time.Hour)
}
