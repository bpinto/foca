package core

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/policy"
	"github.com/bpinto/foca/internal/protocol"
)

// cooledDown reports whether err is a prompt_cooldown refusal.
func cooledDown(t *testing.T, r *rig, err error) bool {
	t.Helper()
	var pe *protocol.Error
	if !errors.As(err, &pe) || pe.Code != protocol.CodeDenied || !strings.Contains(pe.Message, "unapproved prompts") {
		return false
	}
	rej := r.events(audit.TypeRequestRejected)
	return len(rej) > 0 && rej[len(rej)-1].Reason == "prompt_cooldown"
}

// Denial backoff is per resource, so cycling through secrets used to keep
// prompts coming. Strikes count across the whole instance: after three
// unapproved prompts it may not open another for 30s, then 2m, then 5m.
func TestCooldownAfterThreeUnapprovedPrompts(t *testing.T) {
	r := newRig(t, every) // every prompt is denied
	c := r.from("c1", "sid:10:100")
	other := r.from("c2", "sid:20:200") // another session of the same realm
	r.read(t, c, "github-pat")
	r.read(t, other, "npm-token")
	r.clk.advance(3 * time.Second) // past both secrets' denial backoff
	r.read(t, c, "github-pat")
	if r.prompts() != 3 {
		t.Fatalf("%d prompts before the cooldown", r.prompts())
	}

	// Each further strike starts a longer cooldown, up to 5m. (Strikes are
	// forgotten after 10m, so this stays within that.)
	for i, cooldown := range []time.Duration{30 * time.Second, 2 * time.Minute, 5 * time.Minute} {
		if err := r.read(t, other, "npm-token"); !cooledDown(t, r, err) {
			t.Fatalf("strike %d: right after it: %v", i+3, err)
		}
		r.clk.advance(cooldown - time.Second)
		if err := r.read(t, c, "npm-token"); !cooledDown(t, r, err) {
			t.Fatalf("strike %d: a second before its %s cooldown ends: %v", i+3, cooldown, err)
		}
		n := r.prompts()
		r.clk.advance(time.Second)
		r.read(t, c, "npm-token") // allowed, and denied: one more strike
		if r.prompts() != n+1 {
			t.Fatalf("strike %d: no prompt after its %s cooldown", i+3, cooldown)
		}
	}
	if err := r.read(t, other, "github-pat"); !cooledDown(t, r, err) || !strings.Contains(err.Error(), "ask again in 300s") {
		t.Fatalf("strike 6: no 5m cooldown: %v", err)
	}
}

// Timeouts and hang-ups while a prompt is open are strikes too, and the next
// prompt says how many went unanswered. Cancels while waiting in the queue
// aren't, nor are failures to show a prompt at all.
func TestUnansweredPromptsCountAndShow(t *testing.T) {
	r := newRig(t, every, fake.Hang, fake.Hang)
	r.svc.opts.PromptTimeout = 20 * time.Millisecond
	c := r.from("c1", "sid:10:100")
	if err := r.read(t, c, "github-pat"); code(err) != protocol.CodeTimeout {
		t.Fatalf("timeout: %v", err)
	}
	r.auth.Started = make(chan plugin.ApprovalRequest, 1)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := r.svc.ReadSecrets(ctx, c, []string{"common:npm-token"}); errc <- err }()
	<-r.auth.Started
	cancel()
	if err := <-errc; code(err) != protocol.CodeTimeout {
		t.Fatalf("hang-up: %v", err)
	}
	r.auth.SetUnavailable(true)
	r.read(t, c, "npm-token")
	r.auth.SetUnavailable(false)

	r.clk.advance(3 * time.Second)
	r.read(t, c, "github-pat") // denied: the third strike
	if p := r.auth.Requests()[2].Prompt; !strings.HasSuffix(p, "\n🔕 2 prompts unanswered") {
		t.Fatalf("prompt %q", p)
	}
	if err := r.read(t, c, "npm-token"); !cooledDown(t, r, err) {
		t.Fatalf("after two unanswered and one denied: %v", err)
	}
}

// An approval clears the instance's strikes, and so does a wipe.
func TestApprovalAndWipeClearStrikes(t *testing.T) {
	r := newRig(t, every, fake.Deny, fake.Deny, fake.Approve) // then every prompt is denied
	c := r.from("c1", "sid:10:100")
	r.read(t, c, "github-pat")
	r.read(t, c, "npm-token")
	r.clk.advance(3 * time.Second)
	if err := r.read(t, c, "github-pat"); err != nil {
		t.Fatal(err)
	}
	r.clk.advance(3 * time.Second)
	r.read(t, c, "npm-token")
	r.read(t, c, "github-pat")

	// Two strikes since the approval: a third prompt may open.
	r.clk.advance(31 * time.Second) // past denial backoff
	n := r.prompts()
	r.read(t, c, "npm-token")
	if r.prompts() != n+1 {
		t.Fatal("strikes from before an approval still count")
	}
	if err := r.read(t, c, "github-pat"); !cooledDown(t, r, err) {
		t.Fatalf("no cooldown after three strikes: %v", err)
	}

	r.svc.Wipe(context.Background(), WipeManual, nil)
	n = r.prompts()
	r.read(t, c, "github-pat")
	if r.prompts() != n+1 {
		t.Fatal("a wipe didn't clear the strikes")
	}
}

// After a prompt times out or is cancelled, its slot stays held for a
// moment, so a queued prompt can't take its place under the user's finger.
// The caller isn't kept waiting.
func TestPromptPauseHoldsTheSlot(t *testing.T) {
	r := newRig(t, every, fake.Hang)
	r.svc.opts.PromptTimeout = 20 * time.Millisecond
	r.svc.opts.PromptPause = 300 * time.Millisecond
	c := r.from("c1", "sid:10:100")
	start := time.Now()
	r.read(t, c, "github-pat")
	if took := time.Since(start); took > 250*time.Millisecond {
		t.Fatalf("the caller waited out the pause: %s", took)
	}
	if r.svc.queue.pending() != 1 {
		t.Fatal("slot released straight after a timeout")
	}
	waitFor(t, "slot released", func() bool { return r.svc.queue.pending() == 0 })
	if took := time.Since(start); took < 300*time.Millisecond {
		t.Fatalf("slot released after %s", took)
	}

	// A denial doesn't pause.
	r.read(t, c, "npm-token")
	if r.svc.queue.pending() != 0 {
		t.Fatal("slot held after a denial")
	}
}

// Two processes (here, two services) that share the prompt lock never show
// prompts at the same time.
func TestPromptLockIsSharedAcrossServices(t *testing.T) {
	// The runtime directory doesn't exist yet: the first prompt creates it.
	lock := fsutil.PrivateLock(filepath.Join(t.TempDir(), "run"), "prompt.lock")
	a, g := gateRig(t, policy.Policy{Kind: policy.EveryTime})
	a.svc.opts.PromptLock = lock
	b := newRig(t, every, fake.Approve)
	b.svc.opts.PromptLock = lock
	b.auth.Started = make(chan plugin.ApprovalRequest, 1)

	errc := make(chan error, 1)
	go func() { errc <- a.read(t, a.from("c1", "sid:10:100"), "github-pat") }()
	<-g.open
	berr := make(chan error, 1)
	go func() { berr <- b.read(t, b.from("c2", "sid:20:200"), "npm-token") }()
	select {
	case <-b.auth.Started:
		t.Fatal("a second prompt opened while the first was on screen")
	case <-time.After(100 * time.Millisecond):
	}
	g.answer <- true
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	select {
	case <-b.auth.Started:
	case <-time.After(2 * time.Second):
		t.Fatal("the second prompt never opened")
	}
	if err := <-berr; err != nil {
		t.Fatal(err)
	}
}
