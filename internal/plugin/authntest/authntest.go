// Package authntest is the authenticator conformance suite (design §15).
// The core reads an authenticator's answers in one way whatever shows the
// prompt, so every implementation runs the same tests: polkit (against the
// fake authority and the real polkitd), the darwin helper adapter (against
// the fake helper) and the fake authenticator. Only tests import it.
package authntest

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/ids"
	"github.com/bpinto/foca/internal/plugin"
)

// Answer is how the person at the prompt answers it, as a harness scripts
// it.
type Answer int

const (
	Approve Answer = iota
	Deny
	// Ignore leaves the prompt open until the deadline takes it down.
	Ignore
	// Unavailable means no prompt can be shown at all.
	Unavailable
)

func (a Answer) String() string {
	return [...]string{"approve", "deny", "ignore", "unavailable"}[a]
}

// Harness is one authenticator under test, with a way to script it.
type Harness struct {
	Authenticator plugin.Authenticator
	// Answer scripts how the next prompt is answered.
	Answer func(Answer)
	// Can lists the answers the harness can script; tests needing another
	// skip.
	Can []Answer
	// Shown returns the text of every prompt shown so far, as shown, or
	// nil if the harness can't see it.
	Shown func() []string
	// Shows, if set, is how the authenticator writes a prompt's text for
	// its display (polkit escapes markup); nil means as it is.
	Shows func(prompt string) string
	// TakenDown reports whether every prompt shown so far has been taken
	// down, or nil if the harness can't tell.
	TakenDown func() bool
	// Grace is how long after its deadline Approve may take to return.
	Grace time.Duration
}

// Run runs the suite. newHarness is called once per test.
func Run(t *testing.T, newHarness func(t *testing.T) Harness) {
	need := func(t *testing.T, h Harness, a Answer) {
		t.Helper()
		if !slices.Contains(h.Can, a) {
			t.Skipf("this harness can't script %q", a)
		}
		h.Answer(a)
	}
	approve := func(h Harness, ctx context.Context, prompt string) (plugin.ApprovalResult, error) {
		return h.Authenticator.Approve(ctx, plugin.ApprovalRequest{
			ID: ids.New(), Instance: "dev", Operation: "secret.read",
			Resources: []plugin.ResourceRef{{Kind: "secret", ID: "a", Display: "A"}},
			Prompt:    prompt, Timeout: time.Minute,
		})
	}

	t.Run("ApprovedIsApproved", func(t *testing.T) {
		h := newHarness(t)
		need(t, h, Approve)
		res, err := approve(h, context.Background(), "let a program use A (approve this).")
		if err != nil || !res.Approved {
			t.Fatalf("got %+v %v, want approved", res, err)
		}
		if res.Method == "" {
			t.Fatal("an approval names no method")
		}
	})

	t.Run("DeniedIsADenialNotAnError", func(t *testing.T) {
		h := newHarness(t)
		need(t, h, Deny)
		res, err := approve(h, context.Background(), "let a program use A (deny this).")
		if err != nil || res.Approved {
			t.Fatalf("got %+v %v, want a denial with no error", res, err)
		}
	})

	t.Run("UnansweredEndsAtTheDeadline", func(t *testing.T) {
		h := newHarness(t)
		need(t, h, Ignore)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		start := time.Now()
		res, err := approve(h, ctx, "let a program use A (this prompt times out).")
		if res.Approved || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("got %+v %v, want a timeout", res, err)
		}
		if d := time.Since(start); d > time.Second+h.Grace+time.Second {
			t.Fatalf("returned %s after it started", d)
		}
		if h.TakenDown != nil && !h.TakenDown() {
			t.Fatal("the prompt is still up")
		}
	})

	t.Run("HangUpEndsThePrompt", func(t *testing.T) {
		h := newHarness(t)
		need(t, h, Ignore)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(500*time.Millisecond, cancel)
		res, err := approve(h, ctx, "let a program use A (the client hangs up).")
		if res.Approved || err == nil {
			t.Fatalf("got %+v %v, want an error", res, err)
		}
		if h.TakenDown != nil && !h.TakenDown() {
			t.Fatal("the prompt is still up")
		}
	})

	t.Run("UnavailableIsErrUnavailable", func(t *testing.T) {
		h := newHarness(t)
		need(t, h, Unavailable)
		res, err := approve(h, context.Background(), "let a program use A (no prompt can be shown).")
		if res.Approved || !errors.Is(err, plugin.ErrUnavailable) {
			t.Fatalf("got %+v %v, want ErrUnavailable", res, err)
		}
	})

	t.Run("PromptIsShownVerbatim", func(t *testing.T) {
		h := newHarness(t)
		if h.Shown == nil {
			t.Skip("this harness can't see the prompt")
		}
		a := Deny
		if !slices.Contains(h.Can, Deny) {
			a = Approve
		}
		need(t, h, a)
		// Text a prompt layer might interpret: markup, format verbs and
		// polkit's $(…) are all shown as they are, or with markup escaped
		// as the authenticator says.
		prompt := `let a program use "A <b>$(polkit.caller-pid)</b> %s" in VM dev.`
		approve(h, context.Background(), prompt)
		shown := h.Shown()
		want := prompt
		if h.Shows != nil {
			want = h.Shows(prompt)
		}
		if len(shown) != 1 || !strings.Contains(shown[0], want) {
			t.Fatalf("shown %q, want it to contain %q", shown, want)
		}
	})

	t.Run("AvailableShowsNoPrompt", func(t *testing.T) {
		h := newHarness(t)
		ok, why := h.Authenticator.Available(context.Background())
		if !ok && why == "" {
			t.Fatal("unavailable without a reason")
		}
		if h.Shown != nil && len(h.Shown()) > 0 {
			t.Fatalf("Available showed %q", h.Shown())
		}
	})
}
