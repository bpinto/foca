package core

import (
	"context"
	"math"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/protocol"
)

// Denials are never cached as "no". Repeated denials of the same resource
// for the same caller instead space out the prompts (design §9.6), so a
// realm can't keep the user clicking "deny".
var denialDelays = []time.Duration{2 * time.Second, 8 * time.Second, 30 * time.Second}

// denialMemory is how long a denial counts for the next prompt.
const denialMemory = 10 * time.Minute

type denialKey struct {
	instance string
	caller   string // pinned peer session, else the connection
	resource string
}

type denial struct {
	count int
	last  time.Time
}

func denialKeyFor(c Call, r plugin.ResourceRef) denialKey {
	caller := "conn:" + c.Conn
	if c.Peer.PIDStable && c.Peer.Session != "" {
		caller = "session:" + c.Peer.Session
	}
	return denialKey{instance: c.Instance.Name, caller: caller, resource: r.Kind + ":" + r.ID}
}

// live returns the denial record for k, forgetting an old one. Caller holds s.mu.
func (s *Service) liveDenial(k denialKey, now time.Time) *denial {
	d := s.denials[k]
	if d != nil && now.Sub(d.last) >= denialMemory {
		delete(s.denials, k)
		return nil
	}
	return d
}

// denialCount is the most times any of refs was denied lately; the prompt
// shows it.
func (s *Service) denialCount(c Call, refs []plugin.ResourceRef) int {
	now := s.wall()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, r := range refs {
		if d := s.liveDenial(denialKeyFor(c, r), now); d != nil && d.count > n {
			n = d.count
		}
	}
	return n
}

// denied counts a user's denial of refs.
func (s *Service) denied(c Call, refs []plugin.ResourceRef) {
	now := s.wall()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range refs {
		k := denialKeyFor(c, r)
		d := s.liveDenial(k, now)
		if d == nil {
			d = &denial{}
			s.denials[k] = d
		}
		d.count++
		d.last = now
	}
}

// checkBackoff refuses a request that comes too soon after a denial of any
// resource it names. The refusal is a coalesced request.rejected, so a
// flood of retries can't bury other events.
func (s *Service) checkBackoff(ctx context.Context, c Call, a ask) error {
	now := s.wall()
	var wait time.Duration
	s.mu.Lock()
	for _, r := range a.refs {
		d := s.liveDenial(denialKeyFor(c, r), now)
		if d == nil {
			continue
		}
		delay := denialDelays[min(d.count, len(denialDelays))-1]
		wait = max(wait, d.last.Add(delay).Sub(now))
	}
	s.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	e := s.Event(c, audit.TypeRequestRejected, audit.OutcomeRejected)
	e.Resources = a.resources()
	e.Reason = "denial_backoff"
	seq, err := s.RecordRejection(ctx, e)
	if err != nil {
		return s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
	}
	return s.fail(c, protocol.CodeDenied, seq, "denied recently; ask again in %ds", int(math.Ceil(wait.Seconds())))
}

// ---- per-instance cooldown ----

// A strike is a prompt an instance opened that ended without an approval:
// the user denied it, it timed out, or the client hung up while it was on
// screen. Denial backoff is per resource, so a realm with many secrets could
// still keep prompts coming by asking for each in turn, and a prompt left to
// time out costs it nothing. Strikes count across every resource of the
// instance, which the realm can't change by forking or reconnecting.
type strike struct {
	at         time.Time
	unanswered bool // timed out or cancelled, rather than denied
}

// After strikesBeforeCooldown live strikes, the instance opens no prompt
// until the last one is cooldowns[n-3] old (the last value repeats). Strikes
// are forgotten after denialMemory; an approval or a wipe clears them.
var cooldowns = []time.Duration{30 * time.Second, 2 * time.Minute, 5 * time.Minute}

const (
	strikesBeforeCooldown = 3
	maxStrikes            = 16 // per instance; older ones are dropped
)

// liveStrikes returns the instance's strikes within denialMemory, forgetting
// older ones. Caller holds s.mu.
func (s *Service) liveStrikes(instance string, now time.Time) []strike {
	ss := s.strikes[instance]
	i := 0
	for i < len(ss) && now.Sub(ss[i].at) >= denialMemory {
		i++
	}
	if i == len(ss) {
		delete(s.strikes, instance)
		return nil
	}
	if i > 0 {
		ss = append([]strike(nil), ss[i:]...)
		s.strikes[instance] = ss
	}
	return ss
}

// struck records a prompt of c's instance that ended without an approval.
func (s *Service) struck(c Call, unanswered bool) {
	now := s.wall()
	s.mu.Lock()
	defer s.mu.Unlock()
	ss := append(s.liveStrikes(c.Instance.Name, now), strike{at: now, unanswered: unanswered})
	if len(ss) > maxStrikes {
		ss = ss[len(ss)-maxStrikes:]
	}
	s.strikes[c.Instance.Name] = ss
}

// unanswered is how many of the instance's recent prompts timed out or were
// cancelled; the prompt shows it.
func (s *Service) unanswered(c Call) int {
	now := s.wall()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, st := range s.liveStrikes(c.Instance.Name, now) {
		if st.unanswered {
			n++
		}
	}
	return n
}

// checkCooldown refuses a request from an instance whose recent prompts went
// unapproved too often. Like denial backoff, the refusal is a coalesced
// request.rejected and the request doesn't wait.
func (s *Service) checkCooldown(ctx context.Context, c Call, a ask) error {
	now := s.wall()
	s.mu.Lock()
	ss := s.liveStrikes(c.Instance.Name, now)
	var wait time.Duration
	if n := len(ss); n >= strikesBeforeCooldown {
		delay := cooldowns[min(n-strikesBeforeCooldown, len(cooldowns)-1)]
		wait = ss[n-1].at.Add(delay).Sub(now)
	}
	s.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	e := s.Event(c, audit.TypeRequestRejected, audit.OutcomeRejected)
	e.Resources = a.resources()
	e.Reason = "prompt_cooldown"
	seq, err := s.RecordRejection(ctx, e)
	if err != nil {
		return s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
	}
	return s.fail(c, protocol.CodeDenied, seq, "too many unapproved prompts from this instance; ask again in %ds", int(math.Ceil(wait.Seconds())))
}

// mayPrompt runs both checks a read makes before it may open a prompt.
func (s *Service) mayPrompt(ctx context.Context, c Call, a ask) error {
	if err := s.checkBackoff(ctx, c, a); err != nil {
		return err
	}
	return s.checkCooldown(ctx, c, a)
}
