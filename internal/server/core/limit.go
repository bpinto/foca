package core

import (
	"context"
	"sync"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/protocol"
)

// Reads and listings cost the host work before any approval: an unseal of
// the data key, a metadata decrypt and an audit append. A token bucket per
// instance bounds that (design §9.6.1): a burst of requestBurst, refilled at
// requestRate a second. These are fixed, not config.
const (
	requestBurst = 30
	requestRate  = 5
)

type limiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// allow takes a token from the instance's bucket. A wall clock that moved
// backwards refills nothing.
func (l *limiter) allow(instance string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]*bucket{}
	}
	b := l.buckets[instance]
	if b == nil {
		b = &bucket{tokens: requestBurst, last: now}
		l.buckets[instance] = b
	}
	if d := now.Sub(b.last); d > 0 {
		b.tokens = min(requestBurst, b.tokens+d.Seconds()*requestRate)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// limit refuses a request over its instance's rate as busy, before any
// work is done for it. The refusal is a coalesced request.rejected.
func (s *Service) limit(ctx context.Context, c Call, method string) error {
	if s.lim.allow(c.Instance.Name, s.opts.Now()) {
		return nil
	}
	e := s.Event(c, audit.TypeRequestRejected, audit.OutcomeRejected)
	e.Reason = "rate_limited"
	e.Params = map[string]string{"method": method}
	seq, err := s.RecordRejection(ctx, e)
	if err != nil {
		return s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
	}
	return s.fail(c, protocol.CodeBusy, seq, "too many requests; try again shortly")
}
