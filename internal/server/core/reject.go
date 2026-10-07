package core

import (
	"context"
	"sync"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/protocol"
)

// RejectWindow is how long a burst of coalesced events for one instance,
// type and reason is folded into a single audit event.
const RejectWindow = 10 * time.Second

// rejections coalesces the events a realm can cause without any approval
// (design §9.6): request.rejected, secret.read with outcome not_found, and
// secret.list. The first event in a window is written at once; later ones in
// the same window are only counted, and the count is written as one event
// when the next window starts or the service stops. The key is instance,
// type and reason, never the peer: a caller can fork new processes, but it
// can't change its realm. Events that involve an approval never pass
// through here.
type rejections struct {
	mu      sync.Mutex
	windows map[string]*rejWindow
}

type rejWindow struct {
	start time.Time
	seq   uint64
	// first is the window's first event, stripped of everything that is
	// particular to that one request. The count is written in its shape.
	first      audit.Event
	suppressed int
	// reasons counts the suppressed events by their own reason, in a
	// window that several reasons share.
	reasons map[string]int
}

// sharedReasons are reasons that must not be told apart by whether an
// event was written: an unknown secret and one the instance may not see
// answer the same, so they also share a window. Each still keeps its own
// reason in the event written in full and in the count (coalesced.reasons).
var sharedReasons = map[string]string{
	"unknown":               "not_found",
	"not_exposed":           "not_found",
	"uses_unknown_secret":   "uses_unreadable_secret",
	"uses_unexposed_secret": "uses_unreadable_secret",
}

// windowReason is the reason e's window is keyed on.
func windowReason(e *audit.Event) string {
	if r, ok := sharedReasons[e.Reason]; ok {
		return r
	}
	return e.Reason
}

// RecordRejection appends a request.rejected event, or counts it into the
// current window. The returned seq is the event that stands for it. An error
// means nothing was recorded, and the caller must refuse with audit_failed.
func (s *Service) RecordRejection(ctx context.Context, e *audit.Event) (uint64, error) {
	return s.coalesce(ctx, e)
}

// recordCoalesced is record for the other events a realm can cause without
// approval: not_found reads and listings.
func (s *Service) recordCoalesced(ctx context.Context, c Call, e *audit.Event) (uint64, *protocol.Error) {
	seq, err := s.coalesce(ctx, e)
	if err != nil {
		return 0, s.fail(c, protocol.CodeAuditFailed, 0, "could not record the request; refusing it")
	}
	return seq, nil
}

func (s *Service) coalesce(ctx context.Context, e *audit.Event) (uint64, error) {
	key := e.Instance + "\x00" + e.Type + "\x00" + windowReason(e)
	now := s.opts.Now()
	s.rej.mu.Lock()
	defer s.rej.mu.Unlock()
	if w := s.rej.windows[key]; w != nil {
		// Only counted while the sink takes writes: once one failed, an
		// event is written in full, so a stopped sink refuses it.
		if now.Sub(w.start) < RejectWindow && !s.auditFailed.Load() {
			w.suppressed++
			if w.reasons != nil {
				w.reasons[e.Reason]++
			}
			return w.seq, nil
		}
		// A count that can't be written stays, to be tried again.
		if err := s.flushWindow(ctx, w); err != nil {
			return 0, err
		}
		delete(s.rej.windows, key)
	}
	seq, err := s.appendEvent(ctx, e)
	if err != nil {
		return 0, err
	}
	first := audit.Event{Type: e.Type, Outcome: e.Outcome, Instance: e.Instance, Vault: e.Vault,
		Origin: e.Origin, Reason: e.Reason, Approval: e.Approval}
	w := &rejWindow{start: now, seq: seq, first: first}
	if shared := windowReason(e); shared != e.Reason {
		w.first.Reason, w.reasons = shared, map[string]int{}
	}
	s.rej.windows[key] = w
	return seq, nil
}

// FlushRejections writes the counts of all open windows. The server calls it
// on shutdown, before server.stop.
func (s *Service) FlushRejections(ctx context.Context) error {
	s.rej.mu.Lock()
	defer s.rej.mu.Unlock()
	var first error
	for key, w := range s.rej.windows {
		delete(s.rej.windows, key)
		if err := s.flushWindow(ctx, w); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// flushWindow writes one event standing for the window's suppressed ones,
// with how many there were and the seq of the event they followed.
func (s *Service) flushWindow(ctx context.Context, w *rejWindow) error {
	if w.suppressed == 0 {
		return nil
	}
	e := w.first
	e.Coalesced = &audit.Coalesced{Count: w.suppressed, AfterSeq: w.seq, Reasons: w.reasons}
	_, err := s.appendEvent(ctx, &e)
	return err
}
