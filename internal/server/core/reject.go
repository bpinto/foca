package core

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/bpinto/foca/internal/audit"
)

// RejectWindow is how long a burst of rejections for one instance and reason
// is folded into a single audit event.
const RejectWindow = 10 * time.Second

// rejections coalesces request.rejected events (design §9.6). The first
// rejection in a window is written at once; later ones in the same window
// are only counted, and the count is written as one event when the next
// window starts or the service stops. The key is instance and reason, never
// the peer: a caller can fork new processes, but it can't change its realm.
// Access and approval events never pass through here.
type rejections struct {
	mu      sync.Mutex
	windows map[string]*rejWindow
}

type rejWindow struct {
	start      time.Time
	seq        uint64
	instance   string
	reason     string
	suppressed int
}

// RecordRejection appends a request.rejected event, or counts it into the
// current window. The returned seq is the event that stands for it. An error
// means nothing was recorded, and the caller must refuse with audit_failed.
func (s *Service) RecordRejection(ctx context.Context, e *audit.Event) (uint64, error) {
	key := e.Instance + "\x00" + e.Reason
	now := s.opts.Now()
	s.rej.mu.Lock()
	defer s.rej.mu.Unlock()
	if w := s.rej.windows[key]; w != nil {
		if now.Sub(w.start) < RejectWindow {
			w.suppressed++
			return w.seq, nil
		}
		delete(s.rej.windows, key)
		if err := s.flushWindow(ctx, w); err != nil {
			return 0, err
		}
	}
	seq, err := s.opts.Audit.Append(context.WithoutCancel(ctx), e)
	if err != nil {
		return 0, err
	}
	s.rej.windows[key] = &rejWindow{start: now, seq: seq, instance: e.Instance, reason: e.Reason}
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

func (s *Service) flushWindow(ctx context.Context, w *rejWindow) error {
	if w.suppressed == 0 {
		return nil
	}
	e := &audit.Event{Type: audit.TypeRequestRejected, Outcome: audit.OutcomeRejected,
		Instance: w.instance, Reason: w.reason, Count: w.suppressed,
		Params: map[string]string{"coalesced_after_seq": strconv.FormatUint(w.seq, 10)}}
	_, err := s.opts.Audit.Append(context.WithoutCancel(ctx), e)
	return err
}
