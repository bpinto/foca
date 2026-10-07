package audit

import (
	"context"
	"sync"
	"time"

	"github.com/bpinto/foca/internal/ids"
)

// persister is the storage half of a sink. All calls happen under the sink's
// mutex, so implementations need no locking of their own.
type persister interface {
	// begin starts an append. It returns the highest seq already stored by
	// anyone, so seqs stay unique when other processes append to the same
	// file, and end, which must be called once the write is done.
	begin() (lastSeq uint64, end func(), err error)
	write(e *Event) error
	// scan calls fn for each stored event in seq order until fn returns false.
	scan(fn func(Event) bool) error
	close() error
}

// sink implements Append/Query/Subscribe on top of a persister.
type sink struct {
	mu   sync.Mutex
	seq  uint64
	p    persister
	subs map[*subscriber]struct{}
	now  func() time.Time
}

type subscriber struct {
	f  Filter
	ch chan Event
}

const subscriberBuffer = 256

func newSink(p persister, lastSeq uint64) *sink {
	return &sink{p: p, seq: lastSeq, subs: map[*subscriber]struct{}{}, now: time.Now}
}

// Append fills in V, Seq, ID and TS, stores the event durably and returns its
// sequence number. A failed append returns an error; callers must treat that
// as "not recorded" and refuse the access it describes.
func (s *sink) Append(ctx context.Context, e *Event) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	last, end, err := s.p.begin()
	if err != nil {
		return 0, err
	}
	defer end()
	if last > s.seq {
		s.seq = last
	}
	// Sequence numbers may have gaps after a failed write, never duplicates.
	s.seq++
	e.V = Version
	e.Seq = s.seq
	if e.ID == "" {
		e.ID = ids.New()
	}
	if e.TS.IsZero() {
		e.TS = s.now().UTC().Truncate(time.Millisecond)
	}
	// Every stored time is UTC, whatever zone the caller's clock is in.
	if a := e.Approval; a != nil {
		a.GrantedAt, a.ExpiresAt = utc(a.GrantedAt), utc(a.ExpiresAt)
	}
	if err := s.p.write(e); err != nil {
		return 0, err
	}
	for sub := range s.subs {
		if !sub.f.Match(*e) {
			continue
		}
		select {
		case sub.ch <- *e:
		default:
			// A subscriber that can't keep up is dropped; it can
			// resubscribe from the last seq it saw without a gap.
			close(sub.ch)
			delete(s.subs, sub)
		}
	}
	return e.Seq, nil
}

// Query returns matching events with Seq > page.AfterSeq. next is the seq to
// pass as AfterSeq for the following page, or 0 when there are no more.
func (s *sink) Query(ctx context.Context, f Filter, page Page) (events []Event, next uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := page.limit()
	more := false
	err = s.p.scan(func(e Event) bool {
		if e.Seq <= page.AfterSeq || !f.Match(e) {
			return true
		}
		if len(events) == limit {
			more = true
			return false
		}
		events = append(events, e)
		return true
	})
	if err != nil {
		return nil, 0, err
	}
	if more {
		next = events[len(events)-1].Seq
	}
	return events, next, nil
}

// Subscribe streams matching events with Seq > fromSeq: stored ones first,
// then live ones, with no gap between the two. The channel closes when ctx
// ends or the subscriber falls too far behind.
func (s *sink) Subscribe(ctx context.Context, f Filter, fromSeq uint64) (<-chan Event, error) {
	s.mu.Lock()
	var backlog []Event
	err := s.p.scan(func(e Event) bool {
		if e.Seq > fromSeq && f.Match(e) {
			backlog = append(backlog, e)
		}
		return true
	})
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	sub := &subscriber{f: f, ch: make(chan Event, subscriberBuffer)}
	s.subs[sub] = struct{}{}
	s.mu.Unlock()

	out := make(chan Event)
	go func() {
		defer close(out)
		defer s.unsubscribe(sub)
		for _, e := range backlog {
			select {
			case out <- e:
			case <-ctx.Done():
				return
			}
		}
		for {
			select {
			case e, ok := <-sub.ch:
				if !ok {
					return
				}
				select {
				case out <- e:
				case <-ctx.Done():
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

func (s *sink) unsubscribe(sub *subscriber) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.subs[sub]; ok {
		delete(s.subs, sub)
		close(sub.ch)
	}
}

func (s *sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for sub := range s.subs {
		close(sub.ch)
		delete(s.subs, sub)
	}
	return s.p.close()
}

// utc is t in UTC, as a new value: the caller's time is left alone.
func utc(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
