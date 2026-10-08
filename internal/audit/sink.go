package audit

import (
	"context"
	"errors"
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

// sink implements Append on top of a persister, and Query and Follow for a
// sink whose events all pass through this process (Memory).
type sink struct {
	mu   sync.Mutex
	seq  uint64
	p    persister
	subs map[*subscriber]struct{}
	now  func() time.Time
	// closed stops followers from subscribing again after Close.
	closed bool
}

type subscriber struct {
	f  Filter
	ch chan Event
}

const subscriberBuffer = 256

// FromNow, passed to Follow as afterSeq, skips every event already stored:
// only events appended after Follow starts are delivered.
const FromNow = ^uint64(0)

var errClosed = errors.New("audit: sink closed")

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
			// A subscriber that can't keep up is dropped; follow
			// subscribes again from the last seq it delivered.
			close(sub.ch)
			delete(s.subs, sub)
		}
	}
	return e.Seq, nil
}

// query returns matching events with Seq > page.AfterSeq. next is the seq to
// pass as AfterSeq for the following page, or 0 when there are no more.
func (s *sink) query(f Filter, page Page) (events []Event, next uint64, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pq := newPageQuery(f, page)
	if err := s.p.scan(pq.visit); err != nil {
		return nil, 0, err
	}
	events, next = pq.result()
	return events, next, nil
}

// pageQuery collects one page of matching events.
type pageQuery struct {
	f      Filter
	after  uint64
	limit  int
	events []Event
	more   bool
}

func newPageQuery(f Filter, page Page) *pageQuery {
	return &pageQuery{f: f, after: page.AfterSeq, limit: page.limit()}
}

// visit takes one stored event; it returns false once the page is full and
// another match proves there are more.
func (q *pageQuery) visit(e Event) bool {
	if e.Seq <= q.after || !q.f.Match(e) {
		return true
	}
	if len(q.events) == q.limit {
		q.more = true
		return false
	}
	q.events = append(q.events, e)
	return true
}

func (q *pageQuery) result() ([]Event, uint64) {
	if q.more {
		return q.events, q.events[len(q.events)-1].Seq
	}
	return q.events, 0
}

// follow calls fn with each matching event with Seq > afterSeq, stored ones
// first, then live ones as they are appended, with no gap between the two.
// It returns nil when ctx ends, or fn's error.
func (s *sink) follow(ctx context.Context, f Filter, afterSeq uint64, fn func(Event) error) error {
	for {
		sub, backlog, after, err := s.subscribe(f, afterSeq)
		if err != nil {
			return err
		}
		afterSeq, err = feed(ctx, sub, backlog, after, fn)
		s.unsubscribe(sub)
		if err != nil || ctx.Err() != nil {
			return err
		}
		// The subscriber fell behind and was dropped: pick up again from
		// the last event delivered.
	}
}

// subscribe registers a subscriber and returns the stored events it must
// see first. Both happen under the lock, so no event falls between them.
func (s *sink) subscribe(f Filter, afterSeq uint64) (*subscriber, []Event, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, nil, 0, errClosed
	}
	if afterSeq == FromNow {
		afterSeq = s.seq
	}
	var backlog []Event
	err := s.p.scan(func(e Event) bool {
		if e.Seq > afterSeq && f.Match(e) {
			backlog = append(backlog, e)
		}
		return true
	})
	if err != nil {
		return nil, nil, 0, err
	}
	sub := &subscriber{f: f, ch: make(chan Event, subscriberBuffer)}
	s.subs[sub] = struct{}{}
	return sub, backlog, afterSeq, nil
}

// feed delivers the backlog, then live events until ctx ends or the
// subscriber is dropped. It returns the seq of the last event delivered.
func feed(ctx context.Context, sub *subscriber, backlog []Event, afterSeq uint64, fn func(Event) error) (uint64, error) {
	for _, e := range backlog {
		if ctx.Err() != nil {
			return afterSeq, nil
		}
		if err := fn(e); err != nil {
			return afterSeq, err
		}
		afterSeq = e.Seq
	}
	for {
		select {
		case e, ok := <-sub.ch:
			if !ok {
				return afterSeq, nil
			}
			if err := fn(e); err != nil {
				return afterSeq, err
			}
			afterSeq = e.Seq
		case <-ctx.Done():
			return afterSeq, nil
		}
	}
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
	s.closed = true
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
