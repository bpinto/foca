package audit

import (
	"context"
	"time"
)

// Filter selects events. Zero fields match everything.
type Filter struct {
	Since    time.Time
	Until    time.Time
	Types    []string
	Instance string
	Resource *Resource
	Outcome  string
	Mode     string
}

func (f Filter) Match(e Event) bool {
	if !f.Since.IsZero() && e.TS.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && !e.TS.Before(f.Until) {
		return false
	}
	if len(f.Types) > 0 {
		ok := false
		for _, t := range f.Types {
			if t == e.Type {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if f.Instance != "" && f.Instance != e.Instance {
		return false
	}
	if f.Resource != nil {
		if !matchesResource(e, *f.Resource) {
			return false
		}
	}
	if f.Outcome != "" && f.Outcome != e.Outcome {
		return false
	}
	if f.Mode != "" && (e.Approval == nil || e.Approval.Mode != f.Mode) {
		return false
	}
	return true
}

func matchesResource(e Event, r Resource) bool {
	if e.Resource != nil && *e.Resource == r {
		return true
	}
	for _, x := range e.Resources {
		if x == r {
			return true
		}
	}
	return false
}

// Page asks for events with Seq > AfterSeq, at most Limit of them.
type Page struct {
	AfterSeq uint64
	Limit    int
}

const MaxPageLimit = 500

func (p Page) limit() int {
	if p.Limit <= 0 || p.Limit > MaxPageLimit {
		return MaxPageLimit
	}
	return p.Limit
}

// Reader is what foca events reads a log through (design §8.5).
type Reader interface {
	// Query returns matching events with Seq > page.AfterSeq. next is the
	// seq to pass as AfterSeq for the following page, or 0 when there are
	// no more.
	Query(ctx context.Context, f Filter, page Page) (events []Event, next uint64, err error)
	// Follow calls fn with each matching event with Seq > afterSeq
	// (FromNow: only new ones): stored ones, then live ones, with no gap.
	// It returns nil when ctx ends, or fn's error.
	Follow(ctx context.Context, f Filter, afterSeq uint64, fn func(Event) error) error
	Close() error
}
