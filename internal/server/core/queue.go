package core

import (
	"context"
	"errors"
	"sync"
)

var errBusy = errors.New("approval queue full")

// promptQueue lets one prompt be open at a time across the whole service and
// bounds how many requests may wait behind it. With more than one instance,
// no single instance may hold more than half the slots, so one misbehaving
// realm can't keep every other realm's requests out.
type promptQueue struct {
	slot   chan struct{}
	mu     sync.Mutex
	held   int            // active + waiting, all instances
	per    map[string]int // active + waiting, per instance
	max    int            // one active plus max_queue waiting
	maxPer int
}

func newPromptQueue(maxWaiting, instances int) *promptQueue {
	q := &promptQueue{slot: make(chan struct{}, 1), per: map[string]int{}, max: maxWaiting + 1}
	q.maxPer = q.max
	if instances > 1 {
		q.maxPer = max(q.max/2, 1)
	}
	return q
}

func (q *promptQueue) acquire(ctx context.Context, instance string) (release func(), err error) {
	q.mu.Lock()
	if q.held >= q.max || q.per[instance] >= q.maxPer {
		q.mu.Unlock()
		return nil, errBusy
	}
	q.held++
	q.per[instance]++
	q.mu.Unlock()
	leave := func() {
		q.mu.Lock()
		q.held--
		q.per[instance]--
		q.mu.Unlock()
	}
	select {
	case q.slot <- struct{}{}:
		return func() {
			<-q.slot
			leave()
		}, nil
	case <-ctx.Done():
		leave()
		return nil, ctx.Err()
	}
}

// pending reports how many requests hold or wait for the prompt.
func (q *promptQueue) pending() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.held
}
