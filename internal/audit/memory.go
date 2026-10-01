package audit

import "sync/atomic"

// Memory is an in-memory sink for tests. SetFailure makes every later Append
// fail, to exercise fail-closed paths.
type Memory struct {
	*sink
	mem *memPersister
}

type memPersister struct {
	events []Event
	fail   atomic.Pointer[error]
}

func NewMemory() *Memory {
	p := &memPersister{}
	return &Memory{sink: newSink(p, 0), mem: p}
}

// SetFailure makes later appends fail with err; nil restores normal behaviour.
func (m *Memory) SetFailure(err error) {
	if err == nil {
		m.mem.fail.Store(nil)
		return
	}
	m.mem.fail.Store(&err)
}

// Events returns a copy of everything recorded so far.
func (m *Memory) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.mem.events...)
}

func (p *memPersister) write(e *Event) error {
	if err := p.fail.Load(); err != nil {
		return *err
	}
	p.events = append(p.events, *e)
	return nil
}

func (p *memPersister) scan(fn func(Event) bool) error {
	for _, e := range p.events {
		if !fn(e) {
			return nil
		}
	}
	return nil
}

func (p *memPersister) close() error { return nil }
