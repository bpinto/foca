package audit

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Log reads a JSONL audit log, rotated files included, and never writes to
// it. Reads take the log's lock only shared and only while opening files,
// so a reader never holds up an append.
type Log struct {
	files logFiles
	// poll is how often Follow looks for new events.
	poll time.Duration
}

const defaultPoll = 200 * time.Millisecond

// OpenLog opens the log whose current file is path for reading.
func OpenLog(path string) (*Log, error) {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("audit: no audit log at %s", path)
		}
		return nil, fmt.Errorf("audit: %w", err)
	}
	return &Log{files: newLogFiles(path), poll: defaultPoll}, nil
}

// Close exists so a Log can stand in for a sink's reading half.
func (l *Log) Close() error { return nil }

// shared runs fn holding the log's lock shared: no append or rotation is
// under way meanwhile. Each call opens the lock file on its own, since flock
// locks belong to an open file and two holders on one would release each
// other's lock.
func (l *Log) shared(fn func() error) error {
	lf, err := openPrivate(l.files.lock(), os.O_RDONLY|os.O_CREATE)
	if err != nil {
		return err
	}
	defer lf.Close()
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_SH); err != nil {
		return fmt.Errorf("audit: lock: %w", err)
	}
	return fn()
}

// snapshot is the log's files, opened together under the lock so a rotation
// can't fall between them. Rotated files come oldest first.
type snapshot struct {
	rotated []*os.File
	current *os.File
	// size is the current file's size when it was opened: it ends on a
	// whole line, as no append was under way.
	size int64
}

func (s *snapshot) close() {
	for _, f := range s.rotated {
		f.Close()
	}
	if s.current != nil {
		s.current.Close()
	}
}

// open opens the current file and the rotated files that can hold an event
// with Seq > afterSeq, so a query by seq skips older files unread.
func (l *Log) open(afterSeq uint64) (*snapshot, error) {
	s := &snapshot{}
	err := l.shared(func() error {
		if afterSeq != FromNow {
			list, err := l.files.list()
			if err != nil {
				return err
			}
			for i, r := range list {
				// Every event in a rotated file is below the next one's first seq.
				if i+1 < len(list) && list[i+1].first <= afterSeq+1 {
					continue
				}
				f, err := openPrivate(r.path, os.O_RDONLY)
				if err != nil {
					return err
				}
				s.rotated = append(s.rotated, f)
			}
		}
		f, err := openPrivate(l.files.current, os.O_RDONLY)
		if err != nil {
			return err
		}
		s.current = f
		fi, err := f.Stat()
		if err != nil {
			return err
		}
		s.size = fi.Size()
		return nil
	})
	if err != nil {
		s.close()
		return nil, err
	}
	return s, nil
}

// Query returns matching events with Seq > page.AfterSeq, across rotated
// files. next is the seq to pass as AfterSeq for the following page, or 0
// when there are no more.
func (l *Log) Query(ctx context.Context, f Filter, page Page) ([]Event, uint64, error) {
	s, err := l.open(page.AfterSeq)
	if err != nil {
		return nil, 0, err
	}
	defer s.close()
	pq := newPageQuery(f, page)
	for _, file := range append(s.rotated, s.current) {
		if err := ctx.Err(); err != nil {
			return nil, 0, err
		}
		if _, err := readEvents(file, 0, pq.visit); err != nil {
			return nil, 0, fmt.Errorf("audit: read %s: %w", file.Name(), err)
		}
		if pq.more {
			break
		}
	}
	events, next := pq.result()
	return events, next, nil
}

// Follow calls fn with each matching event with Seq > afterSeq (FromNow:
// only those appended from now on). It reads the stored events first, then
// tails the current file, following it across rotations, so every event
// written by any process is delivered once, in order, with no gap. It
// returns nil when ctx ends, fn's error, or an error if the log can't be
// read without a gap.
func (l *Log) Follow(ctx context.Context, f Filter, afterSeq uint64, fn func(Event) error) error {
	s, err := l.open(afterSeq)
	if err != nil {
		return err
	}
	defer s.close()
	var off int64
	if afterSeq == FromNow {
		off, afterSeq = s.size, 0
	}
	t := &tailer{f: f, after: afterSeq, fn: fn}
	for _, file := range s.rotated {
		if ctx.Err() != nil {
			return nil
		}
		if _, err := readEvents(file, 0, t.visit); err != nil || t.err != nil {
			return t.fail(file, err)
		}
	}
	for {
		end, err := readEvents(s.current, off, t.visit)
		if err != nil || t.err != nil {
			return t.fail(s.current, err)
		}
		off = end
		if ctx.Err() != nil {
			return nil
		}
		fi, err := s.current.Stat()
		if err != nil {
			return err
		}
		if fi.Size() < off {
			return fmt.Errorf("audit: %s shrank below what was already read; it was rewritten", s.current.Name())
		}
		next, err := l.rotatedAfter(s.current, t.last)
		if err != nil {
			return err
		}
		if next == nil {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(l.poll):
			}
			continue
		}
		// The file was rotated, so nothing more is appended to it: read its
		// last events, then the files that came after it.
		if _, err := readEvents(s.current, off, t.visit); err != nil || t.err != nil {
			next.close()
			return t.fail(s.current, err)
		}
		for _, file := range next.rotated {
			if _, err := readEvents(file, 0, t.visit); err != nil || t.err != nil {
				next.close()
				return t.fail(file, err)
			}
		}
		s.close()
		*s = *next
		off = 0
	}
}

// rotatedAfter returns nil while mine is still the current file. Once it
// has been rotated, it opens the rotated files after mine and the new
// current file. If mine was already removed, the files between it and the
// oldest one left may have gone too, so that is an error rather than a
// possible gap.
func (l *Log) rotatedAfter(mine *os.File, lastSeq uint64) (*snapshot, error) {
	ms, err := mine.Stat()
	if err != nil {
		return nil, err
	}
	// Most polls find nothing changed; only a change is worth the lock.
	if fi, err := os.Lstat(l.files.current); err == nil && os.SameFile(fi, ms) {
		return nil, nil
	}
	var next *snapshot
	err = l.shared(func() error {
		fi, err := os.Lstat(l.files.current)
		if errors.Is(err, fs.ErrNotExist) {
			// Renamed, but the new file isn't there yet: the next
			// append creates it.
			return nil
		}
		if err != nil || os.SameFile(fi, ms) {
			return err
		}
		list, err := l.files.list()
		if err != nil {
			return err
		}
		at := -1
		for i, r := range list {
			if rfi, err := os.Lstat(r.path); err == nil && os.SameFile(rfi, ms) {
				at = i
			}
		}
		if at < 0 {
			return fmt.Errorf("audit: the log was rotated and its old files removed before they were read; events after seq %d may be missing", lastSeq)
		}
		s := &snapshot{}
		for _, r := range list[at+1:] {
			f, err := openPrivate(r.path, os.O_RDONLY)
			if err != nil {
				s.close()
				return err
			}
			s.rotated = append(s.rotated, f)
		}
		if s.current, err = openPrivate(l.files.current, os.O_RDONLY); err != nil {
			s.close()
			return err
		}
		next = s
		return nil
	})
	return next, err
}

// tailer delivers Follow's events and remembers where it got to.
type tailer struct {
	f     Filter
	after uint64
	fn    func(Event) error
	// last is the seq of the last event read, delivered or not.
	last uint64
	err  error
}

func (t *tailer) visit(e Event) bool {
	t.last = max(t.last, e.Seq)
	if e.Seq <= t.after || !t.f.Match(e) {
		return true
	}
	t.err = t.fn(e)
	return t.err == nil
}

// fail returns fn's error as is, or names the file a read failed on.
func (t *tailer) fail(file *os.File, err error) error {
	if t.err != nil {
		return t.err
	}
	return fmt.Errorf("audit: read %s: %w", file.Name(), err)
}
