package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/bpinto/foca/internal/fsutil"
)

// JSONL is an append-only file sink: one JSON event per line, fsync'd before
// Append returns. Every file must be a regular file owned by the current
// user with no group or other permissions.
//
// The service and the host CLI both append to the same log. Each append
// holds an exclusive flock on the log's lock file and first reads anything
// other processes added, so sequence numbers stay unique across processes.
//
// When the current file reaches the rotation size it is renamed after the
// first seq it holds (audit.jsonl → audit.<seq>.jsonl) and a new one is
// started. The lock is a file of its own because the log files are renamed.
type JSONL struct {
	*sink
	log *Log
}

// Rotation bounds the log. Once the current file holds MaxSize bytes, the
// next append starts a new one, and only the Keep newest rotated files stay.
type Rotation struct {
	MaxSize int64
	Keep    int
}

var DefaultRotation = Rotation{MaxSize: 16 << 20, Keep: 16}

// auditFile is the part of *os.File the persister uses; tests inject faults.
type auditFile interface {
	io.Writer
	io.ReaderAt
	Sync() error
	Truncate(size int64) error
	Stat() (os.FileInfo, error)
	Close() error
}

type jsonlPersister struct {
	files logFiles
	rot   Rotation
	f     auditFile
	// size is the end of the last complete, synced event. A failed write is
	// cut back to it, so a torn line can never prefix a later event.
	size int64
	// lockFile is held open for lock, the cross-process lock.
	lockFile *os.File
	lock     func() (unlock func(), err error)
	// broken is set once the file's state can't be trusted (a failed sync,
	// or a torn write that couldn't be cut back). Every later append fails.
	broken error
}

// maxLine bounds a single stored event when reading the file back.
const maxLine = 1 << 20

func OpenJSONL(path string, rot Rotation) (*JSONL, error) {
	if rot.MaxSize <= 0 || rot.Keep < 1 {
		return nil, fmt.Errorf("audit: invalid rotation %+v", rot)
	}
	files := newLogFiles(path)
	lf, err := openPrivate(files.lock(), os.O_RDWR|os.O_CREATE)
	if err != nil {
		return nil, err
	}
	f, err := openPrivate(path, os.O_RDWR|os.O_APPEND|os.O_CREATE)
	if err != nil {
		lf.Close()
		return nil, err
	}
	p := &jsonlPersister{files: files, rot: rot, f: f, lockFile: lf, lock: flockFile(lf, unix.LOCK_EX)}
	unlock, err := p.lock()
	if err != nil {
		p.close()
		return nil, err
	}
	last, err := p.recover()
	unlock()
	if err != nil {
		p.close()
		return nil, err
	}
	return &JSONL{sink: newSink(p, last), log: &Log{files: files, poll: defaultPoll}}, nil
}

// Query reads the log's files, so it sees events every process appended.
func (j *JSONL) Query(ctx context.Context, f Filter, page Page) ([]Event, uint64, error) {
	return j.log.Query(ctx, f, page)
}

// Follow tails the log's files, so it sees events every process appends.
func (j *JSONL) Follow(ctx context.Context, f Filter, afterSeq uint64, fn func(Event) error) error {
	return j.log.Follow(ctx, f, afterSeq, fn)
}

// openPrivate opens a log file without following a symlink and checks that
// it is a private regular file of this user.
func openPrivate(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	if err := checkPrivateFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: %s: %w", path, err)
	}
	return f, nil
}

func checkPrivateFile(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("mode %o is not private (want 0600)", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("owned by uid %d, not %d", st.Uid, os.Getuid())
	}
	return nil
}

// logFiles names the files of the log whose current file is current.
type logFiles struct {
	dir, stem, current string
}

func newLogFiles(path string) logFiles {
	return logFiles{
		dir:     filepath.Dir(path),
		stem:    strings.TrimSuffix(filepath.Base(path), ".jsonl"),
		current: path,
	}
}

func (l logFiles) lock() string { return filepath.Join(l.dir, l.stem+".lock") }

// rotated is the name of a rotated file whose first event has seq first.
func (l logFiles) rotated(first uint64) string {
	return filepath.Join(l.dir, l.stem+"."+strconv.FormatUint(first, 10)+".jsonl")
}

type rotatedFile struct {
	path  string
	first uint64
}

// list returns the rotated files, oldest first.
func (l logFiles) list() ([]rotatedFile, error) {
	ents, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	var out []rotatedFile
	for _, ent := range ents {
		mid, ok := strings.CutPrefix(ent.Name(), l.stem+".")
		if !ok {
			continue
		}
		mid, ok = strings.CutSuffix(mid, ".jsonl")
		if !ok {
			continue
		}
		first, err := strconv.ParseUint(mid, 10, 64)
		// Only the name rotation writes: no sign, no leading zeros.
		if err != nil || strconv.FormatUint(first, 10) != mid {
			continue
		}
		out = append(out, rotatedFile{path: filepath.Join(l.dir, ent.Name()), first: first})
	}
	slices.SortFunc(out, func(a, b rotatedFile) int { return cmpUint(a.first, b.first) })
	return out, nil
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// recover reads the whole current file: it finds the last seq and ends a
// partial last line left by a crash, so the next event starts on a fresh
// line. A current file with no events yet, just rotated, takes the last seq
// from the newest rotated file.
func (p *jsonlPersister) recover() (uint64, error) {
	last, err := p.catchUp(0)
	if err != nil || last != 0 {
		return last, err
	}
	rotated, err := p.files.list()
	if err != nil || len(rotated) == 0 {
		return 0, err
	}
	f, err := openPrivate(rotated[len(rotated)-1].path, os.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	_, err = readEvents(f, 0, func(e Event) bool {
		last = max(last, e.Seq)
		return true
	})
	return last, err
}

// catchUp reads the current file from offset from, returning the highest
// seq there, and ends a partial last line.
func (p *jsonlPersister) catchUp(from int64) (uint64, error) {
	var last uint64
	end, err := readEvents(p.f, from, func(e Event) bool {
		last = max(last, e.Seq)
		return true
	})
	if err != nil {
		return 0, err
	}
	fi, err := p.f.Stat()
	if err != nil {
		return 0, err
	}
	size := fi.Size()
	if end < size {
		// A crash left a line without its newline. If it is a whole event
		// all the same, its seq is taken, so ending the line can't make
		// two events share a seq.
		if size-end <= maxLine {
			tail := make([]byte, size-end)
			if _, err := p.f.ReadAt(tail, end); err != nil {
				return 0, err
			}
			if e, ok := parseEvent(tail); ok {
				last = max(last, e.Seq)
			}
		}
		if _, err := p.f.Write([]byte("\n")); err != nil {
			return 0, err
		}
		if err := p.f.Sync(); err != nil {
			return 0, err
		}
		size++
	}
	p.size = size
	return last, nil
}

func (p *jsonlPersister) write(e *Event) error {
	if p.broken != nil {
		return p.broken
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	if _, err := p.f.Write(line); err != nil {
		// Part of the line may be on disk. Cut it off, or the next event
		// would be appended to it and become unreadable.
		if terr := p.f.Truncate(p.size); terr != nil {
			p.broken = fmt.Errorf("audit: torn write could not be removed (%v); refusing further events until restart", terr)
		}
		return fmt.Errorf("audit: write: %w", err)
	}
	if err := p.f.Sync(); err != nil {
		// After a failed fsync the kernel may have dropped the data and a
		// later fsync can still succeed, so nothing written from now on
		// could be trusted to be durable.
		p.broken = fmt.Errorf("audit: sync failed (%v); refusing further events until restart", err)
		return fmt.Errorf("audit: sync: %w", err)
	}
	p.size += int64(len(line))
	return nil
}

// scan reads the current file from the start.
func (p *jsonlPersister) scan(fn func(Event) bool) error {
	_, err := readEvents(p.f, 0, fn)
	return err
}

// readEvents reads the lines of r from offset off and calls fn with each
// event until fn returns false. It returns the offset just past the last
// whole line it read: a last line with no newline yet is still being
// written, or was torn by a crash, and is left alone. Lines that don't parse
// or are longer than maxLine are skipped rather than failing the read.
func readEvents(r io.ReaderAt, off int64, fn func(Event) bool) (end int64, err error) {
	br := bufio.NewReaderSize(io.NewSectionReader(r, off, 1<<62), 64*1024)
	end = off
	var line []byte
	var n int64
	over := false
	for {
		chunk, err := br.ReadSlice('\n')
		n += int64(len(chunk))
		if !over && len(line)+len(chunk) <= maxLine+1 {
			line = append(line, chunk...)
		} else {
			over = true
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			return end, nil
		}
		if err != nil {
			return end, err
		}
		end += n
		if !over {
			if e, ok := parseEvent(line[:len(line)-1]); ok && !fn(e) {
				return end, nil
			}
		}
		line, n, over = line[:0], 0, false
	}
}

func parseEvent(line []byte) (Event, bool) {
	var e Event
	if json.Unmarshal(line, &e) != nil || e.V == 0 {
		return Event{}, false
	}
	return e, true
}

func (p *jsonlPersister) close() error {
	err := p.f.Close()
	p.lockFile.Close()
	return err
}

func flockFile(f *os.File, how int) func() (func(), error) {
	return func() (func(), error) {
		if err := unix.Flock(int(f.Fd()), how); err != nil {
			return nil, fmt.Errorf("audit: lock: %w", err)
		}
		return func() { unix.Flock(int(f.Fd()), unix.LOCK_UN) }, nil
	}
}

// begin locks the log and catches up with events other processes appended
// since this one last wrote, so the next seq is above all of them. A full
// current file is rotated first; if that fails, the append fails.
func (p *jsonlPersister) begin() (uint64, func(), error) {
	if p.broken != nil {
		return 0, nil, p.broken
	}
	unlock, err := p.lock()
	if err != nil {
		return 0, nil, err
	}
	last, err := p.catchUpWithOthers()
	if err == nil && p.size >= p.rot.MaxSize {
		if err = p.rotate(); err != nil {
			err = fmt.Errorf("audit: rotate: %w", err)
		}
	}
	if err != nil {
		unlock()
		return 0, nil, err
	}
	return last, unlock, nil
}

func (p *jsonlPersister) catchUpWithOthers() (uint64, error) {
	mine, err := p.f.Stat()
	if err != nil {
		return 0, err
	}
	fi, err := os.Lstat(p.files.current)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	if err != nil || !os.SameFile(fi, mine) {
		// Another process rotated the log: move to the new current file.
		f, err := openPrivate(p.files.current, os.O_RDWR|os.O_APPEND|os.O_CREATE)
		if err != nil {
			return 0, err
		}
		p.f.Close()
		p.f, p.size = f, 0
		return p.recover()
	}
	switch {
	case mine.Size() == p.size:
		return 0, nil
	case mine.Size() > p.size:
		// Someone else appended: read only what they added. catchUp also
		// ends a line another process left torn by a crash.
		return p.catchUp(p.size)
	default:
		// The file shrank, so it was rewritten: read it all again.
		return p.recover()
	}
}

// rotate renames the current file after its first seq, starts a new one and
// removes the oldest rotated files beyond Keep. Called with the lock held.
func (p *jsonlPersister) rotate() error {
	var first uint64
	if _, err := readEvents(p.f, 0, func(e Event) bool {
		first = e.Seq
		return false
	}); err != nil {
		return err
	}
	if first == 0 {
		return errors.New("the current file holds no event to name it after")
	}
	target := p.files.rotated(first)
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("%s already exists", target)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(p.files.current, target); err != nil {
		return err
	}
	// If this fails, the next append finds no current file and creates it.
	f, err := openPrivate(p.files.current, os.O_RDWR|os.O_APPEND|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return err
	}
	p.f.Close()
	p.f, p.size = f, 0
	if err := fsutil.SyncDir(p.files.dir); err != nil {
		return err
	}
	// Removing old files is housekeeping: one that can't be removed stays,
	// which never loses an event.
	if rotated, err := p.files.list(); err == nil {
		for len(rotated) > p.rot.Keep {
			os.Remove(rotated[0].path)
			rotated = rotated[1:]
		}
	}
	return nil
}
