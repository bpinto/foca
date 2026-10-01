package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// JSONL is an append-only file sink: one JSON event per line, fsync'd before
// Append returns. The file must be a regular file owned by the current user
// with no group or other permissions.
type JSONL struct {
	*sink
}

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
	path string
	f    auditFile
	// size is the end of the last complete, synced event. A failed write is
	// cut back to it, so a torn line can never prefix a later event.
	size int64
	// broken is set once the file's state can't be trusted (a failed sync,
	// or a torn write that couldn't be cut back). Every later append fails.
	broken error
}

// maxLine bounds a single stored event when reading the file back.
const maxLine = 1 << 20

func OpenJSONL(path string) (*JSONL, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	if err := checkPrivateFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit: %s: %w", path, err)
	}
	p := &jsonlPersister{path: path, f: f}
	last, err := p.recover()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &JSONL{sink: newSink(p, last)}, nil
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

// recover finds the last sequence number and terminates a partial last line
// left by a crash, so the next event starts on a fresh line.
func (p *jsonlPersister) recover() (uint64, error) {
	var last uint64
	err := p.scan(func(e Event) bool {
		if e.Seq > last {
			last = e.Seq
		}
		return true
	})
	if err != nil {
		return 0, err
	}
	fi, err := p.f.Stat()
	if err != nil {
		return 0, err
	}
	p.size = fi.Size()
	if fi.Size() > 0 {
		b := make([]byte, 1)
		if _, err := p.f.ReadAt(b, fi.Size()-1); err != nil {
			return 0, err
		}
		if b[0] != '\n' {
			if _, err := p.f.Write([]byte("\n")); err != nil {
				return 0, err
			}
			if err := p.f.Sync(); err != nil {
				return 0, err
			}
			p.size++
		}
	}
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

// scan reads the file from the start. Lines that don't parse (for example a
// line truncated by a crash) are skipped rather than failing the whole read.
func (p *jsonlPersister) scan(fn func(Event) bool) error {
	r := bufio.NewReaderSize(io.NewSectionReader(p.f, 0, 1<<62), 64*1024)
	for {
		line, err := readLine(r)
		if len(line) > 0 {
			var e Event
			if json.Unmarshal(line, &e) == nil && e.V != 0 {
				if !fn(e) {
					return nil
				}
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// readLine returns one line without its newline. Overlong lines are skipped.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	over := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !over && buf.Len()+len(chunk) <= maxLine+1 {
			buf.Write(chunk)
		} else {
			over = true
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if over {
			return nil, err
		}
		return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), err
	}
}

func (p *jsonlPersister) close() error { return p.f.Close() }
