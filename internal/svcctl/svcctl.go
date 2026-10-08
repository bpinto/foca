// Package svcctl lets the host CLI find and signal a running service
// (design §6.2). The service records its pid in a 0600 file inside the 0700
// runtime dir. Before signalling, the CLI checks that the pid still belongs
// to the process that wrote the file, that it runs as the same uid, and that
// its executable is foca, so a stale file can't make it signal some other
// process that reused the pid.
package svcctl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/bpinto/foca/internal/fsutil"
)

// ErrNotRunning means there is no live service behind the pid file.
var ErrNotRunning = errors.New("service not running")

// record is one line in the pid file: "<pid> <start>\n". start is the
// kernel's start time for the process, so a reused pid doesn't match.
type record struct {
	pid   int
	start uint64
}

// proc is what the platform reports about a live process.
type proc struct {
	uid   int
	start uint64
	exe   string // full path where the OS gives one; else the command name
}

// WritePIDFile records the current process as the service. It refuses if
// another live service already owns the file. remove deletes the file only
// while it still names this process.
func WritePIDFile(path string) (remove func(), err error) {
	if err := fsutil.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if r, err := read(path); err == nil {
		if _, err := verify(r); err == nil && r.pid != os.Getpid() {
			return nil, fmt.Errorf("a service is already running (pid %d, %s)", r.pid, path)
		}
	}
	self, err := inspect(os.Getpid())
	if err != nil {
		return nil, err
	}
	me := record{pid: os.Getpid(), start: self.start}
	line := fmt.Sprintf("%d %d\n", me.pid, me.start)
	// The pid file only has to outlive this process, not a crash: one in
	// place but not yet durable will do.
	if err := fsutil.WriteFileAtomic(path, []byte(line), 0o600); err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
		return nil, err
	}
	return func() {
		if r, err := read(path); err == nil && r == me {
			os.Remove(path)
		}
	}, nil
}

// PID returns the pid of the verified service behind path, without
// signalling it.
func PID(path string) (int, error) {
	r, err := read(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("%w (no %s)", ErrNotRunning, path)
	}
	if err != nil {
		return 0, err
	}
	h, err := verify(r)
	if err != nil {
		return r.pid, err
	}
	h.close()
	return r.pid, nil
}

// Signal sends sig to the verified service and returns its pid.
func Signal(path string, sig syscall.Signal) (int, error) {
	r, err := read(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("%w (no %s)", ErrNotRunning, path)
	}
	if err != nil {
		return 0, err
	}
	h, err := verify(r)
	if err != nil {
		return r.pid, err
	}
	defer h.close()
	return r.pid, h.signal(sig)
}

// read parses the pid file after checking it is a private regular file
// owned by the current user.
func read(path string) (record, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return record{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return record{}, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || !ok || int(st.Uid) != os.Getuid() {
		return record{}, fmt.Errorf("%s is not a private file of the current user; not trusting it", path)
	}
	b := make([]byte, 64)
	n, _ := f.Read(b)
	fields := strings.Fields(string(b[:n]))
	if len(fields) != 2 {
		return record{}, fmt.Errorf("%s is malformed", path)
	}
	pid, err1 := strconv.Atoi(fields[0])
	start, err2 := strconv.ParseUint(fields[1], 10, 64)
	if err1 != nil || err2 != nil || pid <= 1 {
		return record{}, fmt.Errorf("%s is malformed", path)
	}
	return record{pid: pid, start: start}, nil
}

// verify pins the process where the platform allows it, then checks it is
// the one the file names, ours, and foca.
func verify(r record) (handle, error) {
	h, err := pin(r.pid)
	if err != nil {
		return nil, err
	}
	p, err := inspect(r.pid)
	if err != nil {
		h.close()
		return nil, fmt.Errorf("%w (pid %d is gone; stale pid file)", ErrNotRunning, r.pid)
	}
	switch {
	case r.start != 0 && p.start != r.start:
		h.close()
		return nil, fmt.Errorf("%w (pid %d now belongs to another process; stale pid file)", ErrNotRunning, r.pid)
	case p.uid != os.Getuid():
		h.close()
		return nil, fmt.Errorf("pid %d runs as uid %d, not %d; refusing to signal it", r.pid, p.uid, os.Getuid())
	case !isFoca(p.exe):
		h.close()
		return nil, fmt.Errorf("pid %d is %s, not foca; refusing to signal it", r.pid, p.exe)
	}
	return h, nil
}

// focaNames are the names a foca service runs under: the binary itself,
// and the Nix wrapper's renamed binary.
var focaNames = map[string]bool{"foca": true, ".foca-wrapped": true}

// isFoca accepts foca by name, or the very binary this process runs (which
// covers test binaries and renamed builds).
func isFoca(exe string) bool {
	if focaNames[filepath.Base(exe)] {
		return true
	}
	self, err := inspect(os.Getpid())
	return err == nil && self.exe == exe
}
