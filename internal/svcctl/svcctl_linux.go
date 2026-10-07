package svcctl

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type handle interface {
	signal(syscall.Signal) error
	close()
}

// pidfdHandle pins the process: once open, the fd can never refer to a
// later process that reuses the pid.
type pidfdHandle struct{ fd int }

func (h pidfdHandle) signal(sig syscall.Signal) error {
	return unix.PidfdSendSignal(h.fd, sig, nil, 0)
}
func (h pidfdHandle) close() { unix.Close(h.fd) }

// pidHandle is the fallback for kernels without pidfd_open (before 5.3).
type pidHandle struct{ pid int }

func (h pidHandle) signal(sig syscall.Signal) error { return syscall.Kill(h.pid, sig) }
func (h pidHandle) close()                          {}

func pin(pid int) (handle, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	switch {
	case err == nil:
		return pidfdHandle{fd}, nil
	case errors.Is(err, unix.ESRCH):
		return nil, fmt.Errorf("%w (pid %d is gone; stale pid file)", ErrNotRunning, pid)
	case errors.Is(err, unix.ENOSYS):
		return pidHandle{pid}, nil
	default:
		return nil, err
	}
}

var procRoot = "/proc"

func inspect(pid int) (proc, error) {
	dir := procRoot + "/" + strconv.Itoa(pid)
	stat, err := os.ReadFile(dir + "/stat")
	if err != nil {
		return proc{}, err
	}
	// comm is in parentheses and may contain anything, so parse from the
	// last ')'. starttime is field 22, the 20th after comm.
	i := bytes.LastIndexByte(stat, ')')
	if i < 0 {
		return proc{}, errors.New("malformed stat")
	}
	fields := strings.Fields(string(stat[i+1:]))
	if len(fields) < 20 {
		return proc{}, errors.New("malformed stat")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return proc{}, err
	}
	status, err := os.ReadFile(dir + "/status")
	if err != nil {
		return proc{}, err
	}
	uid := -1
	for _, line := range strings.Split(string(status), "\n") {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "Uid:" {
			// Effective uid: the one signal permission checks against.
			uid, _ = strconv.Atoi(f[2])
		}
	}
	exe, err := os.Readlink(dir + "/exe")
	if errors.Is(err, fs.ErrPermission) {
		// A service hides its executable from other processes (it isn't
		// dumpable). Its name stays readable and has to do: the start time
		// already ties the pid file to this very process.
		exe, err = string(stat[bytes.IndexByte(stat, '(')+1:i]), nil
	}
	if err != nil {
		return proc{}, err
	}
	return proc{uid: uid, start: start, exe: strings.TrimSuffix(exe, " (deleted)")}, nil
}
