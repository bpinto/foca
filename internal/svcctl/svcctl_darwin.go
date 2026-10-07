package svcctl

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/bpinto/foca/internal/darwinproc"
)

type handle interface {
	signal(syscall.Signal) error
	close()
}

// versionHandle pins the process by its pid version, which the kernel
// changes when the pid is reused or the process execs. macOS has no pidfd,
// so a narrow window between the last check and kill(2) remains.
type versionHandle struct {
	pid     int
	version int32
}

func (h versionHandle) signal(sig syscall.Signal) error {
	v, err := darwinproc.PIDVersion(h.pid)
	if err != nil || v != h.version {
		return fmt.Errorf("%w (pid %d changed before it could be signalled)", ErrNotRunning, h.pid)
	}
	return syscall.Kill(h.pid, sig)
}
func (h versionHandle) close() {}

func pin(pid int) (handle, error) {
	v, err := darwinproc.PIDVersion(pid)
	if errors.Is(err, darwinproc.ErrNoProcess) {
		return nil, fmt.Errorf("%w (pid %d is gone; stale pid file)", ErrNotRunning, pid)
	}
	if err != nil {
		return nil, err
	}
	return versionHandle{pid: pid, version: v}, nil
}

// inspect reads the process from the kernel. The executable is the path the
// kernel finds for the file it runs; if that can't be read, the command name
// stands in.
func inspect(pid int) (proc, error) {
	p, err := darwinproc.Info(pid)
	if err != nil {
		return proc{}, err
	}
	exe, err := darwinproc.ExePath(pid)
	if err != nil {
		exe = p.Comm
	}
	return proc{uid: p.UID, start: p.StartTime, exe: exe}, nil
}
