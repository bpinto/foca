package svcctl

import (
	"bytes"
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

type handle interface {
	signal(syscall.Signal) error
	close()
}

// macOS has no pidfd. The start-time check in verify still catches a pid
// that was reused before we looked; the window between that check and kill
// is accepted for now.
type pidHandle struct{ pid int }

func (h pidHandle) signal(sig syscall.Signal) error { return syscall.Kill(h.pid, sig) }
func (h pidHandle) close()                          {}

func pin(pid int) (handle, error) { return pidHandle{pid}, nil }

// inspect reads the process from the kernel. macOS gives the command name
// (truncated to 16 bytes) rather than the executable path without cgo.
func inspect(pid int) (proc, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return proc{}, err
	}
	if int(kp.Proc.P_pid) != pid {
		return proc{}, fmt.Errorf("pid %d not found", pid)
	}
	comm := kp.Proc.P_comm[:]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	tv := kp.Proc.P_starttime
	return proc{
		uid:   int(kp.Eproc.Ucred.Uid),
		start: uint64(tv.Sec)*1_000_000 + uint64(tv.Usec),
		exe:   string(comm),
	}, nil
}
