//go:build darwin

package darwinproc

import (
	"bytes"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// PeerToken reads the audit token of the process at the other end of a
// Unix socket. x/sys has no wrapper that returns all 32 bytes (its string
// getter stops at the first NUL), so it calls getsockopt directly.
func PeerToken(fd int) (AuditToken, error) {
	var buf [32]byte
	n := uint32(len(buf))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_LOCAL, unix.LOCAL_PEERTOKEN,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&n)), 0)
	if errno != 0 {
		return AuditToken{}, fmt.Errorf("LOCAL_PEERTOKEN: %w", errno)
	}
	return ParseAuditToken(buf[:n])
}

const (
	procInfoCallPIDInfo       = 2  // PROC_INFO_CALL_PIDINFO
	procPIDUniqIdentifierInfo = 17 // PROC_PIDUNIQIDENTIFIERINFO
	procPIDPathInfo           = 11 // PROC_PIDPATHINFO
)

// ErrNoProcess means the pid doesn't exist (any more).
var ErrNoProcess = errors.New("no such process")

// PIDVersion returns the current pid version of pid, through
// proc_info(PROC_PIDUNIQIDENTIFIERINFO). Comparing it with an audit token's
// version shows whether pid is still the same process image.
func PIDVersion(pid int) (int32, error) {
	var buf [uniqIdentifierInfoSize]byte
	r, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, procInfoCallPIDInfo, uintptr(pid), procPIDUniqIdentifierInfo, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	switch {
	case errno == unix.ESRCH:
		return 0, ErrNoProcess
	case errno != 0:
		return 0, fmt.Errorf("proc_info(%d): %w", pid, errno)
	case int(r) < len(buf):
		return 0, fmt.Errorf("proc_info(%d): short answer", pid)
	}
	return ParseIDVersion(buf[:])
}

// ExePath returns the path of the file pid runs, which the kernel finds from
// the process's executable vnode (proc_pidpath). The exec path in
// kern.procargs2 can't serve: it sits in the process's own memory, which the
// process can rewrite at any time without its pid version changing.
func ExePath(pid int) (string, error) {
	var buf [pathInfoMaxSize]byte
	_, _, errno := unix.Syscall6(unix.SYS_PROC_INFO, procInfoCallPIDInfo, uintptr(pid), procPIDPathInfo, 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	switch {
	case errno == unix.ESRCH:
		return "", ErrNoProcess
	case errno != 0:
		return "", fmt.Errorf("proc_info(%d) path: %w", pid, errno)
	}
	return ParsePathInfo(buf[:])
}

// Proc is what kinfo_proc and getsid report about a process.
type Proc struct {
	PID    int
	PPID   int
	UID    int
	Comm   string
	SID    int
	HasTTY bool
	// StartTime is microseconds since the epoch.
	StartTime uint64
}

// nodev is NODEV, e_tdev for a process with no controlling terminal.
const nodev = -1

// Info reads pid's kinfo_proc and session id.
func Info(pid int) (Proc, error) {
	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return Proc{}, err
	}
	if int(kp.Proc.P_pid) != pid {
		return Proc{}, ErrNoProcess
	}
	sid, err := unix.Getsid(pid)
	if err != nil {
		return Proc{}, fmt.Errorf("getsid(%d): %w", pid, err)
	}
	comm := kp.Proc.P_comm[:]
	if i := bytes.IndexByte(comm, 0); i >= 0 {
		comm = comm[:i]
	}
	tv := kp.Proc.P_starttime
	return Proc{
		PID:       pid,
		PPID:      int(kp.Eproc.Ppid),
		UID:       int(kp.Eproc.Ucred.Uid),
		Comm:      string(comm),
		SID:       sid,
		HasTTY:    kp.Eproc.Tdev != nodev,
		StartTime: uint64(tv.Sec)*1_000_000 + uint64(tv.Usec),
	}, nil
}
