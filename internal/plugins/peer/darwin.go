//go:build darwin

package peer

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/bpinto/foca/internal/darwinproc"
	"github.com/bpinto/foca/internal/identity"
)

// Darwin identifies peers with LOCAL_PEERCRED (uid, gid) and LOCAL_PEERTOKEN
// (design §4.6). The audit token carries the pid and its version, which the
// kernel changes when the pid is reused or the process execs. After reading
// everything else, the identifier checks that the pid still has that
// version, so all of it describes one process image. That is the macOS
// counterpart of Linux's pidfd, with the same limit: the token describes
// the peer as it is when read, not as it was when it connected, so a peer
// that exec'd before identification is named after its new program
// (design §12.4, "Exec after connect").
type Darwin struct{}

func NewDarwin() *Darwin { return &Darwin{} }

func (d *Darwin) Identify(conn *net.UnixConn) (identity.VerifiedPeer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return identity.VerifiedPeer{}, err
	}
	var cred *unix.Xucred
	var credErr, tokErr error
	var tok darwinproc.AuditToken
	pid := 0
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if tok, tokErr = darwinproc.PeerToken(int(fd)); tokErr == nil {
			pid = tok.PID()
		} else if p, err := unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID); err == nil {
			pid = p
		}
	}); err != nil {
		return identity.VerifiedPeer{}, err
	}
	if credErr != nil {
		return identity.VerifiedPeer{}, fmt.Errorf("LOCAL_PEERCRED: %w", credErr)
	}
	if cred.Version != xucredVersion || cred.Ngroups < 1 {
		return identity.VerifiedPeer{}, errors.New("LOCAL_PEERCRED: unexpected xucred")
	}
	if pid <= 0 {
		return identity.VerifiedPeer{}, errors.New("peer has no pid")
	}

	t := darwinTable{}
	st, err := t.stat(pid)
	if err != nil {
		return identity.VerifiedPeer{}, fmt.Errorf("peer %d: %w", pid, err)
	}
	exe, _ := t.exe(pid)
	session, err := durableSession(t, pid)
	if err != nil {
		return identity.VerifiedPeer{}, fmt.Errorf("peer %d session: %w", pid, err)
	}
	p := identity.VerifiedPeer{
		Source:    "LOCAL_PEERCRED+LOCAL_PEERPID",
		UID:       int(cred.Uid),
		GID:       int(cred.Groups[0]),
		PID:       pid,
		StartTime: st.StartTime,
		Exe:       exe,
		ExeSealed: exe != "" && t.sealed(pid, exe),
		Name:      st.Comm,
		Session:   session,
		Parents:   parents(t, st),
	}

	// Make sure everything we read belongs to the process that connected.
	if tokErr == nil {
		v, err := darwinproc.PIDVersion(pid)
		switch {
		case errors.Is(err, darwinproc.ErrNoProcess):
			return identity.VerifiedPeer{}, fmt.Errorf("peer %d exited during identification", pid)
		case err == nil && v != tok.PIDVersion():
			return identity.VerifiedPeer{}, fmt.Errorf("peer %d changed during identification", pid)
		case err == nil:
			p.Source = "LOCAL_PEERCRED+LOCAL_PEERTOKEN"
			p.PIDStable = true
			return p, nil
		}
		// The version can't be read: handled like a pid without one.
	}
	if again, err := t.stat(pid); err != nil || again.StartTime != st.StartTime {
		return identity.VerifiedPeer{}, fmt.Errorf("peer %d changed during identification", pid)
	}
	// Without a confirmed version the pid could have been reused before
	// the first read. PIDStable stays false, so nothing downstream states
	// these names as fact.
	return p, nil
}

// xucredVersion is XUCRED_VERSION from <sys/ucred.h>.
const xucredVersion = 0

// darwinTable reads processes through sysctl and getsid.
type darwinTable struct{}

func (darwinTable) stat(pid int) (procStat, error) {
	p, err := darwinproc.Info(pid)
	if err != nil {
		return procStat{}, err
	}
	tty := 0
	if p.HasTTY {
		tty = 1
	}
	return procStat{PID: p.PID, Comm: p.Comm, PPID: p.PPID, Session: p.SID, TTY: tty, StartTime: p.StartTime}, nil
}

// exe is the file the process runs, by the path the kernel finds for it,
// with any symlinks resolved.
func (darwinTable) exe(pid int) (string, error) {
	path, err := darwinproc.ExePath(pid)
	if err != nil {
		return "", err
	}
	resolved, _, err := sealedPath(osPathFS{}, path)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

// sealed walks the path again, through every symlink, and checks it still
// leads to exe.
func (darwinTable) sealed(pid int, exe string) bool {
	path, err := darwinproc.ExePath(pid)
	if err != nil {
		return false
	}
	resolved, sealed, err := sealedPath(osPathFS{}, path)
	return err == nil && sealed && resolved == exe
}

type osPathFS struct{}

func (osPathFS) Lstat(path string) (fs.FileMode, uint32, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New(filepath.Clean(path) + ": no owner")
	}
	return fi.Mode(), st.Uid, nil
}

func (osPathFS) Readlink(path string) (string, error) { return os.Readlink(path) }
