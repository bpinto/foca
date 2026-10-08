//go:build linux

package peer

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"

	"github.com/bpinto/foca/internal/identity"
)

// Caller is a process the guest relay serves, as the realm's own kernel
// reports it (design §14).
type Caller struct {
	Info  identity.GuestInfo
	pidfd int
	t     procfsTable
}

// IdentifyCaller reads the process on the other end of conn for the guest
// relay. It keeps the pidfd, so Check can confirm before every request that
// the caller is still the same process. The caller must Close it.
//
// Only what /proc shows every user is kept: pids, start times, comm and
// sessions. The relay runs as its own user, and another user's exe is
// readable only with CAP_SYS_PTRACE, which the relay isn't given: that
// would let whoever takes over its user read any process in the realm.
func (l *Linux) IdentifyCaller(conn *net.UnixConn) (*Caller, error) {
	p, pidfd, err := l.identify(conn)
	if err != nil {
		if pidfd >= 0 {
			unix.Close(pidfd)
		}
		return nil, err
	}
	c := &Caller{pidfd: pidfd, t: procfsTable{root: l.procfs}}
	c.Info = identity.GuestInfo{
		Source: p.Source, PID: p.PID, StartTime: p.StartTime, UID: p.UID, GID: p.GID,
		PIDStable: p.PIDStable, Name: p.Name, Session: p.Session,
	}
	for _, pp := range p.Parents {
		c.Info.Parents = append(c.Info.Parents, identity.Proc{PID: pp.PID, StartTime: pp.StartTime, Name: pp.Name})
	}
	return c, nil
}

// Check reports an error if the caller has exited, or its pid now belongs
// to another process. With a pidfd the kernel says so; without one, a
// changed start time gives a reused pid away.
func (c *Caller) Check() error {
	if c.pidfd >= 0 && exited(c.pidfd) {
		return fmt.Errorf("caller %d has exited", c.Info.PID)
	}
	st, err := c.t.stat(c.Info.PID)
	if err != nil {
		return fmt.Errorf("caller %d has exited", c.Info.PID)
	}
	if st.StartTime != c.Info.StartTime {
		return fmt.Errorf("caller %d is gone; its pid now names another process", c.Info.PID)
	}
	return nil
}

func (c *Caller) Close() {
	if c.pidfd >= 0 {
		unix.Close(c.pidfd)
		c.pidfd = -1
	}
}

// Guest is the caller as read when it connected.
func (c *Caller) Guest() identity.GuestInfo { return c.Info }
