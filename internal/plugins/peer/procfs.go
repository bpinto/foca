// Package peer identifies the process on the other end of a Unix socket from
// kernel data. OS-specific files read the kernel; the rest is pure logic that
// tests drive with a fake process table.
package peer

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"

	"github.com/bpinto/foca/internal/identity"
)

// procStat is the subset of /proc/<pid>/stat we use.
type procStat struct {
	PID       int
	Comm      string
	PPID      int
	Session   int
	TTY       int // tty_nr; 0 means no controlling terminal
	StartTime uint64
}

// procTable reads process information. The Linux implementation reads /proc;
// tests use a map.
type procTable interface {
	stat(pid int) (procStat, error)
	exe(pid int) (string, error)
	// sealed reports whether pid's program file and every directory above
	// it, seen from the process's own root, are owned by root and not
	// writable by others, and on Linux that no other code it runs could
	// have been chosen by someone else (design §4.1.1). exe is the path
	// exe() returned.
	sealed(pid int, exe string) bool
}

// parseStat parses /proc/<pid>/stat. comm may contain spaces and parentheses,
// so fields are taken from after the last ')'.
func parseStat(b []byte) (procStat, error) {
	open := bytes.IndexByte(b, '(')
	close := bytes.LastIndexByte(b, ')')
	if open < 0 || close < open {
		return procStat{}, errors.New("malformed stat")
	}
	pid, err := strconv.Atoi(string(bytes.TrimSpace(b[:open])))
	if err != nil {
		return procStat{}, fmt.Errorf("malformed stat pid: %w", err)
	}
	f := bytes.Fields(b[close+1:])
	// f[0] is field 3 (state); starttime is field 22.
	if len(f) < 20 {
		return procStat{}, errors.New("short stat")
	}
	num := func(i int) (int64, error) { return strconv.ParseInt(string(f[i]), 10, 64) }
	ppid, err1 := num(1)
	sid, err2 := num(3)
	tty, err3 := num(4)
	start, err4 := strconv.ParseUint(string(f[19]), 10, 64)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return procStat{}, fmt.Errorf("malformed stat: %w", err)
	}
	return procStat{
		PID: pid, Comm: string(b[open+1 : close]), PPID: int(ppid),
		Session: int(sid), TTY: int(tty), StartTime: start,
	}, nil
}

const maxHops = 8

// durableSession returns a session key that stays the same across commands
// an agent harness spawns with setsid(), while distinct terminals stay
// distinct.
//
// Rule: starting from the peer's own session, climb to the nearest ancestor
// session that has a controlling terminal. Harness children have no terminal;
// the terminal session they were started from does. If no terminal session is
// found within maxHops, the peer's own session is used, so the fallback is
// always the narrowest choice, never a merged one.
//
// The key includes the session leader's start time so a recycled sid can't
// match an older session.
func durableSession(t procTable, pid int) (string, error) {
	st, err := t.stat(pid)
	if err != nil {
		return "", err
	}
	own, err := sessionKey(t, st)
	if err != nil {
		return "", err
	}
	sid := st.Session
	for i := 0; i < maxHops; i++ {
		leader, err := t.stat(sid)
		if err != nil {
			break // leader gone; can't climb further
		}
		if leader.TTY != 0 {
			return fmt.Sprintf("sid:%d:%d", sid, leader.StartTime), nil
		}
		if leader.PPID <= 1 {
			break
		}
		parent, err := t.stat(leader.PPID)
		if err != nil || parent.Session == sid || parent.Session <= 0 {
			break
		}
		sid = parent.Session
	}
	return own, nil
}

// sessionKey is the key for the peer's own session. Every key carries a
// start time, so it can never match a later session or process that reused
// the number.
func sessionKey(t procTable, peer procStat) (string, error) {
	sid := peer.Session
	if sid <= 0 {
		return "", fmt.Errorf("invalid session %d", sid)
	}
	leader, err := t.stat(sid)
	if err != nil {
		// The leader has exited, and a bare sid could be reused later.
		// Fall back to the peer itself: narrower still, and unique.
		return fmt.Sprintf("pid:%d:%d", peer.PID, peer.StartTime), nil
	}
	return fmt.Sprintf("sid:%d:%d", sid, leader.StartTime), nil
}

// parents returns up to maxHops ancestors, nearest first.
func parents(t procTable, st procStat) []identity.Proc {
	var out []identity.Proc
	ppid := st.PPID
	for i := 0; i < maxHops && ppid > 0; i++ {
		p, err := t.stat(ppid)
		if err != nil {
			break
		}
		exe, _ := t.exe(ppid) // unreadable for other users' processes; fine
		out = append(out, identity.Proc{PID: p.PID, StartTime: p.StartTime, Exe: exe, Name: p.Comm,
			Sealed: exe != "" && t.sealed(ppid, exe)})
		if p.PPID == ppid {
			break
		}
		ppid = p.PPID
	}
	return out
}
