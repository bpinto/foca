package peer

import (
	"errors"
	"testing"
)

type fakeTable map[int]procStat

func (f fakeTable) stat(pid int) (procStat, error) {
	st, ok := f[pid]
	if !ok {
		return procStat{}, errors.New("no such process")
	}
	return st, nil
}

func (f fakeTable) exe(pid int) (string, error) {
	if _, ok := f[pid]; !ok {
		return "", errors.New("no such process")
	}
	return "/bin/" + f[pid].Comm, nil
}

// Everything in the fake table lives in /bin, so it is all sealed.
func (f fakeTable) sealed(pid int, exe string) bool { return true }

func TestParseStatHandlesHostileComm(t *testing.T) {
	line := []byte("4711 (evil) (name x) S 4700 4711 4690 34817 4711 4194304 1 0 0 0 0 0 0 0 20 0 1 0 987654 1000 100 18446744073709551615\n")
	st, err := parseStat(line)
	if err != nil {
		t.Fatal(err)
	}
	if st.PID != 4711 || st.Comm != "evil) (name x" || st.PPID != 4700 || st.Session != 4690 ||
		st.TTY != 34817 || st.StartTime != 987654 {
		t.Fatalf("parsed %+v", st)
	}
	if _, err := parseStat([]byte("garbage")); err == nil {
		t.Fatal("garbage parsed")
	}
}

// A terminal session (zsh, sid 100, has a tty) runs an agent (claude) that
// spawns each command in its own setsid() session without a tty.
func agentTable() fakeTable {
	return fakeTable{
		1:   {PID: 1, Comm: "systemd", PPID: 0, Session: 1, StartTime: 1},
		50:  {PID: 50, Comm: "sshd", PPID: 1, Session: 50, StartTime: 5},
		90:  {PID: 90, Comm: "sshd", PPID: 50, Session: 90, StartTime: 9},
		100: {PID: 100, Comm: "zsh", PPID: 90, Session: 100, TTY: 34816, StartTime: 10},
		110: {PID: 110, Comm: "claude", PPID: 100, Session: 100, TTY: 34816, StartTime: 11},
		200: {PID: 200, Comm: "bash", PPID: 110, Session: 200, StartTime: 20},
		210: {PID: 210, Comm: "foca", PPID: 200, Session: 200, StartTime: 21},
		300: {PID: 300, Comm: "bash", PPID: 110, Session: 300, StartTime: 30},
		310: {PID: 310, Comm: "foca", PPID: 300, Session: 300, StartTime: 31},
		// A second terminal.
		400: {PID: 400, Comm: "zsh", PPID: 90, Session: 400, TTY: 34817, StartTime: 40},
		410: {PID: 410, Comm: "foca", PPID: 400, Session: 400, TTY: 34817, StartTime: 41},
	}
}

func TestDurableSessionCollapsesHarnessChildrenButNotTerminals(t *testing.T) {
	tab := agentTable()
	a, _ := durableSession(tab, 210)
	b, _ := durableSession(tab, 310)
	c, _ := durableSession(tab, 410)
	if a != "sid:100:10" || b != a {
		t.Fatalf("harness children: %q %q, want both sid:100:10", a, b)
	}
	if c != "sid:400:40" {
		t.Fatalf("second terminal: %q", c)
	}
}

func TestDurableSessionFallsBackToOwnSessionNotAWiderOne(t *testing.T) {
	// No session in the chain has a tty (e.g. a daemon); climbing must not
	// merge everything into sshd's session.
	tab := fakeTable{
		1:  {PID: 1, Comm: "systemd", Session: 1, StartTime: 1},
		50: {PID: 50, Comm: "sshd", PPID: 1, Session: 50, StartTime: 5},
		60: {PID: 60, Comm: "worker", PPID: 50, Session: 60, StartTime: 6},
		61: {PID: 61, Comm: "foca", PPID: 60, Session: 60, StartTime: 7},
	}
	got, err := durableSession(tab, 61)
	if err != nil || got != "sid:60:6" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestDurableSessionWithExitedLeader(t *testing.T) {
	tab := fakeTable{
		70: {PID: 70, Comm: "foca", PPID: 1, Session: 69, StartTime: 7},
	}
	got, err := durableSession(tab, 70)
	// No bare "sid:69": that could match a later session reusing 69.
	if err != nil || got != "pid:70:7" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestParentsNearestFirstAndBounded(t *testing.T) {
	tab := agentTable()
	ps := parents(tab, tab[210])
	names := []string{}
	for _, p := range ps {
		names = append(names, p.Name)
	}
	want := []string{"bash", "claude", "zsh", "sshd", "sshd", "systemd"}
	if len(names) != len(want) {
		t.Fatalf("parents %v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("parents %v, want %v", names, want)
		}
	}
	if ps[1].Exe != "/bin/claude" || ps[1].StartTime != 11 {
		t.Fatalf("parent detail %+v", ps[1])
	}
}
