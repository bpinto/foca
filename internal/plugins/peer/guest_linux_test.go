//go:build linux

package peer

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestHelperDialer is not a test: run with FOCA_TEST_DIAL set, it connects
// to that socket and waits, to be a caller in another process.
func TestHelperDialer(t *testing.T) {
	path := os.Getenv("FOCA_TEST_DIAL")
	if path == "" {
		t.Skip("helper process only")
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		os.Exit(1)
	}
	defer c.Close()
	time.Sleep(time.Minute)
}

func listen(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

// The relay's reading of a caller: what /proc shows every user, and the same
// process for as long as it is connected.
func TestIdentifyCallerReadsWhatEveryUserCanAndPins(t *testing.T) {
	l, path := listen(t)
	go func() {
		if c, err := net.Dial("unix", path); err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c, err := NewLinux().IdentifyCaller(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	comm, _ := os.ReadFile("/proc/self/comm")
	g := c.Guest()
	if g.PID != os.Getpid() || g.UID != os.Getuid() || g.Name != strings.TrimSpace(string(comm)) || g.Session == "" || g.StartTime == 0 {
		t.Fatalf("guest %+v", g)
	}
	// Only what every user can read: no exe, so nothing sealed.
	if len(g.Parents) == 0 || g.Parents[0].PID != os.Getppid() {
		t.Fatalf("parents %+v", g.Parents)
	}
	for _, p := range g.Parents {
		if p.Exe != "" || p.Sealed {
			t.Fatalf("parent with an exe: %+v", p)
		}
	}
	if strings.Contains(g.Source, "PIDFD") != g.PIDStable {
		t.Fatalf("source %s, pid_stable %v", g.Source, g.PIDStable)
	}
	if err := c.Check(); err != nil {
		t.Fatalf("check: %v", err)
	}
}

// A caller that exits after it was identified is refused from then on.
func TestCheckRefusesAnExitedCaller(t *testing.T) {
	l, path := listen(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperDialer$")
	cmd.Env = append(os.Environ(), "FOCA_TEST_DIAL="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c, err := NewLinux().IdentifyCaller(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Guest().PID != cmd.Process.Pid {
		t.Fatalf("identified %d, want %d", c.Guest().PID, cmd.Process.Pid)
	}
	if err := c.Check(); err != nil {
		t.Fatalf("live caller: %v", err)
	}
	cmd.Process.Kill()
	cmd.Wait()
	if err := c.Check(); err == nil || !strings.Contains(err.Error(), "exited") {
		t.Fatalf("exited caller: %v", err)
	}
}

// Without a pidfd, a pid that now names another process is told apart by
// its start time.
func TestCheckRefusesAReusedPID(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "7"), 0o700)
	stat := func(start string) {
		os.WriteFile(filepath.Join(root, "7", "stat"),
			[]byte("7 (gh) S 1 7 7 0 0 0 0 0 0 0 0 0 0 0 20 0 1 0 "+start+" 0 0\n"), 0o600)
	}
	stat("100")
	c := &Caller{pidfd: -1, t: procfsTable{root: root}}
	c.Info.PID, c.Info.StartTime = 7, 100
	if err := c.Check(); err != nil {
		t.Fatalf("same process: %v", err)
	}
	stat("200")
	if err := c.Check(); err == nil || !strings.Contains(err.Error(), "another process") {
		t.Fatalf("reused pid: %v", err)
	}
	os.Remove(filepath.Join(root, "7", "stat"))
	if err := c.Check(); err == nil {
		t.Fatal("gone process passed")
	}
}
