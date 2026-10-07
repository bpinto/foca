//go:build darwin

package peer

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/bpinto/foca/internal/darwinproc"
)

// These run on a Mac only. They connect to a socket and check the kernel
// reports the process that connected.

func listen(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	// $TMPDIR on macOS is long; keep the socket path under sun_path.
	dir, err := os.MkdirTemp("/tmp", "fpeer")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func TestDarwinIdentifiesRealPeer(t *testing.T) {
	l, path := listen(t)
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	p, err := NewDarwin().Identify(conn)
	if err != nil {
		t.Fatal(err)
	}
	if p.Source != "LOCAL_PEERCRED+LOCAL_PEERTOKEN" || !p.PIDStable {
		t.Fatalf("source %s pid_stable=%v: the audit token should pin the peer", p.Source, p.PIDStable)
	}
	if p.PID != os.Getpid() || p.UID != os.Getuid() || p.GID != os.Getgid() {
		t.Fatalf("got pid=%d uid=%d gid=%d", p.PID, p.UID, p.GID)
	}
	exe, _ := os.Executable()
	if want, _ := filepath.EvalSymlinks(exe); p.Exe != want {
		t.Fatalf("exe %q, want %q", p.Exe, want)
	}
	if p.ExeSealed {
		t.Fatalf("test binary %s reported sealed", p.Exe)
	}
	if p.Session == "" || p.StartTime == 0 || p.Name == "" {
		t.Fatalf("incomplete peer %+v", p)
	}
}

// A system binary is sealed, and is named after the file it runs.
func TestDarwinSealedSystemPeer(t *testing.T) {
	l, path := listen(t)
	cmd := exec.Command("/usr/bin/nc", "-U", path)
	cmd.Stdin = nil
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	l.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	p, err := NewDarwin().Identify(conn)
	if err != nil {
		t.Fatal(err)
	}
	if p.Exe != "/usr/bin/nc" || !p.ExeSealed || !p.PIDStable || p.PID != cmd.Process.Pid {
		t.Fatalf("got %+v", p)
	}
}

// After the peer exits, its pid no longer has the token's version.
func TestDarwinExitedPeerRefused(t *testing.T) {
	l, path := listen(t)
	cmd := exec.Command("/usr/bin/nc", "-U", path)
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	l.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cmd.Process.Kill()
	cmd.Wait()
	if p, err := NewDarwin().Identify(conn); err == nil {
		t.Fatalf("identified a peer that had exited: %+v", p)
	}
}

// TestHelperPeerExec is not a test: run as a child with PEER_EXEC_SOCKET set,
// it connects, keeps the socket open across exec, says so, and becomes
// /bin/sleep.
func TestHelperPeerExec(t *testing.T) {
	path := os.Getenv("PEER_EXEC_SOCKET")
	if path == "" {
		t.Skip("helper process only")
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		os.Exit(3)
	}
	f, err := c.(*net.UnixConn).File()
	if err != nil {
		os.Exit(4)
	}
	if _, err := unix.FcntlInt(f.Fd(), unix.F_SETFD, 0); err != nil { // survive exec
		os.Exit(5)
	}
	c.Write([]byte{1})
	syscall.Exec("/bin/sleep", []string{"sleep", "30"}, os.Environ())
	os.Exit(6)
}

// A peer that execs after connecting but before it is identified is named
// after its new program. The kernel gives it a new pid version, but the audit
// token is read live and carries that version too, as a Linux pidfd follows
// a process across exec (design §12.4, "Exec after connect"). This pins the
// behaviour, so a change in either direction is noticed.
func TestDarwinPeerThatExecsIsNamedAfterItsNewProgram(t *testing.T) {
	l, path := listen(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperPeerExec$")
	cmd.Env = append(os.Environ(), "PEER_EXEC_SOCKET="+path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	l.SetDeadline(time.Now().Add(5 * time.Second))
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != nil {
		t.Fatalf("child never connected: %v", err)
	}
	// The token was fixed when the child connected. The kernel reports the
	// new path partway through an exec but bumps the pid version only at its
	// end, so wait for both: Identify must meet a finished exec.
	var tok darwinproc.AuditToken
	raw, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var tokErr error
	raw.Control(func(fd uintptr) { tok, tokErr = darwinproc.PeerToken(int(fd)) })
	if tokErr != nil {
		t.Fatal(tokErr)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		p, _ := darwinproc.ExePath(cmd.Process.Pid)
		v, verr := darwinproc.PIDVersion(cmd.Process.Pid)
		if p == "/bin/sleep" && verr == nil && v != tok.PIDVersion() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child never finished exec'ing /bin/sleep: path %q, pid version %d (%v), token version %d", p, v, verr, tok.PIDVersion())
		}
	}
	p, err := NewDarwin().Identify(conn)
	if err != nil {
		t.Fatalf("a peer that exec'd before identification: %v", err)
	}
	if p.Exe != "/bin/sleep" || !p.PIDStable || p.Source != "LOCAL_PEERCRED+LOCAL_PEERTOKEN" {
		t.Fatalf("got exe %q, pid_stable %v, source %s; want /bin/sleep through the token", p.Exe, p.PIDStable, p.Source)
	}
}
