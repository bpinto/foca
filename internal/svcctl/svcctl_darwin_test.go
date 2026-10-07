package svcctl

import (
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/darwinproc"
)

// macOS has no pidfd: pin holds the pid version, which changes when the
// process exits or execs, and signal re-checks it just before kill.
func TestPinRefusesAChangedProcess(t *testing.T) {
	// Pinned while it is sh, then it execs sleep: same pid, new image.
	sh := exec.Command("/bin/sh", "-c", "read x; exec /bin/sleep 30")
	stdin, _ := sh.StdinPipe()
	if err := sh.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sh.Process.Kill(); sh.Wait() })
	h, err := pin(sh.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	stdin.Write([]byte("go\n"))
	// The kernel reports the new path partway through an exec but bumps the
	// pid version only at its end, so wait for both.
	pinned := h.(versionHandle).version
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		p, _ := darwinproc.ExePath(sh.Process.Pid)
		v, verr := darwinproc.PIDVersion(sh.Process.Pid)
		if p == "/bin/sleep" && verr == nil && v != pinned {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sh never finished exec'ing sleep: path %q, pid version %d (%v), pinned %d", p, v, verr, pinned)
		}
	}
	if err := h.signal(syscall.SIGTERM); !errors.Is(err, ErrNotRunning) || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("signalled a process that exec'd after it was pinned: %v", err)
	}
	if err := sh.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("the process was signalled")
	}

	// Pinned, then it exits.
	gone := exec.Command("/bin/sleep", "30")
	if err := gone.Start(); err != nil {
		t.Fatal(err)
	}
	h, err = pin(gone.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	gone.Process.Kill()
	gone.Wait()
	if err := h.signal(syscall.SIGTERM); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("signalled an exited process: %v", err)
	}
}

// inspect names the service by its executable's path, not the
// 16-byte command name.
func TestInspectReportsTheExePath(t *testing.T) {
	sleep := exec.Command("/bin/sleep", "30")
	if err := sleep.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sleep.Process.Kill(); sleep.Wait() })
	p, err := inspect(sleep.Process.Pid)
	if err != nil || p.exe != "/bin/sleep" || p.start == 0 {
		t.Fatalf("got %+v %v", p, err)
	}
}
