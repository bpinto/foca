package svcctl

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestHelperService is not a test: run as a child with SVCCTL_HELPER set, it
// acts as the service. It writes the pid file and exits 0 on SIGHUP.
func TestHelperService(t *testing.T) {
	path := os.Getenv("SVCCTL_HELPER")
	if path == "" {
		t.Skip("helper process only")
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	remove, err := WritePIDFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	defer remove()
	select {
	case <-hup:
		remove()
		os.Exit(0)
	case <-time.After(10 * time.Second):
		os.Exit(4)
	}
}

func startHelper(t *testing.T, pidfile string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperService$")
	cmd.Env = append(os.Environ(), "SVCCTL_HELPER="+pidfile)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if r, err := read(pidfile); err == nil && r.pid == cmd.Process.Pid {
			return cmd
		}
		if time.Now().After(deadline) {
			t.Fatal("helper never wrote its pid file")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func startSleep(t *testing.T) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("no sleep: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	return cmd
}

func runtimeDir(t *testing.T) string {
	dir := filepath.Join(t.TempDir(), "run")
	os.Mkdir(dir, 0o700)
	return dir
}

func TestSignalReachesVerifiedService(t *testing.T) {
	pidfile := filepath.Join(runtimeDir(t), "serve.pid")
	cmd := startHelper(t, pidfile)
	fi, _ := os.Stat(pidfile)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("pid file mode %o", fi.Mode().Perm())
	}
	if pid, err := PID(pidfile); err != nil || pid != cmd.Process.Pid {
		t.Fatalf("pid: %d %v", pid, err)
	}
	// A second service can't take over the file while the first is alive.
	if _, err := WritePIDFile(pidfile); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second service: %v", err)
	}
	pid, err := Signal(pidfile, syscall.SIGHUP)
	if err != nil || pid != cmd.Process.Pid {
		t.Fatalf("signal: %d %v", pid, err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v", err)
	}
	if _, err := os.Stat(pidfile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("pid file left behind")
	}
	if _, err := Signal(pidfile, syscall.SIGHUP); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("after exit: %v", err)
	}
	if _, err := PID(pidfile); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("pid after exit: %v", err)
	}
}

// Every way a pid file can point at the wrong process is refused, and the
// process is left alone.
func TestSignalRefusesUnverifiedProcesses(t *testing.T) {
	dir := runtimeDir(t)
	pidfile := filepath.Join(dir, "serve.pid")
	write := func(content string, mode os.FileMode) {
		os.Remove(pidfile)
		if err := os.WriteFile(pidfile, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}

	// A process that exited: its pid is free (or reused).
	gone := exec.Command("true")
	gone.Run()
	write(fmt.Sprintf("%d 1\n", gone.Process.Pid), 0o600)
	if _, err := Signal(pidfile, syscall.SIGHUP); !errors.Is(err, ErrNotRunning) {
		t.Fatalf("exited pid: %v", err)
	}

	// A live process that isn't foca.
	sleep := startSleep(t)
	p, _ := inspect(sleep.Process.Pid)
	write(fmt.Sprintf("%d %d\n", sleep.Process.Pid, p.start), 0o600)
	if _, err := Signal(pidfile, syscall.SIGHUP); err == nil || !strings.Contains(err.Error(), "not foca") {
		t.Fatalf("other exe: %v", err)
	}

	// The right exe, but a different start time: the pid was reused.
	helperFile := filepath.Join(dir, "helper.pid")
	helper := startHelper(t, helperFile)
	hp, _ := inspect(helper.Process.Pid)
	write(fmt.Sprintf("%d %d\n", helper.Process.Pid, hp.start+1), 0o600)
	if _, err := Signal(pidfile, syscall.SIGHUP); !errors.Is(err, ErrNotRunning) || !strings.Contains(err.Error(), "another process") {
		t.Fatalf("reused pid: %v", err)
	}

	// A pid file others could have written is not trusted.
	write(fmt.Sprintf("%d %d\n", helper.Process.Pid, hp.start), 0o644)
	if _, err := Signal(pidfile, syscall.SIGHUP); err == nil || !strings.Contains(err.Error(), "not a private file") {
		t.Fatalf("group-readable pid file: %v", err)
	}
	for _, bad := range []string{"", "1 0\n", "abc 1\n", "12\n"} {
		write(bad, 0o600)
		if _, err := Signal(pidfile, syscall.SIGHUP); err == nil {
			t.Fatalf("malformed %q accepted", bad)
		}
	}

	// The helper got none of these signals.
	if helper.ProcessState != nil {
		t.Fatal("helper exited")
	}
	if err := helper.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("helper died: %v", err)
	}
}

func TestRemoveLeavesAnotherServicesFile(t *testing.T) {
	pidfile := filepath.Join(runtimeDir(t), "serve.pid")
	remove, err := WritePIDFile(pidfile)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(pidfile, []byte("99999 1\n"), 0o600) // another service took over
	remove()
	if _, err := os.Stat(pidfile); err != nil {
		t.Fatal("removed a pid file naming another process")
	}
}
