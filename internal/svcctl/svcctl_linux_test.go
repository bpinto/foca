package svcctl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A process running as another uid is refused. The uid comes from a fake
// /proc entry over a real, pinnable process.
func TestSignalRefusesOtherUID(t *testing.T) {
	sleep := startSleep(t)
	pid := sleep.Process.Pid
	fake := t.TempDir()
	pdir := filepath.Join(fake, fmt.Sprint(pid))
	os.Mkdir(pdir, 0o755)
	os.WriteFile(filepath.Join(pdir, "stat"), []byte(fmt.Sprintf("%d (foca) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 0", pid)), 0o644)
	os.WriteFile(filepath.Join(pdir, "status"), []byte("Name:\tfoca\nUid:\t0\t0\t0\t0\n"), 0o644)
	os.Symlink("/run/current-system/sw/bin/foca", filepath.Join(pdir, "exe"))
	old := procRoot
	procRoot = fake
	defer func() { procRoot = old }()

	pidfile := filepath.Join(runtimeDir(t), "serve.pid")
	os.WriteFile(pidfile, []byte(fmt.Sprintf("%d 777\n", pid)), 0o600)
	if _, err := Signal(pidfile, syscall.SIGTERM); err == nil || !strings.Contains(err.Error(), "runs as uid 0") {
		t.Fatalf("other uid: %v", err)
	}
	if err := sleep.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("process was signalled")
	}
}
