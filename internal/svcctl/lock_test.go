package svcctl

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Only one holder at a time, and the lock is free again once released.
func TestLockIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dev", "serve.lock")
	release, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(path); !errors.Is(err, ErrServed) {
		t.Fatalf("second lock: %v", err)
	}
	release()
	again, err := Lock(path)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	again()
}

func TestLockRefusesAFileItCantTrust(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "open.lock")
	os.WriteFile(open, nil, 0o644)
	if _, err := Lock(open); err == nil {
		t.Fatal("a lock file others can read accepted")
	}
	link := filepath.Join(dir, "link.lock")
	os.Symlink(filepath.Join(dir, "elsewhere"), link)
	if _, err := Lock(link); err == nil {
		t.Fatal("a symlinked lock file accepted")
	}
}
