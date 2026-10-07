package fsutil

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A crash between any two steps leaves the old file intact, or the new one
// complete, and never a stray temp file next to it.
func TestWriteFileAtomicNeverLeavesAPartialFile(t *testing.T) {
	for _, crash := range []string{"write", "sync", "rename", "syncdir"} {
		t.Run(crash, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "v.fcv")
			if err := WriteFileAtomic(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			failAt = func(s string) error {
				if s == crash {
					return errors.New("crash")
				}
				return nil
			}
			defer func() { failAt = nil }()
			err := WriteFileAtomic(path, []byte("new"), 0o600)
			if err == nil {
				t.Fatal("expected the injected failure")
			}
			// Only a failure after the rename says so, and callers rely on
			// it to leave the new file be.
			if got := errors.Is(err, ErrNotDurable); got != (crash == "syncdir") {
				t.Fatalf("after crash at %s: ErrNotDurable is %v", crash, got)
			}
			got, _ := os.ReadFile(path)
			want := "old"
			if crash == "syncdir" {
				want = "new" // renamed already; only durability is in doubt
			}
			if string(got) != want {
				t.Fatalf("after crash at %s: file is %q, want %q", crash, got, want)
			}
			entries, _ := os.ReadDir(dir)
			if len(entries) != 1 {
				t.Fatalf("leftover files after crash at %s: %v", crash, entries)
			}
			fi, _ := os.Stat(path)
			if fi.Mode().Perm() != 0o600 {
				t.Fatalf("mode %o", fi.Mode().Perm())
			}
		})
	}
}

func TestWriteFileAtomicReplacesSymlinkInsteadOfFollowingIt(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	os.WriteFile(target, []byte("keep"), 0o600)
	path := filepath.Join(dir, "v.fcv")
	os.Symlink(target, path)
	if err := WriteFileAtomic(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatalf("symlink target was written: %q", b)
	}
	if fi, _ := os.Lstat(path); fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("path is still a symlink")
	}
}

func TestLockIsExclusive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.lock")
	unlock, err := Lock(path)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		u, err := Lock(path) // a separate open file description, like another process
		if err == nil {
			u()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("second lock acquired while the first was held")
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(2 * time.Second):
		t.Fatal("second lock never acquired")
	}
}

// LockContext waits for a held lock, and gives up when its context ends.
func TestLockContextWaitsAndGivesUp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prompt.lock")
	unlock, err := LockContext(context.Background(), path, 10*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := LockContext(ctx, path, 10*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock taken while held: %v", err)
	}
	got := make(chan error, 1)
	go func() {
		u, err := LockContext(context.Background(), path, 10*time.Millisecond)
		if err == nil {
			u()
		}
		got <- err
	}()
	time.Sleep(30 * time.Millisecond)
	unlock()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lock never taken after release")
	}
}
