package fsutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// failAt lets tests stop WriteFileAtomic at a named step, as a crash would.
var failAt func(step string) error

func step(name string) error {
	if failAt != nil {
		return failAt(name)
	}
	return nil
}

// WriteFileAtomic replaces path with data so that a crash at any point leaves
// either the old file or the new one, never a mix: write a temp file in the
// same directory, fsync it, rename it over path, then fsync the directory.
// The file gets mode perm; a symlink at path is replaced, never followed.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil && !errors.Is(err, ErrNotDurable) {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err = f.Chmod(perm); err != nil {
		return err
	}
	if err = step("write"); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = step("sync"); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = step("rename"); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	// From here the new file is in place; a failure only means the rename
	// may not be durable yet. Callers must not undo on ErrNotDurable: the
	// new file is what readers see now.
	serr := step("syncdir")
	if serr == nil {
		serr = SyncDir(dir)
	}
	if serr != nil {
		return fmt.Errorf("%s: %w: %w", path, ErrNotDurable, serr)
	}
	return nil
}

// ErrNotDurable: WriteFileAtomic renamed the new file into place, but the
// directory sync failed, so a crash may still bring back the old file.
var ErrNotDurable = errors.New("written, but the directory sync failed, so it may not survive a crash")

// SyncDir makes a rename or create in dir durable.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

// Lock takes an exclusive advisory lock on path, creating it (0600) if
// needed, and blocks until it is free. Writers of a file that gets replaced
// by rename lock a separate, stable lock file instead of the file itself.
func Lock(path string) (unlock func() error, err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() error {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		return f.Close()
	}, nil
}

// PrivateLock returns a function that takes the lock file name in dir,
// creating dir as a private directory first, and waits for it until ctx
// ends.
func PrivateLock(dir, name string) func(context.Context) (release func(), err error) {
	return func(ctx context.Context) (func(), error) {
		if err := EnsurePrivateDir(dir); err != nil {
			return nil, err
		}
		unlock, err := LockContext(ctx, filepath.Join(dir, name), 50*time.Millisecond)
		if err != nil {
			return nil, err
		}
		return func() { unlock() }, nil
	}
}

// LockContext is Lock that gives up when ctx ends. It tries every poll
// rather than blocking in flock, which can't be interrupted.
func LockContext(ctx context.Context, path string, poll time.Duration) (unlock func() error, err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() error {
				unix.Flock(int(f.Fd()), unix.LOCK_UN)
				return f.Close()
			}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("lock %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			f.Close()
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}
