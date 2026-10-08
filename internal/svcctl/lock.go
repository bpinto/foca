package svcctl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/bpinto/foca/internal/fsutil"
)

// ErrServed means another live service holds the instance's lock.
var ErrServed = errors.New("another service is already serving this instance")

// Lock takes the exclusive lock at path, a private file in the instance's
// private directory, and holds it until release. A service takes it before
// it touches the instance's socket or pid file, so two services starting at
// once can't both remove a stale socket and listen, or both write the pid
// file: the second fails here. The kernel drops the lock when the process
// exits, however it exits, so it never goes stale.
func Lock(path string) (release func(), err error) {
	if err := fsutil.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.Mode().IsRegular() || fi.Mode().Perm()&0o077 != 0 || !ok || int(st.Uid) != os.Getuid() {
		f.Close()
		return nil, fmt.Errorf("%s is not a private file of the current user; not trusting it", path)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (%s is locked)", ErrServed, path)
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() { f.Close() }, nil
}
