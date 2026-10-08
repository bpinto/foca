// Package fsutil checks files and directories before foca trusts them.
package fsutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// CheckTrustedFile walks the path, following symlinks, and checks that the
// file and every directory it passes through are owned by the current user
// or root and are not writable by group or others (see walk). Nix store
// paths (root-owned, read-only) pass.
func CheckTrustedFile(path string) (resolved string, err error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s: path must be absolute", path)
	}
	resolved, fi, err := walk(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", resolved)
	}
	return resolved, nil
}

const maxSymlinks = 40

// walk resolves an absolute path one component at a time, following
// symlinks itself, and checks with checkOwnerAndMode every directory it
// passes through, including those it finds a symlink in and those it reaches
// through one, and the entry it ends on. Resolving first and checking only
// the result would miss a symlink in a directory others can write, which
// they could point anywhere. In a sticky directory such as /tmp, others can
// add entries but not replace ours, so a symlink there must be the user's
// or root's.
func walk(path string) (string, os.FileInfo, error) {
	fi, err := os.Lstat("/")
	if err != nil {
		return "", nil, err
	}
	if err := checkOwnerAndMode("/", fi); err != nil {
		return "", nil, err
	}
	cur, dir := "/", fi
	rest := strings.Split(path, "/")
	links := 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			// cur is fully resolved, so its parent is the real parent,
			// already checked on the way down.
			cur = filepath.Dir(cur)
			if dir, err = os.Lstat(cur); err != nil {
				return "", nil, err
			}
			fi = dir
			continue
		}
		next := filepath.Join(cur, c)
		if fi, err = os.Lstat(next); err != nil {
			return "", nil, err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if dir.Mode()&os.ModeSticky != 0 && !ownedByUserOrRoot(fi) {
				return "", nil, fmt.Errorf("%s: symlink in a sticky directory owned by someone else", next)
			}
			if links++; links > maxSymlinks {
				return "", nil, fmt.Errorf("%s: too many symlinks", path)
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", nil, err
			}
			if filepath.IsAbs(target) {
				cur = "/"
				if dir, err = os.Lstat(cur); err != nil {
					return "", nil, err
				}
			}
			rest = append(strings.Split(target, "/"), rest...)
			fi = dir
			continue
		}
		if err := checkOwnerAndMode(next, fi); err != nil {
			return "", nil, err
		}
		if !fi.IsDir() && strings.Trim(strings.Join(rest, "/"), "/") != "" {
			return "", nil, fmt.Errorf("%s: not a directory", next)
		}
		cur = next
		if fi.IsDir() {
			dir = fi
		}
	}
	return cur, fi, nil
}

func ownedByUserOrRoot(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && (int(st.Uid) == os.Getuid() || st.Uid == 0)
}

func checkOwnerAndMode(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read ownership", path)
	}
	if int(st.Uid) != os.Getuid() && st.Uid != 0 {
		return fmt.Errorf("%s: owned by uid %d (want %d or root)", path, st.Uid, os.Getuid())
	}
	perm := fi.Mode().Perm()
	// A sticky world-writable directory such as /tmp is acceptable as an
	// ancestor: others can't replace entries they don't own.
	if fi.IsDir() && fi.Mode()&os.ModeSticky != 0 {
		return nil
	}
	if perm&0o022 != 0 {
		return fmt.Errorf("%s: mode %o is writable by group or others", path, perm)
	}
	return nil
}

// EnsurePrivateDir creates dir (and missing parents) with mode 0700, then
// verifies that dir itself is a real directory owned by the current user with
// exactly mode 0700. A symlink or a directory someone else prepared is refused.
//
// Every directory on the way to it, including those reached through a
// symlink, must be owned by the user or root and not writable by group or
// others, unless it is sticky like /tmp (see walk). Otherwise another user
// could rename dir away and put an older copy, or one of their own, in its
// place.
func EnsurePrivateDir(dir string) error {
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if _, _, err := walk(filepath.Dir(abs)); err != nil {
		return fmt.Errorf("%s: parent directory: %w", dir, err)
	}
	return nil
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return fmt.Errorf("%s: not a directory", dir)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s: not owned by the current user", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("%s: mode %o, want 0700", dir, fi.Mode().Perm())
	}
	return nil
}

// CheckTrustedDir checks that dir and every directory on the way to it,
// including those reached through a symlink, are owned by the current user
// or root and not writable by group or others (sticky ones like /tmp
// excepted; see walk), so no one else can replace what is in it.
func CheckTrustedDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%s: path must be absolute", dir)
	}
	resolved, fi, err := walk(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory", resolved)
	}
	return nil
}
