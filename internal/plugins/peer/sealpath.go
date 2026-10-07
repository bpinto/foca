package peer

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
)

// pathFS is the little of a filesystem sealedPath needs. The darwin
// identifier uses the real one; tests use a map, so the walk is tested on
// any OS.
type pathFS interface {
	// Lstat returns the entry itself, never a symlink's target.
	Lstat(path string) (fs.FileMode, uint32, error) // mode, owner uid
	Readlink(path string) (string, error)
}

const maxSymlinks = 40

// sealedPath resolves an absolute path one component at a time, following
// symlinks itself, and reports the file it reaches and whether that file is
// sealed: it and every directory passed through, including those reached
// through a symlink, are owned by root and not writable by group or others
// (sticky directories pass unless world-writable).
//
// The path macOS reports for a running file (proc_pidpath) is normally free
// of symlinks, but nothing here relies on that. A symlink on the way is
// followed rather than refused: whoever could rewrite it could also have
// chosen the name, and only root can do either when every directory on the
// way is sealed. The symlinks themselves need no check, since replacing one
// needs write access to its directory.
func sealedPath(fsys pathFS, path string) (resolved string, sealed bool, err error) {
	if !filepath.IsAbs(path) {
		return "", false, errors.New("path is not absolute")
	}
	mode, uid, err := fsys.Lstat("/")
	if err != nil {
		return "", false, err
	}
	sealed = sealedEntry(mode, uid)
	cur := "/"
	rest := split(path)
	links := 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			// cur is fully resolved, so its parent is the real parent.
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, c)
		mode, uid, err := fsys.Lstat(next)
		if err != nil {
			return "", false, err
		}
		switch {
		case mode&fs.ModeSymlink != 0:
			if links++; links > maxSymlinks {
				return "", false, errors.New("too many symlinks")
			}
			target, err := fsys.Readlink(next)
			if err != nil {
				return "", false, err
			}
			if filepath.IsAbs(target) {
				cur = "/"
			}
			rest = append(split(target), rest...)
		case mode.IsDir():
			sealed = sealed && sealedEntry(mode, uid)
			cur = next
		case mode.IsRegular() && len(rest) == 0:
			sealed = sealed && sealedEntry(mode, uid)
			cur = next
		default:
			return "", false, errors.New(next + " is not a directory")
		}
	}
	if cur == "/" {
		return "", false, errors.New("path names no file")
	}
	m, _, err := fsys.Lstat(cur)
	if err != nil || !m.IsRegular() {
		return "", false, errors.New(cur + " is not a regular file")
	}
	return cur, sealed, nil
}

func split(p string) []string { return strings.Split(p, "/") }

// sealedEntry: owned by root and not writable by group or others. A sticky
// directory that only its group can write, such as /nix/store (root:nixbld
// 1775), passes too: the group can add entries but not rename or replace
// root's. A world-writable one such as /tmp never passes, since anyone can
// choose a name there.
func sealedEntry(mode fs.FileMode, uid uint32) bool {
	if uid != 0 {
		return false
	}
	if mode.IsDir() && mode&fs.ModeSticky != 0 {
		return mode.Perm()&0o002 == 0
	}
	return mode.Perm()&0o022 == 0
}
