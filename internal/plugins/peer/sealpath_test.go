package peer

import (
	"io/fs"
	"os"
	"strings"
	"testing"
)

type fakeEntry struct {
	mode   fs.FileMode
	uid    uint32
	target string
}

type fakePathFS map[string]fakeEntry

func (f fakePathFS) Lstat(p string) (fs.FileMode, uint32, error) {
	e, ok := f[p]
	if !ok {
		return 0, 0, os.ErrNotExist
	}
	return e.mode, e.uid, nil
}

func (f fakePathFS) Readlink(p string) (string, error) {
	e, ok := f[p]
	if !ok || e.mode&fs.ModeSymlink == 0 {
		return "", os.ErrInvalid
	}
	return e.target, nil
}

// A macOS-like tree: /run is a symlink into /private (nix-darwin), a Nix
// profile links into the store, and Homebrew lives in a user-owned prefix.
func macTree() fakePathFS {
	dir := fs.ModeDir | 0o755
	link := func(t string) fakeEntry { return fakeEntry{mode: fs.ModeSymlink | 0o755, target: t} }
	return fakePathFS{
		"/":                                  {mode: dir},
		"/usr":                               {mode: dir},
		"/usr/bin":                           {mode: dir},
		"/usr/bin/ssh":                       {mode: 0o755},
		"/usr/bin/python3":                   link("../../Library/Python/bin/python3.12"),
		"/Library":                           {mode: dir},
		"/Library/Python":                    {mode: dir},
		"/Library/Python/bin":                {mode: dir},
		"/Library/Python/bin/python3.12":     {mode: 0o755},
		"/private":                           {mode: dir},
		"/private/var":                       {mode: dir},
		"/private/var/run":                   {mode: dir},
		"/private/var/run/current-system":    link("/nix/store/aaa-system"),
		"/run":                               link("private/var/run"),
		"/nix":                               {mode: dir},
		"/nix/store":                         {mode: fs.ModeDir | fs.ModeSticky | 0o775},
		"/nix/store/aaa-system":              {mode: fs.ModeDir | 0o555},
		"/nix/store/aaa-system/sw":           {mode: fs.ModeDir | 0o555},
		"/nix/store/aaa-system/sw/bin":       {mode: fs.ModeDir | 0o555},
		"/nix/store/aaa-system/sw/bin/gh":    link("/nix/store/bbb-gh/bin/gh"),
		"/nix/store/bbb-gh":                  {mode: fs.ModeDir | 0o555},
		"/nix/store/bbb-gh/bin":              {mode: fs.ModeDir | 0o555},
		"/nix/store/bbb-gh/bin/gh":           {mode: 0o555},
		"/opt":                               {mode: dir},
		"/opt/homebrew":                      {mode: dir, uid: 501},
		"/opt/homebrew/bin":                  {mode: dir, uid: 501},
		"/opt/homebrew/bin/gh":               link("../Cellar/gh/2.0/bin/gh"),
		"/opt/homebrew/Cellar":               {mode: dir, uid: 501},
		"/opt/homebrew/Cellar/gh":            {mode: dir, uid: 501},
		"/opt/homebrew/Cellar/gh/2.0":        {mode: dir, uid: 501},
		"/opt/homebrew/Cellar/gh/2.0/bin":    {mode: dir, uid: 501},
		"/opt/homebrew/Cellar/gh/2.0/bin/gh": {mode: 0o755, uid: 501},
		// A root-owned link in a user-owned directory: the user could
		// point it anywhere, so whatever it reaches isn't sealed.
		"/Users":           {mode: dir},
		"/Users/me":        {mode: dir, uid: 501},
		"/Users/me/bin":    {mode: dir, uid: 501},
		"/Users/me/bin/gh": link("/usr/bin/ssh"),
		"/usr/bin/group-w": {mode: 0o775},
		// Anyone can choose a name in /tmp, sticky or not. A root-owned
		// file can land there through a hard link or a FUSE mount.
		"/tmp":             link("private/tmp"),
		"/private/tmp":     {mode: fs.ModeDir | fs.ModeSticky | 0o777},
		"/private/tmp/gh":  {mode: 0o755},
		"/usr/bin/loop":    link("loop"),
		"/usr/bin/dirlink": link("/usr"),
	}
}

func TestSealedPath(t *testing.T) {
	f := macTree()
	cases := []struct {
		path, resolved string
		sealed         bool
	}{
		{"/usr/bin/ssh", "/usr/bin/ssh", true},
		{"/usr/bin/python3", "/Library/Python/bin/python3.12", true},
		{"/run/current-system/sw/bin/gh", "/nix/store/bbb-gh/bin/gh", true},
		{"/usr/bin/./../bin/ssh", "/usr/bin/ssh", true},
		{"/usr/bin/dirlink/bin/ssh", "/usr/bin/ssh", true},
		{"/opt/homebrew/bin/gh", "/opt/homebrew/Cellar/gh/2.0/bin/gh", false},
		{"/Users/me/bin/gh", "/usr/bin/ssh", false},
		{"/usr/bin/group-w", "/usr/bin/group-w", false},
		{"/tmp/gh", "/private/tmp/gh", false},
	}
	for _, c := range cases {
		got, sealed, err := sealedPath(f, c.path)
		if err != nil || got != c.resolved || sealed != c.sealed {
			t.Errorf("%s: got %q sealed=%v err=%v, want %q sealed=%v", c.path, got, sealed, err, c.resolved, c.sealed)
		}
	}
	// "usr/bin/ssh" would resolve to a sealed file from /; it is refused
	// for being relative, not for failing to resolve.
	for _, bad := range []string{"bin/ssh", "usr/bin/ssh", "/usr/bin/loop", "/usr/bin/missing", "/usr/bin/ssh/x", "/usr/bin", "/"} {
		if _, _, err := sealedPath(f, bad); err == nil {
			t.Errorf("%s: no error", bad)
		}
	}
}

// countingFS counts Lstat calls, to show a symlink loop is cut off early.
type countingFS struct {
	fakePathFS
	n *int
}

func (c countingFS) Lstat(p string) (fs.FileMode, uint32, error) {
	*c.n++
	return c.fakePathFS.Lstat(p)
}

// A symlink loop ends after maxSymlinks links, not after the walk has spun
// for a while.
func TestSealedPathCutsSymlinkLoopsShort(t *testing.T) {
	n := 0
	_, _, err := sealedPath(countingFS{macTree(), &n}, "/usr/bin/loop")
	if err == nil || !strings.Contains(err.Error(), "too many symlinks") {
		t.Fatalf("loop: %v", err)
	}
	if n > 4*maxSymlinks {
		t.Fatalf("%d lookups before giving up on a loop", n)
	}
}
