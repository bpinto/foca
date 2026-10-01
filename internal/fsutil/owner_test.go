package fsutil

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

// statInfo is an os.FileInfo with a chosen owner and mode, since a test
// can't create files owned by another user.
type statInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (s statInfo) Name() string       { return "x" }
func (s statInfo) Size() int64        { return 0 }
func (s statInfo) Mode() fs.FileMode  { return s.mode }
func (s statInfo) ModTime() time.Time { return time.Time{} }
func (s statInfo) IsDir() bool        { return s.mode.IsDir() }
func (s statInfo) Sys() any           { return &syscall.Stat_t{Uid: s.uid} }

// Trusted files and their directories belong to the user or root; another
// user's are refused even with a private mode, since they could rewrite them.
func TestOwnerMustBeTheUserOrRoot(t *testing.T) {
	me := uint32(os.Getuid())
	other := me + 1
	if other == 0 {
		other++
	}
	for _, c := range []struct {
		name string
		fi   statInfo
		ok   bool
	}{
		{"own file", statInfo{0o600, me}, true},
		{"root file", statInfo{0o644, 0}, true},
		{"other user's file", statInfo{0o600, other}, false},
		{"other user's directory", statInfo{fs.ModeDir | 0o755, other}, false},
		{"other user's sticky directory", statInfo{fs.ModeDir | fs.ModeSticky | 0o1777, other}, false},
	} {
		if err := checkOwnerAndMode("/x", c.fi); (err == nil) != c.ok {
			t.Errorf("%s: err=%v, want ok=%v", c.name, err, c.ok)
		}
	}
}
