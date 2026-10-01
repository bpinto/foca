package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckTrustedFile(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "ok.toml")
	os.WriteFile(ok, []byte("x"), 0o600)
	if _, err := CheckTrustedFile(ok); err != nil {
		t.Fatalf("private file refused: %v", err)
	}

	gw := filepath.Join(dir, "gw.toml")
	os.WriteFile(gw, []byte("x"), 0o600)
	os.Chmod(gw, 0o620)
	if _, err := CheckTrustedFile(gw); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("group-writable file accepted: %v", err)
	}

	open := filepath.Join(dir, "open")
	os.Mkdir(open, 0o700)
	os.Chmod(open, 0o777)
	inner := filepath.Join(open, "c.toml")
	os.WriteFile(inner, []byte("x"), 0o600)
	if _, err := CheckTrustedFile(inner); err == nil {
		t.Fatal("file under world-writable dir accepted")
	}

	link := filepath.Join(dir, "link.toml")
	os.Symlink(ok, link)
	// macOS temp dirs sit under /var, itself a symlink to /private/var.
	want, _ := filepath.EvalSymlinks(ok)
	got, err := CheckTrustedFile(link)
	if err != nil || got != want {
		t.Fatalf("symlink to trusted file: %q, %v", got, err)
	}

	if _, err := CheckTrustedFile("relative.toml"); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestEnsurePrivateDir(t *testing.T) {
	base := t.TempDir()
	d := filepath.Join(base, "a", "b")
	if err := EnsurePrivateDir(d); err != nil {
		t.Fatal(err)
	}
	os.Chmod(d, 0o755)
	if err := EnsurePrivateDir(d); err == nil {
		t.Fatal("0755 dir accepted")
	}
	link := filepath.Join(base, "link")
	os.Symlink(base, link)
	if err := EnsurePrivateDir(link); err == nil {
		t.Fatal("symlinked dir accepted")
	}

	// A parent others can write lets them swap the private directory out.
	open := filepath.Join(base, "open")
	os.Mkdir(open, 0o700)
	os.Chmod(open, 0o777)
	if err := EnsurePrivateDir(filepath.Join(open, "priv")); err == nil || !strings.Contains(err.Error(), "parent directory") {
		t.Fatalf("world-writable parent accepted: %v", err)
	}
	// Reached through a symlink, the real parent is what counts.
	os.Symlink(open, filepath.Join(base, "via"))
	if err := EnsurePrivateDir(filepath.Join(base, "via", "priv")); err == nil {
		t.Fatal("world-writable parent behind a symlink accepted")
	}
	// A sticky one, like /tmp, is fine.
	os.Chmod(open, 0o777|os.ModeSticky)
	if err := EnsurePrivateDir(filepath.Join(open, "priv2")); err != nil {
		t.Fatalf("sticky parent refused: %v", err)
	}
}

// A symlink in a directory others can write could point anywhere, so the
// directories a path passes through count, not only those of the file it
// reaches.
func TestSymlinkInWritableDirectoryIsNotTrusted(t *testing.T) {
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	if _, err := CheckTrustedFile(sh); err != nil {
		t.Skipf("%s isn't trusted here: %v", sh, err)
	}
	base := t.TempDir()
	open := filepath.Join(base, "open")
	os.Mkdir(open, 0o700)
	os.Chmod(open, 0o777)
	os.Symlink(sh, filepath.Join(open, "tool"))
	if _, err := CheckTrustedFile(filepath.Join(open, "tool")); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("symlink in a world-writable directory accepted: %v", err)
	}

	good := filepath.Join(base, "good")
	os.Mkdir(good, 0o700)
	os.Symlink(good, filepath.Join(open, "via"))
	if err := EnsurePrivateDir(filepath.Join(open, "via", "priv")); err == nil {
		t.Fatal("private dir reached through a symlink in a world-writable directory accepted")
	}

	// The user's own symlink in a sticky directory, like one in /tmp, is fine.
	os.Chmod(open, 0o777|os.ModeSticky)
	if got, err := CheckTrustedFile(filepath.Join(open, "tool")); err != nil || got != sh {
		t.Fatalf("own symlink in a sticky directory: %q, %v", got, err)
	}
	if err := EnsurePrivateDir(filepath.Join(open, "via", "priv")); err != nil {
		t.Fatalf("own symlink in a sticky directory: %v", err)
	}
}

// Symlinks are followed one at a time, relative ones from where they sit,
// and a loop ends with an error.
func TestWalkFollowsSymlinksAndStopsLoops(t *testing.T) {
	base := t.TempDir()
	os.MkdirAll(filepath.Join(base, "a", "b"), 0o700)
	f := filepath.Join(base, "a", "b", "c.toml")
	os.WriteFile(f, []byte("x"), 0o600)
	os.Symlink("b/c.toml", filepath.Join(base, "a", "rel"))
	os.Symlink("../../a/./b/../rel", filepath.Join(base, "a", "b", "up"))
	want, _ := filepath.EvalSymlinks(f)
	for _, p := range []string{filepath.Join(base, "a", "rel"), filepath.Join(base, "a", "b", "up")} {
		if got, err := CheckTrustedFile(p); err != nil || got != want {
			t.Errorf("%s: %q, %v", p, got, err)
		}
	}
	os.Symlink("loop", filepath.Join(base, "loop"))
	if _, err := CheckTrustedFile(filepath.Join(base, "loop")); err == nil || !strings.Contains(err.Error(), "too many symlinks") {
		t.Fatalf("loop: %v", err)
	}
	if _, err := CheckTrustedFile(filepath.Join(f, "x")); err == nil {
		t.Fatal("a path through a file accepted")
	}
}
