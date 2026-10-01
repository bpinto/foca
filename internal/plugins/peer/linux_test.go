//go:build linux

package peer

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Connects to a socket from this test process and checks the kernel reports
// this very process.
func TestLinuxIdentifiesRealPeer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			defer c.Close()
			buf := make([]byte, 1)
			c.Read(buf)
		}
	}()
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p, err := NewLinux().Identify(conn)
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	if strings.Contains(p.Source, "PIDFD") != p.PIDStable {
		t.Fatalf("source %s but pid_stable=%v", p.Source, p.PIDStable)
	}
	// The test binary lives in a directory this user owns.
	if p.ExeSealed {
		t.Fatalf("test binary %s reported sealed", p.Exe)
	}
	if p.PID != os.Getpid() || p.UID != os.Getuid() || p.GID != os.Getgid() {
		t.Fatalf("got pid=%d uid=%d gid=%d", p.PID, p.UID, p.GID)
	}
	if p.Exe != exe {
		t.Fatalf("exe %q, want %q", p.Exe, exe)
	}
	if !strings.HasPrefix(p.Source, "SO_PEERCRED") || p.Session == "" || p.StartTime == 0 {
		t.Fatalf("incomplete peer %+v", p)
	}
	if len(p.Parents) == 0 || p.Parents[0].PID != os.Getppid() {
		t.Fatalf("parents %+v", p.Parents)
	}
	t.Logf("source=%s session=%s", p.Source, p.Session)
}

// fakeProc builds <root>/<pid>/exe, <root>/<pid>/root and the namespace
// links the way procfs presents them, pointing at real files so ownership is
// genuine. The peer shares this process's user namespace, started with an
// empty environment and maps only its exe.
func fakeProc(t *testing.T, exeTarget, root string) procfsTable {
	t.Helper()
	dir := t.TempDir()
	for _, d := range []string{"7/ns", "self/ns"} {
		os.MkdirAll(filepath.Join(dir, d), 0o700)
	}
	links := map[string]string{
		"7/exe": exeTarget, "7/root": root, "7/ns/mnt": "/proc/self/ns/mnt",
		"7/ns/user": "/proc/self/ns/user", "self/ns/user": "/proc/self/ns/user",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	os.WriteFile(filepath.Join(dir, "7/environ"), nil, 0o600)
	p := procfsTable{root: dir, seals: map[string]bool{}}
	p.setMaps(t, mapsLine(t, "r-xp", exeTarget, exeTarget))
	return p
}

// setMaps replaces the fake process's /proc/7/maps.
func (p procfsTable) setMaps(t *testing.T, lines ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(p.root, "7/maps"), []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// mapsLine is a maps line for file, shown under path, as the kernel writes
// it.
func mapsLine(t *testing.T, perms, file, path string) string {
	t.Helper()
	fi, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("7f0000000000-7f0000001000 %s 00000000 %02x:%02x %d                   %s",
		perms, unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), st.Ino, path)
}

// cleanShell starts sh with an empty environment and returns its pid, once
// the loader has mapped a shared library, and that library ("" if none).
func cleanShell(t *testing.T, sh string) (int, string) {
	t.Helper()
	cmd := exec.Command(sh, "-c", "read x")
	cmd.Env = []string{}
	pid := startPeer(t, cmd, sh)
	// The loader maps libraries just after exec; give it a moment.
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/maps")
		for _, line := range strings.Split(string(b), "\n") {
			m, ok := parseMapsLine(line)
			if ok && strings.Contains(m.perms, "x") && strings.Contains(m.path, ".so") && filepath.IsAbs(m.path) &&
				!strings.HasPrefix(filepath.Base(m.path), "ld-") {
				return pid, m.path
			}
		}
	}
	return pid, ""
}

func TestSealedNeedsRootOwnedFileAndDirectories(t *testing.T) {
	// A root-owned system binary, such as the shell.
	sys, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	if fi, _ := os.Stat(sys); !rootOwnedReadOnly(fi) {
		t.Skipf("%s is not root-owned here", sys)
	}
	if !fakeProc(t, sys, "/").sealed(7, sys) {
		t.Fatalf("%s should be sealed", sys)
	}

	// The caller's own copy, named like a trusted tool.
	mine := filepath.Join(t.TempDir(), "gh")
	os.WriteFile(mine, []byte("#!/bin/sh\n"), 0o755)
	if fakeProc(t, mine, "/").sealed(7, mine) {
		t.Fatal("a file the caller owns must not be sealed")
	}

	// A root-owned file reached through a directory the caller can write:
	// the caller could have renamed it, so the name isn't sealed.
	if fakeProc(t, sys, "/").sealed(7, filepath.Join(t.TempDir(), "gh")) {
		t.Fatal("a caller-writable parent directory must not be sealed")
	}

	// Deleted or relative paths never count.
	if fakeProc(t, sys, "/").sealed(7, sys+" (deleted)") || fakeProc(t, sys, "/").sealed(7, "gh") {
		t.Fatal("deleted or relative exe sealed")
	}

	// A path that reaches another file than the one running.
	if other := otherSealedFile(t, sys); other != "" && fakeProc(t, sys, "/").sealed(7, other) {
		t.Fatalf("%s running as %s sealed", sys, other)
	}

	// A peer in another user namespace.
	p := fakeProc(t, sys, "/")
	os.Remove(filepath.Join(p.root, "7/ns/user"))
	os.Symlink(sys, filepath.Join(p.root, "7/ns/user"))
	if p.sealed(7, sys) {
		t.Fatal("a peer in another user namespace sealed")
	}
}

// Anyone can choose a name in a world-writable directory, sticky or not. A
// sticky directory only its group can write, like /nix/store, passes.
func TestStickyWorldWritableDirectoryIsNotSealed(t *testing.T) {
	fi, err := os.Stat("/tmp")
	if err != nil || fi.Mode().Perm()&0o002 == 0 || fi.Mode()&os.ModeSticky == 0 {
		t.Skip("/tmp is not sticky and world-writable here")
	}
	if rootOwnedReadOnly(fi) {
		t.Fatal("/tmp counts as sealed")
	}
	if fi, err := os.Stat("/nix/store"); err == nil && fi.Mode()&os.ModeSticky != 0 && !rootOwnedReadOnly(fi) {
		t.Fatalf("/nix/store (%v) not sealed", fi.Mode())
	}
}

// otherSealedFile finds a sealed system file other than sys, or "".
func otherSealedFile(t *testing.T, sys string) string {
	t.Helper()
next:
	for _, name := range []string{"env", "cat", "ls"} {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if p, err = filepath.EvalSymlinks(p); err != nil || p == sys {
			continue
		}
		for q := p; q != "/"; q = filepath.Dir(q) {
			if fi, err := os.Stat(q); err != nil || !rootOwnedReadOnly(fi) {
				continue next
			}
		}
		return p
	}
	return ""
}

// startPeer starts cmd, which ends up running exe and reading stdin, and
// returns its pid once /proc reports exe. It exits when the test ends.
func startPeer(t *testing.T, cmd *exec.Cmd, exe string) int {
	t.Helper()
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("%v: %v", cmd.Args, err)
	}
	done := make(chan struct{})
	go func() { cmd.Wait(); close(done) }()
	t.Cleanup(func() { in.Close(); <-done })
	link := "/proc/" + strconv.Itoa(cmd.Process.Pid) + "/exe"
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if got, _ := os.Readlink(link); got == exe {
			return cmd.Process.Pid
		}
		select {
		case <-done:
			t.Skipf("%v exited before running %s (no unprivileged user namespaces?)", cmd.Args, exe)
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Skipf("%v never ran %s", cmd.Args, exe)
	return 0
}

// The kernel reports the path a file was exec'd under, and a mount can put
// any file there. Neither trick may lend a process a sealed name. This runs
// for real with unshare(1) wherever unprivileged user namespaces are allowed.
func TestMountsCantLendASealedName(t *testing.T) {
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	other := otherSealedFile(t, sh)
	if other == "" {
		t.Skip("no second sealed system file")
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Skip("no unshare")
	}
	proc := procfsTable{root: "/proc"}

	// In a user and mount namespace of its own, the shell bind-mounts
	// itself over another sealed file and execs that path.
	inside := exec.Command("unshare", "-Urm", sh, "-c",
		`mount --bind "$0" "$1" && exec "$1" -c 'read x; :'`, sh, other)
	pid := startPeer(t, inside, other)
	if proc.sealed(pid, other) {
		t.Fatalf("a shell mounted over %s in its own namespace is sealed", other)
	}

	// From this namespace, a process execs the mounted file through the
	// first one's root: same user namespace, but the path reaches another
	// file than the one running.
	through := exec.Command("/proc/"+strconv.Itoa(pid)+"/root"+other, "-c", "read x; :")
	if pid := startPeer(t, through, other); proc.sealed(pid, other) {
		t.Fatalf("a shell exec'd through another namespace as %s is sealed", other)
	}
}

// A sealed program can run someone else's code: libraries the loader is told
// to add, or any file mapped executable. Neither may keep its sealed name.
func TestLoadedCodeMustBeSealedToo(t *testing.T) {
	sys, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	if fi, _ := os.Stat(sys); !rootOwnedReadOnly(fi) {
		t.Skipf("%s is not root-owned here", sys)
	}
	if !fakeProc(t, sys, "/").sealed(7, sys) {
		t.Fatalf("%s should be sealed", sys)
	}

	for _, env := range []string{"LD_PRELOAD=/home/me/evil.so", "LD_AUDIT=evil.so", "LD_LIBRARY_PATH=/home/me", "LD_ORIGIN_PATH=/home/me"} {
		p := fakeProc(t, sys, "/")
		os.WriteFile(filepath.Join(p.root, "7/environ"), []byte("HOME=/home/me\x00"+env+"\x00"), 0o600)
		if p.sealed(7, sys) {
			t.Errorf("started with %s, still sealed", env)
		}
	}
	p := fakeProc(t, sys, "/")
	os.WriteFile(filepath.Join(p.root, "7/environ"), []byte("MY_LD_PRELOAD=x\x00"), 0o600)
	if !p.sealed(7, sys) {
		t.Error("a variable that only ends like a loader variable unseals")
	}
	p = fakeProc(t, sys, "/")
	os.Remove(filepath.Join(p.root, "7/environ"))
	if p.sealed(7, sys) {
		t.Error("an unreadable environment counts as clean")
	}

	mine := filepath.Join(t.TempDir(), "evil.so")
	os.WriteFile(mine, []byte("\x7fELF"), 0o755)
	exe := mapsLine(t, "r-xp", sys, sys)
	vdso := "ffff00000000-ffff00001000 r-xp 00000000 00:00 0                          [vdso]"
	jit := "7e0000000000-7e0000100000 rwxp 00000000 00:00 0 "
	for _, c := range []struct {
		name   string
		maps   []string
		sealed bool
	}{
		{"anonymous executable memory", []string{exe, vdso, jit}, true},
		{"the caller's own file mapped read-only", []string{exe, mapsLine(t, "r--p", mine, mine)}, true},
		{"the caller's own file mapped executable", []string{exe, mapsLine(t, "r-xp", mine, mine)}, false},
		{"a sealed path naming another file", []string{exe, mapsLine(t, "r-xp", mine, sys)}, false},
		{"a deleted file", []string{exe, mapsLine(t, "r-xp", sys, sys+" (deleted)")}, false},
		{"a garbled line", []string{exe, "garbage"}, false},
		{"no mappings at all", nil, false},
	} {
		p := fakeProc(t, sys, "/")
		if c.maps == nil {
			os.Remove(filepath.Join(p.root, "7/maps"))
		} else {
			p.setMaps(t, c.maps...)
		}
		if got := p.sealed(7, sys); got != c.sealed {
			t.Errorf("%s: sealed=%v, want %v", c.name, got, c.sealed)
		}
	}
}

func TestParseMapsLineKeepsSpacesInPaths(t *testing.T) {
	m, ok := parseMapsLine("7f00-7f01 r-xp 00001000 fd:01 1234                       /opt/my app/lib x.so")
	if !ok || m.perms != "r-xp" || m.dev != unix.Mkdev(0xfd, 1) || m.ino != 1234 || m.path != "/opt/my app/lib x.so" {
		t.Fatalf("got %+v, %v", m, ok)
	}
	if m, ok := parseMapsLine("7f00-7f01 rw-p 00000000 00:00 0"); !ok || !m.anonymous() {
		t.Fatalf("anonymous: %+v, %v", m, ok)
	}
}

// A real shell started with LD_PRELOAD loses its sealed name, even when the
// library it preloads is itself sealed.
func TestPreloadUnsealsARealPeer(t *testing.T) {
	sh, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	proc := procfsTable{root: "/proc", seals: map[string]bool{}}
	pid, lib := cleanShell(t, sh)
	if lib == "" {
		t.Skipf("%s maps no shared library", sh)
	}
	if !proc.sealed(pid, sh) {
		t.Skipf("%s is not sealed here", sh)
	}
	copied := filepath.Join(t.TempDir(), filepath.Base(lib))
	b, err := os.ReadFile(lib)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(copied, b, 0o755)
	for _, preload := range []string{lib, copied} {
		cmd := exec.Command(sh, "-c", "read x")
		cmd.Env = []string{"LD_PRELOAD=" + preload}
		pid := startPeer(t, cmd, sh)
		for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			if b, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/maps"); strings.Contains(string(b), preload) {
				break
			}
		}
		if proc.sealed(pid, sh) {
			t.Errorf("%s with LD_PRELOAD=%s is sealed", sh, preload)
		}
	}
}

// selfConn returns the server end of a connection from this process.
func selfConn(t *testing.T) *net.UnixConn {
	t.Helper()
	path := filepath.Join(t.TempDir(), "s.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// Only a kernel that doesn't know SO_PEERPIDFD falls back to the weaker
// start-time check. Any other failure refuses the peer: without a pidfd, the
// pid might already name another process.
func TestPIDFDErrorsRefuseInsteadOfFallingBack(t *testing.T) {
	old := &Linux{procfs: "/proc", getPIDFD: func(int) (int, error) { return -1, unix.ENOPROTOOPT }}
	p, err := old.Identify(selfConn(t))
	if err != nil || p.PIDStable || p.Source != "SO_PEERCRED" || p.PID != os.Getpid() {
		t.Fatalf("old kernel: %+v, %v", p, err)
	}
	for _, e := range []error{unix.EINVAL, unix.ESRCH, unix.EMFILE} {
		l := &Linux{procfs: "/proc", getPIDFD: func(int) (int, error) { return -1, e }}
		if p, err := l.Identify(selfConn(t)); err == nil {
			t.Errorf("%v: identified as %+v", e, p)
		}
	}
}

// LD_LIBRARY_PATH only adds places to look for libraries, so it keeps a name
// sealed when every entry is a sealed directory, and no other way.
func TestLibraryPathMustNameSealedDirectories(t *testing.T) {
	sys, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Skip("no /bin/sh")
	}
	if !fakeProc(t, sys, "/").sealed(7, sys) {
		t.Skipf("%s is not sealed here", sys)
	}
	sealed := filepath.Dir(sys)
	mine := t.TempDir()
	for _, c := range []struct {
		value  string
		sealed bool
	}{
		{sealed, true},
		{sealed + ":" + filepath.Dir(sealed) + "/", true},
		{sealed + ";" + sealed, true},
		{mine, false},
		{sealed + ":" + mine, false},
		{sealed + "::" + sealed, false},
		{sealed + ":", false},
		{"", false},
		{"lib", false},
		{sealed + "/../" + filepath.Base(sealed), false},
		{"$ORIGIN/../lib", false},
		{sealed + "/missing", false},
	} {
		p := fakeProc(t, sys, "/")
		os.WriteFile(filepath.Join(p.root, "7/environ"), []byte("HOME=/home/me\x00LD_LIBRARY_PATH="+c.value+"\x00"), 0o600)
		if got := p.sealed(7, sys); got != c.sealed {
			t.Errorf("LD_LIBRARY_PATH=%q: sealed=%v, want %v", c.value, got, c.sealed)
		}
	}
}
