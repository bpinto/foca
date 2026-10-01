//go:build linux

package peer

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/bpinto/foca/internal/identity"
)

// Linux identifies peers with SO_PEERCRED, plus SO_PEERPIDFD when the kernel
// supports it (6.5+). A pidfd refers to exactly one process, so if it is still
// alive after /proc has been read, the pid can't have been recycled meanwhile.
type Linux struct {
	procfs string
	// getPIDFD reads SO_PEERPIDFD; nil means the real getsockopt. Tests
	// replace it to see how errors are handled.
	getPIDFD func(fd int) (int, error)
}

func NewLinux() *Linux { return &Linux{procfs: "/proc"} }

// pidfd returns the peer's pidfd, or -1 on a kernel without SO_PEERPIDFD:
// one that doesn't know the option answers ENOPROTOOPT, like for any unknown
// socket option. Any other error, such as a peer that is already gone, is
// returned: falling back to reading /proc by pid would then name whatever
// process holds the pid now.
func (l *Linux) pidfd(fd int) (int, error) {
	get := l.getPIDFD
	if get == nil {
		get = func(fd int) (int, error) { return unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PEERPIDFD) }
	}
	v, err := get(fd)
	switch {
	case err == nil:
		return v, nil
	case errors.Is(err, unix.ENOPROTOOPT):
		return -1, nil
	default:
		return -1, err
	}
}

func (l *Linux) Identify(conn *net.UnixConn) (identity.VerifiedPeer, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return identity.VerifiedPeer{}, err
	}
	var cred *unix.Ucred
	var credErr, pidfdErr error
	pidfd := -1
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		pidfd, pidfdErr = l.pidfd(int(fd))
	}); err != nil {
		return identity.VerifiedPeer{}, err
	}
	if credErr != nil {
		return identity.VerifiedPeer{}, fmt.Errorf("SO_PEERCRED: %w", credErr)
	}
	if pidfd >= 0 {
		defer unix.Close(pidfd)
	}
	if pidfdErr != nil {
		return identity.VerifiedPeer{}, fmt.Errorf("SO_PEERPIDFD: %w", pidfdErr)
	}
	pid := int(cred.Pid)
	if pid <= 0 {
		return identity.VerifiedPeer{}, errors.New("peer has no pid in this namespace")
	}

	t := procfsTable{root: l.procfs, seals: map[string]bool{}}
	st, err := t.stat(pid)
	if err != nil {
		return identity.VerifiedPeer{}, fmt.Errorf("peer %d: %w", pid, err)
	}
	exe, _ := t.exe(pid)
	session, err := durableSession(t, pid)
	if err != nil {
		return identity.VerifiedPeer{}, fmt.Errorf("peer %d session: %w", pid, err)
	}
	p := identity.VerifiedPeer{
		Source:    "SO_PEERCRED",
		UID:       int(cred.Uid),
		GID:       int(cred.Gid),
		PID:       pid,
		StartTime: st.StartTime,
		Exe:       exe,
		ExeSealed: exe != "" && t.sealed(pid, exe),
		Name:      st.Comm,
		Session:   session,
		Parents:   parents(t, st),
	}
	// The server keeps this only for a direct container realm.
	if b, err := os.ReadFile(t.root + "/" + strconv.Itoa(pid) + "/cgroup"); err == nil {
		p.Realm.ContainerID = containerID(b)
	}

	// Make sure everything we read belongs to the process that connected.
	if pidfd >= 0 {
		if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
			return identity.VerifiedPeer{}, fmt.Errorf("peer %d exited during identification", pid)
		}
		p.Source = "SO_PEERCRED+SO_PEERPIDFD"
		p.PIDStable = true
	} else if again, err := t.stat(pid); err != nil || again.StartTime != st.StartTime {
		return identity.VerifiedPeer{}, fmt.Errorf("peer %d changed during identification", pid)
	}
	// Without a pidfd, the pid could have been reused before the first
	// read, and both reads would agree on the wrong process. PIDStable
	// stays false, so nothing downstream states these names as fact.
	return p, nil
}

// procfsTable reads /proc. seals, if set, remembers file and directory checks
// for one identification, since a peer and its parents map mostly the same
// libraries.
type procfsTable struct {
	root  string
	seals map[string]bool
}

func (t procfsTable) stat(pid int) (procStat, error) {
	b, err := os.ReadFile(t.root + "/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return procStat{}, err
	}
	return parseStat(b)
}

func (t procfsTable) exe(pid int) (string, error) {
	return os.Readlink(t.root + "/" + strconv.Itoa(pid) + "/exe")
}

// sealed stats the running file through /proc/<pid>/exe, which reaches the
// inode even inside another mount namespace, and each parent directory
// through /proc/<pid>/root, so a container's paths are checked in the
// container's own tree. Directories are checked with Lstat: a symlink in the
// resolved path means it changed under us, which counts as not sealed.
//
// Mounts can put any file under a sealed name, so two more checks apply:
//   - the peer must share our user namespace. In a namespace of its own,
//     an unprivileged process can bind-mount a file over a sealed path in its
//     own mount namespace;
//   - the exe path, seen from the peer's root, must reach the very inode
//     that runs. A process can exec a file through another namespace's
//     /proc/<pid>/root, and the kernel then reports the path it has there.
//
// A sealed file can still run someone else's code, loaded next to it. So the
// environment it started with must name nothing for the loader to add
// (LD_PRELOAD and the like), and every file it has mapped executable must be
// sealed by the same rules as the exe. Either one unreadable counts as not
// sealed.
func (t procfsTable) sealed(pid int, exe string) bool {
	if !filepath.IsAbs(exe) || strings.HasSuffix(exe, " (deleted)") {
		return false
	}
	base := t.root + "/" + strconv.Itoa(pid)
	if !sameFile(base+"/ns/user", t.root+"/self/ns/user") {
		return false
	}
	fi, err := os.Stat(base + "/exe")
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	view := viewKey(base)
	running := func(at os.FileInfo) bool { return os.SameFile(fi, at) }
	return t.sealedFile(base, view, exe, running) && t.noLoaderInjection(base, view) && t.sealedMappings(base, view)
}

// sealedFile checks that path, seen from the process's root, is a root-owned,
// read-only regular file, the one is accepts, below sealed directories.
func (t procfsTable) sealedFile(base, view, path string, is func(os.FileInfo) bool) bool {
	at, err := os.Lstat(base + "/root" + path)
	if err != nil || !at.Mode().IsRegular() || !rootOwnedReadOnly(at) || !is(at) {
		return false
	}
	return t.sealedDir(base, view, filepath.Dir(path))
}

// sealedDir checks that dir, seen from the process's root, and every
// directory above it are root-owned and not writable by others. Lstat finds
// any symlink on the way, which counts as not sealed.
func (t procfsTable) sealedDir(base, view, dir string) bool {
	for ; ; dir = filepath.Dir(dir) {
		if !t.cached(view, "d"+dir, func() bool {
			di, err := os.Lstat(base + "/root" + dir)
			return err == nil && di.IsDir() && rootOwnedReadOnly(di)
		}) {
			return false
		}
		if dir == "/" {
			return true
		}
	}
}

// cached returns check's result, remembered under view and key for the rest
// of the identification. Without a view nothing is remembered.
func (t procfsTable) cached(view, key string, check func() bool) bool {
	if t.seals == nil || view == "" {
		return check()
	}
	key = view + "\x00" + key
	if v, ok := t.seals[key]; ok {
		return v
	}
	v := check()
	t.seals[key] = v
	return v
}

// viewKey names how a process sees paths: its mount namespace and its root
// directory. Processes with the same key reach the same file by the same
// path, so they can share checks. "" means it couldn't be read.
func viewKey(base string) string {
	ns, err1 := os.Stat(base + "/ns/mnt")
	root, err2 := os.Stat(base + "/root")
	if err1 != nil || err2 != nil {
		return ""
	}
	a, ok1 := ns.Sys().(*syscall.Stat_t)
	b, ok2 := root.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return ""
	}
	return fmt.Sprintf("%d:%d:%d:%d", a.Dev, a.Ino, b.Dev, b.Ino)
}

// loaderVariables make the dynamic loader run code the program didn't ask
// for: added libraries, audit modules, or another directory to resolve
// $ORIGIN against (ld.so(8)).
var loaderVariables = []string{"LD_PRELOAD=", "LD_AUDIT=", "LD_ORIGIN_PATH="}

// noLoaderInjection reads the environment the process started with. It sits
// in the process's memory, so loaded code can blank it; sealedMappings then
// still finds the library while it stays mapped.
//
// LD_LIBRARY_PATH is common in Nix sessions, and refusing it outright would
// put the mark on nearly every name there. It only makes the loader look for
// libraries in other directories, so it passes when every entry is a sealed
// directory: then whatever it finds is root's, like the rest of the program.
func (t procfsTable) noLoaderInjection(base, view string) bool {
	b, err := os.ReadFile(base + "/environ")
	if err != nil {
		return false
	}
	for _, kv := range bytes.Split(b, []byte{0}) {
		for _, v := range loaderVariables {
			if bytes.HasPrefix(kv, []byte(v)) {
				return false
			}
		}
		if dirs, ok := bytes.CutPrefix(kv, []byte("LD_LIBRARY_PATH=")); ok && !t.sealedSearchPath(base, view, string(dirs)) {
			return false
		}
	}
	return true
}

// sealedSearchPath checks every entry of a library search path. glibc splits
// on ':' and ';'. An empty entry means the working directory, and a relative
// one, '.' or '..' depend on it or on symlinks, so they never pass; nor does
// '$', which the loader expands ($ORIGIN, $LIB, $PLATFORM).
func (t procfsTable) sealedSearchPath(base, view, list string) bool {
	for _, dir := range strings.Split(strings.ReplaceAll(list, ";", ":"), ":") {
		if !filepath.IsAbs(dir) || strings.ContainsRune(dir, '$') {
			return false
		}
		for _, c := range strings.Split(dir, "/") {
			if c == "." || c == ".." {
				return false
			}
		}
		if !t.sealedDir(base, view, filepath.Clean(dir)) {
			return false
		}
	}
	return true
}

// sealedMappings checks every file the process has mapped executable. maps
// gives each file's device and inode, so the path must reach that very file,
// as for the exe. Overlayfs shows the underlying file there, whose device
// stat never reports, so on overlayfs the inode number alone must match; if
// that differs too, the file isn't sealed. Anonymous executable memory (JIT
// code, the vDSO) has no file whose name anyone chose, so it isn't checked.
func (t procfsTable) sealedMappings(base, view string) bool {
	b, err := os.ReadFile(base + "/maps")
	if err != nil || len(b) == 0 {
		return false
	}
	for _, line := range strings.Split(strings.TrimSuffix(string(b), "\n"), "\n") {
		m, ok := parseMapsLine(line)
		if !ok {
			return false
		}
		if !strings.Contains(m.perms, "x") || m.anonymous() {
			continue
		}
		// The kernel writes a newline in a name as \012, so a backslash
		// makes the path ambiguous.
		if !filepath.IsAbs(m.path) || strings.HasSuffix(m.path, " (deleted)") || strings.ContainsRune(m.path, '\\') {
			return false
		}
		key := fmt.Sprintf("f%d:%d:%s", m.dev, m.ino, m.path)
		is := func(at os.FileInfo) bool { return m.is(at, base+"/root"+m.path) }
		if !t.cached(view, key, func() bool { return t.sealedFile(base, view, m.path, is) }) {
			return false
		}
	}
	return true
}

// sameFile stats two paths, following links, and reports whether they are
// the same file. Either failing counts as different.
func sameFile(a, b string) bool {
	fa, err := os.Stat(a)
	if err != nil {
		return false
	}
	fb, err := os.Stat(b)
	return err == nil && os.SameFile(fa, fb)
}

// rootOwnedReadOnly: owned by root and not writable by group or others. A
// sticky directory that only its group can write, such as /nix/store
// (root:nixbld 1775), passes too: the group can add entries but not rename
// or replace root's. A world-writable one such as /tmp never passes, since
// anyone can choose a name there.
func rootOwnedReadOnly(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 {
		return false
	}
	if fi.IsDir() && fi.Mode()&os.ModeSticky != 0 {
		return fi.Mode().Perm()&0o002 == 0
	}
	return fi.Mode().Perm()&0o022 == 0
}

// mapping is one line of /proc/<pid>/maps.
type mapping struct {
	perms    string
	dev, ino uint64
	path     string
}

// anonymous: no file behind it. Named anonymous memory shows as [name].
func (m mapping) anonymous() bool {
	return m.ino == 0 && (m.path == "" || strings.HasPrefix(m.path, "["))
}

// is reports whether fi, found at path, is the mapped file.
func (m mapping) is(fi os.FileInfo, path string) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || st.Ino != m.ino {
		return false
	}
	if uint64(st.Dev) == m.dev {
		return true
	}
	var fs unix.Statfs_t
	return unix.Statfs(path, &fs) == nil && fs.Type == unix.OVERLAYFS_SUPER_MAGIC
}

// parseMapsLine parses "start-end perms offset major:minor inode   path".
// The path is everything after the padding, spaces included.
func parseMapsLine(line string) (mapping, bool) {
	rest := line
	var f [5]string
	for i := range f {
		rest = strings.TrimLeft(rest, " ")
		var ok bool
		if f[i], rest, ok = strings.Cut(rest, " "); !ok && i < 4 {
			return mapping{}, false
		}
	}
	major, minor, ok := strings.Cut(f[3], ":")
	mj, err1 := strconv.ParseUint(major, 16, 32)
	mn, err2 := strconv.ParseUint(minor, 16, 32)
	ino, err3 := strconv.ParseUint(f[4], 10, 64)
	if !ok || err1 != nil || err2 != nil || err3 != nil {
		return mapping{}, false
	}
	return mapping{perms: f[1], dev: unix.Mkdev(uint32(mj), uint32(mn)), ino: ino,
		path: strings.TrimLeft(rest, " ")}, true
}
