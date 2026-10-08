// Package polkittest runs polkit for tests: a private system bus, the real
// polkitd on it, an authentication agent and a scripted fake authority.
// Only tests import it.
//
// The real polkitd runs under bubblewrap, so it sees this test's action
// and rules instead of the system's, a fake logind session (c1, active,
// local, the display session of this user), and this test's process as a
// service of that user. It runs as this user: a fake
// /etc/passwd names polkitd's own user after it. Tests that need it skip
// unless FOCA_POLKITD names a polkitd binary (the dev shell and CI set it);
// once it is set, a polkitd that can't start fails the test.
//
// polkit only accepts an agent's answer from uid 0, so no test here can
// approve through the real polkitd. Approvals are tested against the fake.
package polkittest

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// Bus starts a dbus-daemon for this test only and returns its address.
func Bus(t testing.TB) string {
	t.Helper()
	bin, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not found")
	}
	// A short directory: a subtest's TempDir can be too long for a socket path.
	dir, err := os.MkdirTemp("", "fbus")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	conf := filepath.Join(dir, "bus.conf")
	os.WriteFile(conf, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:dir=`+dir+`</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>`), 0o600)
	cmd := exec.Command(bin, "--config-file="+conf, "--nofork", "--print-address=1")
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(line)
}

// Connect connects to the bus at addr, closed when the test ends.
func Connect(t testing.TB, addr string) *dbus.Conn {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// Polkitd is the real polkitd on a private bus.
type Polkitd struct {
	Addr string
	dir  string
	log  *bytes.Buffer
}

// Session is the fake logind session polkitd sees for this user.
type Session struct {
	Active bool
	Remote bool
	// Services are the pids polkitd sees as services of this user, and so
	// in its display session. Empty means this test's own process.
	Services []int
}

// StartPolkitd starts polkitd on the bus at addr with one action file and
// the given rules files (name → JavaScript).
func StartPolkitd(t testing.TB, addr string, policy []byte, rules map[string]string, s Session) *Polkitd {
	t.Helper()
	bin := os.Getenv("FOCA_POLKITD")
	if bin == "" {
		t.Skip("FOCA_POLKITD is not set (the dev shell sets it to polkitd)")
	}
	bwrap, err := exec.LookPath("bwrap")
	if err != nil {
		t.Fatal("FOCA_POLKITD is set but bwrap is not found")
	}
	dir := t.TempDir()
	for _, d := range []string{"actions", "rules.d", "sessions", "users"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	os.WriteFile(filepath.Join(dir, "actions", "foca.policy"), policy, 0o644)
	for name, js := range rules {
		os.WriteFile(filepath.Join(dir, "rules.d", name), []byte(js), 0o644)
	}
	uid, gid := os.Getuid(), os.Getgid()
	name := strconv.Itoa(uid)
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	// polkitd switches to its own user unless it already runs as it.
	var passwd strings.Builder
	fmt.Fprintf(&passwd, "root:x:0:0::/root:/bin/sh\n")
	for _, n := range []string{name, "polkituser", "polkitd"} {
		fmt.Fprintf(&passwd, "%s:x:%d:%d::/:/bin/sh\n", n, uid, gid)
	}
	os.WriteFile(filepath.Join(dir, "passwd"), []byte(passwd.String()), 0o644)
	os.WriteFile(filepath.Join(dir, "group"), fmt.Appendf(nil, "root:x:0:\nfoca:x:%d:\n", gid), 0o644)
	// polkit counts a session with a seat as local.
	remote, seat := "0", "SEAT=seat0\n"
	if s.Remote {
		remote, seat = "1", ""
	}
	active, state := "0", "online"
	if s.Active {
		active, state = "1", "active"
	}
	os.WriteFile(filepath.Join(dir, "sessions", "c1"), fmt.Appendf(nil,
		"UID=%d\nUSER=%s\nACTIVE=%s\nSTATE=%s\nREMOTE=%s\nTYPE=wayland\nCLASS=user\n%sLEADER=1\n",
		uid, name, active, state, remote, seat), 0o644)
	os.WriteFile(filepath.Join(dir, "users", strconv.Itoa(uid)), fmt.Appendf(nil,
		"NAME=%s\nSTATE=%s\nDISPLAY=c1\nSESSIONS=c1\nACTIVE_SESSIONS=c1\n", name, state), 0o644)

	// Hide every directory polkitd might read actions or rules from, and
	// the system's logind state, then put this test's in their place.
	args := []string{"--dev-bind", "/", "/", "--tmpfs", "/run"}
	for _, d := range []string{"/etc/polkit-1", "/usr/share/polkit-1", "/usr/local/share/polkit-1"} {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			args = append(args, "--tmpfs", d)
		}
	}
	bind := func(src, dst string) { args = append(args, "--ro-bind", src, dst) }
	for _, base := range []string{"/run/polkit-1", "/etc/polkit-1", "/usr/share/polkit-1"} {
		if base != "/run/polkit-1" {
			if st, err := os.Stat(base); err != nil || !st.IsDir() {
				continue
			}
		}
		bind(filepath.Join(dir, "actions"), base+"/actions")
		bind(filepath.Join(dir, "rules.d"), base+"/rules.d")
	}
	// polkitd finds a process's user, and so its display session, from its
	// cgroup. Each service looks like one, whatever cgroup it really runs
	// in: a CI runner's is a system service, with no user.
	os.WriteFile(filepath.Join(dir, "cgroup"), fmt.Appendf(nil,
		"0::/user.slice/user-%d.slice/user@%d.service/app.slice/foca.service\n", uid, uid), 0o644)
	if s.Services == nil {
		s.Services = []int{os.Getpid()}
	}
	for _, pid := range s.Services {
		bind(filepath.Join(dir, "cgroup"), fmt.Sprintf("/proc/%d/cgroup", pid))
	}
	bind(filepath.Join(dir, "sessions"), "/run/systemd/sessions")
	bind(filepath.Join(dir, "users"), "/run/systemd/users")
	bind(filepath.Join(dir, "passwd"), "/etc/passwd")
	bind(filepath.Join(dir, "group"), "/etc/group")
	args = append(args, "--die-with-parent", bin, "--no-debug")

	cmd := exec.Command(bwrap, args...)
	cmd.Env = append(os.Environ(), "DBUS_SYSTEM_BUS_ADDRESS="+addr)
	p := &Polkitd{Addr: addr, dir: dir, log: &bytes.Buffer{}}
	cmd.Stdout, cmd.Stderr = p.log, p.log
	if err := cmd.Start(); err != nil {
		t.Fatalf("can't start polkitd under bwrap: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })

	conn := Connect(t, addr)
	deadline := time.Now().Add(10 * time.Second)
	for {
		var has bool
		conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, "org.freedesktop.PolicyKit1").Store(&has)
		if has {
			break
		}
		if cmd.ProcessState != nil || time.Now().After(deadline) {
			t.Fatalf("polkitd didn't start under bwrap (no user namespaces?):\n%s", p.log)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return p
}

// Log is polkitd's output so far.
func (p *Polkitd) Log() string { return p.log.String() }

// ---- authentication agent ----

// Begin is one BeginAuthentication call an agent received.
type Begin struct {
	ActionID string
	Message  string
	Details  map[string]string
	Cookie   string
}

// Agent is an authentication agent for one process. It can't approve
// (polkit takes answers only from uid 0); it dismisses each prompt, or
// holds it until polkit cancels it.
type Agent struct {
	mu        sync.Mutex
	hold      bool
	open      int
	begun     []Begin
	cancelled []string
	cancel    map[string]chan struct{}
	// Started receives each prompt as it opens, if set.
	Started chan Begin
}

const agentPath = dbus.ObjectPath("/io/github/bpinto/foca/TestAgent")

// RegisterAgent registers an agent for the process pid on the bus at addr,
// in the C locale.
func RegisterAgent(t testing.TB, addr string, pid int) *Agent {
	t.Helper()
	return RegisterAgentIn(t, addr, pid, "C")
}

// RegisterAgentIn registers an agent that asks polkit for its messages in
// locale, as an agent passes its LANG.
func RegisterAgentIn(t testing.TB, addr string, pid int, locale string) *Agent {
	t.Helper()
	conn := Connect(t, addr)
	a := &Agent{cancel: map[string]chan struct{}{}}
	if err := conn.Export(agentMethods{a}, agentPath, "org.freedesktop.PolicyKit1.AuthenticationAgent"); err != nil {
		t.Fatal(err)
	}
	start, err := StartTime(pid)
	if err != nil {
		t.Fatal(err)
	}
	subject := struct {
		Kind    string
		Details map[string]dbus.Variant
	}{"unix-process", map[string]dbus.Variant{
		"pid": dbus.MakeVariant(uint32(pid)), "start-time": dbus.MakeVariant(start),
	}}
	err = conn.Object("org.freedesktop.PolicyKit1", "/org/freedesktop/PolicyKit1/Authority").Call(
		"org.freedesktop.PolicyKit1.Authority.RegisterAuthenticationAgent", 0, subject, locale, string(agentPath)).Err
	if err != nil {
		t.Fatalf("register agent: %v", err)
	}
	return a
}

// Hold makes the agent keep each prompt open until polkit cancels it,
// instead of dismissing it.
func (a *Agent) Hold(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.hold = v
}

// Begun returns every prompt the agent was asked to show.
func (a *Agent) Begun() []Begin {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]Begin(nil), a.begun...)
}

// Cancelled returns the cookies polkit cancelled.
func (a *Agent) Cancelled() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.cancelled...)
}

// agentMethods keeps the exported D-Bus methods off Agent's own API.
type agentMethods struct{ a *Agent }

type identity struct {
	Kind    string
	Details map[string]dbus.Variant
}

func (m agentMethods) BeginAuthentication(actionID, message, icon string, details map[string]string, cookie string, ids []identity) *dbus.Error {
	a := m.a
	a.mu.Lock()
	b := Begin{ActionID: actionID, Message: message, Details: details, Cookie: cookie}
	a.begun = append(a.begun, b)
	hold, started := a.hold, a.Started
	done := make(chan struct{})
	a.cancel[cookie] = done
	a.open++
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		a.open--
		delete(a.cancel, cookie)
		a.mu.Unlock()
	}()
	if started != nil {
		started <- b
	}
	if hold {
		select {
		case <-done:
		case <-time.After(30 * time.Second):
		}
	}
	return dbus.NewError("org.freedesktop.PolicyKit1.Error.Cancelled", []any{"dismissed"})
}

func (m agentMethods) CancelAuthentication(cookie string) *dbus.Error {
	a := m.a
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cancelled = append(a.cancelled, cookie)
	if c, ok := a.cancel[cookie]; ok {
		close(c)
		delete(a.cancel, cookie)
	}
	return nil
}

// StartTime is a process's start time in clock ticks since boot, as polkit
// identifies processes (field 22 of /proc/<pid>/stat).
func StartTime(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// The command name may contain spaces; fields start after its ')'.
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, fmt.Errorf("odd /proc/%d/stat", pid)
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 20 {
		return 0, fmt.Errorf("short /proc/%d/stat", pid)
	}
	return strconv.ParseUint(f[19], 10, 64)
}

// Open reports how many prompts the agent is showing.
func (a *Agent) Open() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.open
}
