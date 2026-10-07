package sysbus

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
)

// privateBus starts a dbus-daemon for this test only, run by this user, and
// returns its address.
func privateBus(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not found")
	}
	dir := t.TempDir()
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

// socketPath is the path in a bus address like "unix:path=/x,guid=…".
func socketPath(t *testing.T, addr string) string {
	t.Helper()
	for _, kv := range strings.Split(strings.TrimPrefix(addr, "unix:"), ",") {
		if p, ok := strings.CutPrefix(kv, "path="); ok {
			return p
		}
	}
	t.Fatalf("no path in %q", addr)
	return ""
}

func busID(t *testing.T, c *dbus.Conn) string {
	t.Helper()
	var id string
	if err := c.BusObject().Call("org.freedesktop.DBus.GetId", 0).Store(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// A bus daemon that isn't root's is refused: whoever runs it decides who
// owns logind's and polkit's names.
func TestSystemBusMustBeServedByRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("runs as root, so any bus it starts is root's")
	}
	path := socketPath(t, privateBus(t))
	if c, err := connect(path, 0); err == nil || !strings.Contains(err.Error(), "refusing it") {
		if c != nil {
			c.Close()
		}
		t.Fatalf("a bus run by uid %d was accepted as the system bus: %v", os.Getuid(), err)
	}
	// The same bus with its real owner expected: only the uid was wrong.
	c, err := connect(path, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// The environment can't move the system bus: DBUS_SYSTEM_BUS_ADDRESS is
// never read, and FOCA_SYSTEM_BUS only in test builds.
func TestEnvironmentCantMoveTheSystemBus(t *testing.T) {
	addr := privateBus(t)
	probe, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	private := busID(t, probe)
	onPrivate := func() bool {
		c, err := Connect()
		if err != nil {
			return false // no system bus here, or not root's
		}
		defer c.Close()
		return busID(t, c) == private
	}

	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", addr)
	t.Setenv("FOCA_SYSTEM_BUS", "")
	if onPrivate() {
		t.Fatal("DBUS_SYSTEM_BUS_ADDRESS moved the system bus")
	}
	t.Setenv("FOCA_SYSTEM_BUS", addr)
	if got, want := onPrivate(), testBus != nil; got != want {
		t.Fatalf("FOCA_SYSTEM_BUS used: %v, want %v (test build: %v)", got, want, testBus != nil)
	}
}
