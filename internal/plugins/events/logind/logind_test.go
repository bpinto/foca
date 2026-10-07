package logind

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/bpinto/foca/internal/plugin"
)

// privateBus starts a dbus-daemon for this test only.
func privateBus(t *testing.T) string {
	t.Helper()
	bin, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon not found")
	}
	dir := t.TempDir()
	conf := dir + "/bus.conf"
	os.WriteFile(conf, []byte(`<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
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

// fakeLogind owns org.freedesktop.login1 on the private bus.
type fakeLogind struct {
	conn *dbus.Conn
	mu   sync.Mutex
	list []session
	// inhibits counts delay locks taken; locks are the pipes behind them.
	inhibits int
	locks    []lockPipe
}

// lockPipe is one delay lock: the source gets a copy of r, and the lock is
// held while any copy is open.
type lockPipe struct{ r, w *os.File }

func (f *fakeLogind) ListSessions() ([]session, *dbus.Error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]session(nil), f.list...), nil
}

func (f *fakeLogind) Inhibit(what, who, why, mode string) (dbus.UnixFD, *dbus.Error) {
	r, w, err := os.Pipe()
	if err != nil {
		return 0, dbus.MakeFailedError(err)
	}
	fd := dbus.UnixFD(r.Fd())
	f.mu.Lock()
	f.inhibits++
	f.locks = append(f.locks, lockPipe{r, w})
	f.mu.Unlock()
	return fd, nil
}

// held counts the delay locks the source still holds. Call it only once
// the source has received every lock it asked for: it closes this side's
// copies first.
func (f *fakeLogind) held() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, l := range f.locks {
		l.r.Close()
		// With no read end left open, a write fails (EPIPE).
		if _, err := l.w.Write([]byte{0}); err == nil {
			n++
		}
	}
	return n
}

func (f *fakeLogind) closeLocks() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, l := range f.locks {
		l.r.Close()
		l.w.Close()
	}
}

func startLogind(t *testing.T, addr string, list []session) *fakeLogind {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	f := &fakeLogind{conn: conn, list: list}
	t.Cleanup(f.closeLocks)
	if err := conn.Export(f, managerPath, managerIface); err != nil {
		t.Fatal(err)
	}
	if r, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request name: %v %v", r, err)
	}
	return f
}

func (f *fakeLogind) emit(t *testing.T, path dbus.ObjectPath, name string, values ...any) {
	t.Helper()
	if err := f.conn.Emit(path, name, values...); err != nil {
		t.Fatal(err)
	}
}

const (
	minePath  = dbus.ObjectPath("/org/freedesktop/login1/session/_31")
	otherPath = dbus.ObjectPath("/org/freedesktop/login1/session/_32")
)

func run(t *testing.T, addr string) (<-chan plugin.PlatformEvent, <-chan error, context.CancelFunc) {
	t.Helper()
	src := &Source{Dial: func() (*dbus.Conn, error) { return dbus.Connect(addr) }, UID: 1000}
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan plugin.PlatformEvent, 16)
	errc := make(chan error, 1)
	go func() { errc <- src.Run(ctx, out) }()
	t.Cleanup(cancel)
	return out, errc, cancel
}

// next takes the next event and, like the core, marks it handled.
func next(t *testing.T, out <-chan plugin.PlatformEvent) plugin.EventKind {
	t.Helper()
	select {
	case ev := <-out:
		if ev.Source != "logind" {
			t.Fatalf("source %q", ev.Source)
		}
		ev.Handled()
		return ev.Kind
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
		return ""
	}
}

func TestLogindReportsEveryEventKind(t *testing.T) {
	addr := privateBus(t)
	f := startLogind(t, addr, []session{
		{ID: "1", UID: 1000, User: "dev", Path: minePath},
		{ID: "2", UID: 1001, User: "other", Path: otherPath},
	})
	out, _, _ := run(t, addr)
	if k := next(t, out); k != plugin.EventReady {
		t.Fatalf("first event %q", k)
	}

	// Another user's session locking or ending is none of our business.
	f.emit(t, otherPath, sessionIface+".Lock")
	f.emit(t, otherPath, propsIface+".PropertiesChanged", sessionIface, map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)}, []string{})
	f.emit(t, managerPath, managerIface+".SessionRemoved", "2", otherPath)

	steps := []struct {
		path dbus.ObjectPath
		name string
		args []any
		want plugin.EventKind
	}{
		{managerPath, managerIface + ".PrepareForSleep", []any{true}, plugin.EventSleep},
		{minePath, sessionIface + ".Lock", nil, plugin.EventScreenLock},
		{minePath, propsIface + ".PropertiesChanged", []any{sessionIface, map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(true)}, []string{}}, plugin.EventScreenLock},
		{managerPath, managerIface + ".SessionRemoved", []any{"1", minePath}, plugin.EventSessionEnd},
	}
	// Waking and unlocking change nothing, so they are never reported. Each
	// is sent before a step that is, so a stray event would show up first.
	quiet := map[int][]func(){
		1: {func() { f.emit(t, managerPath, managerIface+".PrepareForSleep", false) }},
		2: {func() { f.emit(t, minePath, sessionIface+".Unlock") }},
		3: {func() {
			f.emit(t, minePath, propsIface+".PropertiesChanged", sessionIface, map[string]dbus.Variant{"LockedHint": dbus.MakeVariant(false)}, []string{})
		}},
	}
	for i, st := range steps {
		for _, emit := range quiet[i] {
			emit()
		}
		f.emit(t, st.path, st.name, st.args...)
		if k := next(t, out); k != st.want {
			t.Fatalf("%s: got %q, want %q", st.name, k, st.want)
		}
	}
	// One delay lock at start, and another after waking for the next suspend.
	f.mu.Lock()
	if f.inhibits != 2 {
		t.Fatalf("%d delay locks taken, want 2", f.inhibits)
	}
	f.mu.Unlock()

	// A session that starts later is followed too.
	f.mu.Lock()
	f.list = append(f.list, session{ID: "3", UID: 1000, Path: "/org/freedesktop/login1/session/_33"})
	f.mu.Unlock()
	f.emit(t, managerPath, managerIface+".SessionNew", "3", dbus.ObjectPath("/org/freedesktop/login1/session/_33"))
	f.emit(t, "/org/freedesktop/login1/session/_33", sessionIface+".Lock")
	if k := next(t, out); k != plugin.EventScreenLock {
		t.Fatalf("new session lock: %q", k)
	}
}

// Suspend waits for the core: the sleep inhibitor is released, and the
// next signal read, only once the core has handled the sleep, or after
// HandledWait if it never does.
func TestLogindHoldsSleepUntilHandled(t *testing.T) {
	for _, tc := range []struct {
		name   string
		wait   time.Duration
		handle bool
	}{
		{"handled", time.Hour, true},
		{"timeout", 200 * time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := privateBus(t)
			f := startLogind(t, addr, []session{{ID: "1", UID: 1000, Path: minePath}})
			src := &Source{Dial: func() (*dbus.Conn, error) { return dbus.Connect(addr) }, UID: 1000, HandledWait: tc.wait}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			out := make(chan plugin.PlatformEvent, 16)
			go src.Run(ctx, out)
			next(t, out)

			f.emit(t, managerPath, managerIface+".PrepareForSleep", true)
			var sleep plugin.PlatformEvent
			select {
			case sleep = <-out:
			case <-time.After(5 * time.Second):
				t.Fatal("no sleep event")
			}
			start := time.Now()
			f.emit(t, minePath, sessionIface+".Lock")
			window := 5 * time.Second // the timeout case reports well before
			if tc.handle {
				window = 300 * time.Millisecond
			}
			select {
			case ev := <-out:
				if tc.handle || time.Since(start) < tc.wait/2 {
					t.Fatalf("%s reported while the sleep was still unhandled", ev.Kind)
				}
			case <-time.After(window):
				if !tc.handle {
					t.Fatal("source held sleep past HandledWait")
				}
				sleep.Handled()
				if k := next(t, out); k != plugin.EventScreenLock {
					t.Fatalf("after the sleep was handled: %q", k)
				}
			}
		})
	}
}

// A process that isn't logind can't send events, even with logind's
// interface names: neither broadcast, where the bus's match rules filter by
// sender, nor addressed straight to the source's connection, which match
// rules don't filter.
func TestLogindIgnoresSignalsFromOthers(t *testing.T) {
	addr := privateBus(t)
	f := startLogind(t, addr, []session{{ID: "1", UID: 1000, Path: minePath}})
	var mu sync.Mutex
	var srcConn *dbus.Conn
	src := &Source{UID: 1000, Dial: func() (*dbus.Conn, error) {
		c, err := dbus.Connect(addr)
		mu.Lock()
		srcConn = c
		mu.Unlock()
		return c, err
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := make(chan plugin.PlatformEvent, 16)
	go src.Run(ctx, out)
	next(t, out)
	mu.Lock()
	dest := srcConn.Names()[0]
	mu.Unlock()

	impostor, err := dbus.Connect(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer impostor.Close()
	impostor.Emit(minePath, sessionIface+".Lock")
	impostor.Emit(managerPath, managerIface+".PrepareForSleep", true)
	direct := func(path dbus.ObjectPath, iface, member string, body ...any) {
		msg := &dbus.Message{Type: dbus.TypeSignal, Headers: map[dbus.HeaderField]dbus.Variant{
			dbus.FieldPath:        dbus.MakeVariant(path),
			dbus.FieldInterface:   dbus.MakeVariant(iface),
			dbus.FieldMember:      dbus.MakeVariant(member),
			dbus.FieldDestination: dbus.MakeVariant(dest),
		}, Body: body}
		if len(body) > 0 {
			msg.Headers[dbus.FieldSignature] = dbus.MakeVariant(dbus.SignatureOf(body...))
		}
		if call := impostor.Send(msg, nil); call.Err != nil {
			t.Fatal(call.Err)
		}
	}
	direct(minePath, sessionIface, "Lock")
	direct(managerPath, managerIface, "PrepareForSleep", true)

	// Something only logind sends, to show nothing came before it.
	f.emit(t, managerPath, managerIface+".SessionRemoved", "1", minePath)
	if k := next(t, out); k != plugin.EventSessionEnd {
		t.Fatalf("got %q from an impostor", k)
	}
}

// Losing the bus is a failure, so the service turns reuse off; a cancelled
// context is a normal stop.
func TestLogindFailureAndStop(t *testing.T) {
	addr := privateBus(t)
	startLogind(t, addr, nil)
	out, errc, cancel := run(t, addr)
	next(t, out)
	cancel()
	if err := <-errc; err != nil {
		t.Fatalf("stop returned %v", err)
	}

	src := &Source{Dial: func() (*dbus.Conn, error) { return dbus.Connect(addr) }, UID: 1000}
	var conn *dbus.Conn
	src.Dial = func() (*dbus.Conn, error) {
		c, err := dbus.Connect(addr)
		conn = c
		return c, err
	}
	out2 := make(chan plugin.PlatformEvent, 4)
	errc2 := make(chan error, 1)
	go func() { errc2 <- src.Run(context.Background(), out2) }()
	next(t, out2)
	conn.Close()
	select {
	case err := <-errc2:
		if err == nil {
			t.Fatal("bus loss reported as a normal stop")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't return after the bus closed")
	}

	// No logind on the bus: Run fails before ready.
	empty := privateBus(t)
	src = &Source{Dial: func() (*dbus.Conn, error) { return dbus.Connect(empty) }, UID: 1000}
	if err := src.Run(context.Background(), make(chan plugin.PlatformEvent, 1)); err == nil {
		t.Fatal("ran without logind")
	}
}

// A wake is followed by a wake, without a sleep between them, when a
// suspend fails or another inhibitor cancels it. Each takes a new delay
// lock, so the one before must go: a lock left open would delay every
// later suspend until logind stopped waiting.
func TestLogindHoldsOneSleepInhibitor(t *testing.T) {
	addr := privateBus(t)
	f := startLogind(t, addr, []session{{ID: "1", UID: 1000, Path: minePath}})
	out, _, _ := run(t, addr)
	next(t, out)
	for range 3 {
		f.emit(t, managerPath, managerIface+".PrepareForSleep", false)
	}
	// Something reported, so every wake before it has been handled.
	f.emit(t, minePath, sessionIface+".Lock")
	if k := next(t, out); k != plugin.EventScreenLock {
		t.Fatalf("got %q", k)
	}
	if n := f.held(); n != 1 {
		t.Fatalf("%d delay locks held, want 1", n)
	}

	// A sleep releases the lock; the wake after it takes one again.
	f.emit(t, managerPath, managerIface+".PrepareForSleep", true)
	if k := next(t, out); k != plugin.EventSleep {
		t.Fatalf("got %q", k)
	}
	f.emit(t, managerPath, managerIface+".PrepareForSleep", false)
	f.emit(t, minePath, sessionIface+".Lock")
	next(t, out)
	if n := f.held(); n != 1 {
		t.Fatalf("after sleep and wake: %d delay locks held, want 1", n)
	}
}

// When org.freedesktop.login1 changes owner, as when logind restarts, the
// new logind's signals come from a name the source doesn't follow. Run
// fails instead of carrying on deaf, so the core wipes, turns reuse off
// and starts the source again, which then follows the new logind.
func TestLogindOwnerChangeEndsRun(t *testing.T) {
	addr := privateBus(t)
	old := startLogind(t, addr, []session{{ID: "1", UID: 1000, Path: minePath}})
	out, errc, _ := run(t, addr)
	next(t, out)

	old.conn.Close()
	f := startLogind(t, addr, []session{{ID: "1", UID: 1000, Path: minePath}})
	f.emit(t, minePath, sessionIface+".Lock")
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "changed owner") {
			t.Fatalf("Run returned %v", err)
		}
	case ev := <-out:
		t.Fatalf("reported %q and kept running", ev.Kind)
	case <-time.After(5 * time.Second):
		t.Fatal("Run kept running after logind changed owner")
	}

	// Started again, it follows the new logind.
	out, _, _ = run(t, addr)
	next(t, out)
	f.emit(t, minePath, sessionIface+".Lock")
	if k := next(t, out); k != plugin.EventScreenLock {
		t.Fatalf("after restart: %q", k)
	}
}
