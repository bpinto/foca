// Package logind reports sleep, screen lock and session end from
// systemd-logind over the system D-Bus (design §4.5).
//
// Only signals sent by org.freedesktop.login1 are matched. The bus resolves
// that name to logind's unique name, so another process on the bus can't
// fake an event. Faking one would only cause a wipe anyway. When that name
// changes owner, as when logind restarts, Run fails, and the core wipes
// and starts it again with the new owner.
package logind

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/sysbus"
)

const (
	busName      = "org.freedesktop.login1"
	dbusName     = "org.freedesktop.DBus"
	managerPath  = dbus.ObjectPath("/org/freedesktop/login1")
	managerIface = "org.freedesktop.login1.Manager"
	sessionIface = "org.freedesktop.login1.Session"
	propsIface   = "org.freedesktop.DBus.Properties"
)

// Source follows logind for one user's sessions.
type Source struct {
	// Dial connects to the bus; tests point it at a private one.
	Dial func() (*dbus.Conn, error)
	UID  int
	// HandledWait bounds how long suspend waits for the core to wipe;
	// zero means plugin.HandledWait.
	HandledWait time.Duration
}

func (s *Source) handledWait() time.Duration {
	if s.HandledWait > 0 {
		return s.HandledWait
	}
	return plugin.HandledWait
}

func New() *Source {
	return &Source{Dial: sysbus.Connect, UID: os.Getuid()}
}

func (s *Source) Name() string { return "logind" }

// session is one entry of Manager.ListSessions.
type session struct {
	ID   string
	UID  uint32
	User string
	Seat string
	Path dbus.ObjectPath
}

// Run subscribes, sends EventReady, then reports events until ctx ends or
// the bus connection fails.
func (s *Source) Run(ctx context.Context, out chan<- plugin.PlatformEvent) error {
	conn, err := s.Dial()
	if err != nil {
		return fmt.Errorf("logind: connect: %w", err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	signals := make(chan *dbus.Signal, 64)
	conn.Signal(signals)
	matches := [][]dbus.MatchOption{
		{dbus.WithMatchInterface(managerIface), dbus.WithMatchMember("PrepareForSleep")},
		{dbus.WithMatchInterface(managerIface), dbus.WithMatchMember("SessionNew")},
		{dbus.WithMatchInterface(managerIface), dbus.WithMatchMember("SessionRemoved")},
		{dbus.WithMatchInterface(sessionIface), dbus.WithMatchMember("Lock")},
		{dbus.WithMatchInterface(propsIface), dbus.WithMatchMember("PropertiesChanged"), dbus.WithMatchArg(0, sessionIface)},
	}
	for _, m := range matches {
		if err := conn.AddMatchSignalContext(ctx, append(m, dbus.WithMatchSender(busName))...); err != nil {
			return s.stopped(ctx, fmt.Errorf("logind: subscribe: %w", err))
		}
	}
	// A logind that restarts has a new unique name, whose signals the
	// sender check below would drop. Any change of owner ends Run instead,
	// so the core wipes and starts the source again. This is subscribed
	// before the owner is read, so no change can fall in between.
	if err := conn.AddMatchSignalContext(ctx, dbus.WithMatchSender(dbusName), dbus.WithMatchInterface(dbusName),
		dbus.WithMatchMember("NameOwnerChanged"), dbus.WithMatchArg(0, busName)); err != nil {
		return s.stopped(ctx, fmt.Errorf("logind: subscribe: %w", err))
	}
	// The sender in each signal is logind's unique name; anything else is
	// ignored even if a match rule let it through.
	var owner string
	if err := conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, busName).Store(&owner); err != nil {
		return s.stopped(ctx, fmt.Errorf("logind: not running: %w", err))
	}
	mine, err := s.sessions(ctx, conn)
	if err != nil {
		return s.stopped(ctx, err)
	}
	inhibit := s.inhibit(ctx, conn)
	defer func() { inhibit.Close() }()

	send := func(k plugin.EventKind) (plugin.PlatformEvent, error) {
		ev := plugin.PlatformEvent{Kind: k, At: time.Now(), Source: "logind", Done: make(chan struct{})}
		select {
		case out <- ev:
			return ev, nil
		case <-ctx.Done():
			return ev, ctx.Err()
		}
	}
	if _, err := send(plugin.EventReady); err != nil {
		return nil
	}

	for {
		var sig *dbus.Signal
		select {
		case <-ctx.Done():
			return nil
		case sig = <-signals:
		}
		if sig == nil {
			return s.stopped(ctx, errors.New("logind: bus connection closed"))
		}
		// Only the bus itself sends as org.freedesktop.DBus.
		if sig.Sender == dbusName && sig.Name == dbusName+".NameOwnerChanged" {
			name, _ := arg[string](sig, 0)
			now, _ := arg[string](sig, 2)
			if name == busName && now != owner {
				return s.stopped(ctx, fmt.Errorf("logind: %s changed owner from %s to %q", busName, owner, now))
			}
			continue
		}
		if sig.Sender != owner {
			continue
		}
		var kind plugin.EventKind
		switch sig.Name {
		case managerIface + ".PrepareForSleep":
			start, _ := arg[bool](sig, 0)
			if !start {
				// Awake: hold the delay lock again for the next suspend.
				// One wake can follow another, so drop any lock still held
				// first: one left open would delay every suspend until
				// logind gives up waiting (InhibitDelayMaxSec).
				inhibit.Close()
				inhibit = s.inhibit(ctx, conn)
				continue
			}
			// Report first, wait until the core has wiped (at most
			// HandledWait), then let the machine sleep.
			ev, err := send(plugin.EventSleep)
			if err != nil {
				return nil
			}
			ev.WaitHandled(ctx, s.handledWait())
			inhibit.Close()
			inhibit = inhibitor{}
			continue
		case managerIface + ".SessionNew":
			fresh, err := s.sessions(ctx, conn)
			if err != nil {
				return s.stopped(ctx, err)
			}
			mine = fresh
			continue
		case managerIface + ".SessionRemoved":
			p, ok := arg[dbus.ObjectPath](sig, 1)
			if !ok || !mine[p] {
				continue
			}
			delete(mine, p)
			kind = plugin.EventSessionEnd
		case sessionIface + ".Lock":
			if !mine[sig.Path] {
				continue
			}
			kind = plugin.EventScreenLock
		case propsIface + ".PropertiesChanged":
			if !mine[sig.Path] {
				continue
			}
			changed, _ := arg[map[string]dbus.Variant](sig, 1)
			v, ok := changed["LockedHint"]
			if !ok {
				continue
			}
			if locked, _ := v.Value().(bool); !locked {
				continue // unlocking changes nothing
			}
			kind = plugin.EventScreenLock
		default:
			continue
		}
		if _, err := send(kind); err != nil {
			return nil
		}
	}
}

// stopped is the error to return: none if ctx ended, since that is a
// normal stop.
func (s *Source) stopped(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// sessions lists the object paths of this user's sessions.
func (s *Source) sessions(ctx context.Context, conn *dbus.Conn) (map[dbus.ObjectPath]bool, error) {
	var list []session
	if err := conn.Object(busName, managerPath).CallWithContext(ctx, managerIface+".ListSessions", 0).Store(&list); err != nil {
		return nil, fmt.Errorf("logind: list sessions: %w", err)
	}
	out := map[dbus.ObjectPath]bool{}
	for _, se := range list {
		if int(se.UID) == s.UID {
			out[se.Path] = true
		}
	}
	return out, nil
}

// inhibitor holds a logind "delay" lock, so suspend waits until the
// sleep event has been handled. Without one (no permission, or logind
// refuses), the event still arrives, and the watchdog is the backstop.
type inhibitor struct{ f *os.File }

func (i inhibitor) Close() {
	if i.f != nil {
		i.f.Close()
	}
}

func (s *Source) inhibit(ctx context.Context, conn *dbus.Conn) inhibitor {
	var fd dbus.UnixFD
	err := conn.Object(busName, managerPath).CallWithContext(ctx, managerIface+".Inhibit", 0,
		"sleep", "foca", "Wipe approval grants before sleep", "delay").Store(&fd)
	if err != nil {
		return inhibitor{}
	}
	return inhibitor{f: os.NewFile(uintptr(fd), "logind-inhibit")}
}

func arg[T any](sig *dbus.Signal, i int) (T, bool) {
	var zero T
	if i >= len(sig.Body) {
		return zero, false
	}
	v, ok := sig.Body[i].(T)
	return v, ok
}
