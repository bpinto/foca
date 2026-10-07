package sysbus

import (
	"fmt"
	"net"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

// connect dials the bus at path and checks, with SO_PEERCRED, that whoever
// listens there did so as uid.
func connect(path string, uid int) (*dbus.Conn, error) {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("system bus: %w", err)
	}
	raw, err := c.SyscallConn()
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("system bus: %w", err)
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		credErr = err
	}
	if credErr != nil {
		c.Close()
		return nil, fmt.Errorf("system bus: SO_PEERCRED: %w", credErr)
	}
	if int(cred.Uid) != uid {
		c.Close()
		return nil, fmt.Errorf("system bus: %s is served by uid %d, not %d; refusing it", path, cred.Uid, uid)
	}
	conn, err := dbus.ConnectUnix(c)
	if err != nil {
		return nil, fmt.Errorf("system bus: %w", err)
	}
	return conn, nil
}
