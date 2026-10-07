// Package sysbus connects to the system D-Bus, where logind and polkit are
// (design §4.1.2, §4.5).
//
// What foca trusts on that bus is the bus's own policy: only logind may own
// org.freedesktop.login1, and only polkitd org.freedesktop.PolicyKit1. So
// the bus must be the system's. It is dialled at its fixed path, never at
// DBUS_SYSTEM_BUS_ADDRESS, which anything that starts foca could set, and
// the daemon on the other end must have opened the socket as root.
package sysbus

import "github.com/godbus/dbus/v5"

// Path is the system bus's socket.
const Path = "/run/dbus/system_bus_socket"

// testBus, set only in test builds, names a private bus to use instead.
var testBus func() string

// Connect connects to the system bus.
func Connect() (*dbus.Conn, error) {
	if testBus != nil {
		if addr := testBus(); addr != "" {
			return dbus.Connect(addr)
		}
	}
	return connect(Path, 0)
}
