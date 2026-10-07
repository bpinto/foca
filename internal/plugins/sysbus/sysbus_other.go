//go:build !linux

package sysbus

import (
	"errors"

	"github.com/godbus/dbus/v5"
)

func connect(string, int) (*dbus.Conn, error) {
	return nil, errors.New("system bus: used only on Linux")
}
