//go:build !linux && !darwin

package client

import (
	"errors"
	"net"
)

// serverUID can't be read on this OS, so DialOwn refuses every socket.
var serverUID = func(net.Conn) (int, error) {
	return 0, errors.New("peer credentials are not supported on this OS")
}
