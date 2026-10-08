//go:build !linux

package relay

import (
	"errors"
	"net"
)

// The relay reads callers from /proc: it runs inside a Linux realm (a VM, or
// a container runtime's VM), never on the host.
func identifyCaller(*net.UnixConn) (Caller, error) {
	return nil, errors.New("the guest relay runs only inside a Linux realm")
}
