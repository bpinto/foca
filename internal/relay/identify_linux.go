//go:build linux

package relay

import (
	"net"

	"github.com/bpinto/foca/internal/plugins/peer"
)

func identifyCaller(conn *net.UnixConn) (Caller, error) {
	return peer.NewLinux().IdentifyCaller(conn)
}
