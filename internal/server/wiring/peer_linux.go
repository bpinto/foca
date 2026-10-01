//go:build linux

package wiring

import (
	"fmt"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/peer"
)

func peerIdentifier(name string) (plugin.PeerIdentifier, error) {
	switch name {
	case "auto", "linux":
		return peer.NewLinux(), nil
	default:
		return nil, fmt.Errorf("peer_identifier %q is not available on linux", name)
	}
}
