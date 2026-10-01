//go:build !linux

package wiring

import (
	"fmt"
	"runtime"

	"github.com/bpinto/foca/internal/plugin"
)

func peerIdentifier(name string) (plugin.PeerIdentifier, error) {
	return nil, fmt.Errorf("no peer identifier for %s yet", runtime.GOOS)
}
