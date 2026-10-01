package peer

import (
	"net"
	"sync"

	"github.com/bpinto/foca/internal/identity"
)

// Static returns a fixed identity for every connection. Tests use it to
// simulate peers the real kernel can't produce, such as another uid or an ssh
// proxy.
type Static struct {
	mu   sync.Mutex
	Peer identity.VerifiedPeer
	Err  error
}

func (s *Static) Set(p identity.VerifiedPeer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Peer = p
}

func (s *Static) Identify(*net.UnixConn) (identity.VerifiedPeer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Peer, s.Err
}
