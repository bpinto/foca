// Package server runs the service: it owns one client socket per instance,
// identifies each connection and hands requests to the core pipeline.
// Nothing reachable through a socket changes state on the host; management
// is host CLI only (design §6.2).
package server

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/server/core"
)

type Options struct {
	Paths       config.Paths
	Instances   []config.Instance
	OpaquePeers []string
	Core        *core.Service
	Peers       plugin.PeerIdentifier
	Version     string
	Log         *slog.Logger
	// MaxConnections is per instance; IdleTimeout closes a connection that
	// sends no complete request for that long. Zero means the config default.
	MaxConnections int
	IdleTimeout    time.Duration
	// WriteTimeout closes a connection whose client doesn't take a response
	// for that long. Zero means DefaultWriteTimeout.
	WriteTimeout time.Duration
	// Events reports sleep and lock so grants can be wiped. nil means
	// none, and reuse stays off.
	Events plugin.PlatformEvents
}

// DefaultWriteTimeout bounds each response write (design §9.6.1).
const DefaultWriteTimeout = 10 * time.Second

type Server struct {
	opts      Options
	ctx       context.Context
	cancel    context.CancelFunc
	listeners []*net.UnixListener
	wg        sync.WaitGroup
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	stopOnce  sync.Once
	done      chan struct{}
	guardDone <-chan struct{}
	uid       int
}

func New(opts Options) *Server {
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.MaxConnections == 0 {
		opts.MaxConnections = config.DefaultMaxConnections
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = config.DefaultIdleTimeout
	}
	if opts.WriteTimeout == 0 {
		opts.WriteTimeout = DefaultWriteTimeout
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{opts: opts, ctx: ctx, cancel: cancel, conns: map[net.Conn]struct{}{},
		done: make(chan struct{}), uid: os.Getuid()}
}

// Start creates the runtime directories and sockets and begins accepting.
func (s *Server) Start() error {
	if err := fsutil.EnsurePrivateDir(s.opts.Paths.RuntimeDir); err != nil {
		return fmt.Errorf("runtime dir: %w", err)
	}
	for _, inst := range s.opts.Instances {
		ci, ok := s.opts.Core.Instance(inst.Name)
		if !ok {
			return fmt.Errorf("instance %s missing from core", inst.Name)
		}
		if err := fsutil.EnsurePrivateDir(s.opts.Paths.InstanceDir(inst.Name)); err != nil {
			return fmt.Errorf("instance %s dir: %w", inst.Name, err)
		}
		l, err := listen(s.opts.Paths.ClientSocket(inst.Name))
		if err != nil {
			s.closeListeners()
			return fmt.Errorf("instance %s socket: %w", inst.Name, err)
		}
		s.listeners = append(s.listeners, l)
		s.wg.Add(1)
		go s.acceptLoop(l, ci)
	}
	e := &audit.Event{Type: audit.TypeServerStart, Outcome: audit.OutcomeOK, Reason: s.opts.Version}
	if _, err := s.opts.Core.Audit().Append(s.ctx, e); err != nil {
		s.closeListeners()
		return fmt.Errorf("audit: %w", err)
	}
	s.guardDone = s.opts.Core.Guard(s.ctx, s.opts.Events, s.opts.Log)
	return nil
}

// listen binds a socket inside an already-verified 0700 directory, so there
// is no window where another user could connect before the chmod.
func listen(path string) (*net.UnixListener, error) {
	if err := config.CheckSocketPath(path); err != nil {
		return nil, err
	}
	if err := removeStale(path); err != nil {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	return l, nil
}

// removeStale deletes a leftover socket from a previous run. It refuses to
// delete anything that isn't a socket and refuses to take over a socket that
// another process is still serving.
func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s exists and is not a socket; refusing to remove it", path)
	}
	if c, err := net.DialTimeout("unix", path, 200*time.Millisecond); err == nil {
		c.Close()
		return fmt.Errorf("%s is in use by another running service", path)
	}
	return os.Remove(path)
}

// acceptor is what acceptLoop needs of a listener; tests fake it.
type acceptor interface {
	AcceptUnix() (*net.UnixConn, error)
}

func (s *Server) acceptLoop(l acceptor, inst *core.Instance) {
	defer s.wg.Done()
	var active atomic.Int64
	var delay time.Duration
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// Out of file descriptors, say: retrying at once would spin.
			// Back off as net/http does, 5 ms doubling up to 1 s.
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			s.opts.Log.Warn("accept failed", "err", err, "retry_in", delay)
			select {
			case <-time.After(delay):
			case <-s.ctx.Done():
				return
			}
			continue
		}
		delay = 0
		if active.Load() >= int64(s.opts.MaxConnections) {
			// Closed before identification: cheap, so a flood can't cost
			// more than the accept. The rejection is coalesced in audit.
			conn.Close()
			s.reject(inst, "too_many_connections", nil)
			continue
		}
		s.mu.Lock()
		if s.ctx.Err() != nil {
			s.mu.Unlock()
			conn.Close()
			return
		}
		active.Add(1)
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go func() {
			defer s.wg.Done()
			defer active.Add(-1)
			defer func() {
				s.mu.Lock()
				delete(s.conns, conn)
				s.mu.Unlock()
				conn.Close()
			}()
			s.serveConn(conn, inst)
		}()
	}
}

// admit identifies the peer and applies connection-level checks. A refused
// connection is audited and closed without a response.
func (s *Server) admit(conn *net.UnixConn, inst *core.Instance) (identity.VerifiedPeer, bool) {
	p, err := s.opts.Peers.Identify(conn)
	reject := func(reason string, peer *identity.VerifiedPeer) { s.reject(inst, reason, peer) }
	if err != nil {
		reject("peer_unidentified", nil)
		return p, false
	}
	p.Opaque = inst.Realm.Peers == identity.PeersOpaque
	container := p.Realm.ContainerID
	p.Realm = inst.Realm
	if inst.Realm.Kind == identity.RealmContainer && !p.Opaque {
		// An opaque peer's cgroup is the proxy's, not the caller's.
		p.Realm.ContainerID = container
	}
	if p.UID != s.uid {
		reject("uid_mismatch", &p)
		return p, false
	}
	if !p.Opaque && s.isOpaquePeer(p) {
		// A proxy on a direct realm. Refuse instead of reinterpreting, so
		// "let ssh use…" can't appear on the prompt.
		reject("opaque_peer_on_direct_realm", &p)
		return p, false
	}
	if p.Opaque && !s.isProxy(p) {
		// The other direction: an opaque realm's peer must be a known proxy.
		// Otherwise a host process on the VM's socket would be prompted as
		// "in VM dev". Only the exe counts here; comm is set by the process.
		reject("direct_peer_on_opaque_realm", &p)
		return p, false
	}
	return p, true
}

// reject records a refused connection. Bursts are coalesced by the core, and
// the connection is refused whether or not the record succeeds.
func (s *Server) reject(inst *core.Instance, reason string, peer *identity.VerifiedPeer) {
	e := &audit.Event{Type: audit.TypeRequestRejected, Outcome: audit.OutcomeRejected,
		Instance: inst.Name, Origin: audit.OriginClientSocket, Reason: reason}
	if peer != nil {
		e.Peer = &audit.Peer{Verified: peer}
	}
	if _, err := s.opts.Core.RecordRejection(s.ctx, e); err != nil {
		s.opts.Log.Error("audit failed for rejected connection", "err", err)
	}
	s.opts.Log.Warn("connection refused", "instance", inst.Name, "reason", reason)
}

// proxyName is how both proxy checks name a peer's exe: Nix wrapper
// unwrapped, and without the " (deleted)" mark Linux adds once the file is
// replaced, as a package upgrade does to a long-running ssh.
func proxyName(exe string) string {
	return identity.DisplayName(strings.TrimSuffix(exe, " (deleted)"), 64)
}

// isProxy reports whether the peer's exe is listed in opaque_peers.
func (s *Server) isProxy(p identity.VerifiedPeer) bool {
	return listed(s.opts.OpaquePeers, proxyName(p.Exe))
}

// isOpaquePeer reports whether the peer looks like a proxy by its exe or by
// its comm. Either is enough to refuse it on a direct realm.
func (s *Server) isOpaquePeer(p identity.VerifiedPeer) bool {
	return listed(s.opts.OpaquePeers, proxyName(p.Exe)) || listed(s.opts.OpaquePeers, identity.DisplayName(p.Name, 64))
}

func listed(names []string, name string) bool {
	return name != "" && slices.Contains(names, name)
}

// Shutdown stops accepting, cancels in-flight work, closes connections and
// records server.stop. Safe to call more than once.
func (s *Server) Shutdown(reason string) {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.cancel()
		for c := range s.conns {
			c.Close()
		}
		s.mu.Unlock()
		s.closeListeners()
		s.wg.Wait()
		// Grants never outlive the service, and a reload starts with none.
		if s.guardDone != nil {
			<-s.guardDone
		}
		wipe := core.WipeShutdown
		if reason == "reload" {
			wipe = core.WipeReload
		}
		if err := s.opts.Core.Wipe(context.Background(), wipe, nil); err != nil {
			s.opts.Log.Error("audit failed for lock", "err", err)
		}
		if err := s.opts.Core.FlushRejections(context.Background()); err != nil {
			s.opts.Log.Error("audit failed for coalesced rejections", "err", err)
		}
		e := &audit.Event{Type: audit.TypeServerStop, Outcome: audit.OutcomeOK, Reason: reason}
		if _, err := s.opts.Core.Audit().Append(context.Background(), e); err != nil {
			s.opts.Log.Error("audit failed for server.stop", "err", err)
		}
		close(s.done)
	})
}

// Done is closed once Shutdown has finished.
func (s *Server) Done() <-chan struct{} { return s.done }

func (s *Server) closeListeners() {
	for _, l := range s.listeners {
		l.Close()
	}
}
