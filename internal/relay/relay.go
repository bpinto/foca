// Package relay is the guest relay (design §14). It runs inside a realm the
// host can't see into, as a user of its own, and is the only process that
// can reach the forwarded socket. For each caller it reads who is asking from
// the realm's kernel and forwards the caller's requests upstream with that
// identity as guest_verified.
//
// One downstream connection gets one upstream connection, opened with its
// first request and never shared, so connection scope means the same with
// or without the relay. Requests are decoded with the host's strict rules and
// re-encoded; raw bytes are never edited or scanned. A request that already
// carries guest_verified is refused, not forwarded.
package relay

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"syscall"
	"time"

	"github.com/bpinto/foca/internal/client"
	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/protocol"
)

// Caller is one downstream process, as the realm's kernel reports it.
type Caller interface {
	// Guest is the caller as read when it connected.
	Guest() identity.GuestInfo
	// Check fails once the caller has exited or its pid names another
	// process.
	Check() error
	Close()
}

type Options struct {
	// Listen is the socket the realm's processes use; Upstream the
	// forwarded socket only the relay's user can reach.
	Listen   string
	Upstream string
	Key      ed25519.PrivateKey
	// Identify reads the caller of a downstream connection. nil means the
	// Linux kernel's answer.
	Identify func(*net.UnixConn) (Caller, error)
	Log      *slog.Logger
	// UID and EUID are the relay's own; tests set them.
	UID, EUID func() int
	// MaxConnections bounds the callers served at once, and MaxPerUser
	// those of one uid, so one user of the realm can't take every
	// upstream connection the host allows. 0 means the default.
	MaxConnections, MaxPerUser int
	// IdleTimeout closes a caller that sends no complete request for
	// that long while none of its requests is in flight. 0 means the
	// default, the host's.
	IdleTimeout time.Duration
	// Now is the clock for refusal logging; tests set it.
	Now func() time.Time
}

type Relay struct {
	opts    Options
	l       *net.UnixListener
	wg      sync.WaitGroup
	refused *refusals

	mu     sync.Mutex
	active int
	perUID map[int]int
}

// Limits on callers. The defaults leave room under the host's
// max_connections (32 by default) for callers of other users.
const (
	DefaultMaxConnections = 32
	DefaultMaxPerUser     = 8
	MaxLimit              = 1024
	DefaultIdleTimeout    = 2 * time.Minute
)

// maxPipelined is how many requests a caller may send ahead of the one being
// forwarded, as on the host.
const maxPipelined = 4

// dialTimeout bounds the upstream connection and the relay's handshake.
const dialTimeout = 10 * time.Second

func New(opts Options) *Relay {
	if opts.Identify == nil {
		opts.Identify = identifyCaller
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.UID == nil {
		opts.UID = os.Getuid
	}
	if opts.EUID == nil {
		opts.EUID = os.Geteuid
	}
	if opts.MaxConnections == 0 {
		opts.MaxConnections = DefaultMaxConnections
	}
	if opts.MaxPerUser == 0 {
		opts.MaxPerUser = DefaultMaxPerUser
	}
	if opts.IdleTimeout == 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Relay{opts: opts, perUID: map[int]int{}, refused: &refusals{log: opts.Log, now: opts.Now, last: map[string]*window{}}}
}

// CheckSetup refuses to run in a setup that would let the realm's users reach
// the forwarded socket or the key (design §14, safeguard 5): the relay must
// not be root, and the upstream socket, if it exists yet, must be its user's
// alone. The host can't see any of this; the signature in relay.hello is the
// real guard. The key file is checked when it is loaded (LoadKey).
func (r *Relay) CheckSetup() error {
	if r.opts.EUID() == 0 {
		return errors.New("refusing to run as root: run the relay as a user of its own, the one ssh logs in as for the forwarded socket")
	}
	if err := r.checkUpstream(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := fsutil.CheckTrustedDir(filepath.Dir(r.opts.Listen)); err != nil {
		return fmt.Errorf("listen socket's directory: %w", err)
	}
	return nil
}

// checkUpstream: the forwarded socket is a socket, owned by the relay's user,
// and no one else may connect (ssh's StreamLocalBindMask 0177 makes it 0600).
// It runs at start and before every upstream connection, since ssh makes the
// socket again each time the host reconnects.
func (r *Relay) checkUpstream() error {
	fi, err := os.Lstat(r.opts.Upstream)
	if err != nil {
		return fmt.Errorf("upstream socket: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case fi.Mode()&os.ModeSocket == 0:
		return fmt.Errorf("upstream %s is not a socket", r.opts.Upstream)
	case !ok || int(st.Uid) != r.opts.UID():
		return fmt.Errorf("upstream socket %s is not owned by the relay's user (uid %d)", r.opts.Upstream, r.opts.UID())
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("upstream socket %s has mode %o: others could reach it without the relay; set StreamLocalBindMask 0177 for the relay's user in sshd_config",
			r.opts.Upstream, fi.Mode().Perm())
	}
	return nil
}

// Start checks the setup and listens. The listen socket is open to every
// user of the realm: that is its purpose.
func (r *Relay) Start() error {
	if err := r.CheckSetup(); err != nil {
		return err
	}
	if err := removeStale(r.opts.Listen); err != nil {
		return err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: r.opts.Listen, Net: "unix"})
	if err != nil {
		return err
	}
	if err := os.Chmod(r.opts.Listen, 0o666); err != nil {
		l.Close()
		return err
	}
	l.SetUnlinkOnClose(true)
	r.l = l
	return nil
}

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
		return fmt.Errorf("%s is in use by another running relay", path)
	}
	return os.Remove(path)
}

// Serve accepts callers until ctx ends, then closes every connection.
func (r *Relay) Serve(ctx context.Context) error {
	return r.serve(ctx, r.l)
}

// listener is what serve needs of the listen socket; tests fake it.
type listener interface {
	AcceptUnix() (*net.UnixConn, error)
	Close() error
}

func (r *Relay) serve(ctx context.Context, l listener) error {
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	var mu sync.Mutex
	conns := map[net.Conn]struct{}{}
	defer func() {
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
		r.wg.Wait()
		r.refused.flush()
	}()
	var delay time.Duration
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			// Out of file descriptors, say: retrying at once would spin.
			// Back off as the host does, 5 ms doubling up to 1 s.
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			r.opts.Log.Warn("accept failed", "err", err, "retry_in", delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		delay = 0
		if !r.take(-1) {
			// Turned away before identification, which costs a read of
			// /proc: a flood costs no more than the accept.
			r.refused.note("too_many_connections", nil)
			writeResp(conn, errResp(nil, protocol.NewError(protocol.CodeBusy, "the guest relay is serving too many callers; try again")))
			conn.Close()
			continue
		}
		mu.Lock()
		conns[conn] = struct{}{}
		mu.Unlock()
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			defer r.release(-1)
			defer func() {
				mu.Lock()
				delete(conns, conn)
				mu.Unlock()
				conn.Close()
			}()
			r.serveConn(ctx, conn)
		}()
	}
}

// take counts a caller against the limits: uid -1 for a connection not yet
// identified (the total), else one of uid's.
func (r *Relay) take(uid int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if uid < 0 {
		if r.active >= r.opts.MaxConnections {
			return false
		}
		r.active++
		return true
	}
	if r.perUID[uid] >= r.opts.MaxPerUser {
		return false
	}
	r.perUID[uid]++
	return true
}

func (r *Relay) release(uid int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if uid < 0 {
		r.active--
		return
	}
	if r.perUID[uid]--; r.perUID[uid] == 0 {
		delete(r.perUID, uid)
	}
}

// answer is one response from upstream, or why there is none.
type answer struct {
	b   []byte
	err error
}

// serveConn relays one caller over an upstream connection of its own,
// opened with its first request.
func (r *Relay) serveConn(ctx context.Context, down *net.UnixConn) {
	caller, err := r.opts.Identify(down)
	if err != nil {
		// No identity means nothing to vouch for: refused, never forwarded
		// with less.
		r.refused.note("unidentified", nil)
		return
	}
	defer caller.Close()
	g := caller.Guest()
	if !r.take(g.UID) {
		r.refused.note("too_many_for_user", &g)
		writeResp(down, errResp(nil, protocol.NewError(protocol.CodeBusy, "too many connections to the guest relay from uid %d; try again", g.UID)))
		return
	}
	defer r.release(g.UID)

	// A caller that hangs up closes the upstream connection at once, so the
	// host cancels a prompt it has open for it.
	cctx, hangUp := context.WithCancel(ctx)
	defer hangUp()
	lines := make(chan []byte, maxPipelined)
	go func() {
		defer close(lines)
		defer hangUp()
		br := bufio.NewReaderSize(down, 64*1024)
		for {
			line, err := protocol.ReadMessage(br)
			if errors.Is(err, protocol.ErrTooLarge) {
				r.refused.note("message_too_large", &g)
				writeResp(down, errResp(nil, protocol.NewError(protocol.CodeParseError, "message too large (max %d bytes)", protocol.MaxMessage)))
				return
			}
			if err != nil {
				return
			}
			select {
			case lines <- line:
			default:
				r.refused.note("too_many_pipelined", &g)
				down.Close()
				return
			}
		}
	}()

	var up *client.Client
	var answers chan answer
	idle := func() { down.SetReadDeadline(time.Now().Add(r.opts.IdleTimeout)) }
	idle()
	for line := range lines {
		// Nothing in flight is cut short by the idle timeout.
		down.SetReadDeadline(time.Time{})
		out, id, perr := Rewrite(line, g)
		if perr != nil {
			r.refused.note(reason(perr), &g)
			writeResp(down, errResp(id, perr))
			idle()
			continue
		}
		if out == nil {
			r.refused.note("notification", &g)
			idle()
			continue
		}
		// Just before forwarding: still the process that was identified
		// (design §14, safeguard 4).
		if err := caller.Check(); err != nil {
			r.refused.note("caller_gone", &g)
			return
		}
		if up == nil {
			if up, err = r.dial(cctx); err != nil {
				r.opts.Log.Error("upstream unavailable", "err", err)
				writeResp(down, errResp(id, protocol.NewError(protocol.CodeInternal, "the guest relay can't reach foca on the host")))
				return
			}
			defer up.Close()
			context.AfterFunc(cctx, func() { up.Close() })
			answers = make(chan answer, 1)
			go r.readUpstream(cctx, up, down, answers)
		}
		if err := up.WriteRaw(out); err != nil {
			return
		}
		a, ok := <-answers
		if !ok {
			return
		}
		if a.err != nil {
			// The host never sends more than a message; if it did, the
			// caller still gets an answer, not a cut connection.
			writeResp(down, errResp(id, protocol.NewError(protocol.CodeInternal, "the host's answer was larger than one message")))
			return
		}
		err = writeLine(down, a.b)
		zero(a.b)
		if err != nil {
			return
		}
		idle()
	}
}

// readUpstream passes the host's answers on. When the host closes the
// connection (a reload, ssh reconnecting, its idle timeout) the caller's
// connection closes too, rather than failing on its next request.
func (r *Relay) readUpstream(ctx context.Context, up *client.Client, down *net.UnixConn, answers chan<- answer) {
	defer close(answers)
	for {
		b, err := up.ReadRaw()
		if err != nil && !errors.Is(err, protocol.ErrTooLarge) {
			down.Close()
			return
		}
		select {
		case answers <- answer{b, err}:
		case <-ctx.Done():
			zero(b)
			return
		}
		if err != nil {
			return
		}
	}
}

// dial opens the caller's upstream connection and proves the relay to the
// host: relay.challenge, then relay.hello signed with the relay's key.
func (r *Relay) dial(ctx context.Context) (*client.Client, error) {
	if err := r.checkUpstream(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	c, err := client.Dial(ctx, r.opts.Upstream)
	if err != nil {
		return nil, err
	}
	var ch protocol.RelayChallengeResult
	if err := c.Call(ctx, protocol.MethodRelayChallenge, protocol.RelayChallengeParams{}, &ch); err != nil {
		c.Close()
		return nil, fmt.Errorf("relay.challenge: %w", err)
	}
	nonce, err := base64.StdEncoding.Strict().DecodeString(ch.Nonce)
	if err != nil || len(nonce) != protocol.NonceSize {
		c.Close()
		return nil, errors.New("relay.challenge: the host sent a malformed nonce")
	}
	sig := ed25519.Sign(r.opts.Key, protocol.RelayMessage(ch.Instance, ch.Connection, nonce))
	if err := c.Call(ctx, protocol.MethodRelayHello, protocol.RelayHelloParams{Signature: base64.StdEncoding.EncodeToString(sig)}, nil); err != nil {
		c.Close()
		return nil, fmt.Errorf("relay.hello: %w", err)
	}
	// The handshake had a deadline; answers to the caller may wait on a
	// prompt for as long as the host allows.
	c.SetDeadline(time.Time{})
	return c, nil
}

var paramsMapType = reflect.TypeOf(map[string]json.RawMessage{})

// Rewrite decodes one request from a caller and returns it re-encoded with
// guest_verified set to g. The envelope and params get the host's strict
// check (exact case, no duplicates, no unknown keys for the method), so
// nothing reaches the host that the two could read differently. A request
// that names guest_verified in any spelling, or calls the relay's own
// handshake, is refused. A method clients can't call is forwarded without
// its params, for the host to refuse and record by name. id is the
// request's id, for an error answer; a notification gives neither a
// request nor an error: it gets no answer. An error's Data.Reason says why,
// for the relay's log.
func Rewrite(line []byte, g identity.GuestInfo) (out []byte, id json.RawMessage, perr *protocol.Error) {
	refuse := func(code int, reason, format string, a ...any) *protocol.Error {
		e := protocol.NewError(code, format, a...)
		e.Data.Reason = reason
		return e
	}
	if !json.Valid(line) {
		return nil, nil, refuse(protocol.CodeParseError, "invalid_json", "invalid JSON")
	}
	req, err := protocol.DecodeRequest(line)
	if err != nil {
		return nil, nil, refuse(protocol.CodeInvalidRequest, "invalid_request", "%v", err)
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return nil, req.ID, refuse(protocol.CodeInvalidRequest, "invalid_request", "not a JSON-RPC 2.0 request")
	}
	if len(req.ID) == 0 {
		// Notifications aren't part of the protocol, and there is no one to
		// answer: dropped.
		return nil, nil, nil
	}
	if req.Method == protocol.MethodRelayChallenge || req.Method == protocol.MethodRelayHello {
		return nil, req.ID, refuse(protocol.CodeMethodNotFound, "relay_method", "%s is the guest relay's own", req.Method)
	}
	params := map[string]json.RawMessage{}
	if raw := req.Params; len(raw) > 0 && string(raw) != "null" {
		if err := protocol.CheckStrict(raw, paramsMapType); err != nil {
			return nil, req.ID, refuse(protocol.CodeInvalidParams, "invalid_params", "invalid params: %v", err)
		}
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, req.ID, refuse(protocol.CodeInvalidParams, "invalid_params", "params must be an object")
		}
		if exact, variant := protocol.GuestKey(raw); exact || variant {
			return nil, req.ID, refuse(protocol.CodeInvalidParams, "forged_guest_verified", "guest_verified is set only by the guest relay")
		}
		known, err := protocol.CheckParams(req.Method, raw)
		if err != nil {
			return nil, req.ID, refuse(protocol.CodeInvalidParams, "invalid_params", "invalid params: %v", err)
		}
		if !known {
			params = map[string]json.RawMessage{}
		}
	}
	gb, err := protocol.Marshal(g)
	if err != nil {
		return nil, req.ID, refuse(protocol.CodeInternal, "internal", "internal error")
	}
	params["guest_verified"] = gb
	pb, err := protocol.Marshal(params)
	if err != nil {
		return nil, req.ID, refuse(protocol.CodeInternal, "internal", "internal error")
	}
	out, err = protocol.Marshal(protocol.Request{JSONRPC: "2.0", ID: req.ID, Method: req.Method, Params: pb})
	if err != nil {
		return nil, req.ID, refuse(protocol.CodeInternal, "internal", "internal error")
	}
	if len(out) > protocol.MaxMessage {
		// The caller's identity made it too large: refused here, as the
		// host would, rather than cut off there.
		zero(out)
		return nil, req.ID, refuse(protocol.CodeParseError, "message_too_large", "message too large with the caller's identity added (max %d bytes)", protocol.MaxMessage)
	}
	return out, req.ID, nil
}

// reason is why the relay refused a request, for its log.
func reason(e *protocol.Error) string {
	if e.Data != nil && e.Data.Reason != "" {
		return e.Data.Reason
	}
	return protocol.CodeName(e.Code)
}

func errResp(id json.RawMessage, e *protocol.Error) protocol.Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return protocol.Response{JSONRPC: "2.0", ID: id, Error: e}
}

func writeResp(w net.Conn, resp protocol.Response) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	return writeLine(w, b)
}

// writeLine sends one line. Answers may hold secret values, so the copy is
// zeroed afterwards.
func writeLine(w net.Conn, b []byte) error {
	buf := append(append(make([]byte, 0, len(b)+1), b...), '\n')
	w.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err := w.Write(buf)
	zero(buf)
	return err
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// refusals logs what the relay refuses on its own, which the host never
// sees. Callers choose how often that happens, so, as the host coalesces
// such events (design §9.6), each reason gets one line per 10 s: the first
// in full, and the next one says how many were left out in between.
type refusals struct {
	log  *slog.Logger
	now  func() time.Time
	mu   sync.Mutex
	last map[string]*window
}

type window struct {
	start   time.Time
	omitted int
}

const refusalWindow = 10 * time.Second

// note logs a refusal for reason. g is the caller, nil if it wasn't
// identified; its name is its own choice, so it is sanitised.
func (r *refusals) note(reason string, g *identity.GuestInfo) {
	r.mu.Lock()
	now := r.now()
	w := r.last[reason]
	if w != nil && now.Sub(w.start) < refusalWindow {
		w.omitted++
		r.mu.Unlock()
		return
	}
	omitted := 0
	if w != nil {
		omitted = w.omitted
	}
	r.last[reason] = &window{start: now}
	r.mu.Unlock()
	attrs := []any{"reason", reason}
	if g != nil {
		attrs = append(attrs, "pid", g.PID, "uid", g.UID, "comm", identity.DisplayName(g.Name, 32))
	}
	if omitted > 0 {
		attrs = append(attrs, "omitted_before", omitted)
	}
	r.log.Warn("refused a caller", attrs...)
}

// flush logs the counts still held, as the relay stops.
func (r *refusals) flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for reason, w := range r.last {
		if w.omitted > 0 {
			r.log.Warn("refused a caller", "reason", reason, "omitted_before", w.omitted)
		}
	}
	r.last = map[string]*window{}
}
