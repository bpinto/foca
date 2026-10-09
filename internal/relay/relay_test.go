//go:build linux

package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/client"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/plugins/peer"
	"github.com/bpinto/foca/internal/plugins/provider/static"
	"github.com/bpinto/foca/internal/plugins/store/memory"
	"github.com/bpinto/foca/internal/protocol"
	"github.com/bpinto/foca/internal/server"
	"github.com/bpinto/foca/internal/server/core"
)

var guest = identity.GuestInfo{Source: "SO_PEERCRED+SO_PEERPIDFD", PID: 812, StartTime: 9, UID: 1000,
	Name: "gh", PIDStable: true, Session: "sid:780:1"}

func TestRewriteAddsGuestVerifiedAndKeepsTheRest(t *testing.T) {
	out, id, perr := Rewrite([]byte(`{"jsonrpc":"2.0","id":"a","method":"secret.read","params":{"names":["dev:x"],"client":{"name":"aws","target":{"exe":"/usr/bin/aws","argv0":"aws"}}}}`), guest)
	if perr != nil || string(id) != `"a"` {
		t.Fatalf("%v %s", perr, id)
	}
	var req struct {
		ID     string `json:"id"`
		Method string `json:"method"`
		Params struct {
			Names  []string            `json:"names"`
			Client identity.ClientInfo `json:"client"`
			Guest  *identity.GuestInfo `json:"guest_verified"`
		} `json:"params"`
	}
	if err := json.Unmarshal(out, &req); err != nil {
		t.Fatal(err)
	}
	if req.ID != "a" || req.Method != "secret.read" || req.Params.Names[0] != "dev:x" || req.Params.Client.Name != "aws" ||
		req.Params.Client.Target == nil || req.Params.Client.Target.Exe != "/usr/bin/aws" ||
		req.Params.Guest == nil || req.Params.Guest.PID != 812 {
		t.Fatalf("forwarded %s", out)
	}
	// No params at all still carry the caller.
	out, _, perr = Rewrite([]byte(`{"jsonrpc":"2.0","id":1,"method":"secret.list"}`), guest)
	if perr != nil || !strings.Contains(string(out), `"guest_verified":{`) {
		t.Fatalf("%v %s", perr, out)
	}
}

// A caller can't bring its own guest_verified, however it spells the key,
// and input another parser could read differently is refused.
func TestRewriteRefusesForgedOrAmbiguousRequests(t *testing.T) {
	cases := map[string]struct {
		line string
		code int
	}{
		"forged":                 {`{"jsonrpc":"2.0","id":1,"method":"secret.list","params":{"guest_verified":{"pid":1}}}`, protocol.CodeInvalidParams},
		"forged, escaped":        {`{"jsonrpc":"2.0","id":1,"method":"secret.list","params":{"guest\u005fverified":{"pid":1}}}`, protocol.CodeInvalidParams},
		"forged, null":           {`{"jsonrpc":"2.0","id":1,"method":"secret.list","params":{"guest_verified":null}}`, protocol.CodeInvalidParams},
		"duplicate key":          {`{"jsonrpc":"2.0","id":1,"method":"secret.read","params":{"names":["a:b"],"names":["a:c"]}}`, protocol.CodeInvalidRequest},
		"duplicate method":       {`{"jsonrpc":"2.0","id":1,"method":"secret.list","method":"secret.read"}`, protocol.CodeInvalidRequest},
		"case variant":           {`{"jsonrpc":"2.0","id":1,"Method":"secret.list"}`, protocol.CodeInvalidRequest},
		"forged, case variant":   {`{"jsonrpc":"2.0","id":1,"method":"secret.list","params":{"Guest_Verified":{"pid":1}}}`, protocol.CodeInvalidParams},
		"forged, long s":         {`{"jsonrpc":"2.0","id":1,"method":"secret.list","params":{"gue\u017ft_verified":{"pid":1}}}`, protocol.CodeInvalidParams},
		"forged, long s raw":     {"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"secret.list\",\"params\":{\"gue\u017ft_verified\":{\"pid\":1}}}", protocol.CodeInvalidParams},
		"forged, unknown method": {`{"jsonrpc":"2.0","id":1,"method":"secret.add","params":{"GUEST_VERIFIED":{"pid":1}}}`, protocol.CodeInvalidParams},
		"unknown key":            {`{"jsonrpc":"2.0","id":1,"method":"secret.read","params":{"names":["a:b"],"scope":"instance"}}`, protocol.CodeInvalidParams},
		"nested case variant":    {`{"jsonrpc":"2.0","id":1,"method":"secret.read","params":{"names":["a:b"],"client":{"Name":"gh"}}}`, protocol.CodeInvalidParams},
		"id an object":           {`{"jsonrpc":"2.0","id":{"a":1},"method":"secret.list"}`, protocol.CodeInvalidRequest},
		"params not object":      {`{"jsonrpc":"2.0","id":1,"method":"secret.list","params":[1]}`, protocol.CodeInvalidParams},
		"relay's handshake":      {`{"jsonrpc":"2.0","id":1,"method":"relay.hello","params":{"signature":"x"}}`, protocol.CodeMethodNotFound},
		"not json":               {`{"jsonrpc"`, protocol.CodeParseError},
	}
	for name, tc := range cases {
		out, _, perr := Rewrite([]byte(tc.line), guest)
		if perr == nil || perr.Code != tc.code || out != nil {
			t.Errorf("%s: got %v, %s", name, perr, out)
		} else if strings.HasPrefix(name, "forged") && perr.Data.Reason != "forged_guest_verified" {
			t.Errorf("%s: refused as %s", name, perr.Data.Reason)
		}
	}
	// Notifications get no answer and aren't forwarded.
	if out, id, perr := Rewrite([]byte(`{"jsonrpc":"2.0","method":"secret.list"}`), guest); out != nil || id != nil || perr != nil {
		t.Fatalf("notification: %s %s %v", out, id, perr)
	}
}

// fakeCaller stands in for the kernel's answer. gone makes Check fail, as
// for a caller that exited or whose pid was reused.
type fakeCaller struct {
	g      identity.GuestInfo
	gone   atomic.Bool
	closed atomic.Bool
}

func (f *fakeCaller) Guest() identity.GuestInfo { return f.g }
func (f *fakeCaller) Close()                    { f.closed.Store(true) }
func (f *fakeCaller) Check() error {
	if f.gone.Load() {
		return errors.New("caller 812 has exited")
	}
	return nil
}

// host is a foca service whose instance dev names the relay's key, reached
// through a proxy that counts upstream connections, as ssh would forward
// them.
type host struct {
	sink     *audit.Memory
	auth     *fake.Authenticator
	upstream string
	conns    atomic.Int64
	// open are the forwarded connections, for a test to cut.
	mu   sync.Mutex
	open []net.Conn
}

func startHost(t *testing.T, pub ed25519.PublicKey) *host {
	t.Helper()
	base := shortDir(t)
	paths := config.Paths{RuntimeDir: filepath.Join(base, "run"), DataDir: filepath.Join(base, "data")}
	store := memory.New()
	store.Put(context.Background(), nil, plugin.SecretMeta{ID: "github-pat", DisplayName: "GitHub PAT"}, plugin.SecretValue{Bytes: []byte("ghp_secret")})
	h := &host{sink: audit.NewMemory(), auth: fake.New()}
	h.auth.Default = fake.Approve
	realm := identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"}
	svc := core.New(core.Options{Authenticator: h.auth, Audit: h.sink, PromptTimeout: 5 * time.Second, MaxQueue: 4, ShowClient: true},
		[]*core.Instance{{Name: "dev", Realm: realm, GuestRelay: pub, Secrets: static.NewVaults(static.New("dev", store, static.Exposure{All: true}, nil))}},
		map[string]plugin.SecretStore{"dev": store})
	ssh := identity.VerifiedPeer{UID: os.Getuid(), PID: 4711, Exe: "/usr/bin/ssh", Name: "ssh", PIDStable: true, Session: "sid:10:100"}
	srv := server.New(server.Options{Paths: paths, Instances: []config.Instance{{Name: "dev", Realm: realm}},
		OpaquePeers: []string{"ssh"}, Core: svc, Peers: &peer.Static{Peer: ssh}, Version: "test", Log: quiet})
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Shutdown("test end") })
	h.upstream = filepath.Join(base, "fwd.sock")
	h.forward(t, paths.ClientSocket("dev"))
	return h
}

// forward listens on h.upstream (0600, like ssh's forwarded socket) and joins
// each connection to target.
func (h *host) forward(t *testing.T, target string) {
	l, err := net.Listen("unix", h.upstream)
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(h.upstream, 0o600)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			h.conns.Add(1)
			h.mu.Lock()
			h.open = append(h.open, c)
			h.mu.Unlock()
			go func() {
				defer c.Close()
				up, err := net.Dial("unix", target)
				if err != nil {
					return
				}
				defer up.Close()
				go func() { io.Copy(up, c); up.Close() }()
				io.Copy(c, up)
			}()
		}
	}()
}

func (h *host) events(typ string) []audit.Event {
	var out []audit.Event
	for _, e := range h.sink.Events() {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

var quiet = slog.New(slog.DiscardHandler)

// shortDir keeps socket paths under the sun_path limit.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "frl")
	if err != nil {
		t.Fatal(err)
	}
	os.Chmod(d, 0o700)
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

type rig struct {
	host    *host
	listen  string
	callers []*fakeCaller
	mu      sync.Mutex
	// identify, if set, replaces handing out a fresh fakeCaller.
	identify func() (Caller, error)
}

// startRelay runs a relay in front of a host that trusts key.
func startRelay(t *testing.T, key ed25519.PrivateKey, trusted ed25519.PublicKey) *rig {
	t.Helper()
	return startRelayWith(t, key, trusted, nil)
}

// startRelayWith is startRelay with the relay's options changed by tweak.
func startRelayWith(t *testing.T, key ed25519.PrivateKey, trusted ed25519.PublicKey, tweak func(*Options)) *rig {
	t.Helper()
	r := &rig{host: startHost(t, trusted)}
	r.listen = filepath.Join(shortDir(t), "relay.sock")
	o := Options{Listen: r.listen, Upstream: r.host.upstream, Key: key, Log: quiet,
		Identify: func(*net.UnixConn) (Caller, error) {
			r.mu.Lock()
			if r.identify != nil {
				defer r.mu.Unlock()
				return r.identify()
			}
			c := &fakeCaller{g: guest}
			r.callers = append(r.callers, c)
			r.mu.Unlock()
			return c, nil
		}}
	if tweak != nil {
		tweak(&o)
	}
	rl := New(o)
	if err := rl.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { rl.Serve(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return r
}

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func (r *rig) dial(t *testing.T) *client.Client {
	t.Helper()
	c, err := client.Dial(context.Background(), r.listen)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func read(t *testing.T, c *client.Client) (string, error) {
	t.Helper()
	var res protocol.SecretReadResult
	err := c.Call(ctx(t), protocol.MethodSecretRead, protocol.SecretReadParams{Names: []string{"dev:github-pat"},
		Common: protocol.Common{Client: &identity.ClientInfo{Name: "aws"}}}, &res)
	if err != nil {
		return "", err
	}
	return res.Secrets[0].Value, nil
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); !cond(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
	}
}

// Through the relay, the host prompts with the program the realm's kernel
// named and records it as guest-verified, next to what the caller claimed.
func TestRelayedReadIsGuestVerified(t *testing.T) {
	pub, priv := keys(t)
	r := startRelay(t, priv, pub)
	v, err := read(t, r.dial(t))
	if err != nil || v != "ghp_secret" {
		t.Fatalf("read: %q %v", v, err)
	}
	if p := r.host.auth.Requests()[0].Prompt; p != "share:\n🔑 GitHub PAT\n🖥️ VM dev\n👤 gh ⚠" {
		t.Fatalf("prompt %q", p)
	}
	ev := r.host.events(audit.TypeSecretRead)[0]
	if ev.Client.GuestVerified == nil || ev.Client.GuestVerified.PID != 812 || ev.Client.Reported == nil || ev.Client.Reported.Name != "aws" {
		t.Fatalf("client %+v", ev.Client)
	}
}

// A relay whose key the host doesn't know never gets a request through.
func TestRelayWithAnotherKeyIsRefused(t *testing.T) {
	pub, _ := keys(t)
	_, priv := keys(t)
	r := startRelay(t, priv, pub)
	if _, err := read(t, r.dial(t)); err == nil {
		t.Fatal("read through an unknown relay")
	}
	if len(r.host.auth.Requests()) != 0 {
		t.Fatal("prompted")
	}
	waitFor(t, func() bool {
		for _, e := range r.host.events(audit.TypeRequestRejected) {
			if e.Reason == "relay_hello_invalid" {
				return true
			}
		}
		return false
	})
}

// One caller, one upstream connection: never shared between callers, and
// kept for all of a caller's requests.
func TestRelayNeverMultiplexes(t *testing.T) {
	pub, priv := keys(t)
	r := startRelay(t, priv, pub)
	a := r.dial(t)
	for i := 0; i < 3; i++ {
		if _, err := read(t, a); err != nil {
			t.Fatal(err)
		}
	}
	if n := r.host.conns.Load(); n != 1 {
		t.Fatalf("one caller used %d upstream connections", n)
	}
	if _, err := read(t, r.dial(t)); err != nil {
		t.Fatal(err)
	}
	if n := r.host.conns.Load(); n != 2 {
		t.Fatalf("two callers used %d upstream connections", n)
	}
}

// A caller that exited, or whose pid now names another process, gets nothing
// forwarded: the host never sees the request.
func TestRelayRefusesACallerThatIsGone(t *testing.T) {
	pub, priv := keys(t)
	r := startRelay(t, priv, pub)
	c := r.dial(t)
	if err := c.Call(ctx(t), protocol.MethodHello, protocol.HelloParams{Protocol: 1}, nil); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.callers[0].gone.Store(true)
	r.mu.Unlock()
	if _, err := read(t, c); err == nil {
		t.Fatal("read for a caller that is gone")
	}
	if len(r.host.auth.Requests()) != 0 || len(r.host.events(audit.TypeSecretRead)) != 0 {
		t.Fatal("the host saw the request")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	waitFor(t, func() bool { return r.callers[0].closed.Load() })
}

// A caller the kernel can't identify isn't relayed at all.
func TestRelayRefusesAnUnidentifiedCaller(t *testing.T) {
	pub, priv := keys(t)
	r := startRelay(t, priv, pub)
	r.mu.Lock()
	r.identify = func() (Caller, error) { return nil, errors.New("no pid in this namespace") }
	r.mu.Unlock()
	if _, err := read(t, r.dial(t)); err == nil {
		t.Fatal("read for an unidentified caller")
	}
	if r.host.conns.Load() != 0 {
		t.Fatal("went upstream for an unidentified caller")
	}
}

// A caller's own guest_verified is refused by the relay; the host never sees it.
func TestRelayRefusesForgedGuestVerified(t *testing.T) {
	pub, priv := keys(t)
	r := startRelay(t, priv, pub)
	c := r.dial(t)
	err := c.Call(ctx(t), protocol.MethodSecretRead, protocol.SecretReadParams{Names: []string{"dev:github-pat"},
		Common: protocol.Common{GuestVerified: &identity.GuestInfo{PID: 1, Name: "gh"}}}, nil)
	var pe *protocol.Error
	if !errors.As(err, &pe) || pe.Code != protocol.CodeInvalidParams {
		t.Fatalf("got %v", err)
	}
	if len(r.host.sink.Events()) > 1 || len(r.host.auth.Requests()) != 0 {
		t.Fatalf("the host saw the forged request: %+v", r.host.sink.Events())
	}
}

// A caller that hangs up while its prompt is open cancels it on the host.
func TestCallerHangUpCancelsTheHostsPrompt(t *testing.T) {
	pub, priv := keys(t)
	r := startRelay(t, priv, pub)
	r.host.auth.Default = fake.Hang
	r.host.auth.Started = make(chan plugin.ApprovalRequest, 1)
	c := r.dial(t)
	go read(t, c)
	select {
	case <-r.host.auth.Started:
	case <-time.After(3 * time.Second):
		t.Fatal("no prompt")
	}
	c.Close()
	waitFor(t, func() bool {
		for _, e := range r.host.events(audit.TypeApprovalTimeout) {
			if e.Reason == "cancelled" {
				return true
			}
		}
		return false
	})
}

func TestRelayRefusesInsecureSetup(t *testing.T) {
	_, priv := keys(t)
	dir := shortDir(t)
	sock := filepath.Join(dir, "fwd.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	file := filepath.Join(dir, "file")
	os.WriteFile(file, nil, 0o600)
	open := filepath.Join(shortDir(t), "open")
	os.Mkdir(open, 0o777)
	os.Chmod(open, 0o777)
	uid := os.Getuid()
	cases := map[string]struct {
		opts Options
		mode os.FileMode
		want string
	}{
		"root":                  {Options{EUID: func() int { return 0 }}, 0o600, "root"},
		"upstream others reach": {Options{}, 0o660, "StreamLocalBindMask"},
		"upstream someone else": {Options{UID: func() int { return uid + 1 }}, 0o600, "not owned"},
		"upstream not a socket": {Options{Upstream: file}, 0o600, "not a socket"},
		"listen dir writable":   {Options{Listen: filepath.Join(open, "relay.sock")}, 0o600, "writable by group or others"},
	}
	for name, tc := range cases {
		os.Chmod(sock, tc.mode)
		o := tc.opts
		o.Key = priv
		if o.Upstream == "" {
			o.Upstream = sock
		}
		if o.Listen == "" {
			o.Listen = filepath.Join(dir, "relay.sock")
		}
		if err := New(o).Start(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	// The forwarded socket appears once the host connects; until then the
	// relay starts, and checks it before every connection.
	os.Chmod(sock, 0o600)
	rl := New(Options{Listen: filepath.Join(dir, "ok.sock"), Upstream: filepath.Join(dir, "later.sock"), Key: priv})
	if err := rl.Start(); err != nil {
		t.Fatalf("no upstream yet: %v", err)
	}
	rl.l.Close()
}

func TestKeygenAndLoadKey(t *testing.T) {
	dir := shortDir(t)
	path := filepath.Join(dir, "relay.key")
	pub, err := Keygen(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", fi.Mode().Perm())
	}
	priv, err := LoadKey(path, os.Getuid())
	if err != nil || !pub.Equal(priv.Public()) {
		t.Fatalf("load: %v", err)
	}
	if _, err := Keygen(path); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("keygen overwrote a key: %v", err)
	}
	if _, err := LoadKey(path, os.Getuid()+1); err == nil {
		t.Fatal("loaded another user's key")
	}
	os.Chmod(path, 0o640)
	if _, err := LoadKey(path, os.Getuid()); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("loaded a key others can read: %v", err)
	}
	os.Chmod(path, 0o600)
	link := filepath.Join(dir, "link.key")
	os.Symlink(path, link)
	if _, err := LoadKey(link, os.Getuid()); err == nil {
		t.Fatal("followed a symlink to the key")
	}
}

// A method clients can't call goes on without its params: the host refuses
// it by name and records it, and no bytes it never checks cross over.
func TestRewriteDropsParamsOfMethodsClientsCantCall(t *testing.T) {
	out, _, perr := Rewrite([]byte(`{"jsonrpc":"2.0","id":1,"method":"secret.add","params":{"name":"x","value":"y"}}`), guest)
	if perr != nil {
		t.Fatal(perr)
	}
	var req struct {
		Method string                     `json:"method"`
		Params map[string]json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(out, &req); err != nil || req.Method != "secret.add" || len(req.Params) != 1 || req.Params["guest_verified"] == nil {
		t.Fatalf("forwarded %s", out)
	}
}

// Re-encoding leaves <, > and & as they are, so a request that fit still
// fits; one that the caller's identity would push past the limit is
// refused here, with an answer, not cut off at the host.
func TestRewriteKeepsRequestsInOneMessage(t *testing.T) {
	line := func(n int) []byte {
		return []byte(`{"jsonrpc":"2.0","id":1,"method":"secret.read","params":{"names":["a:b"],"client":{"name":"` + strings.Repeat("<", n) + `"}}}`)
	}
	in := line(protocol.MaxMessage - 2000)
	out, _, perr := Rewrite(in, guest)
	if perr != nil || len(out) > protocol.MaxMessage || len(out) < len(in) {
		t.Fatalf("%v, %d bytes from %d", perr, len(out), len(in))
	}
	in = line(protocol.MaxMessage - 120)
	out, id, perr := Rewrite(in, guest)
	if out != nil || perr == nil || perr.Code != protocol.CodeParseError || perr.Data.Reason != "message_too_large" || string(id) != "1" {
		t.Fatalf("%v, %d bytes from %d", perr, len(out), len(in))
	}
}

// syncBuffer collects log output from several goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) lines(t *testing.T) []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(s.b.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("log line %q: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}

// The host never sees what the relay refuses itself, so the relay logs it:
// who asked and why, one line per reason per 10 s, then how many were left
// out, so a caller can't flood the journal.
func TestRelayLogsItsOwnRefusalsAtMostOncePerWindow(t *testing.T) {
	pub, priv := keys(t)
	var logs syncBuffer
	var mu sync.Mutex
	now := time.Unix(1000, 0)
	r := startRelayWith(t, priv, pub, func(o *Options) {
		o.Log = slog.New(slog.NewJSONHandler(&logs, nil))
		o.Now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	evil := guest
	evil.Name = "evil\x1b[2Jname"
	r.mu.Lock()
	r.identify = func() (Caller, error) { return &fakeCaller{g: evil}, nil }
	r.mu.Unlock()
	c := r.dial(t)
	forge := func() {
		c.WriteRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"secret.list","params":{"Guest_Verified":{"pid":1}}}`))
		if line, err := c.ReadRaw(); err != nil || !strings.Contains(string(line), `"code":-32602`) {
			t.Fatalf("%s %v", line, err)
		}
	}
	for i := 0; i < 3; i++ {
		forge()
	}
	c.WriteRaw([]byte(`{"jsonrpc":"2.0","method":"secret.list"}`))
	mu.Lock()
	now = now.Add(11 * time.Second)
	mu.Unlock()
	forge()
	got := logs.lines(t)
	var forged []map[string]any
	notification := false
	for _, l := range got {
		switch l["reason"] {
		case "forged_guest_verified":
			forged = append(forged, l)
		case "notification":
			notification = true
		}
	}
	if len(forged) != 2 || !notification {
		t.Fatalf("logged %v", got)
	}
	first, second := forged[0], forged[1]
	if first["pid"] != float64(812) || first["uid"] != float64(1000) || first["comm"] != "evil2Jname" || first["omitted_before"] != nil {
		t.Fatalf("first line %v", first)
	}
	if second["omitted_before"] != float64(2) {
		t.Fatalf("second line %v", second)
	}
	if len(r.host.sink.Events()) > 1 {
		t.Fatalf("the host saw refused requests: %+v", r.host.sink.Events())
	}
}

// Connections cost the host nothing until they send a request: the relay
// goes upstream with a caller's first request, not when it connects.
func TestRelayDialsUpstreamOnTheFirstRequest(t *testing.T) {
	pub, priv := keys(t)
	r := startRelay(t, priv, pub)
	a, b := r.dial(t), r.dial(t)
	r.dial(t)
	time.Sleep(100 * time.Millisecond)
	if n := r.host.conns.Load(); n != 0 {
		t.Fatalf("%d upstream connections for idle callers", n)
	}
	if _, err := read(t, a); err != nil {
		t.Fatal(err)
	}
	if _, err := read(t, b); err != nil {
		t.Fatal(err)
	}
	if n := r.host.conns.Load(); n != 2 {
		t.Fatalf("%d upstream connections for two callers", n)
	}
}

// One user of the realm can't hold every connection the host allows: the
// relay caps callers per uid and in total, and tells the one turned away.
func TestRelayLimitsConnectionsPerUserAndInTotal(t *testing.T) {
	pub, priv := keys(t)
	r := startRelayWith(t, priv, pub, func(o *Options) { o.MaxPerUser, o.MaxConnections = 2, 3 })
	uid := 1000
	r.mu.Lock()
	r.identify = func() (Caller, error) { g := guest; g.UID = uid; return &fakeCaller{g: g}, nil }
	r.mu.Unlock()
	busy := func(c *client.Client) bool {
		c.SetDeadline(time.Now().Add(3 * time.Second))
		line, err := c.ReadRaw()
		if err != nil || !strings.Contains(string(line), `"code":-32006`) {
			return false
		}
		_, err = c.ReadRaw()
		return errors.Is(err, io.EOF) // and closed
	}
	held := []*client.Client{r.dial(t), r.dial(t)}
	for _, c := range held {
		if err := c.Call(ctx(t), protocol.MethodHello, protocol.HelloParams{Protocol: 1}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if !busy(r.dial(t)) {
		t.Fatal("a third connection of uid 1000 was served")
	}
	r.mu.Lock()
	uid = 1001
	r.mu.Unlock()
	other := r.dial(t)
	if err := other.Call(ctx(t), protocol.MethodHello, protocol.HelloParams{Protocol: 1}, nil); err != nil {
		t.Fatalf("another user turned away: %v", err)
	}
	if !busy(r.dial(t)) {
		t.Fatal("a connection beyond the total was served")
	}
	// A slot frees up when its caller leaves.
	held[0].Close()
	waitFor(t, func() bool {
		c, err := client.Dial(context.Background(), r.listen)
		if err != nil {
			return false
		}
		defer c.Close()
		return c.Call(ctx(t), protocol.MethodHello, protocol.HelloParams{Protocol: 1}, nil) == nil
	})
}

// A caller that sends nothing is closed after the idle timeout, but never
// while its request waits on a prompt.
func TestRelayClosesIdleCallersButNotOnesWaiting(t *testing.T) {
	pub, priv := keys(t)
	r := startRelayWith(t, priv, pub, func(o *Options) { o.IdleTimeout = 200 * time.Millisecond })
	idle := r.dial(t)
	start := time.Now()
	idle.SetDeadline(start.Add(3 * time.Second))
	if _, err := idle.ReadRaw(); !errors.Is(err, io.EOF) || time.Since(start) > 2*time.Second {
		t.Fatalf("idle caller: %v after %v", err, time.Since(start))
	}
	r.host.auth.Default = fake.Approve
	r.host.auth.Started = make(chan plugin.ApprovalRequest)
	c := r.dial(t)
	done := make(chan error, 1)
	go func() { _, err := read(t, c); done <- err }()
	time.Sleep(500 * time.Millisecond) // the prompt is open, longer than the idle timeout
	<-r.host.auth.Started
	if err := <-done; err != nil {
		t.Fatalf("read while waiting: %v", err)
	}
}

// When the host closes the upstream connection, the caller's closes too,
// rather than failing on its next request.
func TestRelayClosesTheCallerWhenTheHostHangsUp(t *testing.T) {
	pub, priv := keys(t)
	r := startRelay(t, priv, pub)
	c := r.dial(t)
	if err := c.Call(ctx(t), protocol.MethodHello, protocol.HelloParams{Protocol: 1}, nil); err != nil {
		t.Fatal(err)
	}
	r.host.mu.Lock()
	for _, u := range r.host.open {
		u.Close()
	}
	r.host.mu.Unlock()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.ReadRaw(); !errors.Is(err, io.EOF) {
		t.Fatalf("caller's connection: %v", err)
	}
}

// failingListener fails every accept, as a listener does once the process
// is out of file descriptors.
type failingListener struct{ calls atomic.Int64 }

func (f *failingListener) AcceptUnix() (*net.UnixConn, error) {
	f.calls.Add(1)
	return nil, syscall.EMFILE
}

func (f *failingListener) Close() error { return nil }

// A failing accept is retried after a growing pause, not at once.
func TestRelayFailingAcceptBacksOff(t *testing.T) {
	_, priv := keys(t)
	rl := New(Options{Key: priv, Log: quiet})
	l := &failingListener{}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	rl.serve(ctx, l)
	// 5 + 10 + 20 + 40 + 80 ms: six tries fit in 200 ms.
	if n := l.calls.Load(); n < 2 || n > 7 {
		t.Fatalf("%d accepts in 200ms", n)
	}
}

// A message over the limit gets an answer before the connection closes, as
// on the host.
func TestRelayAnswersAnOversizedMessage(t *testing.T) {
	pub, priv := keys(t)
	r := startRelay(t, priv, pub)
	c := r.dial(t)
	go c.WriteRaw([]byte(`{"x":"` + strings.Repeat("a", protocol.MaxMessage) + `"}`))
	line, err := c.ReadRaw()
	if err != nil || !strings.Contains(string(line), "too large") {
		t.Fatalf("%s %v", line, err)
	}
	if _, err := c.ReadRaw(); err == nil {
		t.Fatal("connection left open")
	}
}
