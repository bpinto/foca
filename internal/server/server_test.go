//go:build linux

// These tests identify peers with SO_PEERCRED through peer.NewLinux, so they
// run on Linux only.

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	"github.com/bpinto/foca/internal/server/core"
)

type env struct {
	srv   *Server
	paths config.Paths
	auth  *fake.Authenticator
	sink  *audit.Memory
	store *memory.Store
}

// start runs a server with one instance per realm given. A nil identifier
// means the real kernel identifier.
func start(t *testing.T, realm identity.Realm, ids plugin.PeerIdentifier) *env {
	t.Helper()
	return startWith(t, realm, ids, nil)
}

func startWith(t *testing.T, realm identity.Realm, ids plugin.PeerIdentifier, tweak func(*Options)) *env {
	t.Helper()
	base, err := os.MkdirTemp("", "fc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	paths := config.Paths{RuntimeDir: filepath.Join(base, "run"), DataDir: filepath.Join(base, "data")}
	store := memory.New()
	store.Put(context.Background(), nil, plugin.SecretMeta{ID: "github-pat", DisplayName: "GitHub PAT"}, plugin.SecretValue{Bytes: []byte("ghp_secret")})
	auth := fake.New()
	sink := audit.NewMemory()
	inst := config.Instance{Name: "dev", Realm: realm, Vault: "dev", Expose: config.Expose{All: true}}
	svc := core.New(core.Options{Authenticator: auth, Audit: sink, PromptTimeout: 2 * time.Second, MaxQueue: 4, ShowClient: true},
		[]*core.Instance{{Name: "dev", Realm: realm, Vault: "dev", Secrets: static.New("dev", store, static.Exposure{All: true}, nil)}},
		map[string]plugin.SecretStore{"dev": store})
	if ids == nil {
		ids = peer.NewLinux()
	}
	opts := Options{Paths: paths, Instances: []config.Instance{inst}, OpaquePeers: []string{"ssh", "socat"},
		Core: svc, Peers: ids, Version: "test"}
	if tweak != nil {
		tweak(&opts)
	}
	srv := New(opts)
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Shutdown("test end") })
	return &env{srv: srv, paths: paths, auth: auth, sink: sink, store: store}
}

var hostRealm = identity.Realm{Kind: "host", Name: "host", Peers: "direct"}
var vmRealm = identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"}

func dial(t *testing.T, path string) *client.Client {
	t.Helper()
	c, err := client.Dial(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func callErr(err error) *protocol.Error {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return pe
	}
	return nil
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestSocketAndDirectoryModes(t *testing.T) {
	e := start(t, hostRealm, nil)
	for _, p := range []string{e.paths.RuntimeDir, e.paths.InstanceDir("dev")} {
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", p, fi.Mode(), err)
		}
	}
	fi, err := os.Lstat(e.paths.ClientSocket("dev"))
	if err != nil || fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("client socket: %v %v", fi.Mode(), err)
	}
	// One socket per instance and nothing else: there is no management socket.
	entries, _ := os.ReadDir(e.paths.InstanceDir("dev"))
	if len(entries) != 1 || entries[0].Name() != "client.sock" {
		t.Fatalf("instance dir holds %v", entries)
	}
}

func TestRequestApprovalAuditOverRealSocket(t *testing.T) {
	e := start(t, hostRealm, nil)
	e.auth.Default = fake.Approve
	c := dial(t, e.paths.ClientSocket("dev"))

	var hello protocol.HelloResult
	if err := c.Call(ctx(t), protocol.MethodHello, protocol.HelloParams{Protocol: 1}, &hello); err != nil {
		t.Fatal(err)
	}
	if hello.Instance != "dev" || hello.Protocol != 1 || len(hello.Features) != 2 {
		t.Fatalf("hello %+v", hello)
	}

	var res protocol.SecretReadResult
	err := c.Call(ctx(t), protocol.MethodSecretRead, protocol.SecretReadParams{Names: []string{"github-pat"},
		Common: protocol.Common{Client: &identity.ClientInfo{PID: 99, Name: "gh\x1b"}}}, &res)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Secrets) != 1 || res.Secrets[0].Value != "ghp_secret" || res.Secrets[0].Encoding != "utf8" {
		t.Fatalf("result %+v", res)
	}

	var read *audit.Event
	for _, ev := range e.sink.Events() {
		if ev.Type == audit.TypeSecretRead {
			ev := ev
			read = &ev
		}
	}
	if read == nil || read.Outcome != audit.OutcomeOK {
		t.Fatalf("no secret.read event: %+v", e.sink.Events())
	}
	// The kernel-verified peer is this test process.
	v := read.Peer.Verified
	if v.PID != os.Getpid() || v.UID != os.Getuid() || !strings.HasPrefix(v.Source, "SO_PEERCRED") || v.Opaque {
		t.Fatalf("verified peer %+v", v)
	}
	// The client's claim is kept apart and sanitised.
	if read.Client == nil || read.Client.Reported.PID != 99 || read.Client.Reported.Name != "gh" {
		t.Fatalf("reported %+v", read.Client)
	}
	// The JSON shape keeps them in separate blocks.
	b, _ := json.Marshal(read)
	if !strings.Contains(string(b), `"peer":{"verified":`) || !strings.Contains(string(b), `"client":{"reported":`) {
		t.Fatalf("event json %s", b)
	}
}

func TestDeniedReadReturnsDenied(t *testing.T) {
	e := start(t, hostRealm, nil)
	c := dial(t, e.paths.ClientSocket("dev"))
	err := c.Call(ctx(t), protocol.MethodSecretRead, protocol.SecretReadParams{Names: []string{"github-pat"}}, nil)
	pe := callErr(err)
	if pe == nil || pe.Code != protocol.CodeDenied || pe.Data.RequestID == "" || pe.Data.EventSeq == 0 {
		t.Fatalf("got %v", err)
	}
}

func TestManagementMethodsRefusedAndAudited(t *testing.T) {
	e := start(t, vmRealm, &peer.Static{Peer: identity.VerifiedPeer{UID: os.Getuid(), PID: 1, Exe: "/usr/bin/ssh", Name: "ssh"}})
	e.auth.Default = fake.Approve
	c := dial(t, e.paths.ClientSocket("dev"))
	for _, m := range []string{"secret.add", "server.shutdown"} {
		err := c.Call(ctx(t), m, map[string]any{"name": "x", "value": "y"}, nil)
		if pe := callErr(err); pe == nil || pe.Code != protocol.CodeForbiddenOnSocket {
			t.Fatalf("%s on client socket: %v", m, err)
		}
	}
	if len(e.auth.Requests()) != 0 {
		t.Fatal("forbidden method reached the authenticator")
	}
	if n := rejected(e, "forbidden_on_socket"); n != 1 {
		t.Fatalf("expected the first rejection recorded at once, got %d", n)
	}
	if _, _, err := e.store.Read(context.Background(), nil, "x"); err == nil {
		t.Fatal("a realm managed to add a secret")
	}
	// Service still up.
	if err := c.Call(ctx(t), protocol.MethodHello, nil, nil); err != nil {
		t.Fatal(err)
	}
	// The second one in the burst is counted, and written on shutdown.
	e.srv.Shutdown("test")
	if n := rejected(e, "forbidden_on_socket"); n != 2 {
		t.Fatalf("expected 2 rejections counted, got %d", n)
	}
}

// rejected sums request.rejected events with reason, counting coalesced ones.
func rejected(e *env, reason string) int {
	n := 0
	for _, ev := range e.sink.Events() {
		if ev.Type == audit.TypeRequestRejected && ev.Reason == reason {
			n += max(ev.Count, 1)
		}
	}
	return n
}

func TestUIDMismatchIsRefusedAndAudited(t *testing.T) {
	e := start(t, hostRealm, &peer.Static{Peer: identity.VerifiedPeer{UID: os.Getuid() + 1, PID: 1, Name: "other"}})
	c := dial(t, e.paths.ClientSocket("dev"))
	if err := c.Call(ctx(t), protocol.MethodHello, nil, nil); err == nil {
		t.Fatal("other uid got a response")
	}
	waitFor(t, func() bool { return hasReject(e.sink, "uid_mismatch") })
}

func TestProxyPeerRefusedOnDirectRealm(t *testing.T) {
	e := start(t, hostRealm, &peer.Static{Peer: identity.VerifiedPeer{UID: os.Getuid(), PID: 1, Exe: "/usr/bin/ssh", Name: "ssh"}})
	if err := dial(t, e.paths.ClientSocket("dev")).Call(ctx(t), protocol.MethodHello, nil, nil); err == nil {
		t.Fatal("ssh peer accepted on a direct realm")
	}
	waitFor(t, func() bool { return hasReject(e.sink, "opaque_peer_on_direct_realm") })

	// The same peer is fine on an opaque (VM) realm: that is what a forward looks like.
	e = start(t, vmRealm, &peer.Static{Peer: identity.VerifiedPeer{UID: os.Getuid(), PID: 1, Exe: "/usr/bin/ssh", Name: "ssh"}})
	if err := dial(t, e.paths.ClientSocket("dev")).Call(ctx(t), protocol.MethodHello, nil, nil); err != nil {
		t.Fatalf("vm realm refused ssh: %v", err)
	}
}

// A host process that isn't a proxy can't pose as the VM on its socket, even
// if it names itself ssh with prctl.
func TestNonProxyPeerRefusedOnOpaqueRealm(t *testing.T) {
	for _, p := range []identity.VerifiedPeer{
		{UID: os.Getuid(), PID: 1, Exe: "/usr/bin/python3", Name: "python3"},
		{UID: os.Getuid(), PID: 1, Exe: "/usr/bin/python3", Name: "ssh"},
		{UID: os.Getuid(), PID: 1, Name: "ssh"},
	} {
		e := start(t, vmRealm, &peer.Static{Peer: p})
		if err := dial(t, e.paths.ClientSocket("dev")).Call(ctx(t), protocol.MethodHello, nil, nil); err == nil {
			t.Fatalf("%+v accepted on an opaque realm", p)
		}
		waitFor(t, func() bool { return hasReject(e.sink, "direct_peer_on_opaque_realm") })
	}
	// A Nix-wrapped ssh is still ssh.
	e := start(t, vmRealm, &peer.Static{Peer: identity.VerifiedPeer{UID: os.Getuid(), PID: 1, Exe: "/nix/store/x/bin/.ssh-wrapped"}})
	if err := dial(t, e.paths.ClientSocket("dev")).Call(ctx(t), protocol.MethodHello, nil, nil); err != nil {
		t.Fatalf("wrapped ssh refused: %v", err)
	}
}

// The container id the identifier read is audited for a direct container
// realm only: on any other realm it would describe a proxy or nothing.
func TestContainerIDIsAuditedOnlyForDirectContainerRealms(t *testing.T) {
	id := strings.Repeat("0123456789abcdef", 4)
	for _, c := range []struct {
		realm identity.Realm
		exe   string
		want  string
	}{
		{identity.Realm{Kind: "container", Name: "web", Peers: "direct"}, "/usr/bin/gh", id},
		{identity.Realm{Kind: "container", Name: "web", Peers: "opaque"}, "/usr/bin/ssh", ""},
		{hostRealm, "/usr/bin/gh", ""},
	} {
		p := identity.VerifiedPeer{UID: os.Getuid(), PID: 1, Exe: c.exe, Realm: identity.Realm{ContainerID: id}}
		e := start(t, c.realm, &peer.Static{Peer: p})
		if err := dial(t, e.paths.ClientSocket("dev")).Call(ctx(t), protocol.MethodSecretList, struct{}{}, nil); err != nil {
			t.Fatalf("%+v: %v", c.realm, err)
		}
		var got *audit.Event
		for _, ev := range e.sink.Events() {
			if ev.Type == audit.TypeSecretList {
				got = &ev
			}
		}
		if got == nil || got.Peer == nil || got.Peer.Verified.Realm.ContainerID != c.want || got.Peer.Verified.Realm.Name != c.realm.Name {
			t.Fatalf("%+v: event %+v", c.realm, got)
		}
		b, _ := json.Marshal(got)
		if c.want != "" && !strings.Contains(string(b), `"container_id":"`+id+`"`) {
			t.Fatalf("container id not in the record: %s", b)
		}
	}
}

func TestBinaryValueRoundTrip(t *testing.T) {
	e := start(t, hostRealm, nil)
	e.auth.Default = fake.Approve
	e.store.Put(context.Background(), nil, plugin.SecretMeta{ID: "bin"}, plugin.SecretValue{Bytes: []byte{0xff, 0x00}})
	var res protocol.SecretReadResult
	if err := dial(t, e.paths.ClientSocket("dev")).Call(ctx(t), protocol.MethodSecretRead, protocol.SecretReadParams{Names: []string{"bin"}}, &res); err != nil {
		t.Fatal(err)
	}
	if res.Secrets[0].Encoding != "base64" || res.Secrets[0].Value != "/wA=" {
		t.Fatalf("binary value %+v", res.Secrets[0])
	}
}

func TestShutdownStopsCleanly(t *testing.T) {
	e := start(t, hostRealm, nil)
	e.srv.Shutdown("test")
	select {
	case <-e.srv.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
	if _, err := os.Lstat(e.paths.ClientSocket("dev")); !os.IsNotExist(err) {
		t.Fatal("socket left behind")
	}
	evs := e.sink.Events()
	if evs[0].Type != audit.TypeServerStart || evs[len(evs)-1].Type != audit.TypeServerStop {
		t.Fatalf("lifecycle events %v", evs)
	}
}

func TestStrictParamsAndProtocolVersion(t *testing.T) {
	e := start(t, hostRealm, nil)
	c := dial(t, e.paths.ClientSocket("dev"))
	err := c.Call(ctx(t), protocol.MethodSecretRead, map[string]any{"names": []string{"github-pat"}, "scope": "instance"}, nil)
	if pe := callErr(err); pe == nil || pe.Code != protocol.CodeInvalidParams {
		t.Fatalf("unknown field: %v", err)
	}
	err = c.Call(ctx(t), protocol.MethodHello, map[string]any{"min_protocol": 2}, nil)
	if pe := callErr(err); pe == nil || pe.Code != protocol.CodeProtocolUnsupported {
		t.Fatalf("min_protocol: %v", err)
	}
	err = c.Call(ctx(t), "secret.steal", nil, nil)
	if pe := callErr(err); pe == nil || pe.Code != protocol.CodeMethodNotFound {
		t.Fatalf("unknown method: %v", err)
	}
	if len(e.auth.Requests()) != 0 {
		t.Fatal("bad requests reached the authenticator")
	}
}

func TestMalformedAndOversizedInput(t *testing.T) {
	e := start(t, hostRealm, nil)
	c := dial(t, e.paths.ClientSocket("dev"))
	c.WriteRaw([]byte("{not json"))
	line, err := c.ReadRaw()
	if err != nil || !strings.Contains(string(line), `"code":-32700`) {
		t.Fatalf("parse error response %s, %v", line, err)
	}
	// Still usable after a parse error.
	if err := c.Call(ctx(t), protocol.MethodHello, nil, nil); err != nil {
		t.Fatal(err)
	}
	c.WriteRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"server.hello","params":{"x":"` + strings.Repeat("a", protocol.MaxMessage) + `"}}`))
	line, err = c.ReadRaw()
	if err != nil || !strings.Contains(string(line), "too large") {
		t.Fatalf("oversized: %s, %v", line, err)
	}
	if _, err := c.ReadRaw(); err == nil {
		t.Fatal("connection not closed after oversized message")
	}
}

func TestStartRefusesLiveOrNonSocketPaths(t *testing.T) {
	e := start(t, hostRealm, nil)
	// A second server on the same paths must not steal live sockets.
	srv2 := New(Options{Paths: e.paths, Instances: e.srv.opts.Instances, Core: e.srv.opts.Core, Peers: peer.NewLinux()})
	if err := srv2.Start(); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("second server: %v", err)
	}
	e.srv.Shutdown("test")

	// A regular file where the socket should be is never deleted.
	os.WriteFile(e.paths.ClientSocket("dev"), []byte("keep"), 0o600)
	srv3 := New(Options{Paths: e.paths, Instances: e.srv.opts.Instances, Core: e.srv.opts.Core, Peers: peer.NewLinux()})
	if err := srv3.Start(); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("non-socket path: %v", err)
	}
	if b, _ := os.ReadFile(e.paths.ClientSocket("dev")); string(b) != "keep" {
		t.Fatal("file was replaced")
	}

	// A stale socket left by a crash is cleaned up.
	os.Remove(e.paths.ClientSocket("dev"))
	l, _ := net.Listen("unix", e.paths.ClientSocket("dev"))
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	srv4 := New(Options{Paths: e.paths, Instances: e.srv.opts.Instances, Core: e.srv.opts.Core, Peers: peer.NewLinux()})
	if err := srv4.Start(); err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	srv4.Shutdown("test")
}

func TestShutdownCancelsPendingApproval(t *testing.T) {
	e := start(t, hostRealm, nil)
	e.auth.Default = fake.Hang
	e.auth.Started = make(chan plugin.ApprovalRequest, 1)
	c := dial(t, e.paths.ClientSocket("dev"))
	errc := make(chan error, 1)
	go func() {
		errc <- c.Call(context.Background(), protocol.MethodSecretRead, protocol.SecretReadParams{Names: []string{"github-pat"}}, nil)
	}()
	<-e.auth.Started
	e.srv.Shutdown("test")
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("pending read succeeded after shutdown")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pending request not released")
	}
}

func hasReject(s *audit.Memory, reason string) bool {
	for _, ev := range s.Events() {
		if ev.Type == audit.TypeRequestRejected && ev.Reason == reason {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Connections beyond the per-instance cap are closed at once and audited;
// a slot frees up when a connection ends.
func TestConnectionCapPerInstance(t *testing.T) {
	e := startWith(t, hostRealm, nil, func(o *Options) { o.MaxConnections = 2 })
	a, b := dial(t, e.paths.ClientSocket("dev")), dial(t, e.paths.ClientSocket("dev"))
	for _, c := range []*client.Client{a, b} {
		if err := c.Call(ctx(t), protocol.MethodHello, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	over := dial(t, e.paths.ClientSocket("dev"))
	if err := over.Call(ctx(t), protocol.MethodHello, nil, nil); err == nil {
		t.Fatal("connection over the cap was served")
	}
	// The server may close the connection before its audit write lands.
	waitFor(t, func() bool { return rejected(e, "too_many_connections") == 1 })
	a.Close()
	var err error
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if err = dial(t, e.paths.ClientSocket("dev")).Call(ctx(t), protocol.MethodHello, nil, nil); err == nil {
			return
		}
	}
	t.Fatalf("slot not freed after close: %v", err)
}

// An idle connection, or one that drips a request byte by byte, is closed.
func TestIdleAndSlowConnectionsAreClosed(t *testing.T) {
	e := startWith(t, hostRealm, nil, func(o *Options) { o.IdleTimeout = 150 * time.Millisecond })
	idle := dial(t, e.paths.ClientSocket("dev"))
	time.Sleep(400 * time.Millisecond)
	if err := idle.Call(ctx(t), protocol.MethodHello, nil, nil); err == nil {
		t.Fatal("idle connection still served")
	}

	slow, err := net.Dial("unix", e.paths.ClientSocket("dev"))
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	req := `{"jsonrpc":"2.0","id":1,"method":"server.hello"}`
	start := time.Now()
	for i := 0; i < len(req); i++ {
		if _, err := slow.Write([]byte{req[i]}); err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	slow.Write([]byte("\n"))
	slow.SetReadDeadline(time.Now().Add(time.Second))
	if n, _ := slow.Read(make([]byte, 64)); n > 0 && time.Since(start) > 150*time.Millisecond {
		t.Fatal("drip-fed request was answered after the idle timeout")
	}
}

// A slow approval doesn't trip the idle timeout.
func TestIdleTimeoutDoesNotApplyWhileHandling(t *testing.T) {
	e := startWith(t, hostRealm, nil, func(o *Options) { o.IdleTimeout = 100 * time.Millisecond })
	e.auth.Started = make(chan plugin.ApprovalRequest, 1)
	e.auth.Default = fake.Hang
	c := dial(t, e.paths.ClientSocket("dev"))
	done := make(chan error, 1)
	go func() {
		done <- c.Call(context.Background(), protocol.MethodSecretRead, protocol.SecretReadParams{Names: []string{"github-pat"}}, nil)
	}()
	<-e.auth.Started
	time.Sleep(300 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("request ended during approval: %v", err)
	default:
	}
}

// A client that hangs up while its prompt is open cancels the prompt and
// frees its queue slot, instead of holding it until prompt_timeout.
func TestHangUpCancelsPendingApproval(t *testing.T) {
	e := start(t, hostRealm, nil)
	e.auth.Default = fake.Hang
	e.auth.Started = make(chan plugin.ApprovalRequest, 1)
	c := dial(t, e.paths.ClientSocket("dev"))
	c.WriteRaw([]byte(`{"jsonrpc":"2.0","id":1,"method":"secret.read","params":{"names":["github-pat"]}}`))
	<-e.auth.Started
	start := time.Now()
	c.Close()
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, ev := range e.sink.Events() {
			if ev.Type == audit.TypeApprovalTimeout && ev.Reason == "cancelled" {
				if time.Since(start) > time.Second {
					t.Fatal("cancelled too late")
				}
				return
			}
		}
	}
	t.Fatalf("hang-up didn't cancel the prompt; events %v", e.sink.Events())
}

// Every way of sending a request the socket refuses leaves an audit record,
// so a realm probing the socket shows up in the log.
func TestEveryRefusedRequestIsAudited(t *testing.T) {
	e := start(t, hostRealm, nil)
	c := dial(t, e.paths.ClientSocket("dev"))
	cases := []struct{ raw, reason string }{
		{`not json`, "parse_error"},
		{`{"jsonrpc":"1.0","id":1,"method":"x"}`, "invalid_request"},
		{`{"jsonrpc":"2.0","id":1,"method":"vault.export\u001b[2J"}`, "method_not_found"},
		{`{"jsonrpc":"2.0","id":1,"method":"secret.read","params":{"names":["a"],"extra":1}}`, "invalid_params"},
		{`{"jsonrpc":"2.0","id":1,"method":"secret.read","params":{"names":[]}}`, "invalid_params"},
		{`{"jsonrpc":"2.0","id":1,"method":"secret.list","params":{"min_protocol":99}}`, "protocol_unsupported"},
	}
	for _, tc := range cases {
		c.WriteRaw([]byte(tc.raw))
		line, err := c.ReadRaw()
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		var resp protocol.Response
		json.Unmarshal(line, &resp)
		if resp.Error == nil || resp.Error.Data == nil || resp.Error.Data.EventSeq == 0 {
			t.Fatalf("%s: response has no audit seq: %s", tc.raw, line)
		}
	}
	// A notification gets no answer, but it is still recorded.
	c.WriteRaw([]byte(`{"jsonrpc":"2.0","method":"secret.add"}`))
	if err := c.Call(ctx(t), protocol.MethodHello, nil, nil); err != nil {
		t.Fatal(err)
	}
	e.srv.Shutdown("test")
	for _, reason := range []string{"parse_error", "invalid_request", "method_not_found", "invalid_params", "protocol_unsupported"} {
		if rejected(e, reason) == 0 {
			t.Errorf("%s not audited", reason)
		}
	}
	if n := rejected(e, "invalid_request"); n != 2 {
		t.Errorf("invalid_request counted %d, want 2 including the notification", n)
	}
	for _, ev := range e.sink.Events() {
		if m := ev.Params["method"]; strings.ContainsAny(m, "\x1b[") {
			t.Errorf("unsanitised method stored: %q", m)
		}
	}
}
