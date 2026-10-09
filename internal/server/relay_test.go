//go:build linux

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/client"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/plugins/peer"
	"github.com/bpinto/foca/internal/protocol"
)

// sshPeer is what the host kernel shows for a forwarded socket.
var sshPeer = identity.VerifiedPeer{UID: os.Getuid(), PID: 4711, Exe: "/usr/bin/ssh", Name: "ssh", PIDStable: true, Session: "sid:10:100"}

// startRelayed runs a VM instance whose config names the relay key pub.
func startRelayed(t *testing.T, pub ed25519.PublicKey) *env {
	t.Helper()
	return startWith(t, vmRealm, &peer.Static{Peer: sshPeer}, func(o *Options) {
		ci, _ := o.Core.Instance("dev")
		ci.GuestRelay = pub
	})
}

func relayKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func challenge(t *testing.T, c *client.Client) protocol.RelayChallengeResult {
	t.Helper()
	var ch protocol.RelayChallengeResult
	if err := c.Call(ctx(t), protocol.MethodRelayChallenge, protocol.RelayChallengeParams{}, &ch); err != nil {
		t.Fatal(err)
	}
	return ch
}

func sign(t *testing.T, key ed25519.PrivateKey, ch protocol.RelayChallengeResult) string {
	t.Helper()
	nonce, err := base64.StdEncoding.DecodeString(ch.Nonce)
	if err != nil || len(nonce) != protocol.NonceSize {
		t.Fatalf("nonce %q", ch.Nonce)
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, protocol.RelayMessage(ch.Instance, ch.Connection, nonce)))
}

// relayHello passes the handshake on a new connection, as the relay does.
func relayHello(t *testing.T, e *env, key ed25519.PrivateKey) *client.Client {
	t.Helper()
	c := dial(t, e.paths.ClientSocket("dev"))
	ch := challenge(t, c)
	if err := c.Call(ctx(t), protocol.MethodRelayHello, protocol.RelayHelloParams{Signature: sign(t, key, ch)}, nil); err != nil {
		t.Fatalf("relay.hello: %v", err)
	}
	return c
}

var guestGh = &identity.GuestInfo{Source: "SO_PEERCRED+SO_PEERPIDFD", PID: 812, StartTime: 9, UID: 1000,
	Name: "gh", PIDStable: true, Session: "sid:780:1"}

func readAs(t *testing.T, c *client.Client, g *identity.GuestInfo, claim *identity.ClientInfo) error {
	t.Helper()
	return c.Call(ctx(t), protocol.MethodSecretRead, protocol.SecretReadParams{
		Common: protocol.Common{GuestVerified: g, Client: claim}, Names: []string{"dev:github-pat"}}, &protocol.SecretReadResult{})
}

// closed reports whether the server has closed c.
func closed(t *testing.T, c *client.Client) bool {
	t.Helper()
	return c.Call(ctx(t), protocol.MethodHello, protocol.HelloParams{Protocol: 1}, nil) != nil
}

func code(err error) int {
	if pe := callErr(err); pe != nil {
		return pe.Code
	}
	return 0
}

// With a relay configured, nothing but the relay's handshake is answered
// before relay.hello passes; the request is refused, recorded and the
// connection closed, never served with weaker identity.
func TestRequestWithoutRelayHelloRefused(t *testing.T) {
	pub, _ := relayKeys(t)
	e := startRelayed(t, pub)
	e.auth.Default = fake.Approve
	for _, method := range []string{protocol.MethodHello, protocol.MethodSecretRead, protocol.MethodSecretList, "secret.add"} {
		c := dial(t, e.paths.ClientSocket("dev"))
		err := c.Call(ctx(t), method, map[string]any{"names": []string{"dev:github-pat"}}, nil)
		if code(err) != protocol.CodeRelayRequired || callErr(err).Data.RequestID == "" {
			t.Fatalf("%s before relay.hello: %v", method, err)
		}
		if !closed(t, c) {
			t.Fatalf("%s: connection left open", method)
		}
	}
	waitFor(t, func() bool { return hasReject(e.sink, "relay_required") })
	if len(e.auth.Requests()) != 0 {
		t.Fatal("prompted without a relay")
	}
}

func TestBadRelayHelloRefused(t *testing.T) {
	pub, priv := relayKeys(t)
	_, other := relayKeys(t)
	e := startRelayed(t, pub)
	hello := func(c *client.Client, sig string) error {
		return c.Call(ctx(t), protocol.MethodRelayHello, protocol.RelayHelloParams{Signature: sig}, nil)
	}
	cases := map[string]func(c *client.Client) error{
		"another key": func(c *client.Client) error { return hello(c, sign(t, other, challenge(t, c))) },
		"another connection's signature": func(c *client.Client) error {
			old := challenge(t, dial(t, e.paths.ClientSocket("dev")))
			challenge(t, c)
			return hello(c, sign(t, priv, old))
		},
		"another instance": func(c *client.Client) error {
			ch := challenge(t, c)
			ch.Instance = "work"
			return hello(c, sign(t, priv, ch))
		},
		"not base64": func(c *client.Client) error { challenge(t, c); return hello(c, "!!") },
		"no challenge": func(c *client.Client) error {
			return hello(c, sign(t, priv, protocol.RelayChallengeResult{Instance: "dev", Nonce: base64.StdEncoding.EncodeToString(make([]byte, 32))}))
		},
		"replayed on its own connection": func(c *client.Client) error {
			ch := challenge(t, c)
			sig := sign(t, priv, ch)
			if err := hello(c, sig); err != nil {
				t.Fatal(err)
			}
			return hello(c, sig)
		},
		"second challenge": func(c *client.Client) error {
			challenge(t, c)
			return c.Call(ctx(t), protocol.MethodRelayChallenge, protocol.RelayChallengeParams{}, nil)
		},
	}
	for name, try := range cases {
		t.Run(name, func(t *testing.T) {
			c := dial(t, e.paths.ClientSocket("dev"))
			if err := try(c); code(err) != protocol.CodeRelayRequired {
				t.Fatalf("got %v", err)
			}
			if !closed(t, c) {
				t.Fatal("connection left open")
			}
		})
	}
	waitFor(t, func() bool { return hasReject(e.sink, "relay_hello_invalid") && hasReject(e.sink, "relay_required") })
}

func TestRelayHandshakeOnlyWhereARelayIsConfigured(t *testing.T) {
	e := start(t, vmRealm, &peer.Static{Peer: sshPeer})
	c := dial(t, e.paths.ClientSocket("dev"))
	if err := c.Call(ctx(t), protocol.MethodRelayChallenge, nil, nil); code(err) != protocol.CodeMethodNotFound {
		t.Fatalf("relay.challenge without a relay: %v", err)
	}
}

// guest_verified from anything but a verified relay is refused: on an
// instance without one, and on a relay instance before relay.hello.
func TestForgedGuestVerifiedRefusedByTheHost(t *testing.T) {
	e := start(t, vmRealm, &peer.Static{Peer: sshPeer})
	e.auth.Default = fake.Approve
	c := dial(t, e.paths.ClientSocket("dev"))
	if err := readAs(t, c, guestGh, nil); code(err) != protocol.CodeInvalidParams {
		t.Fatalf("guest_verified without a relay: %v", err)
	}
	// Exact-case keys only, so no spelling of it slips through either.
	c.WriteRaw([]byte(`{"jsonrpc":"2.0","id":7,"method":"secret.list","params":{"Guest_Verified":{"pid":1}}}`))
	if line, _ := c.ReadRaw(); !strings.Contains(string(line), `"code":-32602`) {
		t.Fatalf("case variant: %s", line)
	}
	waitFor(t, func() bool { return hasReject(e.sink, "forged_guest_verified") })
	if len(e.auth.Requests()) != 0 {
		t.Fatal("prompted for a forged identity")
	}

	pub, _ := relayKeys(t)
	e = startRelayed(t, pub)
	c = dial(t, e.paths.ClientSocket("dev"))
	err := c.Call(ctx(t), protocol.MethodRelayChallenge, protocol.RelayChallengeParams{Common: protocol.Common{GuestVerified: guestGh}}, nil)
	if code(err) != protocol.CodeRelayRequired || !closed(t, c) {
		t.Fatalf("guest_verified before relay.hello: %v", err)
	}
	waitFor(t, func() bool { return hasReject(e.sink, "forged_guest_verified") })
}

// On a relayed connection every request carries the caller as the relay read
// it, and always the same caller: a second process means the relay shares
// connections, which would blur connection scope.
func TestRelayedRequestsNeedOneGuestPerConnection(t *testing.T) {
	pub, priv := relayKeys(t)
	e := startRelayed(t, pub)
	e.auth.Default = fake.Approve
	c := relayHello(t, e, priv)
	if err := readAs(t, c, nil, nil); code(err) != protocol.CodeRelayRequired {
		t.Fatalf("no guest_verified: %v", err)
	}
	bad := *guestGh
	bad.Parents = []identity.Proc{{PID: 790, Exe: "/usr/bin/gh", Sealed: true}} // more than a relay can read
	if err := readAs(t, c, &bad, nil); code(err) != protocol.CodeInvalidParams {
		t.Fatalf("malformed guest_verified: %v", err)
	}
	if err := readAs(t, c, guestGh, nil); err != nil {
		t.Fatal(err)
	}
	other := *guestGh
	other.PID = 813
	if err := readAs(t, c, &other, nil); code(err) != protocol.CodeRelayRequired || !closed(t, c) {
		t.Fatalf("second caller: %v", err)
	}
	waitFor(t, func() bool {
		return hasReject(e.sink, "guest_verified_missing") && hasReject(e.sink, "invalid_guest_verified") && hasReject(e.sink, "relay_multiplexed")
	})
}

// What a caller claims about itself never replaces what the relay read: the
// prompt names the guest-verified program, and the audit log keeps the two
// apart.
func TestReportedFieldsCantOverwriteGuestVerified(t *testing.T) {
	pub, priv := relayKeys(t)
	e := startRelayed(t, pub)
	e.auth.Default = fake.Approve
	c := relayHello(t, e, priv)
	claim := &identity.ClientInfo{PID: 1, Exe: "/usr/bin/aws", Name: "aws", Session: "sid:1:1"}
	if err := c.Call(ctx(t), protocol.MethodHello, protocol.HelloParams{Protocol: 1, Common: protocol.Common{GuestVerified: guestGh, Client: claim}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := readAs(t, c, guestGh, claim); err != nil {
		t.Fatal(err)
	}
	if p := e.auth.Requests()[0].Prompt; p != "share:\n🔑 GitHub PAT\n🖥️ VM dev\n👤 gh ⚠" {
		t.Fatalf("prompt %q", p)
	}
	var read *audit.Event
	for _, ev := range e.sink.Events() {
		if ev.Type == audit.TypeSecretRead {
			ev := ev
			read = &ev
		}
	}
	if read == nil || read.Client == nil || read.Client.GuestVerified == nil || read.Client.Reported == nil {
		t.Fatalf("read event %+v", read)
	}
	g, r := read.Client.GuestVerified, read.Client.Reported
	if g.PID != 812 || g.Name != "gh" || g.Session != guestGh.Session || r.Exe != "/usr/bin/aws" || r.PID != 1 {
		t.Fatalf("guest %+v, reported %+v", g, r)
	}
	if b, _ := json.Marshal(read.Peer); !strings.Contains(string(b), `"exe":"/usr/bin/ssh"`) {
		t.Fatalf("peer %s", b)
	}
}

// On an instance that answers only its relay, a connection that hasn't
// passed relay.hello is closed by any refusal, malformed input included,
// and the refusal is recorded.
func TestRelayOnlyInstanceClosesOnAnyRefusalBeforeHello(t *testing.T) {
	pub, _ := relayKeys(t)
	cases := map[string]struct{ line, reason string }{
		"not json":       {`{not json`, "parse_error"},
		"bad envelope":   {`{"jsonrpc":"1.0","id":1,"method":"secret.list"}`, "invalid_request"},
		"id an object":   {`{"jsonrpc":"2.0","id":{},"method":"secret.list"}`, "invalid_request"},
		"notification":   {`{"jsonrpc":"2.0","method":"secret.list"}`, "invalid_request"},
		"duplicate keys": {`{"jsonrpc":"2.0","id":1,"id":2,"method":"secret.list"}`, "invalid_request"},
	}
	for name, tc := range cases {
		e := startRelayed(t, pub)
		c := dial(t, e.paths.ClientSocket("dev"))
		c.WriteRaw([]byte(tc.line))
		c.SetDeadline(time.Now().Add(3 * time.Second))
		if name != "notification" {
			if line, err := c.ReadRaw(); err != nil || !strings.Contains(string(line), `"error"`) {
				t.Fatalf("%s: answer %s, %v", name, line, err)
			}
		}
		if _, err := c.ReadRaw(); !errors.Is(err, io.EOF) {
			t.Fatalf("%s: connection left open: %v", name, err)
		}
		waitFor(t, func() bool { return hasReject(e.sink, tc.reason) })
	}
}

// Every spelling of guest_verified that encoding/json would fold to it is
// recorded as a forgery, not as just another unknown key.
func TestGuestVerifiedVariantsAreRecordedAsForged(t *testing.T) {
	for _, key := range []string{`Guest_Verified`, `gue\u017ft_verified`, "gue\u017ft_verified", `GUEST_VERIFIED`} {
		e := start(t, vmRealm, &peer.Static{Peer: sshPeer})
		c := dial(t, e.paths.ClientSocket("dev"))
		c.WriteRaw([]byte(`{"jsonrpc":"2.0","id":7,"method":"secret.list","params":{"` + key + `":{"pid":1}}}`))
		if line, _ := c.ReadRaw(); !strings.Contains(string(line), `"code":-32602`) {
			t.Fatalf("%s: %s", key, line)
		}
		waitFor(t, func() bool { return hasReject(e.sink, "forged_guest_verified") })
	}
}

// The relay checks params against the same types the host decodes them
// with, so every method the host answers must have one.
func TestRelayChecksParamsOfEveryClientMethod(t *testing.T) {
	for m := range clientMethods {
		if known, err := protocol.CheckParams(m, json.RawMessage(`{}`)); !known || err != nil {
			t.Errorf("%s: known %v, %v", m, known, err)
		}
	}
}
