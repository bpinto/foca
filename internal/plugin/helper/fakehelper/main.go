// Command fakehelper is a stand-in for foca-darwin that speaks helper
// protocol v1. The conformance suite and end-to-end tests run it on Linux.
//
// Its behaviour comes from $HOME/fake-helper.json (see script). It keeps
// "Keychain" entries as files in $HOME/keychain and appends one line per
// call to $HOME/calls.jsonl, so tests can see what it was sent.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type script struct {
	// Approve: approve (default) | password | deny | hang | unavailable |
	// timeout | internal | crash | approve-then-fail | garbage |
	// wrong-version | huge | ignore-term | not-approved | cancelled
	Approve string `json:"approve"`
	// Unavailable makes "available" answer false with this reason.
	Unavailable string `json:"unavailable"`
	// Kinds overrides what info reports.
	Kinds []string `json:"kinds"`
	// Events are sent after ready, in order. "garbage", "unknown" and
	// "repeat" (the last seq again) send a bad line instead.
	Events []string `json:"events"`
	// EventsThen: wait (default, until stdin closes or SIGTERM; SIGUSR1
	// meanwhile reports a screen lock) | exit
	EventsThen string `json:"events_then"`
}

type call struct {
	Kind    string          `json:"kind"`
	Op      string          `json:"op,omitempty"`
	Env     []string        `json:"env,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Acked   uint64          `json:"acked,omitempty"`
	Started time.Time       `json:"started"`
}

var home = os.Getenv("HOME")

func main() {
	if len(os.Args) != 2 {
		fail("bad_request", "usage: fakehelper <kind>")
	}
	kind := os.Args[1]
	sc := load()
	if kind == "events" {
		events(sc)
		return
	}
	in, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		fail("internal", err.Error())
	}
	var req struct {
		V      int             `json:"v"`
		Op     string          `json:"op"`
		Params json.RawMessage `json:"params"`
	}
	dec := json.NewDecoder(bytes.NewReader(in))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		fail("bad_request", "malformed request: "+err.Error())
	}
	record(call{Kind: kind, Op: req.Op, Env: os.Environ(), Params: req.Params, Started: time.Now()})
	if req.V != 1 {
		fail("bad_request", fmt.Sprintf("protocol version %d is not supported", req.V))
	}
	switch kind + " " + req.Op {
	case "info info":
		kinds := []string{"authenticator", "key-protector", "events"}
		if sc.Kinds != nil {
			kinds = sc.Kinds
		}
		ok(map[string]any{"kinds": kinds, "version": "fake"})
	case "authenticator available":
		if sc.Unavailable != "" {
			ok(map[string]any{"available": false, "reason": sc.Unavailable})
		}
		ok(map[string]any{"available": true})
	case "authenticator approve":
		approve(sc, req.Params)
	case "key-protector seal", "key-protector unseal", "key-protector destroy":
		keychain(req.Op, req.Params)
	default:
		fail("bad_request", fmt.Sprintf("unknown op %q for %q", req.Op, kind))
	}
}

func load() script {
	var sc script
	b, err := os.ReadFile(filepath.Join(home, "fake-helper.json"))
	if err == nil {
		if err := json.Unmarshal(b, &sc); err != nil {
			fail("internal", "fake-helper.json: "+err.Error())
		}
	}
	return sc
}

func approve(sc script, raw json.RawMessage) {
	var p struct {
		Reason                string `json:"reason"`
		TimeoutMS             int64  `json:"timeout_ms"`
		AllowPasswordFallback bool   `json:"allow_password_fallback"`
	}
	if err := strict(raw, &p); err != nil || p.Reason == "" || p.TimeoutMS <= 0 {
		fail("bad_request", "approve needs reason and timeout_ms")
	}
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	switch sc.Approve {
	case "", "approve":
		ok(map[string]any{"approved": true, "method": "biometry"})
	case "password":
		if !p.AllowPasswordFallback {
			fail("unavailable", "biometry unavailable and password fallback is off")
		}
		ok(map[string]any{"approved": true, "method": "password"})
	case "not-approved":
		ok(map[string]any{"approved": false})
	case "deny":
		fail("denied", "user cancelled")
	case "unavailable":
		fail("unavailable", "no biometry enrolled")
	case "timeout":
		fail("timeout", "")
	case "cancelled":
		// The system took the prompt down without being asked to.
		fail("cancelled", "prompt dismissed by the system")
	case "internal":
		fail("internal", "LAError -1000")
	case "crash":
		fmt.Fprintln(os.Stderr, "fake helper crashing")
		os.Exit(3)
	case "approve-then-fail":
		fmt.Print(`{"v":1,"ok":true,"result":{"approved":true,"method":"biometry"}}` + "\n")
		fmt.Fprintln(os.Stderr, "fake helper failing after its answer")
		os.Exit(1)
	case "garbage":
		fmt.Print("not json\n")
		os.Exit(0)
	case "wrong-version":
		fmt.Print(`{"v":2,"ok":true,"result":{"approved":true}}` + "\n")
		os.Exit(0)
	case "huge":
		fmt.Print(`{"v":1,"ok":true,"result":{"approved":true,"method":"` + strings.Repeat("x", 128<<10) + `"}}` + "\n")
		os.Exit(0)
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		select {}
	case "hang":
		// Like the real helper: on SIGTERM take the prompt down and
		// answer cancelled; on its own deadline, answer timeout.
		select {
		case <-term:
			fail("cancelled", "terminated")
		case <-time.After(time.Duration(p.TimeoutMS) * time.Millisecond):
			fail("timeout", "")
		}
	default:
		fail("internal", "unknown script approve "+sc.Approve)
	}
}

var refPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

func keychain(op string, raw json.RawMessage) {
	var p struct {
		Vault   string `json:"vault"`
		VaultID string `json:"vault_id"`
		DEK     []byte `json:"dek"`
		Sealed  []byte `json:"sealed"`
	}
	if err := strict(raw, &p); err != nil || !refPart.MatchString(p.Vault) || !refPart.MatchString(p.VaultID) {
		fail("bad_request", "vault and vault_id are required")
	}
	account := "foca:" + p.Vault + ":" + p.VaultID
	dir := filepath.Join(home, "keychain")
	path := filepath.Join(dir, account)
	if p.Sealed != nil && string(p.Sealed) != account {
		fail("mismatch", "sealed names another entry")
	}
	switch op {
	case "seal":
		if len(p.DEK) == 0 || len(p.DEK) > 64 {
			fail("bad_request", "dek must be 1..64 bytes")
		}
		os.MkdirAll(dir, 0o700)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			fail("exists", account)
		}
		if err != nil {
			fail("internal", err.Error())
		}
		f.Write(p.DEK)
		f.Close()
		ok(map[string]any{"sealed": []byte(account)})
	case "unseal":
		if p.Sealed == nil {
			fail("bad_request", "sealed is required")
		}
		dek, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			fail("not_found", account)
		}
		if err != nil {
			fail("internal", err.Error())
		}
		ok(map[string]any{"dek": dek})
	case "destroy":
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			fail("internal", err.Error())
		}
		ok(map[string]any{})
	}
}

func events(sc script) {
	signal.Ignore(syscall.SIGPIPE)
	term := make(chan os.Signal, 1)
	signal.Notify(term, syscall.SIGTERM)
	in := bufio.NewScanner(os.Stdin)
	if !in.Scan() || !bytes.Contains(in.Bytes(), []byte(`"op":"subscribe"`)) {
		fail("bad_request", "expected subscribe")
	}
	record(call{Kind: "events", Op: "subscribe", Env: os.Environ(), Started: time.Now()})
	acks := make(chan uint64, 8)
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		for in.Scan() {
			var a struct {
				Params struct {
					Seq uint64 `json:"seq"`
				} `json:"params"`
			}
			if json.Unmarshal(in.Bytes(), &a) == nil {
				acks <- a.Params.Seq
			}
		}
	}()
	seq := uint64(0)
	emit := func(ev string) {
		seq++
		fmt.Printf(`{"v":1,"seq":%d,"event":%q}`+"\n", seq, ev)
	}
	emit("ready")
	for _, ev := range sc.Events {
		switch ev {
		case "garbage":
			fmt.Println("{not json")
			continue
		case "unknown":
			emit("lid-open")
			continue
		case "repeat":
			fmt.Printf(`{"v":1,"seq":%d,"event":"screen-lock"}`+"\n", seq)
			continue
		}
		emit(ev)
		if ev == "sleep" {
			select {
			case a := <-acks:
				record(call{Kind: "events", Op: "ack", Acked: a, Started: time.Now()})
			case <-time.After(2 * time.Second):
				record(call{Kind: "events", Op: "ack-timeout", Started: time.Now()})
			}
		}
	}
	if sc.EventsThen == "exit" {
		fmt.Fprintln(os.Stderr, "fake events source failing")
		os.Exit(1)
	}
	// SIGUSR1 reports a screen lock, so end-to-end tests can trigger a wipe.
	usr1 := make(chan os.Signal, 1)
	signal.Notify(usr1, syscall.SIGUSR1)
	for {
		select {
		case <-term:
			return
		case <-closed:
			return
		case <-usr1:
			emit("screen-lock")
		}
	}
}

func strict(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func record(c call) {
	if home == "" {
		return
	}
	// Keep the record small and free of key material.
	var p map[string]any
	if json.Unmarshal(c.Params, &p) == nil {
		for _, k := range []string{"dek"} { // never write key material
			if _, ok := p[k]; ok {
				p[k] = "(redacted)"
			}
		}
		c.Params, _ = json.Marshal(p)
	}
	b, _ := json.Marshal(c)
	f, err := os.OpenFile(filepath.Join(home, "calls.jsonl"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	f.Write(append(b, '\n'))
}

func ok(result any) {
	b, _ := json.Marshal(map[string]any{"v": 1, "ok": true, "result": result})
	os.Stdout.Write(append(b, '\n'))
	os.Exit(0)
}

func fail(code, msg string) {
	b, _ := json.Marshal(map[string]any{"v": 1, "ok": false, "error": map[string]string{"code": code, "message": msg}})
	os.Stdout.Write(append(b, '\n'))
	os.Exit(1)
}
