package helper

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/plugin"
)

// Adapter behaviour that needs a scripted helper. These use the fake only.

func calls(t *testing.T, home string) []call {
	t.Helper()
	f, err := os.Open(filepath.Join(home, "calls.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []call
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var c call
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

type call struct {
	Kind    string          `json:"kind"`
	Op      string          `json:"op"`
	Env     []string        `json:"env"`
	Params  json.RawMessage `json:"params"`
	Acked   uint64          `json:"acked"`
	Started time.Time       `json:"started"`
}

func approve(t *testing.T, script string, fallback bool) (plugin.ApprovalResult, error) {
	t.Helper()
	h, _ := open(t, script, KindAuthenticator)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return NewAuthenticator(h, "touchid", fallback).Approve(ctx, plugin.ApprovalRequest{Prompt: "let gh use GitHub PAT.", Timeout: time.Minute})
}

func TestApproveAnswers(t *testing.T) {
	fakeOnly(t)
	cases := []struct {
		script   string
		fallback bool
		approved bool
		method   string
		err      func(error) bool
	}{
		{script: `{"approve":"approve"}`, approved: true, method: "biometry"},
		{script: `{"approve":"deny"}`},
		{script: `{"approve":"not-approved"}`},
		{script: `{"approve":"password"}`, err: func(e error) bool { return errors.Is(e, plugin.ErrUnavailable) }},
		{script: `{"approve":"password"}`, fallback: true, approved: true, method: "password"},
		{script: `{"approve":"unavailable"}`, err: func(e error) bool { return errors.Is(e, plugin.ErrUnavailable) }},
		{script: `{"approve":"timeout"}`, err: func(e error) bool { return errors.Is(e, context.DeadlineExceeded) }},
		// The system taking the prompt down is a timeout, not a denial.
		{script: `{"approve":"cancelled"}`, err: func(e error) bool { return errors.Is(e, context.DeadlineExceeded) }},
		{script: `{"approve":"internal"}`, err: func(e error) bool { return errors.Is(e, &Error{Code: CodeInternal}) }},
		// Anything the adapter can't read is an error, never an approval.
		{script: `{"approve":"crash"}`, err: func(e error) bool { return e != nil && strings.Contains(e.Error(), "crashing") }},
		// An approval from a helper that then exits non-zero doesn't count.
		{script: `{"approve":"approve-then-fail"}`, err: func(e error) bool { return e != nil && strings.Contains(e.Error(), "answered but then failed") }},
		{script: `{"approve":"garbage"}`, err: func(e error) bool { return e != nil && strings.Contains(e.Error(), "malformed") }},
		{script: `{"approve":"wrong-version"}`, err: func(e error) bool { return e != nil && strings.Contains(e.Error(), "protocol version 2") }},
		{script: `{"approve":"huge"}`, err: func(e error) bool { return e != nil && strings.Contains(e.Error(), "over") }},
	}
	for _, c := range cases {
		r, err := approve(t, c.script, c.fallback)
		if c.err != nil {
			if !c.err(err) || r.Approved {
				t.Errorf("%s fallback=%v: got %+v %v", c.script, c.fallback, r, err)
			}
			continue
		}
		if err != nil || r.Approved != c.approved || r.Method != c.method {
			t.Errorf("%s fallback=%v: got %+v %v", c.script, c.fallback, r, err)
		}
	}
}

// A helper that ignores SIGTERM is killed after the grace period.
func TestHelperIgnoringTermIsKilled(t *testing.T) {
	fakeOnly(t)
	h, _ := open(t, `{"approve":"ignore-term"}`, KindAuthenticator)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewAuthenticator(h, "touchid", false).Approve(ctx, plugin.ApprovalRequest{Prompt: "x", Timeout: time.Minute})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if d := time.Since(start); d < h.cfg.Grace || d > h.cfg.Grace+2*time.Second {
		t.Fatalf("returned after %s; grace is %s", d, h.cfg.Grace)
	}
}

// The helper gets the prompt text and timeout, and an environment with
// nothing in it but HOME, LANG and the protocol version.
func TestHelperRequestAndEnvironment(t *testing.T) {
	fakeOnly(t)
	t.Setenv("FOCA_SECRET_PROBE", "leak")
	t.Setenv("LANG", "en_AU.UTF-8")
	h, home := open(t, "", KindAuthenticator)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := NewAuthenticator(h, "touchid", true).Approve(ctx, plugin.ApprovalRequest{Prompt: "let gh use GitHub PAT.", Timeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
	cs := calls(t, home)
	last := cs[len(cs)-1]
	if last.Kind != "authenticator" || last.Op != "approve" {
		t.Fatalf("last call %+v", last)
	}
	var p approveParams
	json.Unmarshal(last.Params, &p)
	if p.Reason != "let gh use GitHub PAT." || p.TimeoutMS < 15000 || p.TimeoutMS > 20000 || !p.AllowPasswordFallback {
		t.Fatalf("params %+v", p)
	}
	want := map[string]bool{"HOME=" + home: true, "LANG=en_AU.UTF-8": true, "FOCA_HELPER_PROTOCOL=1": true}
	for _, kv := range last.Env {
		if !want[kv] && !strings.HasPrefix(kv, "PWD=") {
			t.Errorf("helper env has %q", kv)
		}
	}
	if len(last.Env) < 3 {
		t.Errorf("helper env %v", last.Env)
	}
}

func TestHelperTrustChecks(t *testing.T) {
	fakeOnly(t)
	ctx := context.Background()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := Open(ctx, Config{Path: "foca-darwin", Log: quiet}); err == nil {
		t.Fatal("relative path accepted")
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "foca-darwin")
	b, _ := os.ReadFile(fakePath)
	os.WriteFile(bin, b, 0o755)
	sum := sha256.Sum256(b)
	pin := hex.EncodeToString(sum[:])

	h, err := Open(ctx, Config{Path: bin, SHA256: strings.ToUpper(pin), Home: dir, Log: quiet}, KindKeyProtector)
	if err != nil {
		t.Fatalf("pinned helper refused: %v", err)
	}
	if _, err := Open(ctx, Config{Path: bin, SHA256: strings.Repeat("0", 64), Home: dir, Log: quiet}); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("pin mismatch: %v", err)
	}

	// The checks run before every spawn, not only at start-up.
	os.Chmod(bin, 0o775)
	if _, err := NewKeyProtector(h, "keychain").Unseal(ctx, plugin.KeyRef{Vault: "v", VaultID: "1"}, []byte("x")); err == nil || !strings.Contains(err.Error(), "writable by group") {
		t.Fatalf("group-writable helper: %v", err)
	}
	os.Chmod(bin, 0o755)
	os.Chmod(dir, 0o777)
	if _, err := Open(ctx, Config{Path: bin, Home: dir, Log: quiet}); err == nil {
		t.Fatal("helper in a world-writable directory accepted")
	}
	os.Chmod(dir, 0o700)
	os.WriteFile(bin, append(b, 0), 0o755)
	if _, err := NewKeyProtector(h, "keychain").Unseal(ctx, plugin.KeyRef{Vault: "v", VaultID: "1"}, []byte("x")); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("replaced helper: %v", err)
	}
}

func TestOpenNeedsEveryKind(t *testing.T) {
	fakeOnly(t)
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, "fake-helper.json"), []byte(`{"kinds":["authenticator"]}`), 0o600)
	_, err := Open(context.Background(), Config{Path: fakePath, Home: home}, KindAuthenticator, KindKeyProtector)
	if err == nil || !strings.Contains(err.Error(), `"key-protector"`) {
		t.Fatalf("got %v", err)
	}
}

func TestKeyProtectorRefusesOddRefs(t *testing.T) {
	fakeOnly(t)
	h, home := open(t, "", KindKeyProtector)
	k := NewKeyProtector(h, "keychain")
	for _, ref := range []plugin.KeyRef{{Vault: "a:b", VaultID: "1"}, {Vault: "a", VaultID: ""}, {Vault: "../x", VaultID: "1"}} {
		if _, err := k.Seal(context.Background(), ref, make([]byte, 32)); err == nil {
			t.Errorf("ref %+v accepted", ref)
		}
	}
	// Refused here, not left to the helper: it was never asked.
	for _, c := range calls(t, home) {
		if c.Kind == KindKeyProtector {
			t.Fatalf("helper was run for an odd ref: %s %s", c.Op, c.Params)
		}
	}
}

// Responses are decoded as strictly as requests: nothing unknown, no
// lookalike keys, and no answer that is both a success and an error.
func TestDecodeResponseIsStrict(t *testing.T) {
	good := `{"v":1,"ok":true,"result":{"approved":true,"method":"biometry"}}`
	var r approveResult
	if err := decodeResponse([]byte(good), &r); err != nil || !r.Approved {
		t.Fatalf("good response: %+v %v", r, err)
	}
	for _, bad := range []string{
		`{"v":1,"ok":true,"result":{"approved":true},"extra":1}`,
		`{"v":1,"ok":true,"result":{"approved":true,"admin":true}}`,
		`{"v":1,"OK":true,"result":{"approved":true}}`,
		`{"v":1,"ok":false,"ok":true,"result":{"approved":true}}`,
		`{"v":1,"ok":true,"result":{"approved":false,"Approved":true}}`,
		`{"v":1,"ok":true,"result":{"approved":true},"error":{"code":"denied"}}`,
		`{"v":1,"ok":false}`,
		`{"v":2,"ok":true,"result":{"approved":true}}`,
	} {
		var r approveResult
		if err := decodeResponse([]byte(bad), &r); err == nil {
			t.Errorf("%s accepted as %+v", bad, r)
		}
	}
}

// runEvents runs the events adapter until it returns, collecting events.
func runEvents(t *testing.T, script string, wait time.Duration) ([]plugin.EventKind, error, string) {
	t.Helper()
	r := runEventsWith(t, script, wait, eventsCore{})
	return r.kinds, r.err, r.home
}

// eventsCore is how the test stands in for the core: it marks each event
// handled, after delay for a sleep, or never for a sleep if ignoreSleep.
// handledWait, if set, shortens how long the source waits for it.
type eventsCore struct {
	delay       time.Duration
	ignoreSleep bool
	handledWait time.Duration
}

type eventsRun struct {
	kinds     []plugin.EventKind
	sleepDone time.Time // when the sleep was marked handled
	err       error
	home      string
}

func runEventsWith(t *testing.T, script string, wait time.Duration, core eventsCore) eventsRun {
	t.Helper()
	h, home := open(t, script, KindEvents)
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	out := make(chan plugin.PlatformEvent, 16)
	r := eventsRun{home: home}
	handled := make(chan struct{})
	go func() {
		defer close(handled)
		for e := range out {
			r.kinds = append(r.kinds, e.Kind)
			if e.Kind == plugin.EventSleep {
				if core.ignoreSleep {
					continue
				}
				time.Sleep(core.delay)
				r.sleepDone = time.Now()
			}
			e.Handled()
		}
	}()
	ev := NewEvents(h, "darwin")
	ev.handledWait = core.handledWait
	r.err = ev.Run(ctx, out)
	close(out)
	<-handled
	return r
}

func TestEventsReportEveryKindAndAckSleep(t *testing.T) {
	fakeOnly(t)
	kinds, err, home := runEvents(t, `{"events":["screen-lock","sleep","session-end"]}`, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := []plugin.EventKind{plugin.EventReady, plugin.EventScreenLock, plugin.EventSleep, plugin.EventSessionEnd}
	if len(kinds) != len(want) {
		t.Fatalf("got %v", kinds)
	}
	for i := range want {
		if kinds[i] != want[i] {
			t.Fatalf("got %v", kinds)
		}
	}
	var acked bool
	for _, c := range calls(t, home) {
		if c.Op == "ack" && c.Acked == 3 {
			acked = true
		}
		if c.Op == "ack-timeout" {
			t.Fatal("sleep wasn't acknowledged")
		}
	}
	if !acked {
		t.Fatal("no ack for the sleep event")
	}
}

// The helper lets the Mac sleep when it gets the ack, so the ack waits until
// the core has handled the sleep (wiped and recorded the lock), or until
// HandledWait if the core never does.
func TestSleepAckedOnlyAfterTheCoreHandledIt(t *testing.T) {
	fakeOnly(t)
	script := `{"events":["sleep"]}`
	ack := func(home string) (time.Time, bool) {
		for _, c := range calls(t, home) {
			if c.Op == "ack-timeout" {
				t.Fatal("sleep wasn't acknowledged")
			}
			if c.Op == "ack" && c.Acked == 2 {
				return c.Started, true
			}
		}
		return time.Time{}, false
	}

	r := runEventsWith(t, script, 1500*time.Millisecond, eventsCore{delay: 300 * time.Millisecond})
	at, ok := ack(r.home)
	if r.err != nil || !ok || r.sleepDone.IsZero() || at.Before(r.sleepDone) {
		t.Fatalf("err %v, acked %v at %v, handled at %v: the ack came before the core was done", r.err, ok, at, r.sleepDone)
	}

	r = runEventsWith(t, script, 1500*time.Millisecond, eventsCore{ignoreSleep: true, handledWait: 200 * time.Millisecond})
	if _, ok := ack(r.home); r.err != nil || !ok {
		t.Fatalf("err %v, acked %v: no ack once HandledWait passed", r.err, ok)
	}
}

// Anything unexpected from the events helper is a failure, so the core
// wipes and turns reuse off until the source is back.
func TestEventsFailures(t *testing.T) {
	fakeOnly(t)
	for script, want := range map[string]string{
		`{"events_then":"exit"}`: "helper exited",
		`{"events":["garbage"]}`: "malformed event",
		`{"events":["unknown"]}`: `unknown event "lid-open"`,
		`{"events":["repeat"]}`:  "seq 1 after 1",
		`{"kinds":["events"],"events":["sleep"],"events_then":"exit"}`: "helper exited",
	} {
		_, err, _ := runEvents(t, script, 10*time.Second)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", script, err, want)
		}
	}
}
