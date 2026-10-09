package helper

// The helper conformance suite (design §5). It runs against the Go fake
// helper by default, and against a real helper with
//
//	FOCA_HELPER=/path/to/foca-darwin go test ./internal/plugin/helper/...
//
// Tests that need a person at the Mac (touch, cancel, lock the screen) run
// only with FOCA_HELPER_INTERACTIVE=1 as well.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/ids"
	"github.com/bpinto/foca/internal/plugin"
)

var fakePath string

func TestMain(m *testing.M) {
	code := func() int {
		if os.Getenv("FOCA_HELPER") != "" {
			return m.Run()
		}
		dir, err := os.MkdirTemp("", "focahelper")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer os.RemoveAll(dir)
		fakePath = filepath.Join(dir, "foca-darwin")
		if out, err := exec.Command("go", "build", "-o", fakePath, "./fakehelper").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "build fake helper: %v\n%s", err, out)
			return 1
		}
		return m.Run()
	}()
	os.Exit(code)
}

// real reports whether the suite runs against a real helper.
func real() bool { return os.Getenv("FOCA_HELPER") != "" }

func interactive(t *testing.T) {
	t.Helper()
	if !real() || os.Getenv("FOCA_HELPER_INTERACTIVE") != "1" {
		t.Skip("needs FOCA_HELPER and FOCA_HELPER_INTERACTIVE=1, and someone at the Mac")
	}
}

func fakeOnly(t *testing.T) {
	t.Helper()
	if real() {
		t.Skip("scripted behaviour: fake helper only")
	}
}

// open starts the helper under test. With the fake, script is written to
// its HOME first; a real helper ignores it.
func open(t *testing.T, script string, need ...string) (*Helper, string) {
	t.Helper()
	home := t.TempDir()
	if script != "" {
		os.WriteFile(filepath.Join(home, "fake-helper.json"), []byte(script), 0o600)
	}
	path := fakePath
	if real() {
		path = os.Getenv("FOCA_HELPER")
		home = os.Getenv("HOME")
	}
	h, err := Open(context.Background(), Config{Path: path, Home: home, Grace: time.Second,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, need...)
	if err != nil {
		t.Fatal(err)
	}
	return h, home
}

func TestConformanceInfo(t *testing.T) {
	h, _ := open(t, "", KindAuthenticator, KindKeyProtector, KindEvents)
	if len(h.kinds) < 3 {
		t.Fatalf("kinds %v", h.kinds)
	}
}

func TestConformanceRejectsBadRequests(t *testing.T) {
	h, _ := open(t, "")
	ctx := context.Background()
	for name, req := range map[string]string{
		"newer protocol": `{"v":2,"op":"info","params":{}}`,
		"unknown op":     `{"v":1,"op":"format-disk","params":{}}`,
		"not json":       `approve please`,
		"unknown field":  `{"v":1,"op":"info","params":{},"admin":true}`,
	} {
		err := h.exchange(ctx, KindInfo, []byte(req), nil)
		if !errors.Is(err, &Error{Code: CodeBadRequest}) {
			t.Errorf("%s: got %v, want bad_request", name, err)
		}
	}
	// An unknown kind fails too, with or without a parsable answer.
	if err := h.exchange(ctx, "launch-missiles", []byte(`{"v":1,"op":"info","params":{}}`), nil); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestConformanceKeyProtector(t *testing.T) {
	h, _ := open(t, "", KindKeyProtector)
	k := NewKeyProtector(h, "keychain")
	ctx := context.Background()
	ref := plugin.KeyRef{Vault: "conformance", VaultID: ids.New()}
	dek := bytes.Repeat([]byte{0x5a}, 32)
	t.Cleanup(func() { k.Destroy(context.Background(), ref, nil) })

	sealed, err := k.Seal(ctx, ref, dek)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, dek) {
		t.Fatal("sealed value contains the key")
	}
	got, err := k.Unseal(ctx, ref, sealed)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unseal: %v %x", err, got)
	}

	// Sealing again for the same vault id never overwrites the entry.
	if _, err := k.Seal(ctx, ref, bytes.Repeat([]byte{1}, 32)); !errors.Is(err, &Error{Code: CodeExists}) {
		t.Fatalf("second seal: %v", err)
	}
	if got, _ := k.Unseal(ctx, ref, sealed); !bytes.Equal(got, dek) {
		t.Fatal("entry overwritten")
	}

	// A key slot naming another vault's entry is refused, so an edited
	// vault header can't borrow another vault's key.
	other := plugin.KeyRef{Vault: "conformance", VaultID: ids.New()}
	t.Cleanup(func() { k.Destroy(context.Background(), other, nil) })
	if _, err := k.Seal(ctx, other, bytes.Repeat([]byte{2}, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Unseal(ctx, other, sealed); !errors.Is(err, &Error{Code: CodeMismatch}) {
		t.Fatalf("unseal with another vault's slot: %v", err)
	}
	if err := k.Destroy(ctx, other, sealed); !errors.Is(err, &Error{Code: CodeMismatch}) {
		t.Fatalf("destroy with another vault's slot: %v", err)
	}

	if err := k.Destroy(ctx, ref, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Unseal(ctx, ref, sealed); !errors.Is(err, &Error{Code: CodeNotFound}) {
		t.Fatalf("unseal after destroy: %v", err)
	}
	if err := k.Destroy(ctx, ref, nil); err != nil {
		t.Fatalf("destroying a missing entry: %v", err)
	}
}

func TestConformanceAvailable(t *testing.T) {
	h, _ := open(t, "", KindAuthenticator)
	ok, why := NewAuthenticator(h, "touchid", false).Available(context.Background())
	t.Logf("available=%v reason=%q", ok, why)
	if !ok && why == "" {
		t.Fatal("unavailable without a reason")
	}
}

// A prompt nobody answers comes down when the deadline passes, and the
// helper is gone by the time Approve returns.
func TestConformanceApproveTimeout(t *testing.T) {
	h, _ := open(t, `{"approve":"hang"}`, KindAuthenticator)
	a := NewAuthenticator(h, "touchid", false)
	// A Mac without Touch ID (a CI runner) answers unavailable at once,
	// with no prompt to time out.
	if ok, why := a.Available(context.Background()); !ok {
		t.Skipf("no prompt can be shown here: %s", why)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := a.Approve(ctx, plugin.ApprovalRequest{Prompt: "let conformance use nothing (this prompt times out).", Timeout: time.Minute})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want a timeout", err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond+h.cfg.Grace+500*time.Millisecond {
		t.Fatalf("took %s", d)
	}
}

func TestConformanceEventsReadyAndStop(t *testing.T) {
	h, _ := open(t, "", KindEvents)
	ev := NewEvents(h, "darwin")
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan plugin.PlatformEvent, 8)
	done := make(chan error, 1)
	go func() { done <- ev.Run(ctx, out) }()
	select {
	case e := <-out:
		if e.Kind != plugin.EventReady || e.Source != "darwin" {
			t.Fatalf("first event %+v", e)
		}
	case err := <-done:
		t.Fatalf("Run returned before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("no ready")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stop: %v", err)
		}
	case <-time.After(h.cfg.Grace + 2*time.Second):
		t.Fatal("Run didn't return after cancel")
	}
}

// ---- interactive, real helper only ----

func TestConformanceInteractiveApprove(t *testing.T) {
	interactive(t)
	h, _ := open(t, "", KindAuthenticator)
	a := NewAuthenticator(h, "touchid", false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	t.Log("touch the sensor to APPROVE")
	r, err := a.Approve(ctx, plugin.ApprovalRequest{Prompt: "share:\n🔑 a test (touch to approve)\n🖥️ VM conformance\n👤 gh ⚠ via claude ⚠\n⏱️ 15m, anything in this VM", Timeout: time.Minute})
	if err != nil || !r.Approved || r.Method != "biometry" {
		t.Fatalf("got %+v %v", r, err)
	}
	t.Log("press CANCEL")
	r, err = a.Approve(ctx, plugin.ApprovalRequest{Prompt: "run:\n⚙️ \"a test\" with step=press-cancel\n🚢 container conformance\n❔ gh via claude (unverified)", Timeout: time.Minute})
	if err != nil || r.Approved {
		t.Fatalf("cancel: got %+v %v, want a denial", r, err)
	}
}

func TestConformanceInteractiveScreenLock(t *testing.T) {
	interactive(t)
	h, _ := open(t, "", KindEvents)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	out := make(chan plugin.PlatformEvent, 8)
	go NewEvents(h, "darwin").Run(ctx, out)
	if e := <-out; e.Kind != plugin.EventReady {
		t.Fatalf("first event %+v", e)
	}
	t.Log("LOCK THE SCREEN (ctrl-cmd-Q), then unlock")
	select {
	case e := <-out:
		if e.Kind != plugin.EventScreenLock {
			t.Fatalf("got %+v", e)
		}
	case <-ctx.Done():
		t.Fatal("no screen-lock event")
	}
}
