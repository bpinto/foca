//go:build foca_testing

// The macOS plugins over the Go fake helper. Production builds refuse them
// off macOS, so these run in test builds.

package wiring

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/config"
)

// buildFakeHelper builds the Go stand-in for foca-darwin and makes it the
// built-in helper path for this test.
func buildFakeHelper(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "fwire")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	bin := filepath.Join(dir, "foca-darwin")
	out, err := exec.Command("go", "build", "-o", bin, "../../plugin/helper/fakehelper").CombinedOutput()
	if err != nil {
		t.Skipf("can't build the fake helper: %v\n%s", err, out)
	}
	setBuiltin(t, bin, pinOf(t, bin))
	return bin
}

func pinOf(t *testing.T, path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func setBuiltin(t *testing.T, path, sum string) {
	oldPath, oldSum := builtinHelperPath, builtinHelperSHA256
	builtinHelperPath, builtinHelperSHA256 = path, sum
	t.Cleanup(func() { builtinHelperPath, builtinHelperSHA256 = oldPath, oldSum })
}

func darwinConfig(t *testing.T, script string) (*config.Config, config.Paths) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home) // the helper's HOME: its script and "Keychain"
	if script != "" {
		os.WriteFile(filepath.Join(home, "fake-helper.json"), []byte(script), 0o600)
	}
	cfg, err := config.Parse([]byte(`version = 1
[plugins]
authenticator   = "touchid"
secret_store    = "vault-file"
key_protector   = "keychain"
platform_events = "darwin"
[instances.dev]
`))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	return cfg, config.Paths{DataDir: filepath.Join(dir, "d"), RuntimeDir: filepath.Join(dir, "r")}
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// touchid, keychain and darwin events all come from the one helper, opened
// once. This runs on any OS: only the helper is platform-specific.
func TestDarwinPluginsWireToTheHelper(t *testing.T) {
	buildFakeHelper(t)
	cfg, paths := darwinConfig(t, "")
	host, err := BuildHost(cfg, paths, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if host.Protector.Name() != "keychain" {
		t.Fatalf("protector %q", host.Protector.Name())
	}
	e := &env{cfg: cfg, log: quiet}
	a, err := authenticator(e, "touchid")
	if err != nil || a.Name() != "touchid" {
		t.Fatalf("authenticator: %v", err)
	}
	ev, err := platformEvents(e)
	if err != nil || ev == nil || ev.Name() != "darwin" {
		t.Fatalf("events: %v %v", ev, err)
	}
	first := e.darwin
	if _, err := keyProtector(e, paths); err != nil || e.darwin != first {
		t.Fatalf("helper opened twice (%v)", err)
	}
}

// Without a built-in path, the helper is the foca-darwin next to the
// running binary.
func TestDarwinHelperDefaultsToTheBinarysDirectory(t *testing.T) {
	setBuiltin(t, "", strings.Repeat("ab", 32))
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	got, err := darwinHelperPath()
	if err != nil || got != filepath.Join(filepath.Dir(exe), "foca-darwin") {
		t.Fatalf("got %q %v", got, err)
	}
	cfg, paths := darwinConfig(t, "")
	_, err = BuildHost(cfg, paths, quiet)
	if err == nil || !strings.Contains(err.Error(), "not at "+got+"; install it next to foca") ||
		!strings.Contains(err.Error(), `authenticator = "touchid"`) {
		t.Fatalf("missing helper: %v", err)
	}
}

func TestDarwinHelperRefusals(t *testing.T) {
	bin := buildFakeHelper(t)

	// A helper that lacks a kind the config uses is refused at start-up.
	cfg, paths := darwinConfig(t, `{"kinds":["authenticator","key-protector"]}`)
	if _, err := BuildHost(cfg, paths, quiet); err == nil || !strings.Contains(err.Error(), `"events"`) {
		t.Fatalf("missing kind: %v", err)
	}

	// So is one that fails the trust checks.
	os.Chmod(bin, 0o777)
	cfg, paths = darwinConfig(t, "")
	if _, err := BuildHost(cfg, paths, quiet); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("world-writable helper: %v", err)
	}
	os.Chmod(bin, 0o755)

	// And one that doesn't match the pin built into foca.
	setBuiltin(t, bin, strings.Repeat("ab", 32))
	cfg, paths = darwinConfig(t, "")
	if _, err := BuildHost(cfg, paths, quiet); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("pin mismatch: %v", err)
	}

	// A build that names a path that isn't there says so.
	setBuiltin(t, filepath.Join(filepath.Dir(bin), "gone"), pinOf(t, bin))
	if _, err := BuildHost(cfg, paths, quiet); err == nil || !strings.Contains(err.Error(), "this build expects it there") {
		t.Fatalf("missing built-in helper: %v", err)
	}
}

// The pin is required: a foca built without one runs no helper at all,
// even a genuine one in the right place.
func TestDarwinHelperNeedsABuiltInPin(t *testing.T) {
	bin := buildFakeHelper(t)
	setBuiltin(t, bin, "")
	cfg, paths := darwinConfig(t, "")
	_, err := BuildHost(cfg, paths, quiet)
	if err == nil || !strings.Contains(err.Error(), "built without its sha256 pin") {
		t.Fatalf("unpinned build: %v", err)
	}
	home := os.Getenv("HOME")
	if _, err := os.Stat(filepath.Join(home, "calls.jsonl")); err == nil {
		t.Fatal("the helper ran")
	}
}
