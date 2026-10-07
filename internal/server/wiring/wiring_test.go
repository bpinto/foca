//go:build !foca_testing

package wiring

import (
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/config"
)

// In a production build, no config can select the always-approving fake.
func TestFakeAuthenticatorRefusedInProductionBuild(t *testing.T) {
	cfg, err := config.Parse([]byte("version = 1\n[plugins]\nauthenticator = \"fake\"\n[instances.dev]\n"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_, err = Build(cfg, config.Paths{DataDir: filepath.Join(dir, "d"), RuntimeDir: filepath.Join(dir, "r")}, "test",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "only available in test builds") {
		t.Fatalf("got %v", err)
	}
	if TestBuild {
		t.Fatal("TestBuild set in a production build")
	}
}

func TestPlannedAuthenticatorsSayTheyAreNotImplemented(t *testing.T) {
	_, err := authenticator("touchid")
	if err == nil || !strings.Contains(err.Error(), "not implemented yet") {
		t.Fatalf("got %v", err)
	}
	if _, err := authenticator("anything"); err == nil {
		t.Fatal("unknown authenticator accepted")
	}
}

func TestPlannedKeyProtectorsSayTheyAreNotImplemented(t *testing.T) {
	cfg, err := config.Parse([]byte("version = 1\n[plugins]\nauthenticator = \"x\"\nsecret_store = \"vault-file\"\nkey_protector = \"keychain\"\n[instances.dev]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyProtector(cfg, config.Paths{}); err == nil || !strings.Contains(err.Error(), "not implemented yet") {
		t.Fatalf("got %v", err)
	}
}
