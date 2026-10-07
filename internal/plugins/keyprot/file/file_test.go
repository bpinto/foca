package file

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bpinto/foca/internal/plugin"
)

func TestSealUnsealRoundTripAndBinding(t *testing.T) {
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "keys")
	p := New(dir)
	ref := plugin.KeyRef{Vault: "dev", VaultID: "01AAA"}
	dek := bytes.Repeat([]byte{7}, 32)
	sealed, err := p.Seal(ctx, ref, dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Unseal(ctx, ref, sealed)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unseal: %v %x", err, got)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("key dir mode %o", fi.Mode().Perm())
	}

	// A sealed key from one vault id doesn't open under another, even
	// when both key files exist.
	other := plugin.KeyRef{Vault: "dev", VaultID: "01BBB"}
	if _, err := p.Seal(ctx, other, dek); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Unseal(ctx, other, sealed); err == nil {
		t.Fatal("sealed key opened under another vault id")
	}

	// Two refs can name the same key file ("dev" + "x-01CCC" and
	// "dev-x" + "01CCC"); the sealed key is still bound to its own vault
	// and id.
	a, b := plugin.KeyRef{Vault: "dev", VaultID: "x-01CCC"}, plugin.KeyRef{Vault: "dev-x", VaultID: "01CCC"}
	pa, _ := p.keyPath(a)
	if pb, _ := p.keyPath(b); pa != pb {
		t.Fatalf("expected one key file, got %s and %s", pa, pb)
	}
	sa, err := p.Seal(ctx, a, dek)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Unseal(ctx, b, sa); err == nil {
		t.Fatal("sealed key opened under another vault sharing its key file")
	}

	// A group-readable key file is refused.
	path, _ := p.keyPath(ref)
	os.Chmod(path, 0o640)
	if _, err := p.Unseal(ctx, ref, sealed); err == nil {
		t.Fatal("group-readable key file accepted")
	}
	os.Chmod(path, 0o600)

	if err := p.Destroy(ctx, ref, sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Unseal(ctx, ref, sealed); err == nil {
		t.Fatal("unsealed after destroy")
	}
}

func TestRejectsPathsInRef(t *testing.T) {
	p := New(t.TempDir())
	if _, err := p.Seal(context.Background(), plugin.KeyRef{Vault: "../x", VaultID: "1"}, make([]byte, 32)); err == nil {
		t.Fatal("path in vault name accepted")
	}
}
