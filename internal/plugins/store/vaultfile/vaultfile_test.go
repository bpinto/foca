package vaultfile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/plugin"
	keyfile "github.com/bpinto/foca/internal/plugins/keyprot/file"
)

var ctx = context.Background()

var cheapKDF = &KDFParams{T: 1, M: minKDFMemory, P: 1}

type vault struct {
	*Store
	prot *keyfile.Protector
	dek  []byte
}

func newVault(t *testing.T, dir, name string) vault {
	t.Helper()
	prot := keyfile.New(filepath.Join(dir, "keys"))
	s := New(filepath.Join(dir, "vaults", name+".fcv"), name)
	if _, err := s.Create(ctx, prot, CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	dek, _, err := s.DEKFunc(prot)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	return vault{s, prot, dek}
}

func (v vault) put(t *testing.T, id, value string) {
	t.Helper()
	if err := v.Put(ctx, v.dek, plugin.SecretMeta{ID: id, Description: "about " + id}, plugin.SecretValue{Bytes: []byte(value)}); err != nil {
		t.Fatal(err)
	}
}

func readRaw(t *testing.T, path string) file_ {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var f file_
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

type file_ = map[string]any

func writeRaw(t *testing.T, path string, f file_) {
	t.Helper()
	b, _ := json.Marshal(f)
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCryptoRoundTrip(t *testing.T) {
	dir := t.TempDir()
	v := newVault(t, dir, "dev")
	v.put(t, "github-pat", "ghp_secret")
	bin := []byte{0, 0xff, 0xfe, '\n'}
	if err := v.Put(ctx, v.dek, plugin.SecretMeta{ID: "bin"}, plugin.SecretValue{Bytes: bin}); err != nil {
		t.Fatal(err)
	}

	// A fresh Store and a fresh unseal, as another process would do.
	s2 := New(v.Path(), "dev")
	dek, release, err := s2.DEKFunc(v.prot)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	metas, err := s2.List(ctx, dek)
	if err != nil || len(metas) != 2 || metas[0].ID != "bin" || metas[1].ID != "github-pat" {
		t.Fatalf("list %v %+v", err, metas)
	}
	if metas[1].Created.IsZero() || metas[1].Description != "about github-pat" {
		t.Fatalf("meta %+v", metas[1])
	}
	_, val, err := s2.Read(ctx, dek, "github-pat")
	if err != nil || string(val.Bytes) != "ghp_secret" {
		t.Fatalf("read %v %q", err, val.Bytes)
	}
	_, val, _ = s2.Read(ctx, dek, "bin")
	if !bytes.Equal(val.Bytes, bin) {
		t.Fatalf("binary value changed: %x", val.Bytes)
	}
	if _, _, err := s2.Read(ctx, dek, "nope"); !errors.Is(err, plugin.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}

	// Nothing readable leaks into the file: no names, tags or values.
	raw, _ := os.ReadFile(v.Path())
	for _, s := range []string{"github-pat", "ghp_secret", `"github"`} {
		if strings.Contains(string(raw), s) {
			t.Fatalf("plaintext %q in vault file", s)
		}
	}
	fi, _ := os.Stat(v.Path())
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("vault mode %o", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(v.Path()))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("vault dir mode %o", di.Mode().Perm())
	}
}

func TestUpdateKeepsCreatedAndUsesFreshNonces(t *testing.T) {
	v := newVault(t, t.TempDir(), "dev")
	v.put(t, "a", "one")
	before := readRaw(t, v.Path())
	v.put(t, "a", "two")
	after := readRaw(t, v.Path())

	metas, _ := v.List(ctx, v.dek)
	if metas[0].Created.IsZero() || metas[0].Updated.IsZero() {
		t.Fatalf("timestamps %+v", metas[0])
	}
	if before["meta"].(map[string]any)["nonce"] == after["meta"].(map[string]any)["nonce"] {
		t.Fatal("meta nonce reused across writes")
	}
	if len(after["entries"].(map[string]any)) != 1 {
		t.Fatal("old entry not dropped")
	}
	for id := range before["entries"].(map[string]any) {
		if _, ok := after["entries"].(map[string]any)[id]; ok {
			t.Fatal("replaced value kept its entry id")
		}
	}
	_, val, _ := v.Read(ctx, v.dek, "a")
	if string(val.Bytes) != "two" {
		t.Fatalf("got %q", val.Bytes)
	}

	if err := v.SetMeta(ctx, v.dek, plugin.SecretMeta{ID: "a", Description: "d", DisplayName: "A"}); err != nil {
		t.Fatal(err)
	}
	m, val, _ := v.Read(ctx, v.dek, "a")
	if string(val.Bytes) != "two" || m.Description != "d" || m.DisplayName != "A" {
		t.Fatalf("set meta: %+v %q", m, val.Bytes)
	}
	if err := v.Delete(ctx, v.dek, "a"); err != nil {
		t.Fatal(err)
	}
	if err := v.Delete(ctx, v.dek, "a"); !errors.Is(err, plugin.ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if f := readRaw(t, v.Path()); len(f["entries"].(map[string]any)) != 0 {
		t.Fatal("entry left after delete")
	}
}

// Every ciphertext is bound to its place: moving one to another entry, to
// "meta", or into another vault makes it undecryptable.
func TestAADSwapRejected(t *testing.T) {
	dir := t.TempDir()
	v := newVault(t, dir, "dev")
	v.put(t, "a", "value-a")
	v.put(t, "b", "value-b")
	w := newVault(t, dir, "work")
	w.put(t, "c", "value-c")

	entryOf := func(s *Store, dek []byte, id string) string {
		f, _ := s.load()
		m, _ := s.openMeta(f, dek)
		for _, e := range m.Secrets {
			if e.ID == id {
				return e.Entry
			}
		}
		t.Fatalf("no entry for %s", id)
		return ""
	}
	ea, eb := entryOf(v.Store, v.dek, "a"), entryOf(v.Store, v.dek, "b")
	ec := entryOf(w.Store, w.dek, "c")
	orig, _ := os.ReadFile(v.Path())

	cases := map[string]struct {
		edit func(f file_)
		read string // secret to read; "" means list (meta)
	}{
		"swap two entries": {func(f file_) {
			es := f["entries"].(map[string]any)
			es[ea], es[eb] = es[eb], es[ea]
		}, "a"},
		"entry box as meta": {func(f file_) {
			f["meta"] = f["entries"].(map[string]any)[ea]
		}, ""},
		"meta box as an entry": {func(f file_) {
			f["entries"].(map[string]any)[ea] = f["meta"]
		}, "a"},
		"entry from another vault": {func(f file_) {
			other := readRaw(t, w.Path())
			f["entries"].(map[string]any)[ea] = other["entries"].(map[string]any)[ec]
		}, "a"},
		"meta from another vault": {func(f file_) {
			f["meta"] = readRaw(t, w.Path())["meta"]
		}, ""},
		"vault_id changed": {func(f file_) { f["vault_id"] = "01J0000000000000000000000" }, ""},
		"version field kept but ciphertext flipped": {func(f file_) {
			b := f["entries"].(map[string]any)[ea].(map[string]any)
			ct := b["ct"].(string)
			b["ct"] = "A" + ct[1:]
			if b["ct"] == ct {
				b["ct"] = "B" + ct[1:]
			}
		}, "a"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			defer os.WriteFile(v.Path(), orig, 0o600)
			f := readRaw(t, v.Path())
			tc.edit(f)
			writeRaw(t, v.Path(), f)
			s := New(v.Path(), "dev")
			var err error
			if tc.read == "" {
				_, err = s.List(ctx, v.dek)
			} else {
				_, _, err = s.Read(ctx, v.dek, tc.read)
			}
			if err == nil {
				t.Fatal("tampered vault decrypted")
			}
		})
	}

	// The whole file copied over another vault's path is refused by name,
	// and wouldn't decrypt under that vault's key anyway.
	copyPath := filepath.Join(dir, "vaults", "work.fcv")
	os.WriteFile(copyPath, orig, 0o600)
	if _, err := New(copyPath, "work").List(ctx, w.dek); err == nil || !strings.Contains(err.Error(), "belongs to vault") {
		t.Fatalf("copied vault: %v", err)
	}
}

func TestWrongKeyAndMissingVault(t *testing.T) {
	dir := t.TempDir()
	v := newVault(t, dir, "dev")
	v.put(t, "a", "x")
	wrong := bytes.Repeat([]byte{1}, 32)
	if _, err := v.List(ctx, wrong); err == nil {
		t.Fatal("listed with the wrong key")
	}
	s := New(filepath.Join(dir, "vaults", "none.fcv"), "none")
	var ni plugin.NotInitialized
	if _, err := s.List(ctx, v.dek); !errors.Is(err, plugin.ErrNotInitialized) || !errors.As(err, &ni) || ni.Vault != "none" {
		t.Fatalf("missing vault: %v", err)
	}
	if _, err := v.Create(ctx, v.prot, CreateOptions{}); err == nil {
		t.Fatal("create replaced an existing vault")
	}
	os.Chmod(v.Path(), 0o644)
	if _, err := New(v.Path(), "dev").List(ctx, v.dek); err == nil {
		t.Fatal("world-readable vault accepted")
	}
}

// The service keeps its Store open; it must see writes made by the CLI
// through a different Store (another process) on the next call.
func TestReaderSeesOtherWritersChanges(t *testing.T) {
	v := newVault(t, t.TempDir(), "dev")
	reader := New(v.Path(), "dev")
	if m, _ := reader.List(ctx, v.dek); len(m) != 0 {
		t.Fatal("not empty")
	}
	writer := New(v.Path(), "dev")
	writer.Put(ctx, v.dek, plugin.SecretMeta{ID: "a"}, plugin.SecretValue{Bytes: []byte("1")})
	if m, _ := reader.List(ctx, v.dek); len(m) != 1 {
		t.Fatalf("reader did not see the write: %+v", m)
	}
	writer.Put(ctx, v.dek, plugin.SecretMeta{ID: "a"}, plugin.SecretValue{Bytes: []byte("2")})
	if _, val, _ := reader.Read(ctx, v.dek, "a"); string(val.Bytes) != "2" {
		t.Fatalf("stale read %q", val.Bytes)
	}
}

// The file and its metadata parse only one way: a duplicate or case-variant
// key, which encoding/json would quietly accept, or trailing data is refused.
func TestAmbiguousVaultFilesAreRefused(t *testing.T) {
	v := newVault(t, t.TempDir(), "dev")
	v.put(t, "a", "x")
	orig, _ := os.ReadFile(v.Path())
	for name, edit := range map[string]func([]byte) []byte{
		"duplicate key": func(b []byte) []byte {
			return bytes.Replace(b, []byte("{"), []byte(`{"vault": "dev",`), 1)
		},
		"case-variant key": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"vault":`), []byte(`"Vault":`), 1)
		},
		"trailing data": func(b []byte) []byte { return append(b, []byte(`{"vault": "dev"}`)...) },
	} {
		t.Run(name, func(t *testing.T) {
			defer os.WriteFile(v.Path(), orig, 0o600)
			b := edit(bytes.Clone(orig))
			if bytes.Equal(b, orig) {
				t.Fatal("edit changed nothing")
			}
			os.WriteFile(v.Path(), b, 0o600)
			if _, err := New(v.Path(), "dev").Header(ctx); err == nil {
				t.Fatal("ambiguous file accepted")
			}
		})
	}

	// The same holds inside the encrypted metadata.
	s := New(v.Path(), "dev")
	f, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	f = f.clone()
	if f.Meta, err = s.seal(f, v.dek, "meta", []byte(`{"secrets":[],"Secrets":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.write(f); err != nil {
		t.Fatal(err)
	}
	if _, err := New(v.Path(), "dev").List(ctx, v.dek); err == nil || !strings.Contains(err.Error(), "bad metadata") {
		t.Fatalf("ambiguous metadata: %v", err)
	}
}

// A write that put the new file in place but couldn't sync its directory
// isn't undone: Create keeps the protector entry the vault on disk needs.
// A write that failed before that leaves neither behind.
func TestCreateKeepsTheKeyOfAVaultWrittenButNotDurable(t *testing.T) {
	defer func() { writeFileAtomic = fsutil.WriteFileAtomic }()
	dir := t.TempDir()
	prot := keyfile.New(filepath.Join(dir, "keys"))

	writeFileAtomic = func(path string, b []byte, perm os.FileMode) error {
		if err := fsutil.WriteFileAtomic(path, b, perm); err != nil {
			return err
		}
		return fmt.Errorf("%w: %w", fsutil.ErrNotDurable, errors.New("EIO"))
	}
	s := New(filepath.Join(dir, "vaults", "dev.fcv"), "dev")
	if _, err := s.Create(ctx, prot, CreateOptions{}); !errors.Is(err, fsutil.ErrNotDurable) {
		t.Fatalf("create: %v", err)
	}
	if _, _, err := New(s.Path(), "dev").DEKFunc(prot)(ctx); err != nil {
		t.Fatalf("the vault written to disk lost its key: %v", err)
	}

	writeFileAtomic = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	s = New(filepath.Join(dir, "vaults", "web.fcv"), "web")
	if _, err := s.Create(ctx, prot, CreateOptions{}); err == nil || errors.Is(err, fsutil.ErrNotDurable) {
		t.Fatalf("create: %v", err)
	}
	if keys, _ := filepath.Glob(filepath.Join(dir, "keys", "web-*")); s.Exists() || len(keys) != 0 {
		t.Fatalf("a failed create left the vault (%v) or its key (%v)", s.Exists(), keys)
	}
}

func TestRecoverySlot(t *testing.T) {
	dir := t.TempDir()
	prot := keyfile.New(filepath.Join(dir, "keys"))
	s := New(filepath.Join(dir, "vaults", "dev.fcv"), "dev")
	h, err := s.Create(ctx, prot, CreateOptions{Recovery: []byte("correct horse"), KDF: cheapKDF})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.SlotTypes) != 2 || h.SlotTypes[1] != SlotPassphrase {
		t.Fatalf("slots %v", h.SlotTypes)
	}
	dek, release, _ := s.DEKFunc(prot)(ctx)
	defer release()
	got, err := s.UnsealPassphrase([]byte("correct horse"))
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("recovery: %v", err)
	}
	if _, err := s.UnsealPassphrase([]byte("wrong")); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	// A crafted file can't ask for absurd KDF memory.
	f := readRaw(t, s.Path())
	f["key_slots"].([]any)[1].(map[string]any)["kdf_params"] = map[string]any{"t": 3, "m": 1 << 30, "p": 4}
	writeRaw(t, s.Path(), f)
	if _, err := New(s.Path(), "dev").UnsealPassphrase([]byte("correct horse")); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("huge kdf: %v", err)
	}
}

func TestUnknownFieldsRefused(t *testing.T) {
	v := newVault(t, t.TempDir(), "dev")
	f := readRaw(t, v.Path())
	f["plaintext"] = "oops"
	writeRaw(t, v.Path(), f)
	if _, err := New(v.Path(), "dev").Header(ctx); err == nil {
		t.Fatal("unknown field accepted")
	}
}
