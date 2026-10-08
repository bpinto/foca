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

// The recovery slot opens the vault with the recovery key, and only with it.
func TestRecoverySlot(t *testing.T) {
	dir := t.TempDir()
	prot := keyfile.New(filepath.Join(dir, "keys"))
	s := New(filepath.Join(dir, "vaults", "dev.fcv"), "dev")
	key := newRecoveryKey(t)
	h, err := s.Create(ctx, prot, CreateOptions{Recovery: key, KDF: cheapKDF})
	if err != nil {
		t.Fatal(err)
	}
	if len(h.SlotTypes) != 2 || h.SlotTypes[1] != SlotRecovery {
		t.Fatalf("slots %v", h.SlotTypes)
	}
	dek, release, _ := s.DEKFunc(prot)(ctx)
	defer release()
	got, err := s.UnsealRecovery(key)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("recovery: %v", err)
	}
	if _, err := s.UnsealRecovery(newRecoveryKey(t)); err == nil || !strings.Contains(err.Error(), "wrong recovery key") {
		t.Fatalf("another key: %v", err)
	}
	if raw, _ := os.ReadFile(s.Path()); bytes.Contains(raw, FormatRecoveryKey(key)) {
		t.Fatal("the recovery key is in the vault file")
	}
	// A crafted file can't ask for absurd KDF memory.
	f := readRaw(t, s.Path())
	f["key_slots"].([]any)[1].(map[string]any)["kdf_params"] = map[string]any{"t": 3, "m": 1 << 30, "p": 4}
	writeRaw(t, s.Path(), f)
	if _, err := New(s.Path(), "dev").UnsealRecovery(key); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("huge kdf: %v", err)
	}
	web := New(filepath.Join(dir, "vaults", "web.fcv"), "web")
	if _, err := web.Create(ctx, prot, CreateOptions{Recovery: []byte("correct horse"), KDF: cheapKDF}); err == nil || web.Exists() {
		t.Fatal("a chosen passphrase was taken as a recovery key")
	}
}

func newRecoveryKey(t *testing.T) []byte {
	t.Helper()
	key, err := NewRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A recovery key has 160 random bits, written in eight groups of four, and
// reads back however it is typed: any case, with or without dashes and
// spaces, I, L and O for 1, 1 and 0.
func TestRecoveryKeyFormat(t *testing.T) {
	key := newRecoveryKey(t)
	if len(key) != 20 || bytes.Equal(key, newRecoveryKey(t)) {
		t.Fatalf("key %x", key)
	}
	written := string(FormatRecoveryKey(key))
	groups := strings.Split(written, "-")
	if len(groups) != 8 {
		t.Fatalf("written %q", written)
	}
	for _, g := range groups {
		if len(g) != 4 || strings.Trim(g, "0123456789ABCDEFGHJKMNPQRSTVWXYZ") != "" {
			t.Fatalf("written %q", written)
		}
	}
	for _, typed := range []string{
		written,
		strings.ToLower(written),
		strings.ReplaceAll(written, "-", ""),
		strings.ReplaceAll(written, "-", " "),
		" " + strings.ReplaceAll(strings.ReplaceAll(written, "1", "l"), "0", "O") + " ",
	} {
		got, err := ParseRecoveryKey([]byte(typed))
		if err != nil || !bytes.Equal(got, key) {
			t.Errorf("%q: %x %v", typed, got, err)
		}
	}
	for _, bad := range []string{"", written[:len(written)-1], written + "0", "U" + written[1:], "correct horse battery staple"} {
		if _, err := ParseRecoveryKey([]byte(bad)); err == nil {
			t.Errorf("%q parsed", bad)
		}
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

// renamed is a protector under another name, as after moving a vault to
// another key protector.
type renamed struct {
	plugin.KeyProtector
	name string
}

func (r renamed) Name() string { return r.name }

// The recovery key seals the key again with the configured
// protector: the data and DEK stay, the old protector slots go, and the
// recovery slot stays for next time. A wrong key changes nothing.
func TestResealWithTheRecoveryKey(t *testing.T) {
	dir := t.TempDir()
	prot := keyfile.New(filepath.Join(dir, "keys"))
	s := New(filepath.Join(dir, "vaults", "dev.fcv"), "dev")
	key := newRecoveryKey(t)
	if _, err := s.Create(ctx, prot, CreateOptions{Recovery: key, KDF: cheapKDF}); err != nil {
		t.Fatal(err)
	}
	dek, release, _ := s.DEKFunc(prot)(ctx)
	if err := s.Put(ctx, dek, plugin.SecretMeta{ID: "a"}, plugin.SecretValue{Bytes: []byte("value")}); err != nil {
		t.Fatal(err)
	}
	release()
	before, _ := os.ReadFile(s.Path())

	next := renamed{keyfile.New(filepath.Join(dir, "other-keys")), "next"}
	if _, err := s.Reseal(ctx, next, newRecoveryKey(t)); err == nil || !strings.Contains(err.Error(), "wrong recovery key") {
		t.Fatalf("wrong key: %v", err)
	}
	if after, _ := os.ReadFile(s.Path()); !bytes.Equal(before, after) {
		t.Fatal("a refused reseal changed the file")
	}

	replaced, err := s.Reseal(ctx, next, key)
	if err != nil || len(replaced) != 1 || replaced[0] != "file" {
		t.Fatalf("reseal: %v %v", replaced, err)
	}
	h, _ := New(s.Path(), "dev").Header(ctx)
	if len(h.SlotTypes) != 2 || h.SlotTypes[0] != "next" || h.SlotTypes[1] != SlotRecovery {
		t.Fatalf("slots %v", h.SlotTypes)
	}
	s2 := New(s.Path(), "dev")
	if _, _, err := s2.DEKFunc(prot)(ctx); err == nil {
		t.Fatal("the replaced protector still opens the vault")
	}
	dek2, release2, err := s2.DEKFunc(next)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release2()
	if _, v, err := s2.Read(ctx, dek2, "a"); err != nil || string(v.Bytes) != "value" {
		t.Fatalf("read after reseal: %q %v", v.Bytes, err)
	}

	noRecovery := newVault(t, t.TempDir(), "web")
	if _, err := noRecovery.Reseal(ctx, next, key); err == nil || !strings.Contains(err.Error(), "has no recovery slot") {
		t.Fatalf("vault without recovery: %v", err)
	}
}

// A recovery slot that the key opens but that wraps some other DEK is
// refused before anything is sealed or written: the working protector slot
// stays.
func TestResealRefusesARecoverySlotForAnotherKey(t *testing.T) {
	dir := t.TempDir()
	prot := keyfile.New(filepath.Join(dir, "keys"))
	s := New(filepath.Join(dir, "vaults", "dev.fcv"), "dev")
	key := newRecoveryKey(t)
	if _, err := s.Create(ctx, prot, CreateOptions{Recovery: key, KDF: cheapKDF}); err != nil {
		t.Fatal(err)
	}
	f, _ := s.load()
	f = f.clone()
	slot, err := recoverySlot(f, bytes.Repeat([]byte{7}, dekSize), key, cheapKDF)
	if err != nil {
		t.Fatal(err)
	}
	f.KeySlots[1] = slot
	if err := s.write(f); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(s.Path())

	next := renamed{keyfile.New(filepath.Join(dir, "other-keys")), "next"}
	if _, err := s.Reseal(ctx, next, key); err == nil || !strings.Contains(err.Error(), "doesn't open this vault") {
		t.Fatalf("reseal: %v", err)
	}
	if after, _ := os.ReadFile(s.Path()); !bytes.Equal(before, after) {
		t.Fatal("a refused reseal changed the file")
	}
	if _, _, err := New(s.Path(), "dev").DEKFunc(prot)(ctx); err != nil {
		t.Fatalf("the working slot was lost: %v", err)
	}
}

// Rekey encrypts every value and the metadata again under a new DEK and a
// new vault id, with fresh entry ids and nonces. The secrets come through
// intact; the old DEK, the old recovery key and, once destroyed, the old
// protector entry open nothing in the new file. A copy of the old file
// still opens with its old recovery key: rekey can't reach copies.
func TestRekeyReplacesEveryKeyAndKeepsTheSecrets(t *testing.T) {
	dir := t.TempDir()
	prot := keyfile.New(filepath.Join(dir, "keys"))
	s := New(filepath.Join(dir, "vaults", "dev.fcv"), "dev")
	oldKey := newRecoveryKey(t)
	h, err := s.Create(ctx, prot, CreateOptions{Recovery: oldKey, KDF: cheapKDF})
	if err != nil {
		t.Fatal(err)
	}
	oldDEK, _, _ := s.DEKFunc(prot)(ctx)
	bin := []byte{0, 0xff, '\n'}
	s.Put(ctx, oldDEK, plugin.SecretMeta{ID: "a", Description: "about a"}, plugin.SecretValue{Bytes: []byte("value-a")})
	s.Put(ctx, oldDEK, plugin.SecretMeta{ID: "bin"}, plugin.SecretValue{Bytes: bin})
	before, _ := s.List(ctx, oldDEK)
	oldRaw, _ := os.ReadFile(s.Path())
	copyPath := filepath.Join(dir, "copy", "vaults", "dev.fcv")
	os.MkdirAll(filepath.Dir(copyPath), 0o700)
	os.WriteFile(copyPath, oldRaw, 0o600)

	newKey := newRecoveryKey(t)
	r, err := s.Rekey(ctx, prot, CreateOptions{Recovery: newKey, KDF: cheapKDF})
	if err != nil {
		t.Fatal(err)
	}
	if r.Old.VaultID != h.VaultID || r.New.VaultID == h.VaultID || len(r.Replaced) != 1 || r.Replaced[0] != "file" {
		t.Fatalf("rekeyed %+v", r)
	}
	if err := prot.Destroy(ctx, r.Old, r.OldSealed); err != nil {
		t.Fatal(err)
	}

	s2 := New(s.Path(), "dev")
	hdr, _ := s2.Header(ctx)
	if hdr.VaultID != r.New.VaultID || len(hdr.SlotTypes) != 2 || hdr.SlotTypes[1] != SlotRecovery {
		t.Fatalf("header %+v", hdr)
	}
	dek, release, err := s2.DEKFunc(prot)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if bytes.Equal(dek, oldDEK) {
		t.Fatal("the DEK didn't change")
	}
	after, err := s2.List(ctx, dek)
	if err != nil || len(after) != 2 || after[0] != before[0] || after[1] != before[1] {
		t.Fatalf("metadata %v: %+v, was %+v", err, after, before)
	}
	if _, v, err := s2.Read(ctx, dek, "a"); err != nil || string(v.Bytes) != "value-a" {
		t.Fatalf("read a: %q %v", v.Bytes, err)
	}
	if _, v, err := s2.Read(ctx, dek, "bin"); err != nil || !bytes.Equal(v.Bytes, bin) {
		t.Fatalf("read bin: %x %v", v.Bytes, err)
	}
	// Nothing of the old file is reused.
	oldF, newF := readRaw(t, copyPath), readRaw(t, s.Path())
	for id := range oldF["entries"].(map[string]any) {
		if _, ok := newF["entries"].(map[string]any)[id]; ok {
			t.Fatal("an entry id was kept")
		}
	}
	if oldF["meta"].(map[string]any)["nonce"] == newF["meta"].(map[string]any)["nonce"] {
		t.Fatal("the meta nonce was kept")
	}

	if _, err := s2.List(ctx, oldDEK); err == nil {
		t.Fatal("the old DEK opens the new file")
	}
	if _, err := s2.UnsealRecovery(oldKey); err == nil || !strings.Contains(err.Error(), "wrong recovery key") {
		t.Fatalf("the old recovery key: %v", err)
	}
	if got, err := s2.UnsealRecovery(newKey); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("the new recovery key: %v", err)
	}
	// The old file's protector slot names the old entry, which is gone.
	f := readRaw(t, s.Path())
	f["key_slots"].([]any)[0] = oldF["key_slots"].([]any)[0]
	writeRaw(t, s.Path(), f)
	if _, _, err := New(s.Path(), "dev").DEKFunc(prot)(ctx); err == nil {
		t.Fatal("the old protector slot opens the new file")
	}
	old := New(copyPath, "dev")
	if _, _, err := old.DEKFunc(prot)(ctx); err == nil {
		t.Fatal("the old copy still opens through the destroyed protector entry")
	}
	if got, err := old.UnsealRecovery(oldKey); err != nil || !bytes.Equal(got, oldDEK) {
		t.Fatalf("the old copy with its old recovery key: %v", err)
	}
}

// failingSeal is a protector whose Seal fails.
type failingSeal struct{ plugin.KeyProtector }

func (failingSeal) Seal(context.Context, plugin.KeyRef, []byte) ([]byte, error) {
	return nil, errors.New("no TPM")
}

// A rekey that fails part way leaves the old vault as it was, openable, and
// no protector entry for the new one behind.
func TestRekeyFailingMidwayLeavesTheOldVault(t *testing.T) {
	defer func() { writeFileAtomic = fsutil.WriteFileAtomic }()
	dir := t.TempDir()
	prot := keyfile.New(filepath.Join(dir, "keys"))
	v := newVault(t, dir, "dev")
	v.put(t, "a", "value-a")
	before, _ := os.ReadFile(v.Path())

	if _, err := v.Rekey(ctx, failingSeal{prot}, CreateOptions{}); err == nil {
		t.Fatal("rekey without a seal")
	}
	writeFileAtomic = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	if _, err := v.Rekey(ctx, prot, CreateOptions{}); err == nil || errors.Is(err, fsutil.ErrNotDurable) {
		t.Fatalf("rekey with a failing write: %v", err)
	}
	writeFileAtomic = fsutil.WriteFileAtomic

	if after, _ := os.ReadFile(v.Path()); !bytes.Equal(before, after) {
		t.Fatal("a failed rekey changed the file")
	}
	if keys, _ := filepath.Glob(filepath.Join(dir, "keys", "*")); len(keys) != 1 {
		t.Fatalf("protector entries left: %v", keys)
	}
	dek, release, err := New(v.Path(), "dev").DEKFunc(prot)(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, val, err := v.Read(ctx, dek, "a"); err != nil || string(val.Bytes) != "value-a" {
		t.Fatalf("read: %q %v", val.Bytes, err)
	}
}
