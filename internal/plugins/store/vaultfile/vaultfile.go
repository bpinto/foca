// Package vaultfile is the encrypted vault file (design §10).
//
// A random 256-bit data key (DEK) encrypts everything. It is stored only
// wrapped, in key slots: one per key protector, plus an optional recovery
// passphrase. Metadata and each value are separate AES-256-GCM boxes, with a
// fresh random nonce on every write and AAD that binds each box to its place:
//
//	format|version|vault_id|vault|<entry-id or "meta">
//
// so ciphertexts can't be moved between entries, vaults or files. Entry ids
// are random, so the plaintext file doesn't reveal secret names.
//
// The service only reads vault files and re-reads one when it changes on
// disk. The host CLI writes them under an exclusive lock, atomically.
package vaultfile

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/ids"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/protocol"
)

const (
	Format  = "foca-vault"
	Version = 1
	Cipher  = "aes-256-gcm"

	dekSize   = 32
	nonceSize = 12
	// maxFile bounds what is read into memory from disk.
	maxFile = 64 << 20
)

// SlotPassphrase is the type of the optional recovery key slot.
const SlotPassphrase = "passphrase"

type file struct {
	Format   string         `json:"format"`
	Version  int            `json:"version"`
	VaultID  string         `json:"vault_id"`
	Vault    string         `json:"vault"`
	Cipher   string         `json:"cipher"`
	KeySlots []KeySlot      `json:"key_slots"`
	Meta     box            `json:"meta"`
	Entries  map[string]box `json:"entries"`
}

// KeySlot holds the DEK wrapped by one protector, or by the recovery
// passphrase. []byte fields are base64 in the file.
type KeySlot struct {
	Type      string     `json:"type"`
	Sealed    []byte     `json:"sealed,omitempty"`
	KDF       string     `json:"kdf,omitempty"`
	KDFParams *KDFParams `json:"kdf_params,omitempty"`
	Salt      []byte     `json:"salt,omitempty"`
	Nonce     []byte     `json:"nonce,omitempty"`
	Wrapped   []byte     `json:"wrapped,omitempty"`
}

type box struct {
	Nonce []byte `json:"nonce"`
	CT    []byte `json:"ct"`
}

// metaPlain is the decrypted "meta" box.
type metaPlain struct {
	Secrets []metaEntry `json:"secrets"`
}

type metaEntry struct {
	plugin.SecretMeta
	Entry string `json:"entry"`
}

// Header is the plaintext part of a vault file.
type Header struct {
	Vault     string
	VaultID   string
	SlotTypes []string
}

// Store is one vault file. It implements plugin.SecretStore.
type Store struct {
	path  string
	vault string
	now   func() time.Time

	mu     sync.Mutex
	cached *file
	stamp  stamp
	// unlock is set while this process holds the write lock.
	unlock func() error
}

// stamp identifies one version of the file on disk. Writes replace the file
// by rename, so every write changes at least the inode.
type stamp struct {
	dev, ino uint64
	size     int64
	mtime    int64
}

// New returns the store for vault at path. Nothing is read until used.
func New(path, vault string) *Store {
	return &Store{path: path, vault: vault, now: time.Now}
}

func (s *Store) Path() string { return s.path }

func (s *Store) lockPath() string { return s.path + ".lock" }

// Exists reports whether the vault file is there.
func (s *Store) Exists() bool {
	_, err := os.Lstat(s.path)
	return err == nil
}

// Lock takes the vault's exclusive write lock, held until unlock. The host
// CLI holds it across a whole operation (check, approve, write, audit), so
// two writers can't interleave. Put and Delete take it themselves when it
// isn't held.
func (s *Store) Lock() (unlock func() error, err error) {
	if err := fsutil.EnsurePrivateDir(filepath.Dir(s.path)); err != nil {
		return nil, err
	}
	u, err := fsutil.Lock(s.lockPath())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.unlock = u
	s.mu.Unlock()
	return func() error {
		s.mu.Lock()
		s.unlock = nil
		s.mu.Unlock()
		return u()
	}, nil
}

// CreateOptions are the choices made at init.
type CreateOptions struct {
	// Recovery, if set, adds a passphrase key slot. The caller zeroes it.
	Recovery []byte
	// KDF overrides the recovery slot's Argon2id cost (tests only).
	KDF *KDFParams
}

// Create writes a new, empty vault: a fresh DEK and vault id, sealed by
// protector. It refuses to replace an existing vault.
func (s *Store) Create(ctx context.Context, protector plugin.KeyProtector, opts CreateOptions) (Header, error) {
	unlock, err := s.lockIfNeeded()
	if err != nil {
		return Header{}, err
	}
	defer unlock()
	if s.Exists() {
		return Header{}, fmt.Errorf("vault %s already exists at %s", s.vault, s.path)
	}
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Header{}, err
	}
	defer zero(dek)
	f := &file{Format: Format, Version: Version, VaultID: ids.New(), Vault: s.vault, Cipher: Cipher,
		Entries: map[string]box{}}
	sealed, err := protector.Seal(ctx, plugin.KeyRef{Vault: s.vault, VaultID: f.VaultID}, dek)
	if err != nil {
		return Header{}, fmt.Errorf("seal the vault key: %w", err)
	}
	f.KeySlots = append(f.KeySlots, KeySlot{Type: protector.Name(), Sealed: sealed})
	if opts.Recovery != nil {
		slot, err := passphraseSlot(f, dek, opts.Recovery, opts.KDF)
		if err != nil {
			return Header{}, err
		}
		f.KeySlots = append(f.KeySlots, slot)
	}
	if err := s.sealMeta(f, dek, metaPlain{Secrets: []metaEntry{}}); err != nil {
		return Header{}, err
	}
	if err := s.write(f); err != nil {
		if errors.Is(err, fsutil.ErrNotDurable) {
			// The vault is in place and needs its key: keep it.
			return f.header(), err
		}
		// Don't leave a protector entry behind for a vault that doesn't exist.
		protector.Destroy(context.WithoutCancel(ctx), plugin.KeyRef{Vault: s.vault, VaultID: f.VaultID}, sealed)
		return Header{}, err
	}
	return f.header(), nil
}

func (f *file) header() Header {
	h := Header{Vault: f.Vault, VaultID: f.VaultID}
	for _, k := range f.KeySlots {
		h.SlotTypes = append(h.SlotTypes, k.Type)
	}
	return h
}

// Header reads the plaintext header.
func (s *Store) Header(context.Context) (Header, error) {
	f, err := s.load()
	if err != nil {
		return Header{}, err
	}
	return f.header(), nil
}

// DEKFunc returns a function that unseals the DEK through protector on each
// call. The release function zeroes it.
func (s *Store) DEKFunc(protector plugin.KeyProtector) plugin.DEKFunc {
	return func(ctx context.Context) ([]byte, func(), error) {
		f, err := s.load()
		if err != nil {
			return nil, nil, err
		}
		for _, k := range f.KeySlots {
			if k.Type != protector.Name() {
				continue
			}
			dek, err := protector.Unseal(ctx, plugin.KeyRef{Vault: f.Vault, VaultID: f.VaultID}, k.Sealed)
			if err != nil {
				return nil, nil, fmt.Errorf("vault %s: unseal: %w", s.vault, err)
			}
			if len(dek) != dekSize {
				zero(dek)
				return nil, nil, fmt.Errorf("vault %s: unsealed key has the wrong size", s.vault)
			}
			return dek, func() { zero(dek) }, nil
		}
		return nil, nil, fmt.Errorf("vault %s has no key slot for protector %q", s.vault, protector.Name())
	}
}

// ---- SecretStore ----

func (s *Store) List(_ context.Context, dek []byte) ([]plugin.SecretMeta, error) {
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	m, err := s.openMeta(f, dek)
	if err != nil {
		return nil, err
	}
	out := make([]plugin.SecretMeta, len(m.Secrets))
	for i, e := range m.Secrets {
		out[i] = e.SecretMeta
	}
	return out, nil
}

// Read decrypts the metadata and exactly one entry.
func (s *Store) Read(_ context.Context, dek []byte, id string) (plugin.SecretMeta, plugin.SecretValue, error) {
	f, err := s.load()
	if err != nil {
		return plugin.SecretMeta{}, plugin.SecretValue{}, err
	}
	m, err := s.openMeta(f, dek)
	if err != nil {
		return plugin.SecretMeta{}, plugin.SecretValue{}, err
	}
	for _, e := range m.Secrets {
		if e.ID != id {
			continue
		}
		b, ok := f.Entries[e.Entry]
		if !ok {
			return plugin.SecretMeta{}, plugin.SecretValue{}, fmt.Errorf("vault %s: entry for %q is missing", s.vault, id)
		}
		v, err := s.open(f, dek, e.Entry, b)
		if err != nil {
			return plugin.SecretMeta{}, plugin.SecretValue{}, err
		}
		return e.SecretMeta, plugin.SecretValue{Bytes: v}, nil
	}
	return plugin.SecretMeta{}, plugin.SecretValue{}, plugin.ErrNotFound
}

// Put adds or replaces a secret. The value gets a new random entry id; the
// old entry is dropped. The caller still owns and should zero v.
func (s *Store) Put(_ context.Context, dek []byte, meta plugin.SecretMeta, v plugin.SecretValue) error {
	return s.update(dek, func(f *file, m *metaPlain) error {
		now := s.now().UTC().Truncate(time.Millisecond)
		entry, err := newEntryID(f)
		if err != nil {
			return err
		}
		f.Entries[entry], err = s.seal(f, dek, entry, v.Bytes)
		if err != nil {
			return err
		}
		for i, e := range m.Secrets {
			if e.ID == meta.ID {
				meta.Created = e.Created
				meta.Updated = now
				delete(f.Entries, e.Entry)
				m.Secrets[i] = metaEntry{SecretMeta: meta, Entry: entry}
				return nil
			}
		}
		meta.Created = now
		meta.Updated = time.Time{}
		m.Secrets = append(m.Secrets, metaEntry{SecretMeta: meta, Entry: entry})
		return nil
	})
}

// SetMeta replaces a secret's metadata and keeps its value.
func (s *Store) SetMeta(_ context.Context, dek []byte, meta plugin.SecretMeta) error {
	return s.update(dek, func(f *file, m *metaPlain) error {
		for i, e := range m.Secrets {
			if e.ID == meta.ID {
				meta.Created = e.Created
				meta.Updated = s.now().UTC().Truncate(time.Millisecond)
				m.Secrets[i].SecretMeta = meta
				return nil
			}
		}
		return plugin.ErrNotFound
	})
}

func (s *Store) Delete(_ context.Context, dek []byte, id string) error {
	return s.update(dek, func(f *file, m *metaPlain) error {
		for i, e := range m.Secrets {
			if e.ID == id {
				delete(f.Entries, e.Entry)
				m.Secrets = append(m.Secrets[:i], m.Secrets[i+1:]...)
				return nil
			}
		}
		return plugin.ErrNotFound
	})
}

// update re-reads the file under the write lock, applies fn to it and its
// decrypted metadata, and writes the result atomically.
func (s *Store) update(dek []byte, fn func(*file, *metaPlain) error) error {
	unlock, err := s.lockIfNeeded()
	if err != nil {
		return err
	}
	defer unlock()
	f, err := s.load()
	if err != nil {
		return err
	}
	f = f.clone()
	m, err := s.openMeta(f, dek)
	if err != nil {
		return err
	}
	if err := fn(f, &m); err != nil {
		return err
	}
	sort.Slice(m.Secrets, func(i, j int) bool { return m.Secrets[i].ID < m.Secrets[j].ID })
	if err := s.sealMeta(f, dek, m); err != nil {
		return err
	}
	return s.write(f)
}

func (s *Store) lockIfNeeded() (func() error, error) {
	s.mu.Lock()
	held := s.unlock != nil
	s.mu.Unlock()
	if held {
		return func() error { return nil }, nil
	}
	return s.Lock()
}

// ---- file I/O ----

// load returns the parsed file, re-reading it only when it changed on disk.
func (s *Store) load() (*file, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fh, err := os.OpenFile(s.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		s.cached = nil
		return nil, fmt.Errorf("%w (run foca init --vault %s)", plugin.NotInitialized{Vault: s.vault}, s.vault)
	}
	if err != nil {
		return nil, fmt.Errorf("vault %s: %w", s.vault, err)
	}
	defer fh.Close()
	fi, err := fh.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkPrivate(fi); err != nil {
		return nil, fmt.Errorf("vault %s: %s: %w", s.vault, s.path, err)
	}
	st := stampOf(fi)
	if s.cached != nil && st == s.stamp {
		return s.cached, nil
	}
	if fi.Size() > maxFile {
		return nil, fmt.Errorf("vault %s: file is larger than %d bytes", s.vault, maxFile)
	}
	b, err := io.ReadAll(io.LimitReader(fh, maxFile+1))
	if err != nil {
		return nil, err
	}
	f, err := s.parse(b)
	if err != nil {
		return nil, err
	}
	s.cached, s.stamp = f, st
	return f, nil
}

func (s *Store) parse(b []byte) (*file, error) {
	var f file
	if err := decodeStrict(b, &f); err != nil {
		return nil, fmt.Errorf("vault %s: not a vault file: %w", s.vault, err)
	}
	switch {
	case f.Format != Format:
		return nil, fmt.Errorf("vault %s: format %q is not %q", s.vault, f.Format, Format)
	case f.Version != Version:
		return nil, fmt.Errorf("vault %s: version %d is not supported", s.vault, f.Version)
	case f.Cipher != Cipher:
		return nil, fmt.Errorf("vault %s: cipher %q is not supported", s.vault, f.Cipher)
	case f.Vault != s.vault:
		// A file copied or renamed from another vault.
		return nil, fmt.Errorf("vault %s: file %s belongs to vault %q", s.vault, s.path, f.Vault)
	case f.VaultID == "":
		return nil, fmt.Errorf("vault %s: missing vault_id", s.vault)
	}
	if f.Entries == nil {
		f.Entries = map[string]box{}
	}
	return &f, nil
}

// decodeStrict decodes JSON as strictly as the protocol does: unknown,
// duplicate or case-variant keys and trailing data are refused, so no two
// readers can find different contents in the same bytes.
func decodeStrict(b []byte, v any) error {
	if err := protocol.CheckStrict(b, reflect.TypeOf(v)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Store) write(f *file) error {
	if err := fsutil.EnsurePrivateDir(filepath.Dir(s.path)); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	err = writeFileAtomic(s.path, append(b, '\n'), 0o600)
	s.mu.Lock()
	s.cached = nil
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("vault %s: write: %w", s.vault, err)
	}
	return nil
}

// writeFileAtomic is fsutil.WriteFileAtomic; tests make it fail.
var writeFileAtomic = fsutil.WriteFileAtomic

func (f *file) clone() *file {
	c := *f
	c.KeySlots = append([]KeySlot(nil), f.KeySlots...)
	c.Entries = make(map[string]box, len(f.Entries))
	for k, v := range f.Entries {
		c.Entries[k] = v
	}
	return &c
}

func checkPrivate(fi os.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("mode %o is not private (want 0600)", fi.Mode().Perm())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != os.Getuid() {
		return errors.New("not owned by the current user")
	}
	return nil
}

func stampOf(fi os.FileInfo) stamp {
	st := stamp{size: fi.Size(), mtime: fi.ModTime().UnixNano()}
	if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
		st.dev, st.ino = uint64(sys.Dev), uint64(sys.Ino)
	}
	return st
}

// ---- crypto ----

func (s *Store) aad(f *file, slot string) []byte {
	return []byte(Format + "|" + strconv.Itoa(f.Version) + "|" + f.VaultID + "|" + f.Vault + "|" + slot)
}

func (s *Store) seal(f *file, dek []byte, slot string, plain []byte) (box, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return box{}, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return box{}, err
	}
	return box{Nonce: nonce, CT: gcm.Seal(nil, nonce, plain, s.aad(f, slot))}, nil
}

func (s *Store) open(f *file, dek []byte, slot string, b box) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if len(b.Nonce) != nonceSize {
		return nil, fmt.Errorf("vault %s: bad nonce in %s", s.vault, slot)
	}
	out, err := gcm.Open(nil, b.Nonce, b.CT, s.aad(f, slot))
	if err != nil {
		// Wrong key, a tampered box, or a box moved from elsewhere.
		return nil, fmt.Errorf("vault %s: %s does not decrypt (wrong key, or the file was altered)", s.vault, slot)
	}
	return out, nil
}

func (s *Store) openMeta(f *file, dek []byte) (metaPlain, error) {
	b, err := s.open(f, dek, "meta", f.Meta)
	if err != nil {
		return metaPlain{}, err
	}
	defer zero(b)
	var m metaPlain
	if err := decodeStrict(b, &m); err != nil {
		return metaPlain{}, fmt.Errorf("vault %s: bad metadata: %w", s.vault, err)
	}
	return m, nil
}

func (s *Store) sealMeta(f *file, dek []byte, m metaPlain) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	defer zero(b)
	f.Meta, err = s.seal(f, dek, "meta", b)
	return err
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != dekSize {
		return nil, errors.New("vault key has the wrong size")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newEntryID(f *file) (string, error) {
	for {
		b := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, b); err != nil {
			return "", err
		}
		id := hex.EncodeToString(b)
		if _, taken := f.Entries[id]; !taken && id != "meta" {
			return id, nil
		}
	}
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
