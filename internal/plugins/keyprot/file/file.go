// Package file is the test key protector: the key that wraps a vault's data
// key lives in a 0600 file in the data dir, so anyone who can read that
// directory as the user can decrypt the vault. Only test builds (-tags
// foca_testing) can select it.
package file

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/plugin"
)

const (
	keySize   = 32
	nonceSize = 12
)

type Protector struct {
	dir string
}

// New returns a protector that keeps its keys in dir (created 0700).
func New(dir string) *Protector { return &Protector{dir: dir} }

func (p *Protector) Name() string { return "file" }

// keyPath is per vault id, so initialising a vault can never overwrite the
// key of another one, even one with the same name.
func (p *Protector) keyPath(ref plugin.KeyRef) (string, error) {
	if ref.Vault == "" || ref.VaultID == "" || filepath.Base(ref.Vault) != ref.Vault || filepath.Base(ref.VaultID) != ref.VaultID {
		return "", fmt.Errorf("file protector: invalid key ref %+v", ref)
	}
	return filepath.Join(p.dir, ref.Vault+"-"+ref.VaultID+".key"), nil
}

func aad(ref plugin.KeyRef) []byte {
	return []byte("foca-file-protector|1|" + ref.Vault + "|" + ref.VaultID)
}

func (p *Protector) Seal(_ context.Context, ref plugin.KeyRef, dek []byte) ([]byte, error) {
	path, err := p.keyPath(ref)
	if err != nil {
		return nil, err
	}
	if err := fsutil.EnsurePrivateDir(p.dir); err != nil {
		return nil, fmt.Errorf("file protector: %w", err)
	}
	kek, err := readKey(path)
	if errors.Is(err, os.ErrNotExist) {
		kek, err = createKey(path)
	}
	if err != nil {
		return nil, err
	}
	defer zero(kek)
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize, nonceSize+len(dek)+gcm.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, dek, aad(ref)), nil
}

func (p *Protector) Unseal(_ context.Context, ref plugin.KeyRef, sealed []byte) ([]byte, error) {
	path, err := p.keyPath(ref)
	if err != nil {
		return nil, err
	}
	kek, err := readKey(path)
	if err != nil {
		return nil, err
	}
	defer zero(kek)
	gcm, err := newGCM(kek)
	if err != nil {
		return nil, err
	}
	if len(sealed) < nonceSize+gcm.Overhead() {
		return nil, errors.New("file protector: sealed key is too short")
	}
	dek, err := gcm.Open(nil, sealed[:nonceSize], sealed[nonceSize:], aad(ref))
	if err != nil {
		return nil, errors.New("file protector: the sealed key does not match this vault's key file")
	}
	return dek, nil
}

// Destroy overwrites and removes the key file. The vault can't be opened
// with this protector afterwards.
func (p *Protector) Destroy(_ context.Context, ref plugin.KeyRef, _ []byte) error {
	path, err := p.keyPath(ref)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	f.Write(make([]byte, keySize))
	f.Sync()
	f.Close()
	if err := os.Remove(path); err != nil {
		return err
	}
	return fsutil.SyncDir(p.dir)
}

func createKey(path string) ([]byte, error) {
	kek := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("file protector: %w", err)
	}
	_, werr := f.Write(kek)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(path)
		return nil, fmt.Errorf("file protector: write %s: %w", path, err)
	}
	if err := fsutil.SyncDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	return kek, nil
}

// readKey refuses a key file that isn't a private regular file of ours.
func readKey(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("file protector: %s is not a regular file", path)
	case fi.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("file protector: %s has mode %o, want 0600", path, fi.Mode().Perm())
	case !ok || int(st.Uid) != os.Getuid():
		return nil, fmt.Errorf("file protector: %s is not owned by the current user", path)
	case fi.Size() != keySize:
		return nil, fmt.Errorf("file protector: %s is not a key file", path)
	}
	kek := make([]byte, keySize)
	if _, err := io.ReadFull(f, kek); err != nil {
		return nil, err
	}
	return kek, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
