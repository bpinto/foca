package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Keygen creates the relay's key pair in a new 0600 file at path, as PKCS #8
// PEM, and returns the public key for the host's config. It never
// overwrites a key: the host's config names the one there.
func Keygen(path string) (ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("%s already exists; the host's config names the key in it (foca relay pubkey prints it)", path)
		}
		return nil, err
	}
	werr := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := errors.Join(werr, f.Sync(), f.Close()); err != nil {
		os.Remove(path)
		return nil, err
	}
	return pub, nil
}

// LoadKey reads the relay's private key. The file must be a regular file of
// the relay's user that no one else can read (design §14, safeguard 5).
func LoadKey(path string, uid int) (ed25519.PrivateKey, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("relay key: %w", err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("relay key %s is not a regular file", path)
	case !ok || int(st.Uid) != uid:
		return nil, fmt.Errorf("relay key %s is not owned by the relay's user (uid %d)", path, uid)
	case fi.Mode().Perm()&0o077 != 0:
		return nil, fmt.Errorf("relay key %s has mode %o: anyone who reads it can pass for the relay; chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("relay key: %w", err)
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("relay key %s is not a PEM private key", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("relay key %s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("relay key %s is not an Ed25519 key", path)
	}
	return priv, nil
}
