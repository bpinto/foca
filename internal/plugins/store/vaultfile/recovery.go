package vaultfile

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// KDFParams are Argon2id's cost parameters: time, memory in KiB, threads.
type KDFParams struct {
	T uint32 `json:"t"`
	M uint32 `json:"m"`
	P uint8  `json:"p"`
}

// DefaultKDF is the recovery slot's cost (design §10).
var DefaultKDF = KDFParams{T: 3, M: 64 * 1024, P: 4}

// Bounds on parameters read from a file, so a crafted file can't make an
// unlock attempt use unbounded memory or time.
const (
	maxKDFTime   = 16
	maxKDFMemory = 1 << 20 // 1 GiB
	minKDFMemory = 8 * 1024
	saltSize     = 16
)

// passphraseSlot wraps dek with a key derived from the passphrase. The key
// derived from the passphrase only ever wraps the random DEK; data is never
// encrypted with it directly.
func passphraseSlot(f *file, dek, passphrase []byte, params *KDFParams) (KeySlot, error) {
	if len(passphrase) == 0 {
		return KeySlot{}, errors.New("recovery passphrase must not be empty")
	}
	p := DefaultKDF
	if params != nil {
		p = *params
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return KeySlot{}, err
	}
	kek := argon2.IDKey(passphrase, salt, p.T, p.M, p.P, dekSize)
	defer zero(kek)
	gcm, err := newGCM(kek)
	if err != nil {
		return KeySlot{}, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return KeySlot{}, err
	}
	return KeySlot{
		Type: SlotPassphrase, KDF: "argon2id", KDFParams: &p, Salt: salt, Nonce: nonce,
		Wrapped: gcm.Seal(nil, nonce, dek, slotAAD(f)),
	}, nil
}

func slotAAD(f *file) []byte {
	return []byte(Format + "|" + fmt.Sprint(f.Version) + "|" + f.VaultID + "|" + f.Vault + "|slot:" + SlotPassphrase)
}

// UnsealPassphrase recovers the DEK from the recovery slot. The caller zeroes
// both the passphrase and the returned key.
func (s *Store) UnsealPassphrase(passphrase []byte) ([]byte, error) {
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	for _, k := range f.KeySlots {
		if k.Type != SlotPassphrase {
			continue
		}
		p := k.KDFParams
		if k.KDF != "argon2id" || p == nil || p.T == 0 || p.T > maxKDFTime || p.M < minKDFMemory || p.M > maxKDFMemory || p.P == 0 {
			return nil, fmt.Errorf("vault %s: unsupported recovery slot parameters", s.vault)
		}
		if len(k.Salt) < saltSize || len(k.Nonce) != nonceSize {
			return nil, fmt.Errorf("vault %s: malformed recovery slot", s.vault)
		}
		kek := argon2.IDKey(passphrase, k.Salt, p.T, p.M, p.P, dekSize)
		defer zero(kek)
		gcm, err := newGCM(kek)
		if err != nil {
			return nil, err
		}
		dek, err := gcm.Open(nil, k.Nonce, k.Wrapped, slotAAD(f))
		if err != nil {
			return nil, fmt.Errorf("vault %s: wrong recovery passphrase", s.vault)
		}
		return dek, nil
	}
	return nil, fmt.Errorf("vault %s has no recovery slot", s.vault)
}
