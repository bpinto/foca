package vaultfile

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/bpinto/foca/internal/plugin"
)

// A recovery key is 160 random bits that foca makes, never a passphrase a
// person picks: bound to a TPM, the recovery slot is the one way into a
// copied vault file, so it must be out of reach of a guess. It is written as
// eight groups of four Crockford base32 characters.
const RecoveryKeySize = 20

var crockford = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

// recoveryKeyChars is the length of a written key, without dashes.
var recoveryKeyChars = crockford.EncodedLen(RecoveryKeySize)

// KDFParams are Argon2id's cost parameters: time, memory in KiB, threads.
type KDFParams struct {
	T uint32 `json:"t"`
	M uint32 `json:"m"`
	P uint8  `json:"p"`
}

// DefaultKDF is the recovery slot's cost (design §10). The key's 160 random
// bits are what keep it from a guess; the cost is a second line.
var DefaultKDF = KDFParams{T: 3, M: 64 * 1024, P: 4}

// Bounds on parameters read from a file, so a crafted file can't make an
// unlock attempt use unbounded memory or time.
const (
	maxKDFTime   = 16
	maxKDFMemory = 1 << 20 // 1 GiB
	minKDFMemory = 8 * 1024
	saltSize     = 16
)

// NewRecoveryKey returns a new random recovery key. The caller zeroes it.
func NewRecoveryKey() ([]byte, error) {
	key := make([]byte, RecoveryKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// FormatRecoveryKey writes key the way a person copies it down:
// XXXX-XXXX-…, eight groups. The caller zeroes the result.
func FormatRecoveryKey(key []byte) []byte {
	chars := make([]byte, crockford.EncodedLen(len(key)))
	defer zero(chars)
	crockford.Encode(chars, key)
	out := make([]byte, 0, len(chars)+len(chars)/4)
	for i, c := range chars {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, c)
	}
	return out
}

// ParseRecoveryKey reads a recovery key as typed: case, dashes and spaces
// don't matter, and I, L and O read as 1, 1 and 0. The caller zeroes both.
func ParseRecoveryKey(typed []byte) ([]byte, error) {
	chars := make([]byte, 0, recoveryKeyChars)
	defer func() { zero(chars[:cap(chars)]) }()
	wrongLength := fmt.Errorf("a recovery key has %d characters, in groups of 4", recoveryKeyChars)
	for _, c := range typed {
		switch {
		case c == '-' || c == ' ' || c == '\t':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		switch c {
		case 'I', 'L':
			c = '1'
		case 'O':
			c = '0'
		}
		if len(chars) == recoveryKeyChars {
			return nil, wrongLength
		}
		chars = append(chars, c)
	}
	if len(chars) != recoveryKeyChars {
		return nil, wrongLength
	}
	key := make([]byte, RecoveryKeySize)
	if n, err := crockford.Decode(key, chars); err != nil || n != RecoveryKeySize {
		zero(key)
		return nil, errors.New("that is not a recovery key: it has characters other than 0-9 and A-Z without U")
	}
	return key, nil
}

// recoverySlot wraps dek with a key derived from the recovery key. That key
// only ever wraps the random DEK; data is never encrypted with it directly.
func recoverySlot(f *file, dek, key []byte, params *KDFParams) (KeySlot, error) {
	if len(key) != RecoveryKeySize {
		return KeySlot{}, fmt.Errorf("a recovery key is %d random bytes, from NewRecoveryKey", RecoveryKeySize)
	}
	p := DefaultKDF
	if params != nil {
		p = *params
	}
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return KeySlot{}, err
	}
	kek := argon2.IDKey(key, salt, p.T, p.M, p.P, dekSize)
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
		Type: SlotRecovery, KDF: "argon2id", KDFParams: &p, Salt: salt, Nonce: nonce,
		Wrapped: gcm.Seal(nil, nonce, dek, slotAAD(f)),
	}, nil
}

func slotAAD(f *file) []byte {
	return []byte(Format + "|" + fmt.Sprint(f.Version) + "|" + f.VaultID + "|" + f.Vault + "|slot:" + SlotRecovery)
}

// UnsealRecovery recovers the DEK from the recovery slot with the recovery
// key, as ParseRecoveryKey returns it. The caller zeroes both.
func (s *Store) UnsealRecovery(key []byte) ([]byte, error) {
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	return s.unsealRecovery(f, key)
}

func (s *Store) unsealRecovery(f *file, key []byte) ([]byte, error) {
	for _, k := range f.KeySlots {
		if k.Type != SlotRecovery {
			continue
		}
		p := k.KDFParams
		if k.KDF != "argon2id" || p == nil || p.T == 0 || p.T > maxKDFTime || p.M < minKDFMemory || p.M > maxKDFMemory || p.P == 0 {
			return nil, fmt.Errorf("vault %s: unsupported recovery slot parameters", s.vault)
		}
		if len(k.Salt) < saltSize || len(k.Nonce) != nonceSize {
			return nil, fmt.Errorf("vault %s: malformed recovery slot", s.vault)
		}
		kek := argon2.IDKey(key, k.Salt, p.T, p.M, p.P, dekSize)
		defer zero(kek)
		gcm, err := newGCM(kek)
		if err != nil {
			return nil, err
		}
		dek, err := gcm.Open(nil, k.Nonce, k.Wrapped, slotAAD(f))
		if err != nil {
			return nil, fmt.Errorf("vault %s: wrong recovery key", s.vault)
		}
		return dek, nil
	}
	return nil, fmt.Errorf("vault %s has no recovery slot", s.vault)
}

// Reseal unlocks the DEK with the recovery key and seals it again with
// protector, so the vault opens with it in today's state: after the boot
// state a TPM key was bound to changed, or to move to another protector. It
// replaces every protector slot, keeps the recovery slot, and returns the
// types of the slots it replaced. The data and the DEK don't change.
func (s *Store) Reseal(ctx context.Context, protector plugin.KeyProtector, key []byte) (replaced []string, err error) {
	unlock, err := s.lockIfNeeded()
	if err != nil {
		return nil, err
	}
	defer unlock()
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	dek, err := s.unsealRecovery(f, key)
	if err != nil {
		return nil, err
	}
	defer zero(dek)
	// The slot only proves the key opens it. A slot that wraps some other
	// key would replace the working protector slot with a useless one.
	if _, err := s.openMeta(f, dek); err != nil {
		return nil, fmt.Errorf("vault %s: the recovery slot holds a key that doesn't open this vault: %w", s.vault, err)
	}
	sealed, err := protector.Seal(ctx, plugin.KeyRef{Vault: f.Vault, VaultID: f.VaultID}, dek)
	if err != nil {
		return nil, fmt.Errorf("seal the vault key: %w", err)
	}
	nf := f.clone()
	nf.KeySlots = []KeySlot{{Type: protector.Name(), Sealed: sealed}}
	for _, k := range f.KeySlots {
		if k.Type == SlotRecovery {
			nf.KeySlots = append(nf.KeySlots, k)
		} else {
			replaced = append(replaced, k.Type)
		}
	}
	if err := s.write(nf); err != nil {
		return nil, err
	}
	return replaced, nil
}
