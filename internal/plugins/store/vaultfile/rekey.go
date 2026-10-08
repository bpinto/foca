package vaultfile

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/ids"
	"github.com/bpinto/foca/internal/plugin"
)

// Rekeyed is what Rekey replaced: the key ref and protector slot before and
// after. The caller destroys Old once the change is recorded, or New to
// undo it.
type Rekeyed struct {
	Old, New             plugin.KeyRef
	OldSealed, NewSealed []byte
	// Replaced are the types of the protector slots the old file had.
	Replaced []string
}

// Rekey encrypts the vault again under a new DEK and a new vault id. It
// unseals the old DEK through protector, decrypts the metadata and every
// value, and seals each again under the new DEK with fresh nonces and
// fresh entry ids. The new file has a protector slot and, if opts.Recovery
// is set, a recovery slot for that key; nothing of the old one is kept.
//
// A copy of the old file still opens with its old slots: the old recovery
// key, and on the TPM the old protector slot, still open it. Rekey stops
// them opening the vault from now on, which is all it can do.
func (s *Store) Rekey(ctx context.Context, protector plugin.KeyProtector, opts CreateOptions) (Rekeyed, error) {
	unlock, err := s.lockIfNeeded()
	if err != nil {
		return Rekeyed{}, err
	}
	defer unlock()
	f, err := s.load()
	if err != nil {
		return Rekeyed{}, err
	}
	old, oldSealed, err := s.unseal(ctx, f, protector)
	if err != nil {
		return Rekeyed{}, err
	}
	defer zero(old)
	m, err := s.openMeta(f, old)
	if err != nil {
		return Rekeyed{}, err
	}

	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return Rekeyed{}, err
	}
	defer zero(dek)
	nf := &file{Format: Format, Version: Version, VaultID: ids.New(), Vault: f.Vault, Cipher: Cipher,
		Entries: map[string]box{}}
	for i, e := range m.Secrets {
		b, ok := f.Entries[e.Entry]
		if !ok {
			return Rekeyed{}, fmt.Errorf("vault %s: entry for %q is missing", s.vault, e.ID)
		}
		v, err := s.open(f, old, e.Entry, b)
		if err != nil {
			return Rekeyed{}, err
		}
		entry, err := newEntryID(nf)
		if err == nil {
			nf.Entries[entry], err = s.seal(nf, dek, entry, v)
		}
		zero(v)
		if err != nil {
			return Rekeyed{}, err
		}
		m.Secrets[i].Entry = entry
	}
	if err := s.sealMeta(nf, dek, m); err != nil {
		return Rekeyed{}, err
	}
	var recovery []KeySlot
	if opts.Recovery != nil {
		slot, err := recoverySlot(nf, dek, opts.Recovery, opts.KDF)
		if err != nil {
			return Rekeyed{}, err
		}
		recovery = append(recovery, slot)
	}

	r := Rekeyed{
		Old:       plugin.KeyRef{Vault: f.Vault, VaultID: f.VaultID},
		New:       plugin.KeyRef{Vault: nf.Vault, VaultID: nf.VaultID},
		OldSealed: oldSealed,
	}
	for _, k := range f.KeySlots {
		if k.Type != SlotRecovery {
			r.Replaced = append(r.Replaced, k.Type)
		}
	}
	if r.NewSealed, err = protector.Seal(ctx, r.New, dek); err != nil {
		return Rekeyed{}, fmt.Errorf("seal the new vault key: %w", err)
	}
	nf.KeySlots = append([]KeySlot{{Type: protector.Name(), Sealed: r.NewSealed}}, recovery...)
	if err := s.write(nf); err != nil {
		if errors.Is(err, fsutil.ErrNotDurable) {
			// The new file is in place and needs its key; a crash may
			// still bring back the old one, which needs its own.
			return r, err
		}
		protector.Destroy(context.WithoutCancel(ctx), r.New, r.NewSealed)
		return Rekeyed{}, err
	}
	return r, nil
}
