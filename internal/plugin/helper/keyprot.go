package helper

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/bpinto/foca/internal/plugin"
)

// KeyProtector seals vault keys through the helper (the Keychain on macOS).
// The helper names each entry after the vault and its id, so initialising
// one vault can never overwrite another vault's key.
type KeyProtector struct {
	h    *Helper
	name string
}

func NewKeyProtector(h *Helper, name string) *KeyProtector {
	return &KeyProtector{h: h, name: name}
}

func (k *KeyProtector) Name() string { return k.name }

// refPart keeps vault names and ids free of the separator the helper uses
// to build entry names.
var refPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

type keyParams struct {
	Vault   string `json:"vault"`
	VaultID string `json:"vault_id"`
	DEK     []byte `json:"dek,omitempty"`
	Sealed  []byte `json:"sealed,omitempty"`
}

type sealResult struct {
	Sealed []byte `json:"sealed"`
}

type unsealResult struct {
	DEK []byte `json:"dek"`
}

const keyCallTimeout = 30 * time.Second

func (k *KeyProtector) params(ref plugin.KeyRef) (keyParams, error) {
	if !refPart.MatchString(ref.Vault) || !refPart.MatchString(ref.VaultID) {
		return keyParams{}, fmt.Errorf("%s protector: invalid key ref %+v", k.name, ref)
	}
	return keyParams{Vault: ref.Vault, VaultID: ref.VaultID}, nil
}

func (k *KeyProtector) Seal(ctx context.Context, ref plugin.KeyRef, dek []byte) ([]byte, error) {
	p, err := k.params(ref)
	if err != nil {
		return nil, err
	}
	p.DEK = dek
	ctx, cancel := context.WithTimeout(ctx, keyCallTimeout)
	defer cancel()
	var r sealResult
	if err := k.h.call(ctx, KindKeyProtector, "seal", p, &r); err != nil {
		return nil, k.wrap("seal", err)
	}
	if len(r.Sealed) == 0 {
		return nil, fmt.Errorf("%s protector: seal returned nothing", k.name)
	}
	return r.Sealed, nil
}

func (k *KeyProtector) Unseal(ctx context.Context, ref plugin.KeyRef, sealed []byte) ([]byte, error) {
	p, err := k.params(ref)
	if err != nil {
		return nil, err
	}
	p.Sealed = sealed
	ctx, cancel := context.WithTimeout(ctx, keyCallTimeout)
	defer cancel()
	var r unsealResult
	if err := k.h.call(ctx, KindKeyProtector, "unseal", p, &r); err != nil {
		return nil, k.wrap("unseal", err)
	}
	if len(r.DEK) == 0 {
		return nil, fmt.Errorf("%s protector: unseal returned no key", k.name)
	}
	return r.DEK, nil
}

// Destroy removes the vault's entry. sealed may be nil (an init being
// undone); a missing entry is not an error.
func (k *KeyProtector) Destroy(ctx context.Context, ref plugin.KeyRef, sealed []byte) error {
	p, err := k.params(ref)
	if err != nil {
		return err
	}
	p.Sealed = sealed
	ctx, cancel := context.WithTimeout(ctx, keyCallTimeout)
	defer cancel()
	if err := k.h.call(ctx, KindKeyProtector, "destroy", p, nil); err != nil {
		return k.wrap("destroy", err)
	}
	return nil
}

func (k *KeyProtector) wrap(op string, err error) error {
	var he *Error
	if errors.As(err, &he) {
		switch he.Code {
		case CodeNotFound:
			return fmt.Errorf("%s protector: %s: no key for this vault: %w", k.name, op, err)
		case CodeExists:
			return fmt.Errorf("%s protector: %s: a key for this vault id already exists; refusing to overwrite it: %w", k.name, op, err)
		case CodeMismatch:
			return fmt.Errorf("%s protector: %s: the vault's key slot names another vault: %w", k.name, op, err)
		}
	}
	return fmt.Errorf("%s protector: %s: %w", k.name, op, err)
}
