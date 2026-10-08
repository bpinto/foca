// Package tpm is the TPM 2.0 key protector (design §4.2). A vault's data key
// is sealed to this machine's TPM, under its storage key, so a copied vault
// file and data directory can't be opened anywhere else. By default the
// sealed key is also bound to PCR 7, the Secure Boot state: if that changes,
// the TPM refuses to unseal until the vault is sealed again with its recovery
// key (foca recover).
//
// Every command that carries the key runs in a session salted with the
// storage key and encrypted, so the key never crosses the bus to the TPM in
// clear. The protector keeps nothing on disk: the sealed object lives in the
// vault's key slot.
package tpm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/protocol"
)

// Open connects to the TPM. Each seal or unseal opens it and closes it again.
type Open func() (transport.TPMCloser, error)

type Protector struct {
	open    Open
	pcrs    []int
	efivars string
}

// EFIVars is where Linux shows the firmware's EFI variables.
const EFIVars = "/sys/firmware/efi/efivars"

// New returns a protector that seals to the SHA-256 bank of pcrs (none: the
// sealed key opens whatever the boot state). efivars is the EFI variables
// directory, EFIVars outside tests: with PCR 7, sealing needs Secure Boot on.
func New(open Open, pcrs []int, efivars string) *Protector {
	pcrs = slices.Clone(pcrs)
	slices.Sort(pcrs)
	return &Protector{open: open, pcrs: pcrs, efivars: efivars}
}

func (p *Protector) Name() string { return "tpm" }

// ErrBootStateChanged: the PCRs the key is bound to no longer match.
var ErrBootStateChanged = errors.New("the boot state the vault key is bound to has changed")

// sealed is what the vault's key slot holds. SRK is the name of the
// storage key it was sealed under: the TPM's answer to CreatePrimary is
// checked against it before any session is salted with that key, so
// something between foca and the TPM can't offer its own key instead.
type sealed struct {
	V    int   `json:"v"`
	PCRs []int `json:"pcrs"`
	// PCRDigest is the digest of the PCR values sealed to, so a refusal
	// can tell a changed boot state from an altered slot.
	PCRDigest []byte `json:"pcr_digest,omitempty"`
	SRK       []byte `json:"srk"`
	Public    []byte `json:"public"`
	Private   []byte `json:"private"`
}

const sealedVersion = 1

func (p *Protector) Seal(_ context.Context, ref plugin.KeyRef, dek []byte) ([]byte, error) {
	if ref.Vault == "" || ref.VaultID == "" {
		return nil, fmt.Errorf("tpm protector: invalid key ref %+v", ref)
	}
	if slices.Contains(p.pcrs, 7) {
		if err := checkSecureBoot(p.efivars); err != nil {
			return nil, err
		}
	}
	t, err := p.open()
	if err != nil {
		return nil, fmt.Errorf("tpm protector: open the TPM: %w", err)
	}
	defer t.Close()
	srk, err := storageKey(t)
	if err != nil {
		return nil, err
	}
	defer srk.flush(t)

	pub := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:    true,
			FixedParent: true,
			NoDA:        true,
			// Without PCRs, the empty auth value opens it; with them,
			// only the PCR policy does.
			UserWithAuth: len(p.pcrs) == 0,
		},
	}
	var pcrDigest []byte
	if len(p.pcrs) > 0 {
		if pcrDigest, err = readPCRs(t, p.pcrs); err != nil {
			return nil, err
		}
		policy, err := pcrPolicy(pcrDigest, p.pcrs)
		if err != nil {
			return nil, err
		}
		pub.AuthPolicy = tpm2.TPM2BDigest{Buffer: policy}
	}
	rsp, err := tpm2.Create{
		ParentHandle: srk.auth(true),
		InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
			Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: dek}),
		}},
		InPublic: tpm2.New2B(pub),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm protector: seal: %w", err)
	}
	return json.Marshal(sealed{V: sealedVersion, PCRs: p.pcrs, PCRDigest: pcrDigest, SRK: srk.name.Buffer,
		Public: tpm2.Marshal(rsp.OutPublic), Private: tpm2.Marshal(rsp.OutPrivate)})
}

func (p *Protector) Unseal(_ context.Context, _ plugin.KeyRef, blob []byte) ([]byte, error) {
	var s sealed
	if err := decodeSealed(blob, &s); err != nil || s.V != sealedVersion || len(s.SRK) == 0 ||
		len(s.PCRDigest) != pcrDigestSize(s.PCRs) {
		return nil, errors.New("tpm protector: the sealed key is not one this version can read")
	}
	if !slices.Equal(s.PCRs, p.pcrs) {
		return nil, fmt.Errorf("tpm protector: the key is bound to PCRs %v, but the config says %v; run foca recover to seal it again", s.PCRs, p.pcrs)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](s.Public)
	if err != nil {
		return nil, fmt.Errorf("tpm protector: sealed key: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](s.Private)
	if err != nil {
		return nil, fmt.Errorf("tpm protector: sealed key: %w", err)
	}

	t, err := p.open()
	if err != nil {
		return nil, fmt.Errorf("tpm protector: open the TPM: %w", err)
	}
	defer t.Close()
	srk, err := storageKey(t)
	if err != nil {
		return nil, err
	}
	defer srk.flush(t)
	if !bytes.Equal(srk.name.Buffer, s.SRK) {
		// Checked before the key salts a session: a substitute's key would
		// let whoever holds it read the unsealed key off the bus.
		return nil, errors.New("tpm protector: this TPM's storage key isn't the one the key was sealed under (sealed on another machine, the TPM was cleared, or something between foca and the TPM answers for it)")
	}
	obj, err := tpm2.Load{ParentHandle: srk.auth(false), InPrivate: *priv, InPublic: *pub}.Execute(t)
	if err != nil {
		// The TPM checks the object's integrity under its storage key:
		// another TPM's object fails it, and so does an altered one.
		return nil, fmt.Errorf("tpm protector: this TPM can't load the sealed key (sealed on another machine, the TPM was cleared, or the key slot was altered): %w", err)
	}
	defer tpm2.FlushContext{FlushHandle: obj.ObjectHandle}.Execute(t)

	if len(s.PCRs) > 0 {
		// The loaded public area is the TPM's, so its policy is the truth;
		// the slot's PCR record must match it. Only then does a PCR
		// mismatch mean the boot state changed.
		pa, err := pub.Contents()
		if err != nil {
			return nil, fmt.Errorf("tpm protector: sealed key: %w", err)
		}
		recorded, err := pcrPolicy(s.PCRDigest, s.PCRs)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(recorded, pa.AuthPolicy.Buffer) {
			return nil, errors.New("tpm protector: the key slot was altered: its PCR record doesn't match the sealed key's policy")
		}
		now, err := readPCRs(t, s.PCRs)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(now, s.PCRDigest) {
			return nil, fmt.Errorf("tpm protector: %w (PCR %v); run foca recover with the vault's recovery key", ErrBootStateChanged, s.PCRs)
		}
	}

	var sess tpm2.Session
	if len(s.PCRs) == 0 {
		sess = tpm2.HMAC(tpm2.TPMAlgSHA256, 16, srk.salted(), tpm2.AESEncryption(128, tpm2.EncryptOut))
	} else {
		ps, closeSession, err := tpm2.PolicySession(t, tpm2.TPMAlgSHA256, 16, srk.salted(), tpm2.AESEncryption(128, tpm2.EncryptOut))
		if err != nil {
			return nil, fmt.Errorf("tpm protector: policy session: %w", err)
		}
		defer closeSession()
		// An empty digest makes the TPM use the PCRs' current values.
		if _, err := (tpm2.PolicyPCR{PolicySession: ps.Handle(), Pcrs: selection(s.PCRs)}).Execute(t); err != nil {
			return nil, fmt.Errorf("tpm protector: PCR policy: %w", err)
		}
		sess = ps
	}
	out, err := tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: obj.ObjectHandle, Name: obj.Name, Auth: sess}}.Execute(t)
	if errors.Is(err, tpm2.TPMRCPolicyFail) {
		// The PCRs read as sealed a moment ago, so this isn't the boot
		// state: they changed in between, or something else is wrong.
		return nil, fmt.Errorf("tpm protector: the TPM refused the key's PCR policy although PCR %v read as sealed: %w", s.PCRs, err)
	}
	if err != nil {
		return nil, fmt.Errorf("tpm protector: unseal: %w", err)
	}
	return out.OutData.Buffer, nil
}

// Destroy does nothing: the sealed key lives only in the vault's key slot.
func (p *Protector) Destroy(context.Context, plugin.KeyRef, []byte) error { return nil }

// srk is the storage key, created the same each time from the owner
// hierarchy's seed.
type srk struct {
	handle tpm2.TPMHandle
	name   tpm2.TPM2BName
	pub    tpm2.TPMTPublic
}

func storageKey(t transport.TPM) (*srk, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm protector: create the storage key: %w", err)
	}
	pub, err := rsp.OutPublic.Contents()
	if err != nil {
		tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t)
		return nil, fmt.Errorf("tpm protector: storage key: %w", err)
	}
	return &srk{handle: rsp.ObjectHandle, name: rsp.Name, pub: *pub}, nil
}

func (k *srk) flush(t transport.TPM) { tpm2.FlushContext{FlushHandle: k.handle}.Execute(t) }

// salted salts a session with the storage key, so only this TPM can derive
// its session key.
func (k *srk) salted() tpm2.AuthOption { return tpm2.Salted(k.handle, k.pub) }

// auth authorizes using the storage key in a salted session, which also
// encrypts the command's first parameter if encryptIn is set.
func (k *srk) auth(encryptIn bool) tpm2.AuthHandle {
	opts := []tpm2.AuthOption{k.salted()}
	if encryptIn {
		opts = append(opts, tpm2.AESEncryption(128, tpm2.EncryptIn))
	}
	return tpm2.AuthHandle{Handle: k.handle, Name: k.name, Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, opts...)}
}

func selection(pcrs []int) tpm2.TPMLPCRSelection {
	idx := make([]uint, len(pcrs))
	for i, p := range pcrs {
		idx[i] = uint(p)
	}
	return tpm2.TPMLPCRSelection{PCRSelections: []tpm2.TPMSPCRSelection{
		{Hash: tpm2.TPMAlgSHA256, PCRSelect: tpm2.PCClientCompatible.PCRs(idx...)},
	}}
}

// readPCRs returns the digest PolicyPCR binds to: SHA-256 over the PCRs'
// current values in the SHA-256 bank.
func readPCRs(t transport.TPM, pcrs []int) ([]byte, error) {
	rsp, err := tpm2.PCRRead{PCRSelectionIn: selection(pcrs)}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm protector: read PCRs: %w", err)
	}
	if len(rsp.PCRValues.Digests) != len(pcrs) {
		return nil, fmt.Errorf("tpm protector: the TPM returned %d of %d PCRs in the SHA-256 bank", len(rsp.PCRValues.Digests), len(pcrs))
	}
	h := sha256.New()
	for _, d := range rsp.PCRValues.Digests {
		h.Write(d.Buffer)
	}
	return h.Sum(nil), nil
}

// pcrPolicy is the policy digest of PolicyPCR over pcrs holding the values
// whose digest is pcrDigest.
func pcrPolicy(pcrDigest []byte, pcrs []int) ([]byte, error) {
	calc, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		return nil, err
	}
	if err := (tpm2.PolicyPCR{PcrDigest: tpm2.TPM2BDigest{Buffer: pcrDigest}, Pcrs: selection(pcrs)}).Update(calc); err != nil {
		return nil, err
	}
	return calc.Hash().Digest, nil
}

// decodeSealed reads a key slot as strictly as the protocol reads a
// request: unknown, duplicate or case-variant keys and trailing data are
// refused.
func decodeSealed(b []byte, s *sealed) error {
	if err := protocol.CheckStrict(b, reflect.TypeOf(s)); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	return dec.Decode(s)
}

// pcrDigestSize is how long a slot's PCR digest is: none without PCRs.
func pcrDigestSize(pcrs []int) int {
	if len(pcrs) == 0 {
		return 0
	}
	return sha256.Size
}

// secureBootVar is the firmware's SecureBoot variable (EFI global variable
// GUID). In efivarfs it reads as 4 attribute bytes, then 1 when Secure Boot
// is on and 0 when it is off.
const secureBootVar = "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

// checkSecureBoot refuses to bind to PCR 7 unless Secure Boot is on. PCR 7
// measures the Secure Boot state and keys, not what boots: with Secure Boot
// off it reads the same whatever OS or bootloader runs, so the binding would
// look like protection and be none.
func checkSecureBoot(efivars string) error {
	way := "set [key_protectors.tpm] pcrs without 7: PCRs that measure what boots (for example [0, 2, 4]), or [] to bind to no boot state"
	b, err := readSmall(filepath.Join(efivars, secureBootVar))
	switch {
	case err != nil:
		return fmt.Errorf("tpm protector: PCR 7 binds the vault key to Secure Boot, but foca can't tell whether it is on (%v): turn Secure Boot on, or %s", err, way)
	case len(b) != 5 || b[4] > 1:
		return fmt.Errorf("tpm protector: PCR 7 binds the vault key to Secure Boot, but the firmware's SecureBoot variable reads %x: turn Secure Boot on, or %s", b, way)
	case b[4] == 0:
		return fmt.Errorf("tpm protector: Secure Boot is off, so PCR 7 reads the same whatever boots: turn Secure Boot on, or %s", way)
	}
	return nil
}

func readSmall(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 64))
}
