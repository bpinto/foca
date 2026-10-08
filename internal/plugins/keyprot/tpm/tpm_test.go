package tpm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2/transport"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/keyprot/tpm/tpmtest"
)

var (
	ctx = context.Background()
	ref = plugin.KeyRef{Vault: "common", VaultID: "01VAULT"}
	dek = bytes.Repeat([]byte{0xa5}, 32)
)

func seal(t *testing.T, p *Protector) []byte {
	t.Helper()
	blob, err := p.Seal(ctx, ref, dek)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestSealUnsealRoundTrip(t *testing.T) {
	sock := tpmtest.Start(t)
	for name, pcrs := range map[string][]int{"pcr 7": {7}, "no pcrs": nil, "several": {7, 0, 2}} {
		t.Run(name, func(t *testing.T) {
			p := New(tpmtest.Open(sock), pcrs, sbOn(t))
			blob := seal(t, p)
			got, err := p.Unseal(ctx, ref, blob)
			if err != nil || !bytes.Equal(got, dek) {
				t.Fatalf("unseal = %x, %v", got, err)
			}
			// The slot holds a TPM object, never the key itself.
			if bytes.Contains(blob, dek) || bytes.Contains(blob, dek[:8]) {
				t.Fatal("the sealed blob contains the key")
			}
		})
	}
}

// A changed boot state (PCR 7) keeps the key sealed until it is sealed again
// with the recovery key.
func TestBootStateChangeRefusesUnseal(t *testing.T) {
	sock := tpmtest.Start(t)
	bound := New(tpmtest.Open(sock), []int{7}, sbOn(t))
	unbound := New(tpmtest.Open(sock), nil, sbOn(t))
	boundBlob, unboundBlob := seal(t, bound), seal(t, unbound)

	tpmtest.ExtendPCR(t, sock, 7)
	_, err := bound.Unseal(ctx, ref, boundBlob)
	if !errors.Is(err, ErrBootStateChanged) || !strings.Contains(err.Error(), "foca recover") {
		t.Fatalf("unseal after PCR 7 changed: %v", err)
	}
	if got, err := unbound.Unseal(ctx, ref, unboundBlob); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("a key bound to no PCRs: %v", err)
	}
	// Sealing again binds to the new state.
	if got, err := bound.Unseal(ctx, ref, seal(t, bound)); err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("after sealing again: %v", err)
	}
}

// A vault file copied to another machine can't be opened there.
func TestAnotherTPMCantUnseal(t *testing.T) {
	blob := seal(t, New(tpmtest.Open(tpmtest.Start(t)), []int{7}, sbOn(t)))
	other := New(tpmtest.Open(tpmtest.Start(t)), []int{7}, sbOn(t))
	if _, err := other.Unseal(ctx, ref, blob); err == nil || !strings.Contains(err.Error(), "sealed on another machine") {
		t.Fatalf("unseal on another TPM: %v", err)
	}
}

func TestTamperedOrForeignBlobsAreRefused(t *testing.T) {
	sock := tpmtest.Start(t)
	p := New(tpmtest.Open(sock), []int{7}, sbOn(t))
	blob := seal(t, p)
	var s sealed
	json.Unmarshal(blob, &s)
	s.Private[len(s.Private)-1] ^= 1
	flipped, _ := json.Marshal(s)
	noSRK, _ := json.Marshal(sealed{V: s.V, PCRs: s.PCRs, Public: s.Public, Private: s.Private})
	for name, b := range map[string][]byte{
		"flipped bit":   flipped,
		"not json":      []byte("x"),
		"other version": []byte(`{"v":2}`),
		"no srk":        noSRK,
		"duplicate key": append([]byte(`{"pcrs":[],`), blob[1:]...),
		"case variant":  bytes.Replace(blob, []byte(`"pcrs"`), []byte(`"PCRs"`), 1),
		"trailing data": append(bytes.Clone(blob), blob...),
	} {
		if _, err := p.Unseal(ctx, ref, b); err == nil {
			t.Errorf("%s: unsealed", name)
		}
	}
	// A key sealed under other PCRs than the config names is refused, not
	// opened under the weaker binding.
	loose := seal(t, New(tpmtest.Open(sock), nil, sbOn(t)))
	if _, err := p.Unseal(ctx, ref, loose); err == nil || !strings.Contains(err.Error(), "run foca recover") {
		t.Fatalf("key bound to other PCRs: %v", err)
	}
}

func TestNoTPMIsAnError(t *testing.T) {
	p := New(func() (transport.TPMCloser, error) { return nil, errors.New("no such device") }, []int{7}, sbOn(t))
	if _, err := p.Seal(ctx, ref, dek); err == nil || !strings.Contains(err.Error(), "open the TPM") {
		t.Fatalf("seal: %v", err)
	}
}

// recorder keeps every byte sent to and received from the TPM.
type recorder struct {
	transport.TPMCloser
	wire *bytes.Buffer
}

func (r recorder) Send(in []byte) ([]byte, error) {
	r.wire.Write(in)
	out, err := r.TPMCloser.Send(in)
	r.wire.Write(out)
	return out, err
}

// The key crosses the bus to the TPM only inside encrypted sessions: no
// command or response carries it in clear, sealing or unsealing.
func TestTheKeyNeverCrossesTheBusInClear(t *testing.T) {
	sock := tpmtest.Start(t)
	for name, pcrs := range map[string][]int{"pcr 7": {7}, "no pcrs": nil} {
		t.Run(name, func(t *testing.T) {
			var wire bytes.Buffer
			p := New(func() (transport.TPMCloser, error) {
				tp, err := tpmtest.Open(sock)()
				return recorder{tp, &wire}, err
			}, pcrs, sbOn(t))
			got, err := p.Unseal(ctx, ref, seal(t, p))
			if err != nil || !bytes.Equal(got, dek) {
				t.Fatalf("unseal: %v", err)
			}
			if wire.Len() == 0 || bytes.Contains(wire.Bytes(), dek[:8]) {
				t.Fatalf("the key crossed the bus in clear (%d bytes recorded)", wire.Len())
			}
		})
	}
}

// The slot records the storage key it was sealed under. A TPM, or something
// on the bus, that answers with another storage key is refused before that
// key salts any session.
func TestAnotherStorageKeyIsRefused(t *testing.T) {
	sock := tpmtest.Start(t)
	p := New(tpmtest.Open(sock), []int{7}, sbOn(t))
	blob := seal(t, p)
	var s sealed
	json.Unmarshal(blob, &s)
	s.SRK[len(s.SRK)-1] ^= 1
	other, _ := json.Marshal(s)
	var sent int
	counting := New(func() (transport.TPMCloser, error) {
		tp, err := tpmtest.Open(sock)()
		return counter{tp, &sent}, err
	}, []int{7}, sbOn(t))
	if got, err := counting.Unseal(ctx, ref, other); err == nil || !strings.Contains(err.Error(), "storage key isn't the one") {
		t.Fatalf("unseal under another storage key: %x %v", got, err)
	}
	// CreatePrimary, then FlushContext: nothing was loaded or unsealed.
	if sent != 2 {
		t.Fatalf("%d commands reached the TPM", sent)
	}
}

// counter counts the commands sent to the TPM.
type counter struct {
	transport.TPMCloser
	n *int
}

func (c counter) Send(in []byte) ([]byte, error) {
	*c.n++
	return c.TPMCloser.Send(in)
}

// A refused unseal says the boot state changed only when it did. A slot
// whose PCR record doesn't match the sealed object's policy, as one swapped
// for an object sealed to other PCRs, is reported as altered, so nobody is
// sent to foca recover for it.
func TestAnAlteredSlotIsNotABootStateChange(t *testing.T) {
	sock := tpmtest.Start(t)
	p := New(tpmtest.Open(sock), []int{7}, sbOn(t))

	// An object sealed to PCR 0, in a slot that claims PCR 7.
	var s sealed
	json.Unmarshal(seal(t, New(tpmtest.Open(sock), []int{0}, sbOn(t))), &s)
	s.PCRs = []int{7}
	swapped, _ := json.Marshal(s)
	// The right object with another PCR record.
	json.Unmarshal(seal(t, p), &s)
	s.PCRDigest[0] ^= 1
	edited, _ := json.Marshal(s)

	for name, b := range map[string][]byte{"swapped object": swapped, "edited record": edited} {
		_, err := p.Unseal(ctx, ref, b)
		if err == nil || errors.Is(err, ErrBootStateChanged) || strings.Contains(err.Error(), "foca recover") || !strings.Contains(err.Error(), "altered") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// sbOn is a directory of EFI variables with Secure Boot on.
func sbOn(t *testing.T) string { return tpmtest.EFIVars(t, true) }

// PCR 7 is the Secure Boot state and keys, not what boots: with Secure Boot
// off it reads the same whatever runs. So sealing to it needs Secure Boot on,
// and says so when it can't tell. Other PCRs, or none, are an explicit
// choice in the config and seal either way.
func TestPCR7NeedsSecureBootOn(t *testing.T) {
	sock := tpmtest.Start(t)
	off := tpmtest.EFIVars(t, false)
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, secureBootVar), []byte{6, 0, 0, 0, 7}, 0o644)
	for name, c := range map[string]struct {
		pcrs    []int
		efivars string
		want    string
	}{
		"off":           {[]int{7}, off, "Secure Boot is off"},
		"with others":   {[]int{0, 7}, off, "Secure Boot is off"},
		"unknown":       {[]int{7}, t.TempDir(), "can't tell whether it is on"},
		"unreadable":    {[]int{7}, bad, "reads 0600000007"},
		"on":            {[]int{7}, sbOn(t), ""},
		"other pcrs":    {[]int{0, 2, 4}, off, ""},
		"no pcrs":       {nil, off, ""},
		"no efi at all": {[]int{0}, "/nonexistent", ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := New(tpmtest.Open(sock), c.pcrs, c.efivars).Seal(ctx, ref, dek)
			switch {
			case c.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "pcrs without 7")):
				t.Fatalf("sealed or said something else: %v", err)
			}
		})
	}
}
