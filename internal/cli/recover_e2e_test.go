//go:build foca_testing

package cli

import (
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/plugins/keyprot/tpm/tpmtest"
	"github.com/bpinto/foca/internal/plugins/store/vaultfile"
)

// tpmWorld is the e2e world with its vault keys sealed to a software TPM.
func tpmWorld(t *testing.T) (*world, string) {
	sock := tpmtest.Start(t)
	t.Setenv("FOCA_TPM_SOCKET", sock)
	t.Setenv("FOCA_EFIVARS", tpmtest.EFIVars(t, true))
	return newWorldWith(t, func(string) string {
		return strings.Replace(e2eConfig, `key_protector = "file"`, `key_protector = "tpm"`, 1)
	}), sock
}

// A key bound to PCR 7 stays sealed after the boot state changes, until the
// recovery key seals it again.
func TestRecoverAfterTheBootStateChanged(t *testing.T) {
	w, sock := tpmWorld(t)
	if _, errs, code := w.run("", "init", "--vault", "common"); code != 1 || !strings.Contains(errs, "pass --recovery") {
		t.Fatalf("init without recovery: %d %s", code, errs)
	}
	key := string(w.ok("", "init", "--vault", "common", "--recovery"))
	w.ok("ghp_123", "add", "common:github-pat")
	stop := w.serve()
	defer func() { stop() }()
	if out := w.ok("", "get", "-i", "work", "common:github-pat"); string(out) != "ghp_123" {
		t.Fatalf("get: %q", out)
	}

	tpmtest.ExtendPCR(t, sock, 7)
	if _, errs, code := w.run("", "get", "-i", "work", "common:github-pat"); code != 1 || !strings.Contains(errs, "internal") {
		t.Fatalf("get after the boot state changed: %d %s", code, errs)
	}
	sealedAway := false
	for _, e := range w.events() {
		if e.Type == audit.TypeSecretRead && e.Outcome == audit.OutcomeError && e.Error != nil && strings.Contains(e.Error.Message, "foca recover") {
			sealedAway = true
		}
	}
	if !sealedAway {
		t.Fatal("the refused read wasn't audited with the way out")
	}

	other, _ := vaultfile.NewRecoveryKey()
	if _, errs, code := w.run(string(vaultfile.FormatRecoveryKey(other)), "recover", "--vault", "common"); code != 1 || !strings.Contains(errs, "wrong recovery key") {
		t.Fatalf("recover with another key: %d %s", code, errs)
	}
	_, errs, _ := w.run(key, "recover", "--vault", "common")
	if !strings.Contains(errs, "sealed vault common's key again with tpm") {
		t.Fatalf("recover: %s", errs)
	}
	if out := w.ok("", "get", "-i", "work", "common:github-pat"); string(out) != "ghp_123" {
		t.Fatalf("get after recover: %q", out)
	}
	var rec audit.Event
	for _, e := range w.events() {
		if e.Type == audit.TypeVaultRecover {
			rec = e
		}
	}
	if rec.Outcome != audit.OutcomeOK || rec.Params["protector"] != "tpm" || rec.Params["replaced"] != "tpm" || rec.Approval == nil {
		t.Fatalf("recover event %+v", rec)
	}
}
