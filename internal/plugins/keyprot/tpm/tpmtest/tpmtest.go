// Package tpmtest runs swtpm, a software TPM 2.0, for tests. It is imported
// only by tests.
package tpmtest

import (
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// Start runs swtpm for the test and returns its socket. FOCA_SWTPM names the
// swtpm binary (the dev shell sets it); without it the test is skipped, and
// with it, a swtpm that can't start fails the test.
func Start(t testing.TB) string {
	t.Helper()
	bin := os.Getenv("FOCA_SWTPM")
	if bin == "" {
		t.Skip("FOCA_SWTPM is not set (nix develop sets it)")
	}
	// A short directory: the socket path must fit in sun_path.
	dir, err := os.MkdirTemp("", "ftpm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "tpm.sock")
	cmd := exec.Command(bin, "socket", "--tpm2", "--tpmstate", "dir="+dir,
		"--server", "type=unixio,path="+sock, "--ctrl", "type=unixio,path="+filepath.Join(dir, "ctrl.sock"),
		"--flags", "startup-clear,not-need-init")
	if testing.Verbose() {
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start swtpm: %v", err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		if fi, err := os.Stat(sock); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return sock
		}
		if time.Now().After(deadline) {
			t.Fatal("swtpm never opened its socket")
		}
	}
}

// Open connects to the swtpm at sock.
func Open(sock string) func() (transport.TPMCloser, error) {
	return func() (transport.TPMCloser, error) { return linuxudstpm.Open(sock) }
}

// ExtendPCR extends pcr in the SHA-256 bank, as booting something else does.
func ExtendPCR(t testing.TB, sock string, pcr int) {
	t.Helper()
	tp, err := linuxudstpm.Open(sock)
	if err != nil {
		t.Fatal(err)
	}
	defer tp.Close()
	d := sha256.Sum256([]byte("something else booted"))
	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{Handle: tpm2.TPMHandle(pcr), Auth: tpm2.PasswordAuth(nil)},
		Digests:   tpm2.TPMLDigestValues{Digests: []tpm2.TPMTHA{{HashAlg: tpm2.TPMAlgSHA256, Digest: d[:]}}},
	}.Execute(tp)
	if err != nil {
		t.Fatal(err)
	}
}

// EFIVars returns a directory of EFI variables in which Secure Boot reads
// as on or off.
func EFIVars(t testing.TB, secureBoot bool) string {
	t.Helper()
	dir := t.TempDir()
	v := byte(0)
	if secureBoot {
		v = 1
	}
	// 4 attribute bytes (non-volatile, boot and runtime access), then the value.
	b := []byte{0x06, 0, 0, 0, v}
	if err := os.WriteFile(filepath.Join(dir, "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}
