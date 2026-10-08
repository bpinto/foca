//go:build foca_testing

package wiring

import (
	"context"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"

	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	keyfile "github.com/bpinto/foca/internal/plugins/keyprot/file"
)

// In test builds only, "fake" approves everything. Production builds can't
// select it, so no config line can turn approval off.
func init() {
	TestBuild = true
	authenticators["fake"] = func(*env) (plugin.Authenticator, error) {
		a := fake.New()
		a.Default = fake.Approve
		return a, nil
	}
}

// readyEvents is the test builds' "fake" platform-events source: healthy at
// once, and it never reports anything. Tests wipe with `foca lock`.
type readyEvents struct{}

func (readyEvents) Name() string { return "fake" }

func (readyEvents) Run(ctx context.Context, out chan<- plugin.PlatformEvent) error {
	select {
	case out <- plugin.PlatformEvent{Kind: plugin.EventReady, At: time.Now(), Source: "fake"}:
	case <-ctx.Done():
		return nil
	}
	<-ctx.Done()
	return nil
}

func init() {
	eventSources["fake"] = func(*env) (plugin.PlatformEvents, error) { return readyEvents{}, nil }
}

// In test builds only, "file" keeps each vault key in a plain file, and
// FOCA_TPM_SOCKET points the TPM protector at a software TPM (swtpm), and
// FOCA_EFIVARS at a directory of fake EFI variables.
func init() {
	protectors["file"] = func(_ *env, paths config.Paths) (plugin.KeyProtector, error) {
		return keyfile.New(paths.KeysDir()), nil
	}
	device := openTPM
	openTPM = func(path string) (transport.TPMCloser, error) {
		if sock := os.Getenv("FOCA_TPM_SOCKET"); sock != "" {
			return linuxudstpm.Open(sock)
		}
		return device(path)
	}
	vars := efiVars
	efiVars = func() string {
		if dir := os.Getenv("FOCA_EFIVARS"); dir != "" {
			return dir
		}
		return vars()
	}
}
