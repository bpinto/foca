package wiring

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/config"
)

// An offered action's command is trust-checked at start-up, as a helper is,
// and the service refuses to start if it fails. Actions no instance is
// offered aren't checked.
func TestActionCommandsAreCheckedAtStartUp(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	bad := filepath.Join(dir, "bad")
	os.WriteFile(good, []byte("#!/bin/sh\n"), 0o700)
	os.WriteFile(bad, []byte("#!/bin/sh\n"), 0o700)
	os.Chmod(bad, 0o722)
	cfgFor := func(offered string) *config.Config {
		c, err := config.Parse([]byte(fmt.Sprintf(`version = 1
[plugins]
authenticator = "fake"
secret_store = "memory"
[instances.dev]
actions = [%s]
[actions.good]
command = %q
[actions.bad]
command = %q
[actions.missing]
command = "/nonexistent/foca-action"
`, offered, good, bad)))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if err := checkActions(cfgFor(`"good"`)); err != nil {
		t.Fatal(err)
	}
	err := checkActions(cfgFor(`"good", "bad", "missing"`))
	if err == nil || !strings.Contains(err.Error(), "actions.bad: command not trusted") ||
		!strings.Contains(err.Error(), "actions.missing: command not trusted") {
		t.Fatalf("got %v", err)
	}
}
