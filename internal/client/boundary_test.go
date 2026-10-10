package client

import (
	"os/exec"
	"strings"
	"testing"
)

// Code that runs inside a realm (the client, later the CLI) must
// never link service-side code: no vault, keys, plugins or server.
func TestClientSideDoesNotImportServiceSide(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/bpinto/foca/internal/client").Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, banned := range []string{"/internal/server", "/internal/plugins", "/internal/plugin", "/internal/audit", "/internal/config"} {
			if strings.HasSuffix(dep, banned) || strings.Contains(dep, banned+"/") {
				t.Errorf("internal/client depends on %s", dep)
			}
		}
	}
}
