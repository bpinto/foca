package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/svcctl"
)

// In a terminal stdout and stderr interleave: the table comes first, and the
// instances it leaves out follow, the idle ones on one line.
func TestHostGrantsTableComesBeforeTheNotes(t *testing.T) {
	var both bytes.Buffer
	e := &Env{Stdout: &both, Stderr: &both}
	out := []hostGrants{
		{Instance: "cliniko", Running: true, Reuse: true, Grants: []svcctl.Grant{}},
		{Instance: "dotfiles", Running: true, Reuse: true, Grants: []svcctl.Grant{{Kind: "secret", Name: "dotfiles:github-read-only",
			Scope: "peer-session", ExpiresAt: time.Date(2026, 10, 12, 22, 39, 27, 0, time.UTC)}}},
		{Instance: "homelab", Running: true, Reuse: true, Grants: []svcctl.Grant{}},
		{Instance: "old", Error: "service not running (no pid file)"},
	}
	if err := printHostGrants(e, out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(both.String()), "\n")
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "INSTANCE") || !strings.HasPrefix(lines[1], "dotfiles") ||
		lines[2] != "no live grants: cliniko, homelab" || lines[3] != "old: service not running (no pid file)" {
		t.Fatalf("output:\n%s", both.String())
	}
}
