//go:build foca_testing

package cli

import (
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/audit"
)

// Two instances with private vaults: each sees only its own, and asking for
// the other's secret looks exactly like asking for one that doesn't exist.
func TestPrivateVaultsCantSeeEachOther(t *testing.T) {
	w := newWorldWith(t, func(string) string {
		return `version = 1
[plugins]
authenticator = "fake"
platform_events = "none"
secret_store = "vault-file"
key_protector = "file"
[instances.a]
realm = { kind = "host" }
[instances.b]
realm = { kind = "host" }
`
	})
	w.ok("", "init", "--vault", "a")
	w.ok("", "init", "--vault", "b")
	w.ok("secret-a", "add", "a:tok")
	w.ok("secret-b", "add", "b:tok")
	stop := w.serve()
	defer stop()

	if out := w.ok("", "get", "-i", "a", "a:tok"); string(out) != "secret-a" {
		t.Fatalf("a: %q", out)
	}
	_, other, _ := w.run("", "get", "-i", "a", "b:tok")
	_, missing, _ := w.run("", "get", "-i", "a", "b:nope")
	if !strings.Contains(other, "not_found") || strings.Replace(other, "b:tok", "X", 1) != strings.Replace(missing, "b:nope", "X", 1) {
		t.Fatalf("another instance's secret:\n%s\nvs a missing one:\n%s", other, missing)
	}
	if out := string(w.ok("", "list", "-i", "a")); !strings.Contains(out, "a:tok") || strings.Contains(out, "b:tok") {
		t.Fatalf("list a:\n%s", out)
	}
	if out := string(w.ok("", "list", "-i", "b")); !strings.Contains(out, "b:tok") || strings.Contains(out, "a:tok") {
		t.Fatalf("list b:\n%s", out)
	}
	audited := false
	for _, e := range w.events() {
		if e.Type == audit.TypeSecretRead && e.Instance == "a" && e.Outcome == audit.OutcomeNotFound && e.Resource.ID == "b:tok" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("the attempt on b's secret wasn't audited")
	}
}
