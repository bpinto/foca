//go:build foca_testing

package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
)

// foca events reads what the host CLI and the service both record, the
// service's live, while it runs.
func TestEventsSeeTheServiceAndTheHostCLI(t *testing.T) {
	w := newWorld(t)
	w.ok("", "init", "--vault", "common")
	w.ok("ghp_123", "add", "common:github-pat")
	stop := w.serve()
	defer stop()

	ew := &eventsWorld{t: t, vars: w.vars}
	out, stopFollow := ew.follow("--from-seq", "1", "--type", "secret.read")
	w.ok("", "get", "-i", "dev", "common:github-pat")
	waitForType(t, out, audit.TypeSecretRead)
	if code := stopFollow(); code != 0 {
		t.Fatalf("follow exit %d", code)
	}
	var read audit.Event
	json.Unmarshal([]byte(strings.TrimSpace(out.String())), &read)
	if read.Instance != "dev" || read.Resource.ID != "common:github-pat" || read.Peer == nil || read.Peer.Verified == nil ||
		read.Approval == nil || read.Approval.Mode != audit.ModeFresh {
		t.Fatalf("followed %s", out)
	}

	q := w.ok("", "events", "query")
	var types []string
	for _, line := range strings.Split(strings.TrimSpace(string(q)), "\n") {
		var e audit.Event
		json.Unmarshal([]byte(line), &e)
		types = append(types, e.Type+"/"+e.Origin)
	}
	for _, want := range []string{"vault.init/host-cli", "secret.add/host-cli", "server.start/", "secret.read/client-socket"} {
		if !contains(types, want) {
			t.Errorf("query has no %s: %v", want, types)
		}
	}
}

func waitForType(t *testing.T, out *syncBuffer, typ string) {
	t.Helper()
	waitUntil(t, func() bool { return strings.Contains(out.String(), `"type":"`+typ+`"`) })
}

func waitUntil(t *testing.T, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
