//go:build foca_testing

package wiring

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/server/core"
)

// [approval] prompt_show_client and skip_ancestors reach the prompt. The
// prompt text is recorded in approval.granted, so the test reads it there.
func TestApprovalSettingsReachThePrompt(t *testing.T) {
	// A sealed "wrapperx" started by a sealed gh, from the host.
	peer := identity.VerifiedPeer{UID: 1, PID: 2, StartTime: 3, Exe: "/usr/bin/wrapperx", ExeSealed: true, PIDStable: true,
		Session: "sid:2:3", Parents: []identity.Proc{{PID: 1, Exe: "/usr/bin/gh", Sealed: true}}}
	for _, c := range []struct {
		name, approval, want string
	}{
		{"defaults", "", "share:\n🔑 dev:tok\n👤 wrapperx via gh"},
		{"skip_ancestors", "skip_ancestors = [\"wrapperx\"]\n", "share:\n🔑 dev:tok\n👤 gh"},
		{"prompt_show_client = false", "prompt_show_client = false\n", "share:\n🔑 dev:tok"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := config.Parse([]byte("version = 1\n[plugins]\nauthenticator = \"fake\"\nsecret_store = \"memory\"\nplatform_events = \"none\"\n" +
				"[approval]\n" + c.approval + "[instances.dev]\n"))
			if err != nil {
				t.Fatal(err)
			}
			base := t.TempDir()
			paths := config.Paths{DataDir: filepath.Join(base, "d"), RuntimeDir: filepath.Join(base, "r")}
			b, err := Build(cfg, paths, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer b.Audit.Close()
			ctx := context.Background()
			b.Stores["dev"].Put(ctx, nil, plugin.SecretMeta{ID: "tok"}, plugin.SecretValue{Bytes: []byte("v")})
			inst, _ := b.Core.Instance("dev")
			out, err := b.Core.ReadSecrets(ctx, core.Call{RequestID: "r", Origin: audit.OriginClientSocket, Conn: "c", Instance: inst, Peer: peer}, []string{"dev:tok"})
			if err != nil {
				t.Fatal(err)
			}
			core.ZeroSecrets(out)
			evs, _, err := b.Audit.Query(ctx, audit.Filter{Types: []string{audit.TypeApprovalGranted}}, audit.Page{})
			if err != nil || len(evs) != 1 {
				t.Fatalf("approval events %+v %v", evs, err)
			}
			if got := evs[0].Approval.PromptText; got != c.want {
				t.Fatalf("prompt %q, want %q", got, c.want)
			}
		})
	}
}
