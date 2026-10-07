//go:build foca_testing

package wiring

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/client"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/protocol"
)

// End to end through config, wiring, real sockets, the Linux identifier and
// the JSONL audit file.
func TestBuildFromConfigEndToEnd(t *testing.T) {
	base, _ := os.MkdirTemp("", "tgw")
	defer os.RemoveAll(base)
	cfg, err := config.Parse([]byte("version = 1\n[plugins]\nauthenticator = \"fake\"\nsecret_store = \"memory\"\nplatform_events = \"none\"\n[instances.dev]\n"))
	if err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{DataDir: filepath.Join(base, "d"), RuntimeDir: filepath.Join(base, "r")}
	b, err := Build(cfg, paths, "test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Audit.Close()
	if err := b.Server.Start(); err != nil {
		t.Fatal(err)
	}
	defer b.Server.Shutdown("test")

	ctx := context.Background()
	// Seed the in-memory store directly, without the host CLI.
	b.Stores["dev"].Put(ctx, nil, plugin.SecretMeta{ID: "tok"}, plugin.SecretValue{Bytes: []byte("v1")})
	c, err := client.Dial(ctx, paths.ClientSocket("dev"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var res protocol.SecretReadResult
	if err := c.Call(ctx, protocol.MethodSecretRead, protocol.SecretReadParams{Names: []string{"dev:tok"}}, &res); err != nil {
		t.Fatal(err)
	}
	if res.Secrets[0].Value != "v1" {
		t.Fatalf("got %+v", res)
	}

	fi, err := os.Stat(paths.AuditLog())
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("audit log %v %v", fi, err)
	}
	log, _ := os.ReadFile(paths.AuditLog())
	if len(log) == 0 || strings.Contains(string(log), `"v1"`) {
		t.Fatalf("audit log empty or contains the secret value:\n%s", log)
	}
}
