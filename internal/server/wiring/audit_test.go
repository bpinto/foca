package wiring

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
)

// [audit] sizes the log the sink writes: a file over max_file_size_mib is
// rotated by the next append.
func TestAuditRotationComesFromConfig(t *testing.T) {
	cfg, err := config.Parse([]byte("version = 1\n[plugins]\nauthenticator = \"x\"\nsecret_store = \"memory\"\n[audit]\nmax_file_size_mib = 1\nkeep_files = 1\n[instances.dev]\n"))
	if err != nil {
		t.Fatal(err)
	}
	paths := config.Paths{DataDir: filepath.Join(t.TempDir(), "d")}
	os.Mkdir(paths.DataDir, 0o700)
	full := `{"v":1,"seq":1,"id":"a","ts":"2026-10-08T00:00:00Z","type":"lock","outcome":"ok"}` + "\n" +
		strings.Repeat("x", 1<<20) + "\n"
	os.WriteFile(paths.AuditLog(), []byte(full), 0o600)

	sink, err := openAudit(cfg, paths)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if seq, err := sink.Append(context.Background(), &audit.Event{Type: audit.TypeLock, Outcome: audit.OutcomeOK}); err != nil || seq != 2 {
		t.Fatalf("append: %d %v", seq, err)
	}
	if _, err := os.Stat(filepath.Join(paths.DataDir, "audit.1.jsonl")); err != nil {
		t.Fatalf("not rotated: %v", err)
	}
}
