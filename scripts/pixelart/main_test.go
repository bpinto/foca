package main

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// The icons in apps/macos/Resources are this command's output: a grid
// changed without running it again fails here.
func TestCommittedIconsMatchTheArt(t *testing.T) {
	out := t.TempDir()
	if err := run(out, ""); err != nil {
		t.Fatal(err)
	}
	committed := filepath.Join("..", "..", "apps", "macos", "Resources")
	n := 0
	err := filepath.WalkDir(out, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(out, path)
		want, _ := os.ReadFile(path)
		got, err := os.ReadFile(filepath.Join(committed, rel))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s differs from the art (run: go run ./scripts/pixelart apps/macos/Resources)", rel)
		}
		n++
		return nil
	})
	if err != nil || n != 14 {
		t.Fatalf("rendered %d files: %v", n, err)
	}
}
