package audit

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func openRotating(t *testing.T, rot Rotation) (*JSONL, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := OpenJSONL(path, rot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func appendN(t *testing.T, s *JSONL, n int) {
	t.Helper()
	for range n {
		if _, err := s.Append(context.Background(), &Event{Type: TypeSecretRead, Outcome: OutcomeOK}); err != nil {
			t.Fatal(err)
		}
	}
}

func seqsOf(evs []Event) []uint64 {
	var out []uint64
	for _, e := range evs {
		out = append(out, e.Seq)
	}
	return out
}

func rotatedNames(t *testing.T, path string) []string {
	t.Helper()
	list, err := newLogFiles(path).list()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range list {
		names = append(names, filepath.Base(r.path))
	}
	return names
}

// With a one-byte limit every append after the first starts a new file.
func TestJSONLRotatesBySizeAndKeepsTheNewestFiles(t *testing.T) {
	s, path := openRotating(t, Rotation{MaxSize: 1, Keep: 2})
	appendN(t, s, 5)
	if got := rotatedNames(t, path); !slices.Equal(got, []string{"audit.3.jsonl", "audit.4.jsonl"}) {
		t.Fatalf("rotated files %v", got)
	}
	for _, name := range []string{"audit.3.jsonl", "audit.4.jsonl", "audit.jsonl", "audit.lock"} {
		fi, err := os.Stat(filepath.Join(filepath.Dir(path), name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, fi, err)
		}
	}
	evs, _, err := s.Query(context.Background(), Filter{}, Page{})
	if err != nil {
		t.Fatal(err)
	}
	if got := seqsOf(evs); !slices.Equal(got, []uint64{3, 4, 5}) {
		t.Fatalf("query across files %v", got)
	}
}

func TestQueryPagesAcrossRotatedFiles(t *testing.T) {
	s, _ := openRotating(t, Rotation{MaxSize: 1, Keep: 100})
	appendN(t, s, 7)
	ctx := context.Background()
	var after uint64
	var pages [][]uint64
	for {
		evs, next, err := s.Query(ctx, Filter{}, Page{AfterSeq: after, Limit: 3})
		if err != nil {
			t.Fatal(err)
		}
		pages = append(pages, seqsOf(evs))
		if next == 0 {
			break
		}
		after = next
	}
	want := [][]uint64{{1, 2, 3}, {4, 5, 6}, {7}}
	if !slices.EqualFunc(pages, want, slices.Equal) {
		t.Fatalf("pages %v, want %v", pages, want)
	}
}

// Rotated files are named after their first seq, so a query by seq doesn't
// open a file that only holds older events. The proof: an older file that
// can't be opened (it isn't private) fails a full query but not a later one.
func TestQuerySkipsRotatedFilesBelowAfterSeq(t *testing.T) {
	s, path := openRotating(t, Rotation{MaxSize: 1, Keep: 100})
	appendN(t, s, 5)
	os.Chmod(filepath.Join(filepath.Dir(path), "audit.2.jsonl"), 0o644)
	ctx := context.Background()
	if _, _, err := s.Query(ctx, Filter{}, Page{}); err == nil || !strings.Contains(err.Error(), "not private") {
		t.Fatalf("full query read past a non-private file: %v", err)
	}
	evs, _, err := s.Query(ctx, Filter{}, Page{AfterSeq: 2})
	if err != nil {
		t.Fatal(err)
	}
	if got := seqsOf(evs); !slices.Equal(got, []uint64{3, 4, 5}) {
		t.Fatalf("query after 2: %v", got)
	}
}

// A process that starts right after a rotation, before the new current file
// has an event, still continues the seq.
func TestJSONLContinuesSeqFromTheNewestRotatedFile(t *testing.T) {
	s, path := openRotating(t, DefaultRotation)
	appendN(t, s, 3)
	s.Close()
	if err := os.Rename(path, filepath.Join(filepath.Dir(path), "audit.1.jsonl")); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenJSONL(path, DefaultRotation)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if seq, err := s2.Append(context.Background(), &Event{Type: TypeLock, Outcome: OutcomeOK}); err != nil || seq != 4 {
		t.Fatalf("seq %d, %v; want 4", seq, err)
	}
}

// A rotation that can't happen fails the append: the log never grows past
// its limit silently, and nothing unrecorded is reported as recorded.
func TestJSONLRotationThatFailsRefusesTheAppend(t *testing.T) {
	s, path := openRotating(t, Rotation{MaxSize: 1, Keep: 2})
	appendN(t, s, 1)
	os.WriteFile(filepath.Join(filepath.Dir(path), "audit.1.jsonl"), nil, 0o600)
	if _, err := s.Append(context.Background(), &Event{Type: TypeLock, Outcome: OutcomeOK}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("append with a blocked rotation: %v", err)
	}
	if lines := logLines(t, path); len(lines) != 1 {
		t.Fatalf("%d events stored, want 1", len(lines))
	}
}

// Two writers, as the service and the host CLI, append and rotate while a
// reader in a third process follows: it sees every event once, in order.
func TestLogFollowSeesEveryWriterAcrossRotations(t *testing.T) {
	rot := Rotation{MaxSize: 600, Keep: 1000}
	service, path := openRotating(t, rot)
	cli, err := OpenJSONL(path, rot)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	l, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.poll = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := follow(t, ctx, l, Filter{}, 0)

	const n = 100
	var wg sync.WaitGroup
	for _, s := range []*JSONL{service, cli} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range n {
				s.Append(ctx, &Event{Type: TypeSecretRead, Outcome: OutcomeOK})
				time.Sleep(100 * time.Microsecond)
			}
		}()
	}
	wg.Wait()
	seqs := got.next(t, 2*n)
	for i, seq := range seqs {
		if seq != uint64(i+1) {
			t.Fatalf("event %d has seq %d: %v", i, seq, seqs)
		}
	}
	if len(rotatedNames(t, path)) < 2 {
		t.Fatal("the test didn't rotate")
	}
}

// If the files after the one Follow was reading are removed before it gets
// to them, events may be lost: Follow says so instead of skipping them.
func TestLogFollowRefusesAGapLeftByRemovedFiles(t *testing.T) {
	s, path := openRotating(t, Rotation{MaxSize: 1, Keep: 1})
	appendN(t, s, 1)
	l, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	l.poll = time.Millisecond
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- l.Follow(context.Background(), Filter{}, 0, func(Event) error {
			<-release
			return nil
		})
	}()
	time.Sleep(20 * time.Millisecond) // Follow is holding event 1
	appendN(t, s, 3)                  // rotates three times, keeping one file
	close(release)
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "after seq 1 may be missing") {
			t.Fatalf("follow ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow didn't notice the gap")
	}
}

// A line still being written is not an event yet: Follow waits for its
// newline instead of skipping it as unreadable.
func TestLogFollowWaitsForAWholeLine(t *testing.T) {
	s, path := openRotating(t, DefaultRotation)
	appendN(t, s, 1)
	l, _ := OpenLog(path)
	l.poll = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := follow(t, ctx, l, Filter{}, 1)
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	defer f.Close()
	line := `{"v":1,"seq":2,"id":"x","ts":"2026-10-08T00:00:00Z","type":"lock","outcome":"ok"}`
	f.WriteString(line[:30])
	select {
	case e := <-got.ch:
		t.Fatalf("delivered half a line: %+v", e)
	case <-time.After(50 * time.Millisecond):
	}
	f.WriteString(line[30:] + "\n")
	if seqs := got.next(t, 1); seqs[0] != 2 {
		t.Fatalf("got %v", seqs)
	}
}

func TestLogFollowRefusesARewrittenFile(t *testing.T) {
	s, path := openRotating(t, DefaultRotation)
	appendN(t, s, 2)
	l, _ := OpenLog(path)
	l.poll = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := follow(t, ctx, l, Filter{}, 0)
	got.next(t, 2)
	os.Truncate(path, 0)
	select {
	case err := <-got.done:
		if err == nil || !strings.Contains(err.Error(), "rewritten") {
			t.Fatalf("follow ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("follow didn't notice the file shrink")
	}
}

func TestOpenLogNeedsAnExistingLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if _, err := OpenLog(path); err == nil || !strings.Contains(err.Error(), "no audit log at "+path) {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "audit.lock")); err == nil {
		t.Fatal("OpenLog created a file")
	}
}

// A follower that falls behind the memory sink's buffer resumes where it
// was, with no gap.
func TestMemoryFollowResumesWhenItFallsBehind(t *testing.T) {
	m := NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Append(ctx, &Event{Type: TypeSecretRead})
	release := make(chan struct{})
	var seqs []uint64
	done := make(chan error, 1)
	go func() {
		done <- m.Follow(ctx, Filter{}, 0, func(e Event) error {
			if e.Seq == 1 {
				<-release
			}
			seqs = append(seqs, e.Seq)
			if len(seqs) == 2*subscriberBuffer+1 {
				cancel()
			}
			return nil
		})
	}()
	time.Sleep(20 * time.Millisecond)
	for range 2 * subscriberBuffer {
		m.Append(ctx, &Event{Type: TypeSecretRead})
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for i, seq := range seqs {
		if seq != uint64(i+1) {
			t.Fatalf("event %d has seq %d", i, seq)
		}
	}
}
