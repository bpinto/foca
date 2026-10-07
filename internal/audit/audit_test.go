package audit

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/identity"
)

type appender interface {
	Append(context.Context, *Event) (uint64, error)
	Query(context.Context, Filter, Page) ([]Event, uint64, error)
	Subscribe(context.Context, Filter, uint64) (<-chan Event, error)
	Close() error
}

func sinks(t *testing.T) map[string]func() appender {
	return map[string]func() appender{
		"memory": func() appender { return NewMemory() },
		"jsonl": func() appender {
			s, err := OpenJSONL(filepath.Join(t.TempDir(), "audit.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	}
}

func TestAppendFillsEnvelopeAndQueries(t *testing.T) {
	for name, mk := range sinks(t) {
		t.Run(name, func(t *testing.T) {
			s := mk()
			defer s.Close()
			ctx := context.Background()
			for i, typ := range []string{TypeSecretRead, TypeApprovalGranted, TypeSecretRead} {
				e := &Event{Type: typ, Outcome: OutcomeOK, Instance: "dev",
					Resource: &Resource{Kind: "secret", ID: "a"}}
				seq, err := s.Append(ctx, e)
				if err != nil {
					t.Fatal(err)
				}
				if seq != uint64(i+1) || e.V != Version || e.ID == "" || e.TS.IsZero() {
					t.Fatalf("envelope not filled: %+v", e)
				}
			}
			got, next, err := s.Query(ctx, Filter{Types: []string{TypeSecretRead}}, Page{})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 || got[0].Seq != 1 || got[1].Seq != 3 || next != 0 {
				t.Fatalf("query: %d events, next=%d", len(got), next)
			}
			page, next, _ := s.Query(ctx, Filter{}, Page{Limit: 2})
			if len(page) != 2 || next != 2 {
				t.Fatalf("paging: %d events next=%d", len(page), next)
			}
			rest, next, _ := s.Query(ctx, Filter{}, Page{AfterSeq: next, Limit: 2})
			if len(rest) != 1 || rest[0].Seq != 3 || next != 0 {
				t.Fatalf("second page: %+v next=%d", rest, next)
			}
		})
	}
}

func TestSubscribeBackfillsThenStreamsWithoutGap(t *testing.T) {
	for name, mk := range sinks(t) {
		t.Run(name, func(t *testing.T) {
			s := mk()
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.Append(ctx, &Event{Type: TypeSecretRead, Outcome: OutcomeOK})
			s.Append(ctx, &Event{Type: TypeSecretRead, Outcome: OutcomeOK})
			ch, err := s.Subscribe(ctx, Filter{}, 1)
			if err != nil {
				t.Fatal(err)
			}
			s.Append(ctx, &Event{Type: TypeLock, Outcome: OutcomeOK})
			var seqs []uint64
			for len(seqs) < 2 {
				select {
				case e := <-ch:
					seqs = append(seqs, e.Seq)
				case <-time.After(2 * time.Second):
					t.Fatalf("timed out; got %v", seqs)
				}
			}
			if seqs[0] != 2 || seqs[1] != 3 {
				t.Fatalf("got %v, want [2 3]", seqs)
			}
		})
	}
}

func TestMemoryFailureIsReported(t *testing.T) {
	m := NewMemory()
	m.SetFailure(errors.New("disk full"))
	if _, err := m.Append(context.Background(), &Event{Type: TypeSecretRead}); err == nil {
		t.Fatal("expected failure")
	}
	if len(m.Events()) != 0 {
		t.Fatal("failed append was stored")
	}
}

func TestJSONLPersistsAcrossReopenAndRepairsPartialLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := OpenJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Append(context.Background(), &Event{Type: TypeSecretRead, Outcome: OutcomeOK})
	s.Close()
	// Simulate a crash mid-write.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"v":1,"seq":2,"ty`)
	f.Close()

	s, err = OpenJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seq, err := s.Append(context.Background(), &Event{Type: TypeLock, Outcome: OutcomeOK})
	if err != nil || seq != 2 {
		t.Fatalf("seq after reopen = %d, %v", seq, err)
	}
	evs, _, _ := s.Query(context.Background(), Filter{}, Page{})
	if len(evs) != 2 || evs[1].Type != TypeLock {
		t.Fatalf("events after repair: %+v", evs)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
}

func TestJSONLRefusesNonPrivateFileAndSymlink(t *testing.T) {
	dir := t.TempDir()
	open := filepath.Join(dir, "open.jsonl")
	os.WriteFile(open, nil, 0o644)
	os.Chmod(open, 0o644)
	if _, err := OpenJSONL(open); err == nil || !strings.Contains(err.Error(), "not private") {
		t.Fatalf("expected refusal, got %v", err)
	}
	target := filepath.Join(dir, "target")
	os.WriteFile(target, nil, 0o600)
	link := filepath.Join(dir, "link.jsonl")
	os.Symlink(target, link)
	if _, err := OpenJSONL(link); err == nil {
		t.Fatal("followed a symlink")
	}
}

func TestVerifiedAndReportedStaySeparateOnTheWire(t *testing.T) {
	e := Event{
		Type:   TypeSecretRead,
		Peer:   &Peer{Verified: &identity.VerifiedPeer{Source: "SO_PEERCRED", PID: 10, Exe: "/usr/bin/ssh"}},
		Client: &Client{Reported: &identity.ClientInfo{PID: 812, Exe: "/bin/gh"}},
	}
	b, _ := json.Marshal(e)
	var m map[string]map[string]map[string]any
	json.Unmarshal(b, &m)
	if m["peer"]["verified"]["exe"] != "/usr/bin/ssh" || m["client"]["reported"]["exe"] != "/bin/gh" {
		t.Fatalf("unexpected shape: %s", b)
	}
	if _, ok := m["client"]["verified"]; ok {
		t.Fatal("client block must not contain a verified field")
	}
}

// A clock in another zone still records UTC: one log never mixes
// "15:33+01:00" with "14:33Z" for the same moment.
func TestEveryStoredTimeIsUTC(t *testing.T) {
	for name, mk := range sinks(t) {
		t.Run(name, func(t *testing.T) {
			s := mk()
			defer s.Close()
			zone := time.FixedZone("WEST", 3600)
			granted := time.Date(2026, 10, 9, 15, 33, 18, 389e6, zone)
			expires := granted.Add(time.Hour)
			e := &Event{Type: TypeApprovalGranted, Outcome: OutcomeOK,
				Approval: &Approval{Mode: ModeFresh, GrantedAt: &granted, ExpiresAt: &expires}}
			if _, err := s.Append(context.Background(), e); err != nil {
				t.Fatal(err)
			}
			if granted.Location() != zone {
				t.Fatal("the caller's time was changed")
			}
			got, _, err := s.Query(context.Background(), Filter{}, Page{})
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(got[0])
			if !strings.Contains(string(b), `"granted_at":"2026-10-09T14:33:18.389Z","expires_at":"2026-10-09T15:33:18.389Z"`) ||
				!strings.HasSuffix(got[0].TS.Format(time.RFC3339Nano), "Z") {
				t.Fatalf("stored times not in UTC: %s", b)
			}
		})
	}
}

// faultyFile fails chosen operations on an otherwise real file.
type faultyFile struct {
	auditFile
	tornWrites int // next n writes store half the bytes, then fail
	failSyncs  int // next n syncs fail
}

func (f *faultyFile) Write(b []byte) (int, error) {
	if f.tornWrites > 0 {
		f.tornWrites--
		n, _ := f.auditFile.Write(b[:len(b)/2])
		return n, errors.New("no space left on device")
	}
	return f.auditFile.Write(b)
}

func (f *faultyFile) Sync() error {
	if f.failSyncs > 0 {
		f.failSyncs--
		return errors.New("input/output error")
	}
	return f.auditFile.Sync()
}

func openFaulty(t *testing.T) (*JSONL, *faultyFile, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	s, err := OpenJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	p := s.sink.p.(*jsonlPersister)
	ff := &faultyFile{auditFile: p.f}
	p.f = ff
	return s, ff, path
}

// A torn write must not swallow the next event, which was reported durable.
func TestJSONLTornWriteDoesNotSwallowNextEvent(t *testing.T) {
	ctx := context.Background()
	s, ff, path := openFaulty(t)
	s.Append(ctx, &Event{Type: "a", Outcome: OutcomeOK})
	ff.tornWrites = 1
	if _, err := s.Append(ctx, &Event{Type: "b", Outcome: OutcomeOK}); err == nil {
		t.Fatal("torn write reported success")
	}
	seq, err := s.Append(ctx, &Event{Type: "c", Outcome: OutcomeOK})
	if err != nil {
		t.Fatalf("append after recovered write: %v", err)
	}
	evs, _, _ := s.Query(ctx, Filter{}, Page{})
	if len(evs) != 2 || evs[1].Type != "c" || evs[1].Seq != seq {
		t.Fatalf("readable events %+v", evs)
	}
	// The torn part was cut off, not left behind as a broken line.
	raw, _ := os.ReadFile(path)
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if !json.Valid([]byte(line)) {
			t.Fatalf("torn line left in the log: %q", line)
		}
	}
	s.Close()

	// After a restart the sequence continues past every event confirmed.
	s2, err := OpenJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if next, _ := s2.Append(ctx, &Event{Type: "d", Outcome: OutcomeOK}); next <= seq {
		t.Fatalf("seq %d reused after restart (last confirmed %d)", next, seq)
	}
}

// After a failed fsync nothing more is accepted, even if sync recovers.
func TestJSONLFailedSyncLatches(t *testing.T) {
	ctx := context.Background()
	s, ff, _ := openFaulty(t)
	defer s.Close()
	ff.failSyncs = 1
	if _, err := s.Append(ctx, &Event{Type: "a", Outcome: OutcomeOK}); err == nil {
		t.Fatal("failed sync reported success")
	}
	if _, err := s.Append(ctx, &Event{Type: "b", Outcome: OutcomeOK}); err == nil {
		t.Fatal("append accepted after a failed sync")
	}
}

// The service and the host CLI each open the log and append concurrently.
// Every event must get its own seq, and seqs must rise in file order.
func TestJSONLSeqUniqueAcrossProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	service, err := OpenJSONL(path)
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	cli, err := OpenJSONL(path) // its own open file, as another process has
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ctx := context.Background()
	const n = 50
	done := make(chan error, 2)
	for _, s := range []*JSONL{service, cli} {
		go func(s *JSONL) {
			for range n {
				if _, err := s.Append(ctx, &Event{Type: TypeSecretRead, Outcome: OutcomeOK}); err != nil {
					done <- err
					return
				}
			}
			done <- nil
		}(s)
	}
	for range 2 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2*n {
		t.Fatalf("%d lines, want %d", len(lines), 2*n)
	}
	var prev uint64
	for i, l := range lines {
		var e Event
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if e.Seq <= prev {
			t.Fatalf("line %d: seq %d after %d", i, e.Seq, prev)
		}
		prev = e.Seq
	}
	// A CLI that opens after the service has written continues from it.
	late, _ := OpenJSONL(path)
	defer late.Close()
	if seq, _ := late.Append(ctx, &Event{Type: TypeSecretAdd, Outcome: OutcomeOK}); seq != prev+1 {
		t.Fatalf("late seq %d, want %d", seq, prev+1)
	}
	if seq, _ := service.Append(ctx, &Event{Type: TypeSecretRead, Outcome: OutcomeOK}); seq != prev+2 {
		t.Fatalf("service seq after CLI write %d, want %d", seq, prev+2)
	}
}
