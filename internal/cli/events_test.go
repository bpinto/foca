package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/identity"
)

// eventsWorld is a data dir with an audit log, and the env to run foca
// events against it.
type eventsWorld struct {
	t    *testing.T
	vars map[string]string
	log  *audit.JSONL
}

func newEventsWorld(t *testing.T) *eventsWorld {
	t.Helper()
	base := t.TempDir()
	vars := map[string]string{
		"FOCA_CONFIG":      filepath.Join(base, "config.toml"),
		"FOCA_DATA_DIR":    filepath.Join(base, "d"),
		"FOCA_RUNTIME_DIR": filepath.Join(base, "r"),
	}
	os.Mkdir(vars["FOCA_DATA_DIR"], 0o700)
	log, err := audit.OpenJSONL(filepath.Join(vars["FOCA_DATA_DIR"], "audit.jsonl"), audit.Rotation{MaxSize: 1, Keep: 100})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { log.Close() })
	return &eventsWorld{t: t, vars: vars, log: log}
}

func (w *eventsWorld) add(e audit.Event) {
	w.t.Helper()
	if _, err := w.log.Append(context.Background(), &e); err != nil {
		w.t.Fatal(err)
	}
}

func (w *eventsWorld) run(args ...string) (string, string, int) {
	env, out, errb := testEnv(w.t, w.vars)
	code := Main(args, env, "test")
	return out.String(), errb.String(), code
}

// seqs reads query output: the seq of each event, and next_after_seq.
func seqs(t *testing.T, out string) (got []uint64, next uint64) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var m struct {
			Seq          uint64  `json:"seq"`
			NextAfterSeq *uint64 `json:"next_after_seq"`
		}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("not JSON: %q", line)
		}
		if m.NextAfterSeq != nil {
			next = *m.NextAfterSeq
			continue
		}
		if next != 0 {
			t.Fatal("an event after next_after_seq")
		}
		got = append(got, m.Seq)
	}
	return got, next
}

func TestEventsQueryFilters(t *testing.T) {
	w := newEventsWorld(t)
	old := time.Now().Add(-2 * time.Hour).UTC()
	gh := &audit.Resource{Kind: "secret", ID: "common:github-pat"}
	w.add(audit.Event{Type: audit.TypeSecretRead, Outcome: audit.OutcomeOK, Instance: "dev", Resource: gh, TS: old,
		Approval: &audit.Approval{Mode: audit.ModeFresh}})
	w.add(audit.Event{Type: audit.TypeSecretRead, Outcome: audit.OutcomeOK, Instance: "work", Resource: gh,
		Approval: &audit.Approval{Mode: audit.ModeReused}})
	w.add(audit.Event{Type: audit.TypeApprovalDenied, Outcome: audit.OutcomeDenied, Instance: "dev",
		Resources: []audit.Resource{*gh, {Kind: "action", ID: "aws-creds"}}})
	w.add(audit.Event{Type: audit.TypeLock, Outcome: audit.OutcomeOK, Reason: "manual"})

	for _, c := range []struct {
		args []string
		want []uint64
	}{
		{nil, []uint64{1, 2, 3, 4}},
		{[]string{"--type", "secret.read"}, []uint64{1, 2}},
		{[]string{"--type", "secret.read", "--type", "lock"}, []uint64{1, 2, 4}},
		{[]string{"--instance", "dev"}, []uint64{1, 3}},
		{[]string{"-i", "work", "--type", "secret.read"}, []uint64{2}},
		{[]string{"--resource", "secret:common:github-pat"}, []uint64{1, 2, 3}},
		{[]string{"--resource", "action:aws-creds"}, []uint64{3}},
		{[]string{"--outcome", "denied"}, []uint64{3}},
		{[]string{"--mode", "reused"}, []uint64{2}},
		{[]string{"--since", "1h"}, []uint64{2, 3, 4}},
		{[]string{"--until", "1h"}, []uint64{1}},
		{[]string{"--since", old.Format(time.RFC3339Nano), "--until", old.Add(time.Millisecond).Format(time.RFC3339Nano)}, []uint64{1}},
		{[]string{"--after-seq", "2"}, []uint64{3, 4}},
	} {
		out, errs, code := w.run(append([]string{"events", "query"}, c.args...)...)
		if code != 0 {
			t.Fatalf("%v: exit %d: %s", c.args, code, errs)
		}
		if got, next := seqs(t, out); !slices.Equal(got, c.want) || next != 0 {
			t.Errorf("%v: got %v next %d, want %v", c.args, got, next, c.want)
		}
	}
}

// Every event is printed whole, as recorded: what an approval was for and
// which identity level vouched for what.
func TestEventsQueryPrintsWholeEvents(t *testing.T) {
	w := newEventsWorld(t)
	w.add(audit.Event{Type: audit.TypeSecretRead, Outcome: audit.OutcomeOK, Instance: "dev",
		Resource: &audit.Resource{Kind: "secret", ID: "a"}, Origin: audit.OriginClientSocket,
		Approval: &audit.Approval{ID: "ap1", Mode: audit.ModeFresh, Authenticator: "fake"}})
	out, _, _ := w.run("events", "query")
	var e audit.Event
	if err := json.Unmarshal([]byte(out), &e); err != nil {
		t.Fatal(err)
	}
	if e.V != 1 || e.Seq != 1 || e.ID == "" || e.TS.IsZero() || e.Origin != audit.OriginClientSocket ||
		e.Approval == nil || e.Approval.ID != "ap1" || e.Resource.ID != "a" {
		t.Fatalf("printed %s", out)
	}
}

// A verified name is recorded exactly, terminal controls and bidi overrides
// included, but printed escaped, so it can't act on the terminal reading it.
// The JSON still decodes to the recorded name.
func TestEventsPrintNonPrintingRunesEscaped(t *testing.T) {
	w := newEventsWorld(t)
	name := "a\u009b31m\u202egpj.exe\u200b\u2028\u00a0café 日本 😀"
	w.add(audit.Event{Type: audit.TypeSecretRead, Outcome: audit.OutcomeOK,
		Peer: &audit.Peer{Verified: &identity.VerifiedPeer{Name: name}}})
	check := func(out string) {
		t.Helper()
		for _, r := range []string{"\u009b", "\u202e", "\u200b", "\u2028", "\u00a0"} {
			if strings.Contains(out, r) {
				t.Fatalf("%U printed raw: %q", []rune(r)[0], out)
			}
		}
		if !strings.Contains(out, `\u009b`) || !strings.Contains(out, "café 日本 😀") {
			t.Fatalf("printed %q", out)
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &e); err != nil || e.Peer.Verified.Name != name {
			t.Fatalf("decoded %v, %v", e.Peer, err)
		}
	}
	out, _, _ := w.run("events", "query")
	check(out)
	fout, stop := w.follow("--from-seq", "1")
	waitFor(t, fout, []uint64{1})
	stop()
	check(fout.String())
}

func TestEventsQueryPages(t *testing.T) {
	w := newEventsWorld(t)
	for range 5 {
		w.add(audit.Event{Type: audit.TypeSecretRead, Outcome: audit.OutcomeOK})
	}
	var all []uint64
	args := []string{"events", "query", "--limit", "2"}
	for range 5 {
		out, errs, code := w.run(args...)
		if code != 0 {
			t.Fatalf("exit %d: %s", code, errs)
		}
		got, next := seqs(t, out)
		all = append(all, got...)
		if next == 0 {
			break
		}
		args = []string{"events", "query", "--limit", "2", "--after-seq", jsonNumber(next)}
	}
	if !slices.Equal(all, []uint64{1, 2, 3, 4, 5}) {
		t.Fatalf("pages gave %v", all)
	}
}

func jsonNumber(n uint64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// A filter that can't match because of a typo is a usage error, not an
// empty answer.
func TestEventsFilterFlagsAreChecked(t *testing.T) {
	w := newEventsWorld(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"query", "--type", "secret.reads"}, `--type "secret.reads" is not an event type`},
		{[]string{"query", "--outcome", "allowed"}, `--outcome "allowed"`},
		{[]string{"query", "--mode", "cached"}, `--mode "cached"`},
		{[]string{"query", "--resource", "github-pat"}, `--resource "github-pat"`},
		{[]string{"query", "--resource", "vault:x"}, `--resource "vault:x"`},
		{[]string{"query", "--resource", "secret:a b"}, `--resource "secret:a b"`},
		{[]string{"query", "--resource", "secret:github-pat"}, `--resource "secret:github-pat"`},
		{[]string{"query", "--since", "yesterday"}, `--since "yesterday" is neither`},
		{[]string{"query", "--since=-1h"}, `--since "-1h" is neither`},
		{[]string{"query", "--since", "1h", "--until", "2h"}, "is not before --until"},
		{[]string{"query", "--limit", "0"}, "--limit 0 is outside 1..500"},
		{[]string{"query", "--limit", "501"}, "--limit 501 is outside 1..500"},
		{[]string{"query", "--instance", "Dev!"}, `--instance "Dev!"`},
		{[]string{"follow", "--type", "nope"}, `--type "nope"`},
	} {
		_, errs, code := w.run(append([]string{"events"}, c.args...)...)
		if code != 2 || !strings.Contains(errs, c.want) {
			t.Errorf("%v: exit %d, stderr %q; want 2 and %q", c.args, code, errs, c.want)
		}
	}
}

func TestEventsWithoutALog(t *testing.T) {
	w := newEventsWorld(t)
	w.vars["FOCA_DATA_DIR"] = filepath.Join(t.TempDir(), "none")
	for _, cmd := range []string{"query", "follow"} {
		_, errs, code := w.run("events", cmd)
		if code != 1 || !strings.Contains(errs, "no audit log at") {
			t.Errorf("%s: exit %d: %s", cmd, code, errs)
		}
	}
}

// syncBuffer is stdout for a command running in another goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// follow runs foca events follow in the background. stop sends it SIGINT
// and returns its exit code.
func (w *eventsWorld) follow(args ...string) (out *syncBuffer, stop func() int) {
	env, _, errb := testEnv(w.t, w.vars)
	out = &syncBuffer{}
	env.Stdout = out
	sigs := make(chan chan<- os.Signal, 1)
	env.Signals = func(ch chan<- os.Signal) { sigs <- ch }
	code := make(chan int, 1)
	go func() { code <- Main(append([]string{"events", "follow"}, args...), env, "test") }()
	sig := <-sigs
	return out, func() int {
		sig <- syscall.SIGINT
		select {
		case c := <-code:
			if c != 0 {
				w.t.Logf("stderr: %s", errb.String())
			}
			return c
		case <-time.After(5 * time.Second):
			w.t.Fatal("follow didn't stop on SIGINT")
			return -1
		}
	}
}

// waitFor waits until out holds the events with these seqs.
func waitFor(t *testing.T, out *syncBuffer, want []uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := seqs(t, out.String())
		if slices.Equal(got, want) {
			return
		}
		if len(got) > len(want) || time.Now().After(deadline) {
			t.Fatalf("followed %v, want %v", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// --from-seq backfills, then follow goes live with no gap and no repeat,
// across the files rotation starts (this world rotates on every event).
func TestEventsFollowBackfillsThenGoesLive(t *testing.T) {
	w := newEventsWorld(t)
	for range 3 {
		w.add(audit.Event{Type: audit.TypeSecretRead, Outcome: audit.OutcomeOK})
	}
	out, stop := w.follow("--from-seq", "2")
	waitFor(t, out, []uint64{2, 3})
	w.add(audit.Event{Type: audit.TypeLock, Outcome: audit.OutcomeOK})
	w.add(audit.Event{Type: audit.TypeSecretRead, Outcome: audit.OutcomeOK})
	waitFor(t, out, []uint64{2, 3, 4, 5})
	if code := stop(); code != 0 {
		t.Fatalf("exit %d", code)
	}
}

func TestEventsFollowFiltersAndStartsFromNow(t *testing.T) {
	w := newEventsWorld(t)
	w.add(audit.Event{Type: audit.TypeSecretRead, Outcome: audit.OutcomeOK})
	out, stop := w.follow("--type", "lock")
	defer stop()
	// follow may not have opened the log yet; append until it prints.
	deadline := time.Now().Add(5 * time.Second)
	for out.String() == "" && time.Now().Before(deadline) {
		w.add(audit.Event{Type: audit.TypeSecretRead, Outcome: audit.OutcomeOK})
		w.add(audit.Event{Type: audit.TypeLock, Outcome: audit.OutcomeOK})
		time.Sleep(20 * time.Millisecond)
	}
	for _, line := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var e audit.Event
		json.Unmarshal([]byte(line), &e)
		if e.Type != audit.TypeLock || e.Seq == 1 {
			t.Fatalf("followed %s", line)
		}
	}
}

func TestEventsFollowFromSeqZeroIsEverything(t *testing.T) {
	w := newEventsWorld(t)
	w.add(audit.Event{Type: audit.TypeSecretRead, Outcome: audit.OutcomeOK})
	out, stop := w.follow("--from-seq", "0")
	defer stop()
	waitFor(t, out, []uint64{1})
}
