package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/plugins/provider/static"
	"github.com/bpinto/foca/internal/plugins/store/memory"
	"github.com/bpinto/foca/internal/protocol"
)

// failOn wraps a sink and fails appends of chosen event types.
type failOn struct {
	*audit.Memory
	mu    sync.Mutex
	types map[string]bool
}

func (f *failOn) set(types ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.types = map[string]bool{}
	for _, t := range types {
		f.types[t] = true
	}
}

func (f *failOn) Append(ctx context.Context, e *audit.Event) (uint64, error) {
	f.mu.Lock()
	fail := f.types[e.Type]
	f.mu.Unlock()
	if fail {
		return 0, errors.New("disk full")
	}
	return f.Memory.Append(ctx, e)
}

type harness struct {
	svc   *Service
	auth  *fake.Authenticator
	sink  *failOn
	store *memory.Store
	inst  *Instance
}

func newHarness(t *testing.T, decisions ...fake.Decision) *harness {
	t.Helper()
	store := memory.New()
	ctx := context.Background()
	store.Put(ctx, nil, plugin.SecretMeta{ID: "github-pat", DisplayName: "GitHub PAT"}, plugin.SecretValue{Bytes: []byte("ghp_secret")})
	store.Put(ctx, nil, plugin.SecretMeta{ID: "npm-token", DisplayName: "npm token"}, plugin.SecretValue{Bytes: []byte("npm_secret")})
	store.Put(ctx, nil, plugin.SecretMeta{ID: "prod-db"}, plugin.SecretValue{Bytes: []byte("pw")})
	auth := fake.New(decisions...)
	sink := &failOn{Memory: audit.NewMemory()}
	inst := &Instance{
		Name:    "dev",
		Realm:   identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"},
		Vault:   "common",
		Secrets: static.NewVaults(static.New("common", store, static.Exposure{IDs: []string{"github-pat", "npm-token"}}, nil)),
	}
	svc := New(Options{Authenticator: auth, Audit: sink, PromptTimeout: time.Second, MaxQueue: 1, ShowClient: true,
		SkipAncestors: []string{"bash", "zsh", "foca"}},
		[]*Instance{inst}, map[string]plugin.SecretStore{"common": store})
	return &harness{svc: svc, auth: auth, sink: sink, store: store, inst: inst}
}

func (h *harness) call() Call {
	return Call{
		RequestID: "req-1", Origin: audit.OriginClientSocket, Instance: h.inst,
		Peer:     identity.VerifiedPeer{Source: "SO_PEERCRED", PID: 4711, Exe: "/usr/bin/ssh", Name: "ssh", Opaque: true, Realm: h.inst.Realm},
		Reported: &identity.ClientInfo{PID: 812, Exe: "/nix/store/x/bin/aws", Name: "aws", Parents: []identity.Proc{{Name: "bash"}, {Name: "claude"}}},
	}
}

func types(evs []audit.Event) []string {
	var out []string
	for _, e := range evs {
		out = append(out, e.Type+":"+e.Outcome)
	}
	return out
}

func wantTypes(t *testing.T, evs []audit.Event, want ...string) {
	t.Helper()
	got := types(evs)
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("events\n got: %v\nwant: %v", got, want)
	}
}

func code(err error) int {
	var pe *protocol.Error
	if errors.As(err, &pe) {
		return pe.Code
	}
	return 0
}

func TestApproveReadAudit(t *testing.T) {
	h := newHarness(t, fake.Approve)
	got, err := h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:github-pat"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Value) != "ghp_secret" {
		t.Fatalf("got %+v", got)
	}
	evs := h.sink.Events()
	wantTypes(t, evs, "approval.granted:ok", "secret.read:ok")
	read := evs[1]
	if read.Approval == nil || read.Approval.Mode != audit.ModeFresh || read.Approval.ID != evs[0].Approval.ID ||
		read.Approval.Authenticator != "fake" {
		t.Fatalf("read approval %+v", read.Approval)
	}
	if read.Instance != "dev" || read.Vault != "common" || read.Resource.ID != "common:github-pat" {
		t.Fatalf("read event %+v", read)
	}
	// Verified and reported identity are recorded separately.
	if read.Peer.Verified.Exe != "/usr/bin/ssh" || read.Client.Reported.Exe != "/nix/store/x/bin/aws" {
		t.Fatalf("identity blocks %+v %+v", read.Peer.Verified, read.Client.Reported)
	}
	if read.Client.GuestVerified != nil {
		t.Fatal("guest_verified must stay empty without a relay")
	}
	if evs[0].Approval.PromptText == "" {
		t.Fatal("prompt text not recorded")
	}
}

func TestDenyIsAuditedAndReturnsNothing(t *testing.T) {
	h := newHarness(t, fake.Deny)
	got, err := h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:github-pat", "common:npm-token"})
	if code(err) != protocol.CodeDenied || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
	evs := h.sink.Events()
	wantTypes(t, evs, "approval.denied:denied", "secret.read:denied", "secret.read:denied")
	if len(evs[0].Resources) != 2 || evs[1].Reason != "user_denied" {
		t.Fatalf("deny events %+v", evs)
	}
}

func TestBatchShowsOnePromptListingAllNames(t *testing.T) {
	h := newHarness(t, fake.Approve)
	got, err := h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:github-pat", "common:npm-token", "common:github-pat"})
	if err != nil || len(got) != 2 {
		t.Fatalf("got %v, %v", got, err)
	}
	reqs := h.auth.Requests()
	if len(reqs) != 1 || len(reqs[0].Resources) != 2 {
		t.Fatalf("prompts %+v", reqs)
	}
	if !strings.Contains(reqs[0].Prompt, "GitHub PAT and npm token") {
		t.Fatalf("prompt %q", reqs[0].Prompt)
	}
	wantTypes(t, h.sink.Events(), "approval.granted:ok", "secret.read:ok", "secret.read:ok")
}

func TestAuditFailureRefusesAccess(t *testing.T) {
	for _, failType := range []string{audit.TypeApprovalGranted, audit.TypeSecretRead} {
		t.Run(failType, func(t *testing.T) {
			h := newHarness(t, fake.Approve)
			h.sink.set(failType)
			got, err := h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:github-pat"})
			if code(err) != protocol.CodeAuditFailed || got != nil {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
	t.Run("list", func(t *testing.T) {
		h := newHarness(t)
		h.sink.set(audit.TypeSecretList)
		if _, err := h.svc.ListSecrets(context.Background(), h.call()); code(err) != protocol.CodeAuditFailed {
			t.Fatalf("list: %v", err)
		}
	})
}

func TestUnexposedLooksLikeMissingButIsAuditedWithReason(t *testing.T) {
	h := newHarness(t, fake.Approve)
	_, errUnexposed := h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:prod-db"})
	_, errMissing := h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:nope"})
	if code(errUnexposed) != protocol.CodeNotFound || code(errMissing) != protocol.CodeNotFound {
		t.Fatalf("errors %v / %v", errUnexposed, errMissing)
	}
	if strings.Replace(errUnexposed.Error(), "prod-db", "X", 1) != strings.Replace(errMissing.Error(), "nope", "X", 1) {
		t.Fatalf("messages differ: %q vs %q", errUnexposed, errMissing)
	}
	if len(h.auth.Requests()) != 0 {
		t.Fatal("prompted for a secret that doesn't resolve")
	}
	evs := h.sink.Events()
	wantTypes(t, evs, "secret.read:not_found", "secret.read:not_found")
	if evs[0].Reason != "not_exposed" || evs[1].Reason != "unknown" {
		t.Fatalf("reasons %q %q", evs[0].Reason, evs[1].Reason)
	}
}

func TestPartialBatchNeverPrompts(t *testing.T) {
	h := newHarness(t, fake.Approve)
	_, err := h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:github-pat", "common:prod-db"})
	if code(err) != protocol.CodeNotFound || len(h.auth.Requests()) != 0 {
		t.Fatalf("err %v, prompts %d", err, len(h.auth.Requests()))
	}
}

func TestTimeoutAndUnavailable(t *testing.T) {
	h := newHarness(t, fake.Hang)
	h.svc.opts.PromptTimeout = 50 * time.Millisecond
	_, err := h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:github-pat"})
	if code(err) != protocol.CodeTimeout {
		t.Fatalf("timeout: %v", err)
	}
	wantTypes(t, h.sink.Events(), "approval.timeout:denied", "secret.read:denied")

	h = newHarness(t, fake.Approve)
	h.auth.SetUnavailable(true)
	_, err = h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:github-pat"})
	if code(err) != protocol.CodeAuthUnavailable {
		t.Fatalf("unavailable: %v", err)
	}
	wantTypes(t, h.sink.Events(), "approval.denied:error", "secret.read:denied")
}

func TestQueueFullIsBusyAndAudited(t *testing.T) {
	h := newHarness(t)
	h.auth.Default = fake.Hang
	h.auth.Started = make(chan plugin.ApprovalRequest, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// MaxQueue=1: one open prompt + one waiting; the third is refused.
	for i := 0; i < 2; i++ {
		go h.svc.ReadSecrets(ctx, h.call(), []string{"common:github-pat"})
	}
	<-h.auth.Started
	deadline := time.Now().Add(2 * time.Second)
	for h.svc.queue.pending() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	_, err := h.svc.ReadSecrets(ctx, h.call(), []string{"common:github-pat"})
	if code(err) != protocol.CodeBusy {
		t.Fatalf("third request: %v", err)
	}
	found := false
	for _, e := range h.sink.Events() {
		if e.Type == audit.TypeRequestRejected && e.Reason == "busy" {
			found = true
		}
	}
	if !found {
		t.Fatal("busy rejection not audited")
	}
}

func TestAddSecretRequiresApprovalAndValidates(t *testing.T) {
	h := newHarness(t, fake.Deny, fake.Approve)
	c := h.call()
	c.Origin = audit.OriginHostCLI
	ns := NewSecret{ID: "new-token", DisplayName: "New token", Value: []byte("v")}
	if _, err := h.svc.AddSecret(context.Background(), c, ns); code(err) != protocol.CodeDenied {
		t.Fatalf("denied add: %v", err)
	}
	if _, _, err := h.store.Read(context.Background(), nil, "new-token"); err == nil {
		t.Fatal("denied add was stored")
	}
	if _, err := h.svc.AddSecret(context.Background(), c, ns); err != nil {
		t.Fatal(err)
	}
	if _, err := h.svc.AddSecret(context.Background(), c, ns); code(err) != protocol.CodeInvalidParams {
		t.Fatalf("duplicate add: %v", err)
	}
	bad := ns
	bad.ID, bad.DisplayName = "other", "evil‮eman"
	if _, err := h.svc.AddSecret(context.Background(), c, bad); code(err) != protocol.CodeInvalidParams {
		t.Fatalf("bidi display name: %v", err)
	}
	wantTypes(t, h.sink.Events(), "approval.denied:denied", "secret.add:denied", "approval.granted:ok", "secret.add:ok")
}

func TestAddSecretRolledBackWhenAuditFails(t *testing.T) {
	h := newHarness(t, fake.Approve)
	h.sink.set(audit.TypeSecretAdd)
	_, err := h.svc.AddSecret(context.Background(), h.call(), NewSecret{ID: "x", Value: []byte("v")})
	if code(err) != protocol.CodeAuditFailed {
		t.Fatalf("got %v", err)
	}
	if _, _, err := h.store.Read(context.Background(), nil, "x"); err == nil {
		t.Fatal("unrecorded secret left in store")
	}
}

// A batch whose names can't all be shown is refused before any prompt.
func TestOversizedBatchRefusedBeforePrompting(t *testing.T) {
	h := newHarness(t, fake.Approve)
	var names []string
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("tok-%02d", i)
		h.store.Put(context.Background(), nil, plugin.SecretMeta{ID: id, DisplayName: "Token number " + id}, plugin.SecretValue{Bytes: []byte("v")})
		names = append(names, "common:"+id)
	}
	h.inst.Secrets = static.NewVaults(static.New("common", h.store, static.Exposure{All: true}, nil))
	_, err := h.svc.ReadSecrets(context.Background(), h.call(), names)
	var pe *protocol.Error
	if !errors.As(err, &pe) || pe.Code != protocol.CodeInvalidParams {
		t.Fatalf("want invalid_params, got %v", err)
	}
	if n := len(h.auth.Requests()); n != 0 {
		t.Fatalf("%d prompts shown", n)
	}
	evs := h.sink.Events()
	last := evs[len(evs)-1]
	if last.Type != audit.TypeRequestRejected || last.Reason != "prompt_too_long" || len(last.Resources) != 20 {
		t.Fatalf("audit %+v", last)
	}
}

// With several instances, one can't hold every prompt slot.
func TestOneInstanceCantFillTheWholeQueue(t *testing.T) {
	h := newHarness(t)
	other := &Instance{Name: "work", Realm: identity.Realm{Kind: "vm", Name: "work", Peers: "opaque"}, Vault: "common",
		Secrets: static.NewVaults(static.New("common", h.store, static.Exposure{All: true}, nil))}
	auth := fake.New()
	auth.Default = fake.Hang
	auth.Started = make(chan plugin.ApprovalRequest, 8)
	// max_queue 3: four slots, at most two per instance.
	svc := New(Options{Authenticator: auth, Audit: h.sink, PromptTimeout: 5 * time.Second, MaxQueue: 3, ShowClient: true},
		[]*Instance{h.inst, other}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dev := h.call()
	for i := 0; i < 2; i++ {
		go svc.ReadSecrets(ctx, dev, []string{"common:github-pat"})
	}
	<-auth.Started
	for deadline := time.Now().Add(2 * time.Second); svc.queue.pending() < 2 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := svc.ReadSecrets(ctx, dev, []string{"common:github-pat"}); code(err) != protocol.CodeBusy {
		t.Fatalf("dev's third request: %v", err)
	}
	work := dev
	work.Instance = other
	done := make(chan error, 1)
	wctx, wcancel := context.WithCancel(ctx)
	go func() { _, err := svc.ReadSecrets(wctx, work, []string{"common:github-pat"}); done <- err }()
	for deadline := time.Now().Add(2 * time.Second); svc.queue.pending() < 3 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	if svc.queue.pending() != 3 {
		t.Fatal("work was kept out of the queue by dev")
	}
	wcancel()
	if err := <-done; code(err) != protocol.CodeTimeout {
		t.Fatalf("cancelled wait: %v", err)
	}
}

// One instance among several holds at most half the slots (one open prompt
// plus max_queue waiting), and always at least one.
func TestQueueShareIsAtMostHalf(t *testing.T) {
	for _, c := range []struct{ maxQueue, instances, want int }{
		{4, 2, 2}, {3, 2, 2}, {1, 2, 1}, {0, 2, 1}, {4, 1, 5}, {7, 3, 4},
	} {
		if got := newPromptQueue(c.maxQueue, c.instances).maxPer; got != c.want {
			t.Errorf("max_queue %d, %d instances: %d slots per instance, want %d", c.maxQueue, c.instances, got, c.want)
		}
	}
}

// A burst of rejections becomes one event plus one count, never one per try.
func TestRejectionBurstsAreCoalesced(t *testing.T) {
	h := newHarness(t)
	now := time.Unix(1000, 0)
	h.svc.opts.Now = func() time.Time { return now }
	ctx := context.Background()
	rej := func(reason string) uint64 {
		seq, err := h.svc.RecordRejection(ctx, &audit.Event{Type: audit.TypeRequestRejected, Outcome: audit.OutcomeRejected, Instance: "dev", Reason: reason})
		if err != nil {
			t.Fatal(err)
		}
		return seq
	}
	first := rej("busy")
	for i := 0; i < 99; i++ {
		if seq := rej("busy"); seq != first {
			t.Fatalf("suppressed rejection points at seq %d, want %d", seq, first)
		}
	}
	rej("forbidden_on_socket") // another reason has its own window
	now = now.Add(RejectWindow)
	rej("busy") // next window: flushes the count, then records
	if err := h.svc.FlushRejections(ctx); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range h.sink.Events() {
		got = append(got, fmt.Sprintf("%s/%d", e.Reason, e.Count))
	}
	want := "busy/0 forbidden_on_socket/0 busy/99 busy/0"
	if strings.Join(got, " ") != want {
		t.Fatalf("events %v, want %s", got, want)
	}
}

// A client that hangs up after approval gets nothing decrypted, and the
// outcome is still recorded.
func TestCancelledAfterApprovalServesNothing(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	h.svc.opts.Authenticator = hangUpThenApprove{cancel}
	_, err := h.svc.ReadSecrets(ctx, h.call(), []string{"common:github-pat"})
	if code(err) != protocol.CodeTimeout {
		t.Fatalf("got %v", err)
	}
	evs := h.sink.Events()
	last := evs[len(evs)-1]
	if last.Type != audit.TypeSecretRead || last.Outcome != audit.OutcomeError || last.Reason != "cancelled" {
		t.Fatalf("last event %+v", last)
	}
}

// hangUpThenApprove approves, but only after the client has gone.
type hangUpThenApprove struct{ hangUp context.CancelFunc }

func (hangUpThenApprove) Name() string                             { return "fake" }
func (hangUpThenApprove) Available(context.Context) (bool, string) { return true, "" }
func (a hangUpThenApprove) Approve(context.Context, plugin.ApprovalRequest) (plugin.ApprovalResult, error) {
	a.hangUp()
	return plugin.ApprovalResult{Approved: true, Method: "fake"}, nil
}

// brokenStore fails List or Delete on demand.
type brokenStore struct {
	*memory.Store
	failList, failDelete bool
}

func (b *brokenStore) List(ctx context.Context, dek []byte) ([]plugin.SecretMeta, error) {
	if b.failList {
		return nil, errors.New("vault unreadable")
	}
	return b.Store.List(ctx, dek)
}

func (b *brokenStore) Delete(ctx context.Context, dek []byte, id string) error {
	if b.failDelete {
		return errors.New("vault read-only")
	}
	return b.Store.Delete(ctx, dek, id)
}

func TestAddSecretHandlesStoreErrors(t *testing.T) {
	h := newHarness(t)
	h.auth.Default = fake.Approve
	bs := &brokenStore{Store: h.store, failList: true}
	h.svc.stores["common"] = bs
	ctx := context.Background()

	// The duplicate check can't run, so the add doesn't either.
	_, err := h.svc.AddSecret(ctx, h.call(), NewSecret{ID: "github-pat", Value: []byte("overwritten")})
	if code(err) != protocol.CodeInternal {
		t.Fatalf("list failure: %v", err)
	}
	if _, v, _ := h.store.Read(ctx, nil, "github-pat"); string(v.Bytes) != "ghp_secret" {
		t.Fatalf("existing secret overwritten: %q", v.Bytes)
	}
	if n := len(h.auth.Requests()); n != 0 {
		t.Fatalf("%d prompts for an add that can't be checked", n)
	}

	// Audit and rollback both fail: the error names what was left behind.
	bs.failList, bs.failDelete = false, true
	h.sink.set(audit.TypeSecretAdd)
	_, err = h.svc.AddSecret(ctx, h.call(), NewSecret{ID: "x", Value: []byte("v")})
	if code(err) != protocol.CodeAuditFailed || !strings.Contains(err.Error(), `secret "x" is stored`) {
		t.Fatalf("rollback failure: %v", err)
	}
}
