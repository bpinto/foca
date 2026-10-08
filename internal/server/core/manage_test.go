package core

import (
	"context"
	"errors"
	"strings"
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

// sharedVault: dev reads npm-token in common and all of web, work reads
// github-pat in common, and web reads all of its own vault.
type sharedVault struct {
	svc   *Service
	auth  *fake.Authenticator
	sink  *failOn
	store *memory.Store
	call  Call
}

// exposes answers Instance.Exposes from what an instance reads, by vault.
func exposes(by map[string]static.Exposure) func(vault, id string) bool {
	return func(vault, id string) bool {
		e, ok := by[vault]
		return ok && e.Allows(plugin.SecretMeta{ID: id})
	}
}

func newSharedVault(t *testing.T) *sharedVault {
	t.Helper()
	store := memory.New()
	ctx := context.Background()
	store.Put(ctx, nil, plugin.SecretMeta{ID: "npm-token"}, plugin.SecretValue{Bytes: []byte("npm_secret")})
	store.Put(ctx, nil, plugin.SecretMeta{ID: "github-pat"}, plugin.SecretValue{Bytes: []byte("ghp_secret")})
	dev := &Instance{Name: "dev", Realm: identity.Realm{Kind: "vm", Name: "dev"}, Vaults: []string{"common", "web"},
		Exposes: exposes(map[string]static.Exposure{"common": {IDs: []string{"npm-token"}}, "web": {All: true}})}
	work := &Instance{Name: "work", Realm: identity.Realm{Kind: "vm", Name: "work"}, Vaults: []string{"common"},
		Exposes: exposes(map[string]static.Exposure{"common": {IDs: []string{"github-pat"}}})}
	web := &Instance{Name: "web", Realm: identity.Realm{Kind: "container", Name: "web"}, Vaults: []string{"web"},
		Exposes: exposes(map[string]static.Exposure{"web": {All: true}})}
	auth := fake.New()
	auth.Default = fake.Approve
	sink := &failOn{Memory: audit.NewMemory()}
	svc := New(Options{Authenticator: auth, Audit: sink, PromptTimeout: time.Second, MaxQueue: 1},
		[]*Instance{dev, work, web}, map[string]plugin.SecretStore{"common": store, "web": memory.New()})
	return &sharedVault{svc: svc, auth: auth, sink: sink, store: store,
		call: HostCall("r", "common", identity.VerifiedPeer{Source: "self", PID: 1})}
}

func (v *sharedVault) lastPrompt() string {
	reqs := v.auth.Requests()
	return reqs[len(reqs)-1].Prompt
}

func (v *sharedVault) lastEvent(typ string) audit.Event {
	evs := v.sink.Events()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Type == typ {
			return evs[i]
		}
	}
	return audit.Event{}
}

func ptr[T any](v T) *T { return &v }

// Adding a secret to a vault that realms read whole makes it visible to
// them; the prompt and the audit event say so before and after.
func TestAddNamesEveryRealmThatWillSeeTheSecret(t *testing.T) {
	v := newSharedVault(t)
	ctx := context.Background()
	if _, err := v.svc.AddSecret(ctx, v.call, NewSecret{Vault: "web", ID: "web-key", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if got := v.lastPrompt(); got != "add web-key to vault web, visible in container web and VM dev." {
		t.Fatalf("prompt %q", got)
	}
	if e := v.lastEvent(audit.TypeSecretAdd); e.Params["visible_to"] != "dev,web" || e.Vault != "web" {
		t.Fatalf("event %+v", e)
	}
	if _, err := v.svc.AddSecret(ctx, v.call, NewSecret{ID: "unread", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if got := v.lastPrompt(); got != "add unread to vault common, visible to no instance." {
		t.Fatalf("prompt %q", got)
	}
}

// Two vaults can hold the same id: they are two secrets, named by their vaults.
func TestTheSameIDInTwoVaultsIsTwoSecrets(t *testing.T) {
	v := newSharedVault(t)
	ctx := context.Background()
	if _, err := v.svc.AddSecret(ctx, v.call, NewSecret{Vault: "web", ID: "github-pat", Value: []byte("v")}); err != nil {
		t.Fatal(err)
	}
	if got := v.lastPrompt(); got != "add github-pat to vault web, visible in container web and VM dev." {
		t.Fatalf("prompt %q", got)
	}
	if e := v.lastEvent(audit.TypeSecretAdd); e.Resource.ID != "web:github-pat" || e.Vault != "web" {
		t.Fatalf("event %+v", e)
	}
	if _, v2, err := v.store.Read(ctx, nil, "github-pat"); err != nil || string(v2.Bytes) != "ghp_secret" {
		t.Fatalf("common:github-pat changed: %q %v", v2.Bytes, err)
	}
}

// Editing never changes who reads a secret; the prompt and the event name
// the realms that do.
func TestEditNamesEveryRealmThatReadsIt(t *testing.T) {
	v := newSharedVault(t)
	ctx := context.Background()

	if _, err := v.svc.EditSecret(ctx, v.call, SecretEdit{ID: "github-pat", DisplayName: ptr("GitHub PAT")}); err != nil {
		t.Fatal(err)
	}
	if got := v.lastPrompt(); got != "change GitHub PAT in vault common, visible in VM work." {
		t.Fatalf("prompt %q", got)
	}
	e := v.lastEvent(audit.TypeSecretUpdate)
	if e.Outcome != audit.OutcomeOK || e.Params["visible_to"] != "work" || e.Vault != "common" {
		t.Fatalf("event %+v", e)
	}

	// A value change keeps metadata and is recorded as such, without the value.
	if _, err := v.svc.EditSecret(ctx, v.call, SecretEdit{ID: "github-pat", Value: []byte("ghp_new")}); err != nil {
		t.Fatal(err)
	}
	m, val, _ := v.store.Read(ctx, nil, "github-pat")
	if string(val.Bytes) != "ghp_new" || m.DisplayName != "GitHub PAT" {
		t.Fatalf("after value edit: %+v %q", m, val.Bytes)
	}
	if e := v.lastEvent(audit.TypeSecretUpdate); e.Params["value"] != "changed" {
		t.Fatalf("value change not recorded: %v", e.Params)
	}
	for _, e := range v.sink.Events() {
		if strings.Contains(e.Params["value"], "ghp") {
			t.Fatal("value in audit event")
		}
	}
}
func TestEditValidationAndDenial(t *testing.T) {

	v := newSharedVault(t)
	ctx := context.Background()
	if _, err := v.svc.EditSecret(ctx, v.call, SecretEdit{ID: "github-pat"}); code(err) != protocol.CodeInvalidParams {
		t.Fatalf("empty edit: %v", err)
	}
	if _, err := v.svc.EditSecret(ctx, v.call, SecretEdit{ID: "nope", Value: []byte("x")}); code(err) != protocol.CodeNotFound {
		t.Fatalf("missing: %v", err)
	}
	if _, err := v.svc.EditSecret(ctx, v.call, SecretEdit{ID: "github-pat", DisplayName: ptr("a\nb")}); code(err) != protocol.CodeInvalidParams {
		t.Fatalf("bad display name: %v", err)
	}
	if n := len(v.auth.Requests()); n != 0 {
		t.Fatalf("%d prompts for invalid edits", n)
	}
	v.auth.Default = fake.Deny
	if _, err := v.svc.EditSecret(ctx, v.call, SecretEdit{ID: "github-pat", Value: []byte("x")}); code(err) != protocol.CodeDenied {
		t.Fatalf("denied: %v", err)
	}
	if _, val, _ := v.store.Read(ctx, nil, "github-pat"); string(val.Bytes) != "ghp_secret" {
		t.Fatalf("denied edit changed the value: %q", val.Bytes)
	}
	if e := v.lastEvent(audit.TypeSecretUpdate); e.Outcome != audit.OutcomeDenied {
		t.Fatalf("denial not audited: %+v", e)
	}
}

func TestRemoveNamesRealmsThatLoseIt(t *testing.T) {
	v := newSharedVault(t)
	ctx := context.Background()
	if _, err := v.svc.RemoveSecret(ctx, v.call, "", "npm-token"); err != nil {
		t.Fatal(err)
	}
	if got := v.lastPrompt(); got != "remove npm-token from vault common, hiding it from VM dev." {
		t.Fatalf("prompt %q", got)
	}
	if e := v.lastEvent(audit.TypeSecretRemove); e.Outcome != audit.OutcomeOK || e.Params["hidden_from"] != "dev" {
		t.Fatalf("event %+v", e)
	}
	if _, _, err := v.store.Read(ctx, nil, "npm-token"); !errors.Is(err, plugin.ErrNotFound) {
		t.Fatal("not removed")
	}
	if _, err := v.svc.RemoveSecret(ctx, v.call, "", "npm-token"); code(err) != protocol.CodeNotFound {
		t.Fatalf("second remove: %v", err)
	}
}

// If the change can't be recorded, it is undone.
func TestEditAndRemoveRolledBackWhenAuditFails(t *testing.T) {
	v := newSharedVault(t)
	ctx := context.Background()
	v.sink.set(audit.TypeSecretUpdate)
	_, err := v.svc.EditSecret(ctx, v.call, SecretEdit{ID: "github-pat", DisplayName: ptr("x"), Value: []byte("new")})
	if code(err) != protocol.CodeAuditFailed {
		t.Fatalf("edit: %v", err)
	}
	m, val, _ := v.store.Read(ctx, nil, "github-pat")
	if string(val.Bytes) != "ghp_secret" || m.DisplayName != "" {
		t.Fatalf("edit not undone: %+v %q", m, val.Bytes)
	}

	v.sink.set(audit.TypeSecretRemove)
	if _, err := v.svc.RemoveSecret(ctx, v.call, "", "npm-token"); code(err) != protocol.CodeAuditFailed {
		t.Fatalf("remove: %v", err)
	}
	m, val, err = v.store.Read(ctx, nil, "npm-token")
	if err != nil || string(val.Bytes) != "npm_secret" || m.ID != "npm-token" {
		t.Fatalf("remove not undone: %v %+v %q", err, m, val.Bytes)
	}
}

func TestInitVaultNamesItsUsersAndUndoesUnrecorded(t *testing.T) {
	v := newSharedVault(t)
	ctx := context.Background()
	created, undone := 0, 0
	create := func(context.Context) (string, func(context.Context) error, error) {
		created++
		return "01VAULT", func(context.Context) error { undone++; return nil }, nil
	}
	if err := v.svc.InitVault(ctx, v.call, "common", create); err != nil {
		t.Fatal(err)
	}
	if got := v.lastPrompt(); got != "create vault common for VM dev and VM work." {
		t.Fatalf("prompt %q", got)
	}
	if e := v.lastEvent(audit.TypeVaultInit); e.Params["vault_id"] != "01VAULT" || e.Params["used_by"] != "dev,work" {
		t.Fatalf("event %+v", e)
	}

	v.auth.Default = fake.Deny
	if err := v.svc.InitVault(ctx, v.call, "web", create); code(err) != protocol.CodeDenied || created != 1 {
		t.Fatalf("denied init: %v, created %d", err, created)
	}

	v.auth.Default = fake.Approve
	v.sink.set(audit.TypeVaultInit)
	if err := v.svc.InitVault(ctx, v.call, "web", create); code(err) != protocol.CodeAuditFailed || undone != 1 {
		t.Fatalf("unrecorded init: %v, undone %d", err, undone)
	}
	if err := v.svc.InitVault(ctx, v.call, "nope", create); code(err) != protocol.CodeInvalidParams {
		t.Fatalf("unknown vault: %v", err)
	}
}

// A vault that hasn't been created yet reads as not_initialized, audited.
func TestMissingVaultIsNotInitialized(t *testing.T) {
	h := newHarness(t)
	h.inst.Secrets = static.New("common", h.store, static.Exposure{All: true},
		func(context.Context) ([]byte, func(), error) {
			return nil, nil, plugin.NotInitialized{Vault: "common"}
		})
	ctx := context.Background()
	if _, err := h.svc.ListSecrets(ctx, h.call()); code(err) != protocol.CodeNotInitialized {
		t.Fatalf("list: %v", err)
	}
	if _, err := h.svc.ReadSecrets(ctx, h.call(), []string{"common:github-pat"}); code(err) != protocol.CodeNotInitialized || !strings.Contains(err.Error(), "vault common is not initialized") {
		t.Fatalf("read: %v", err)
	}
	evs := h.sink.Events()
	if len(evs) != 2 || evs[1].Error == nil || evs[1].Error.Code != "not_initialized" {
		t.Fatalf("events %+v", evs)
	}
	if len(h.auth.Requests()) != 0 {
		t.Fatal("prompted for a vault that doesn't exist")
	}
}

// Recovery names every realm of the vault and the protector, records what it
// replaced, and is undone if it can't be recorded.
func TestRecoverVaultNamesItsUsersAndUndoesUnrecorded(t *testing.T) {
	v := newSharedVault(t)
	ctx := context.Background()
	resealed, undone := 0, 0
	reseal := func(context.Context) ([]string, func(context.Context) error, error) {
		resealed++
		return []string{"tpm"}, func(context.Context) error { undone++; return nil }, nil
	}
	if err := v.svc.RecoverVault(ctx, v.call, "common", "tpm", reseal); err != nil {
		t.Fatal(err)
	}
	if got := v.lastPrompt(); got != "seal vault common's key again with tpm using its recovery key, for VM dev and VM work." {
		t.Fatalf("prompt %q", got)
	}
	e := v.lastEvent(audit.TypeVaultRecover)
	if e.Outcome != audit.OutcomeOK || e.Vault != "common" || e.Params["protector"] != "tpm" || e.Params["replaced"] != "tpm" || e.Params["used_by"] != "dev,work" {
		t.Fatalf("event %+v", e)
	}

	v.auth.Default = fake.Deny
	if err := v.svc.RecoverVault(ctx, v.call, "common", "tpm", reseal); code(err) != protocol.CodeDenied || resealed != 1 {
		t.Fatalf("denied recover: %v, resealed %d", err, resealed)
	}
	v.auth.Default = fake.Approve
	v.sink.set(audit.TypeVaultRecover)
	if err := v.svc.RecoverVault(ctx, v.call, "common", "tpm", reseal); code(err) != protocol.CodeAuditFailed || undone != 1 {
		t.Fatalf("unrecorded recover: %v, undone %d", err, undone)
	}
	v.sink.set("")
	failing := func(context.Context) ([]string, func(context.Context) error, error) {
		return nil, nil, errors.New("no TPM")
	}
	if err := v.svc.RecoverVault(ctx, v.call, "common", "tpm", failing); code(err) != protocol.CodeInternal {
		t.Fatalf("failed reseal: %v", err)
	}
	if e := v.lastEvent(audit.TypeVaultRecover); e.Outcome != audit.OutcomeError || !strings.Contains(e.Error.Message, "no TPM") {
		t.Fatalf("failed reseal not audited: %+v", e)
	}
}

// A rekey names every realm of the vault and the protector, records the old
// and new vault ids, and is undone if it can't be recorded.
func TestRekeyVaultNamesItsUsersAndUndoesUnrecorded(t *testing.T) {
	v := newSharedVault(t)
	ctx := context.Background()
	rekeyed, undone := 0, 0
	rekey := func(context.Context) (Rekeyed, func(context.Context) error, error) {
		rekeyed++
		return Rekeyed{OldVaultID: "01OLD", VaultID: "01NEW", Replaced: []string{"tpm"}, Recovery: true},
			func(context.Context) error { undone++; return nil }, nil
	}
	if err := v.svc.RekeyVault(ctx, v.call, "common", "tpm", rekey); err != nil {
		t.Fatal(err)
	}
	if got := v.lastPrompt(); got != "encrypt vault common again under a new key, sealed with tpm, for VM dev and VM work." {
		t.Fatalf("prompt %q", got)
	}
	e := v.lastEvent(audit.TypeVaultRekey)
	if e.Outcome != audit.OutcomeOK || e.Vault != "common" || e.Approval == nil || e.Params["protector"] != "tpm" ||
		e.Params["old_vault_id"] != "01OLD" || e.Params["vault_id"] != "01NEW" || e.Params["replaced"] != "tpm" ||
		e.Params["recovery_key"] != "true" || e.Params["used_by"] != "dev,work" {
		t.Fatalf("event %+v", e)
	}

	v.auth.Default = fake.Deny
	if err := v.svc.RekeyVault(ctx, v.call, "common", "tpm", rekey); code(err) != protocol.CodeDenied || rekeyed != 1 {
		t.Fatalf("denied rekey: %v, rekeyed %d", err, rekeyed)
	}
	v.auth.Default = fake.Approve
	v.sink.set(audit.TypeVaultRekey)
	if err := v.svc.RekeyVault(ctx, v.call, "common", "tpm", rekey); code(err) != protocol.CodeAuditFailed || undone != 1 {
		t.Fatalf("unrecorded rekey: %v, undone %d", err, undone)
	}
	v.sink.set("")
	failing := func(context.Context) (Rekeyed, func(context.Context) error, error) {
		return Rekeyed{}, nil, errors.New("no TPM")
	}
	if err := v.svc.RekeyVault(ctx, v.call, "common", "tpm", failing); code(err) != protocol.CodeInternal {
		t.Fatalf("failed rekey: %v", err)
	}
	if e := v.lastEvent(audit.TypeVaultRekey); e.Outcome != audit.OutcomeError || !strings.Contains(e.Error.Message, "no TPM") {
		t.Fatalf("failed rekey not audited: %+v", e)
	}
}
