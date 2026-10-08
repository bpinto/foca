package core

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/protocol"
	"github.com/bpinto/foca/internal/secretname"
)

// Host operations: add, edit, remove and init. They run in the host CLI
// process, never behind a socket. The CLI builds its own Service over the
// same authenticator, stores and audit log, and holds the vault's write lock
// for the whole operation, so nothing changes between the checks here and
// the write.
//
// Each one follows the same order: check, approve, write, audit. If the
// audit write fails, the change is undone, so nothing exists that the audit
// log doesn't know about.

// HostCall is the Call for an operation the host CLI runs on vault. self is
// the CLI process itself, as the kernel reports it.
func HostCall(requestID, vault string, self identity.VerifiedPeer) Call {
	realm := identity.Realm{Kind: identity.RealmHost, Name: "cli", Peers: identity.PeersDirect}
	self.Realm = realm
	return Call{RequestID: requestID, Origin: audit.OriginHostCLI, Peer: self,
		Instance: &Instance{Realm: realm, Vault: vault}}
}

// inVault returns c with its instance pointed at vault, so prompts and audit
// events name the vault being changed.
func inVault(c Call, vault string) Call {
	inst := *c.Instance
	inst.Vault = vault
	c.Instance = &inst
	return c
}

// withKey runs fn with vault's data key, zeroed afterwards.
func (s *Service) withKey(ctx context.Context, vault string, fn func(dek []byte) error) error {
	keys := s.opts.Keys[vault]
	if keys == nil {
		return fn(nil)
	}
	dek, release, err := keys(ctx)
	if err != nil {
		return err
	}
	defer release()
	return fn(dek)
}

func (s *Service) store(c Call, vault string) (plugin.SecretStore, *protocol.Error) {
	st, ok := s.stores[vault]
	if !ok {
		return nil, s.fail(c, protocol.CodeInvalidParams, 0, "unknown vault %q", vault)
	}
	return st, nil
}

// find returns the metadata of id in vault.
func (s *Service) find(ctx context.Context, store plugin.SecretStore, vault, id string) (plugin.SecretMeta, bool, error) {
	var metas []plugin.SecretMeta
	err := s.withKey(ctx, vault, func(dek []byte) (err error) {
		metas, err = store.List(ctx, dek)
		return err
	})
	if err != nil {
		return plugin.SecretMeta{}, false, err
	}
	for _, m := range metas {
		if m.ID == id {
			return m, true, nil
		}
	}
	return plugin.SecretMeta{}, false, nil
}

// usersOf returns the instances (realms and names) configured to use vault.
func (s *Service) usersOf(vault string) ([]identity.Realm, []string) {
	var realms []identity.Realm
	var names []string
	for _, inst := range s.instances {
		if slices.Contains(inst.Vaults, vault) {
			realms = append(realms, inst.Realm)
			names = append(names, inst.Name)
		}
	}
	slices.Sort(names)
	slices.SortFunc(realms, func(a, b identity.Realm) int { return strings.Compare(a.Kind+a.Name, b.Kind+b.Name) })
	return realms, names
}

// recordOrUndo appends e. If that fails, it runs undo and reports what, if
// anything, was left behind.
func (s *Service) recordOrUndo(ctx context.Context, c Call, e *audit.Event, what string, undo func(context.Context) error) error {
	if _, aerr := s.record(ctx, c, e); aerr != nil {
		if uerr := undo(context.WithoutCancel(ctx)); uerr != nil {
			// Nothing more can be recorded. Say plainly what was left
			// behind, so the operator can fix it.
			return s.fail(c, protocol.CodeAuditFailed, 0,
				"could not record the change, and could not undo it (%v): %s without an audit record", uerr, what)
		}
		return aerr
	}
	return nil
}

func validMeta(displayName, description string) error {
	if err := validLabel("display_name", displayName, 64); err != nil {
		return err
	}
	if err := validLabel("description", description, 512); err != nil {
		return err
	}
	return nil
}

// Change reports which instances see a secret after a host operation, and
// which ones stopped seeing it, by instance name.
type Change struct {
	VisibleTo  []string
	HiddenFrom []string
}

// ---- secret.add ----

type NewSecret struct {
	Vault       string
	ID          string
	DisplayName string
	Description string
	Value       []byte
}

func (s *Service) AddSecret(ctx context.Context, c Call, ns NewSecret) (Change, error) {
	if ns.Vault == "" {
		ns.Vault = c.Instance.Vault
	}
	store, perr := s.store(c, ns.Vault)
	if perr != nil {
		return Change{}, perr
	}
	if !validSecretID(ns.ID) {
		return Change{}, s.fail(c, protocol.CodeInvalidParams, 0, "invalid secret name %q", ns.ID)
	}
	if err := validMeta(ns.DisplayName, ns.Description); err != nil {
		return Change{}, s.fail(c, protocol.CodeInvalidParams, 0, "%v", err)
	}
	if len(ns.Value) == 0 {
		return Change{}, s.fail(c, protocol.CodeInvalidParams, 0, "value must not be empty")
	}
	c = inVault(c, ns.Vault)
	_, exists, err := s.find(ctx, store, ns.Vault, ns.ID)
	if err != nil {
		// Without the list we can't rule out overwriting a secret.
		return Change{}, s.internal(ctx, c, audit.TypeSecretAdd, secretname.Join(ns.Vault, ns.ID), err)
	}
	if exists {
		return Change{}, s.fail(c, protocol.CodeInvalidParams, 0, "secret %q already exists in vault %q", ns.ID, ns.Vault)
	}

	ref := plugin.ResourceRef{Kind: "secret", ID: secretname.Join(ns.Vault, ns.ID), Vault: ns.Vault, Display: displayOr(ns.DisplayName, ns.ID)}
	meta := plugin.SecretMeta{ID: ns.ID, DisplayName: ns.DisplayName, Description: ns.Description}
	// The prompt names every realm that can read the secret once it exists.
	visible, visibleNames := s.visibleTo(ns.Vault, ns.ID)
	appr, err := s.approveVisible(ctx, c, "secret.add", []plugin.ResourceRef{ref}, audit.TypeSecretAdd, visible, nil)
	if err != nil {
		return Change{}, err
	}
	err = s.withKey(ctx, ns.Vault, func(dek []byte) error {
		return store.Put(ctx, dek, meta, plugin.SecretValue{Bytes: ns.Value})
	})
	if err != nil {
		return Change{}, s.internal(ctx, c, audit.TypeSecretAdd, secretname.Join(ns.Vault, ns.ID), err)
	}
	e := s.Event(c, audit.TypeSecretAdd, audit.OutcomeOK)
	e.Resource = &audit.Resource{Kind: "secret", ID: secretname.Join(ns.Vault, ns.ID)}
	e.Params = map[string]string{"visible_to": strings.Join(visibleNames, ",")}
	e.Approval = appr
	if err := s.recordOrUndo(ctx, c, e, "secret "+quote(ns.ID)+" is stored in vault "+quote(ns.Vault)+"; remove it",
		func(ctx context.Context) error {
			return s.withKey(ctx, ns.Vault, func(dek []byte) error { return store.Delete(ctx, dek, ns.ID) })
		}); err != nil {
		return Change{}, err
	}
	return Change{VisibleTo: visibleNames}, nil
}

// ---- secret.update ----

// SecretEdit changes a secret. Nil fields are kept as they are.
type SecretEdit struct {
	Vault       string
	ID          string
	DisplayName *string
	Description *string
	Value       []byte
}

func (s *Service) EditSecret(ctx context.Context, c Call, ed SecretEdit) (Change, error) {
	if ed.Vault == "" {
		ed.Vault = c.Instance.Vault
	}
	store, perr := s.store(c, ed.Vault)
	if perr != nil {
		return Change{}, perr
	}
	if !validSecretID(ed.ID) {
		return Change{}, s.fail(c, protocol.CodeInvalidParams, 0, "invalid secret name %q", ed.ID)
	}
	if ed.DisplayName == nil && ed.Description == nil && ed.Value == nil {
		return Change{}, s.fail(c, protocol.CodeInvalidParams, 0, "nothing to change")
	}
	if ed.Value != nil && len(ed.Value) == 0 {
		return Change{}, s.fail(c, protocol.CodeInvalidParams, 0, "value must not be empty")
	}
	c = inVault(c, ed.Vault)
	old, exists, err := s.find(ctx, store, ed.Vault, ed.ID)
	if err != nil {
		return Change{}, s.internal(ctx, c, audit.TypeSecretUpdate, secretname.Join(ed.Vault, ed.ID), err)
	}
	if !exists {
		return Change{}, s.fail(c, protocol.CodeNotFound, 0, "secret %q not found in vault %q", ed.ID, ed.Vault)
	}
	meta := old
	if ed.DisplayName != nil {
		meta.DisplayName = *ed.DisplayName
	}
	if ed.Description != nil {
		meta.Description = *ed.Description
	}
	if err := validMeta(meta.DisplayName, meta.Description); err != nil {
		return Change{}, s.fail(c, protocol.CodeInvalidParams, 0, "%v", err)
	}

	// The prompt names every realm that reads the secret.
	visible, visibleNames := s.visibleTo(ed.Vault, ed.ID)
	ref := plugin.ResourceRef{Kind: "secret", ID: secretname.Join(ed.Vault, ed.ID), Vault: ed.Vault, Display: meta.Display()}
	appr, err := s.approveVisible(ctx, c, "secret.update", []plugin.ResourceRef{ref}, audit.TypeSecretUpdate, visible, nil)
	if err != nil {
		return Change{}, err
	}

	var oldValue plugin.SecretValue
	defer oldValue.Zero()
	err = s.withKey(ctx, ed.Vault, func(dek []byte) error {
		_, v, err := store.Read(ctx, dek, ed.ID)
		if err != nil {
			return err
		}
		oldValue = v
		value := v
		if ed.Value != nil {
			value = plugin.SecretValue{Bytes: ed.Value}
		}
		return store.Put(ctx, dek, meta, value)
	})
	if err != nil {
		return Change{}, s.internal(ctx, c, audit.TypeSecretUpdate, secretname.Join(ed.Vault, ed.ID), err)
	}
	e := s.Event(c, audit.TypeSecretUpdate, audit.OutcomeOK)
	e.Resource = &audit.Resource{Kind: "secret", ID: secretname.Join(ed.Vault, ed.ID)}
	e.Params = map[string]string{"visible_to": strings.Join(visibleNames, ",")}
	if ed.Value != nil {
		e.Params["value"] = "changed"
	}
	e.Approval = appr
	if err := s.recordOrUndo(ctx, c, e, "secret "+quote(ed.ID)+" in vault "+quote(ed.Vault)+" was changed",
		func(ctx context.Context) error {
			return s.withKey(ctx, ed.Vault, func(dek []byte) error { return store.Put(ctx, dek, old, oldValue) })
		}); err != nil {
		return Change{}, err
	}
	return Change{VisibleTo: visibleNames}, nil
}

// ---- secret.remove ----

func (s *Service) RemoveSecret(ctx context.Context, c Call, vault, id string) (Change, error) {
	if vault == "" {
		vault = c.Instance.Vault
	}
	store, perr := s.store(c, vault)
	if perr != nil {
		return Change{}, perr
	}
	if !validSecretID(id) {
		return Change{}, s.fail(c, protocol.CodeInvalidParams, 0, "invalid secret name %q", id)
	}
	c = inVault(c, vault)
	meta, exists, err := s.find(ctx, store, vault, id)
	if err != nil {
		return Change{}, s.internal(ctx, c, audit.TypeSecretRemove, secretname.Join(vault, id), err)
	}
	if !exists {
		return Change{}, s.fail(c, protocol.CodeNotFound, 0, "secret %q not found in vault %q", id, vault)
	}
	hidden, hiddenNames := s.visibleTo(vault, id)
	ref := plugin.ResourceRef{Kind: "secret", ID: secretname.Join(vault, id), Vault: vault, Display: meta.Display()}
	appr, err := s.approveVisible(ctx, c, "secret.remove", []plugin.ResourceRef{ref}, audit.TypeSecretRemove, nil, hidden)
	if err != nil {
		return Change{}, err
	}

	var oldValue plugin.SecretValue
	defer oldValue.Zero()
	err = s.withKey(ctx, vault, func(dek []byte) error {
		_, v, err := store.Read(ctx, dek, id)
		if err != nil {
			return err
		}
		oldValue = v
		return store.Delete(ctx, dek, id)
	})
	if err != nil {
		return Change{}, s.internal(ctx, c, audit.TypeSecretRemove, secretname.Join(vault, id), err)
	}
	e := s.Event(c, audit.TypeSecretRemove, audit.OutcomeOK)
	e.Resource = &audit.Resource{Kind: "secret", ID: secretname.Join(vault, id)}
	e.Params = map[string]string{"hidden_from": strings.Join(hiddenNames, ",")}
	e.Approval = appr
	if err := s.recordOrUndo(ctx, c, e, "secret "+quote(id)+" was removed from vault "+quote(vault),
		func(ctx context.Context) error {
			return s.withKey(ctx, vault, func(dek []byte) error { return store.Put(ctx, dek, meta, oldValue) })
		}); err != nil {
		return Change{}, err
	}
	return Change{HiddenFrom: hiddenNames}, nil
}

// ---- vault.init ----

// VaultCreator creates the vault once approval is given. undo destroys it
// again if the audit record can't be written.
type VaultCreator func(ctx context.Context) (vaultID string, undo func(context.Context) error, err error)

// InitVault creates vault after approval. The caller has already checked
// that it doesn't exist yet, under the vault's write lock.
func (s *Service) InitVault(ctx context.Context, c Call, vault string, create VaultCreator) error {
	if _, perr := s.store(c, vault); perr != nil {
		return perr
	}
	c = inVault(c, vault)
	users, userNames := s.usersOf(vault)
	ref := plugin.ResourceRef{Kind: "vault", ID: vault, Display: vault}
	appr, err := s.approveVisible(ctx, c, "vault.init", []plugin.ResourceRef{ref}, audit.TypeVaultInit, users, nil)
	if err != nil {
		return err
	}
	id, undo, err := create(ctx)
	if err != nil {
		e := s.Event(c, audit.TypeVaultInit, audit.OutcomeError)
		e.Resource = &audit.Resource{Kind: "vault", ID: vault}
		e.Error = &audit.ErrorInfo{Code: "internal", Message: err.Error()}
		seq, aerr := s.record(ctx, c, e)
		if aerr != nil {
			return aerr
		}
		return s.fail(c, protocol.CodeInternal, seq, "could not create vault %s: %v", vault, err)
	}
	e := s.Event(c, audit.TypeVaultInit, audit.OutcomeOK)
	e.Resource = &audit.Resource{Kind: "vault", ID: vault}
	e.Params = map[string]string{"vault_id": id, "used_by": strings.Join(userNames, ",")}
	e.Approval = appr
	return s.recordOrUndo(ctx, c, e, "vault "+quote(vault)+" was created", undo)
}

func displayOr(d, id string) string {
	if d != "" {
		return d
	}
	return id
}

func quote(s string) string { return `"` + s + `"` }

// ---- vault.recover ----

// VaultResealer seals the vault's key again once approval is given, and
// returns the types of the key slots it replaced. undo puts the vault back
// as it was if the audit record can't be written.
type VaultResealer func(ctx context.Context) (replaced []string, undo func(context.Context) error, err error)

// RecoverVault seals vault's key again with protector after approval, using
// its recovery key, after the boot state a TPM key is bound to
// changed. The caller has already checked the key, under the vault's
// write lock.
func (s *Service) RecoverVault(ctx context.Context, c Call, vault, protector string, reseal VaultResealer) error {
	if _, perr := s.store(c, vault); perr != nil {
		return perr
	}
	c = inVault(c, vault)
	users, userNames := s.usersOf(vault)
	a := ask{op: "vault.recover", accessType: audit.TypeVaultRecover,
		refs: []plugin.ResourceRef{{Kind: "vault", ID: vault, Display: vault}}, visible: users,
		params: map[string]string{"protector": protector}}
	release, err := s.admit(ctx, c, a)
	if err != nil {
		return err
	}
	appr, err := s.ask(ctx, c, a, release)
	if err != nil {
		return err
	}
	replaced, undo, err := reseal(ctx)
	if err != nil {
		e := s.Event(c, audit.TypeVaultRecover, audit.OutcomeError)
		e.Resource = &audit.Resource{Kind: "vault", ID: vault}
		e.Error = &audit.ErrorInfo{Code: "internal", Message: err.Error()}
		seq, aerr := s.record(ctx, c, e)
		if aerr != nil {
			return aerr
		}
		return s.fail(c, protocol.CodeInternal, seq, "could not recover vault %s: %v", vault, err)
	}
	e := s.Event(c, audit.TypeVaultRecover, audit.OutcomeOK)
	e.Resource = &audit.Resource{Kind: "vault", ID: vault}
	e.Params = map[string]string{"protector": protector, "replaced": strings.Join(replaced, ","), "used_by": strings.Join(userNames, ",")}
	e.Approval = appr
	return s.recordOrUndo(ctx, c, e, "vault "+quote(vault)+" was sealed again with "+protector, undo)
}

// ---- vault.rekey ----

// Rekeyed is what a rekey changed, for the audit record.
type Rekeyed struct {
	OldVaultID, VaultID string
	// Replaced are the protector slots the old file had.
	Replaced []string
	// Recovery reports whether the new file has a recovery key.
	Recovery bool
}

// VaultRekeyer encrypts the vault again under a new key once approval is
// given. undo puts the old vault back if the audit record can't be written.
type VaultRekeyer func(ctx context.Context) (Rekeyed, func(context.Context) error, error)

// RekeyVault encrypts vault again under a new key, sealed with protector,
// after approval. The caller holds the vault's write lock.
func (s *Service) RekeyVault(ctx context.Context, c Call, vault, protector string, rekey VaultRekeyer) error {
	if _, perr := s.store(c, vault); perr != nil {
		return perr
	}
	c = inVault(c, vault)
	users, userNames := s.usersOf(vault)
	a := ask{op: "vault.rekey", accessType: audit.TypeVaultRekey,
		refs: []plugin.ResourceRef{{Kind: "vault", ID: vault, Display: vault}}, visible: users,
		params: map[string]string{"protector": protector}}
	release, err := s.admit(ctx, c, a)
	if err != nil {
		return err
	}
	appr, err := s.ask(ctx, c, a, release)
	if err != nil {
		return err
	}
	r, undo, err := rekey(ctx)
	if err != nil {
		e := s.Event(c, audit.TypeVaultRekey, audit.OutcomeError)
		e.Resource = &audit.Resource{Kind: "vault", ID: vault}
		e.Error = &audit.ErrorInfo{Code: "internal", Message: err.Error()}
		seq, aerr := s.record(ctx, c, e)
		if aerr != nil {
			return aerr
		}
		return s.fail(c, protocol.CodeInternal, seq, "could not rekey vault %s: %v", vault, err)
	}
	e := s.Event(c, audit.TypeVaultRekey, audit.OutcomeOK)
	e.Resource = &audit.Resource{Kind: "vault", ID: vault}
	e.Params = map[string]string{"protector": protector, "old_vault_id": r.OldVaultID, "vault_id": r.VaultID,
		"replaced": strings.Join(r.Replaced, ","), "recovery_key": strconv.FormatBool(r.Recovery),
		"used_by": strings.Join(userNames, ",")}
	e.Approval = appr
	return s.recordOrUndo(ctx, c, e, "vault "+quote(vault)+" was encrypted again under a new key", undo)
}
