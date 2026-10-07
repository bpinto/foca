package static

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/secretname"
)

// Vaults is the secrets of every vault one instance reads, one Provider
// each (design §7.1). Its resources are named "<vault>:<id>" (package
// secretname), so the same id in two vaults is two secrets, and each name
// says which vault it is read from.
type Vaults struct {
	vaults []*Provider
}

func NewVaults(vaults ...*Provider) *Vaults { return &Vaults{vaults: vaults} }

func (v *Vaults) Kind() string { return "secret" }

func (v *Vaults) find(vault string) *Provider {
	for _, p := range v.vaults {
		if p.Vault() == vault {
			return p
		}
	}
	return nil
}

// qualify names r by its vault. A secret without a display name is shown by
// its full name.
func qualify(r plugin.Resource, vault string) plugin.Resource {
	if r.Ref.Display == r.Ref.ID {
		r.Ref.Display = secretname.Join(vault, r.Ref.ID)
	}
	r.Ref.ID, r.Ref.Vault = secretname.Join(vault, r.Ref.ID), vault
	return r
}

// List lists every vault. A vault not created yet holds nothing; only when
// none of them is created is the answer its not-initialized error, so the
// caller can say which vault to create.
func (v *Vaults) List(ctx context.Context) ([]plugin.Resource, error) {
	var out []plugin.Resource
	var notInit error
	created := false
	for _, p := range v.vaults {
		rs, err := p.List(ctx)
		if errors.Is(err, plugin.ErrNotInitialized) {
			notInit = err
			continue
		}
		if err != nil {
			return nil, err
		}
		created = true
		for _, r := range rs {
			out = append(out, qualify(r, p.Vault()))
		}
	}
	if !created && notInit != nil {
		return nil, notInit
	}
	slices.SortFunc(out, func(a, b plugin.Resource) int { return strings.Compare(a.Ref.ID, b.Ref.ID) })
	return out, nil
}

// Resolve looks name up in the vault it names. A vault the instance doesn't
// read holds nothing it can see.
func (v *Vaults) Resolve(ctx context.Context, name string) (plugin.Resource, error) {
	vault, id, ok := secretname.Split(name)
	if !ok {
		return plugin.Resource{}, plugin.ErrNotFound
	}
	p := v.find(vault)
	if p == nil {
		return plugin.Resource{}, plugin.ErrNotFound
	}
	r, err := p.Resolve(ctx, id)
	if err != nil {
		return plugin.Resource{}, err
	}
	return qualify(r, vault), nil
}

func (v *Vaults) Validate(_ context.Context, _ plugin.Resource, params map[string]string) (map[string]string, error) {
	if len(params) != 0 {
		return nil, errors.New("secrets take no parameters")
	}
	return nil, nil
}

// Serve reads r from the vault it names.
func (v *Vaults) Serve(ctx context.Context, r plugin.Resource, params map[string]string) (plugin.Result, error) {
	vault, id, ok := secretname.Split(r.Ref.ID)
	p := v.find(vault)
	if !ok || p == nil {
		return plugin.Result{}, fmt.Errorf("read %s: %w", r.Ref.ID, plugin.ErrNotExposed)
	}
	r.Ref.ID = id
	return p.Serve(ctx, r, params)
}
