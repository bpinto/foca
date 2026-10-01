// Package static exposes vault secrets as "secret:<id>" resources, filtered by
// one instance's exposure rules.
package static

import (
	"context"
	"errors"
	"fmt"

	"github.com/bpinto/foca/internal/plugin"
)

// Exposure decides which secrets of a vault one instance may see.
type Exposure struct {
	All  bool
	IDs  []string
	Tags []string
}

func (e Exposure) Allows(m plugin.SecretMeta) bool {
	if e.All {
		return true
	}
	for _, id := range e.IDs {
		if id == m.ID {
			return true
		}
	}
	for _, want := range e.Tags {
		for _, t := range m.Tags {
			if t == want {
				return true
			}
		}
	}
	return false
}

// DEKFunc returns the vault's data key and a function that releases it.
// The memory store doesn't encrypt, so a nil DEKFunc is allowed.
type DEKFunc func(ctx context.Context) (dek []byte, release func(), err error)

type Provider struct {
	vault  string
	store  plugin.SecretStore
	expose Exposure
	dek    DEKFunc
}

func New(vault string, store plugin.SecretStore, expose Exposure, dek DEKFunc) *Provider {
	return &Provider{vault: vault, store: store, expose: expose, dek: dek}
}

func (p *Provider) Kind() string  { return "secret" }
func (p *Provider) Vault() string { return p.vault }

func (p *Provider) withDEK(ctx context.Context, fn func(dek []byte) error) error {
	if p.dek == nil {
		return fn(nil)
	}
	dek, release, err := p.dek(ctx)
	if err != nil {
		return err
	}
	defer release()
	return fn(dek)
}

func (p *Provider) List(ctx context.Context) ([]plugin.Resource, error) {
	var out []plugin.Resource
	err := p.withDEK(ctx, func(dek []byte) error {
		metas, err := p.store.List(ctx, dek)
		if err != nil {
			return err
		}
		for _, m := range metas {
			if p.expose.Allows(m) {
				out = append(out, toResource(m))
			}
		}
		return nil
	})
	return out, err
}

// Resolve returns plugin.ErrNotExposed for a secret that exists but isn't
// exposed. It matches plugin.ErrNotFound, so callers treat both the same; the
// core only uses the difference for the audit reason.
func (p *Provider) Resolve(ctx context.Context, id string) (plugin.Resource, error) {
	var r plugin.Resource
	err := p.withDEK(ctx, func(dek []byte) error {
		metas, err := p.store.List(ctx, dek)
		if err != nil {
			return err
		}
		for _, m := range metas {
			if m.ID != id {
				continue
			}
			if !p.expose.Allows(m) {
				return plugin.ErrNotExposed
			}
			r = toResource(m)
			return nil
		}
		return plugin.ErrNotFound
	})
	return r, err
}

func (p *Provider) Validate(_ context.Context, _ plugin.Resource, params map[string]string) (map[string]string, error) {
	if len(params) != 0 {
		return nil, errors.New("secrets take no parameters")
	}
	return nil, nil
}

func (p *Provider) Serve(ctx context.Context, r plugin.Resource, _ map[string]string) (plugin.Result, error) {
	var res plugin.Result
	err := p.withDEK(ctx, func(dek []byte) error {
		meta, v, err := p.store.Read(ctx, dek, r.Ref.ID)
		if err != nil {
			return err
		}
		// Exposure is re-checked at serve time in case the secret's tags
		// changed between resolve and serve.
		if !p.expose.Allows(meta) {
			v.Zero()
			return plugin.ErrNotExposed
		}
		res.Value = v.Bytes
		return nil
	})
	if err != nil {
		return plugin.Result{}, fmt.Errorf("read %s: %w", r.Ref.ID, err)
	}
	return res, nil
}

func toResource(m plugin.SecretMeta) plugin.Resource {
	return plugin.Resource{
		Ref:         plugin.ResourceRef{Kind: "secret", ID: m.ID, Display: m.Display()},
		Description: m.Description,
		Tags:        append([]string(nil), m.Tags...),
	}
}
