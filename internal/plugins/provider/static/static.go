// Package static exposes vault secrets as "secret:<id>" resources: Provider
// for one vault, filtered by one instance's exposure, and Vaults for every
// vault an instance reads.
package static

import (
	"context"
	"errors"
	"fmt"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/secretname"
)

// Exposure is what one instance may read in one vault: all of it, or the
// secrets it names.
type Exposure struct {
	All bool
	IDs []string
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
	return false
}

// DEKFunc is plugin.DEKFunc; nil means the store doesn't encrypt.
type DEKFunc = plugin.DEKFunc

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

// Resolve looks up every id against one read of the vault's metadata, so a
// request unseals the data key once however many names it carries. A secret
// that exists but isn't exposed gets plugin.ErrNotExposed. That matches
// plugin.ErrNotFound, so callers treat both the same; the core only uses the
// difference for the audit reason.
func (p *Provider) Resolve(ctx context.Context, ids []string) ([]plugin.Resource, []error, error) {
	rs, errs, _, err := p.resolve(ctx, ids)
	return rs, errs, err
}

// resolve is Resolve, and also counts how each secret the instance may read
// in the vault is shown, from the same read: by its display name, else by its
// full name. Vaults uses the counts to tell apart secrets shown alike.
func (p *Provider) resolve(ctx context.Context, ids []string) (rs []plugin.Resource, errs []error, shown map[string]int, err error) {
	rs = make([]plugin.Resource, len(ids))
	errs = make([]error, len(ids))
	shown = map[string]int{}
	err = p.withDEK(ctx, func(dek []byte) error {
		metas, err := p.store.List(ctx, dek)
		if err != nil {
			return err
		}
		byID := make(map[string]plugin.SecretMeta, len(metas))
		for _, m := range metas {
			byID[m.ID] = m
			if !p.expose.Allows(m) {
				continue
			}
			// As Vaults shows it: a secret without a display name by its
			// full name.
			if label := m.Display(); label != m.ID {
				shown[label]++
			} else {
				shown[secretname.Join(p.vault, m.ID)]++
			}
		}
		for i, id := range ids {
			m, ok := byID[id]
			switch {
			case !ok:
				errs[i] = plugin.ErrNotFound
			case !p.expose.Allows(m):
				errs[i] = plugin.ErrNotExposed
			default:
				rs[i] = toResource(m)
			}
		}
		return nil
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return rs, errs, shown, nil
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
		// Exposure is checked again, so Serve never returns a secret that
		// Resolve wouldn't.
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
	}
}
