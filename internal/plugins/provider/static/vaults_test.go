package static

import (
	"context"
	"errors"
	"testing"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/store/memory"
)

// store holds one secret per id, with "<id>@<vault>" as its value.
func store(t *testing.T, vault string, ids ...string) *memory.Store {
	t.Helper()
	s := memory.New()
	for _, id := range ids {
		s.Put(context.Background(), nil, plugin.SecretMeta{ID: id}, plugin.SecretValue{Bytes: []byte(id + "@" + vault)})
	}
	return s
}

// The same id in two vaults is two secrets, each named by its vault.
func TestVaultsNameEverySecretByItsVault(t *testing.T) {
	ctx := context.Background()
	v := NewVaults(
		New("common", store(t, "common", "github-pat", "prod-db"), Exposure{IDs: []string{"github-pat"}}, nil),
		New("dev", store(t, "dev", "github-pat"), Exposure{All: true}, nil),
	)
	list, err := v.List(ctx)
	if err != nil || len(list) != 2 || list[0].Ref.ID != "common:github-pat" || list[0].Ref.Vault != "common" ||
		list[1].Ref.ID != "dev:github-pat" || list[1].Ref.Display != "dev:github-pat" {
		t.Fatalf("list = %+v, %v", list, err)
	}
	for _, name := range []string{"common:github-pat", "dev:github-pat"} {
		r, err := v.Resolve(ctx, name)
		if err != nil || r.Ref.ID != name {
			t.Fatalf("resolve %s = %+v, %v", name, r, err)
		}
		res, err := v.Serve(ctx, r, nil)
		if want := name[len(r.Ref.Vault)+1:] + "@" + r.Ref.Vault; err != nil || string(res.Value) != want {
			t.Fatalf("serve %s = %q, %v", name, res.Value, err)
		}
	}
	if _, err := v.Resolve(ctx, "common:prod-db"); !errors.Is(err, plugin.ErrNotExposed) {
		t.Fatalf("unexposed secret: %v", err)
	}
	for _, name := range []string{"common:missing", "other:github-pat", "github-pat"} {
		if _, err := v.Resolve(ctx, name); !errors.Is(err, plugin.ErrNotFound) || errors.Is(err, plugin.ErrNotExposed) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// A secret is only served from the vault it names, and only if that
	// vault exposes it.
	for _, id := range []string{"common:prod-db", "other:github-pat", "github-pat"} {
		if _, err := v.Serve(ctx, plugin.Resource{Ref: plugin.ResourceRef{ID: id}}, nil); !errors.Is(err, plugin.ErrNotExposed) {
			t.Fatalf("serve of %s: %v", id, err)
		}
	}
}

// A vault not created yet holds nothing; a name in it is not_initialized,
// and only when no vault is created is a listing.
func TestVaultsNotInitialized(t *testing.T) {
	ctx := context.Background()
	missing := func(context.Context) ([]byte, func(), error) {
		return nil, nil, plugin.NotInitialized{Vault: "dev"}
	}
	v := NewVaults(
		New("common", store(t, "common", "github-pat"), Exposure{All: true}, nil),
		New("dev", store(t, "dev"), Exposure{All: true}, missing),
	)
	if _, err := v.Resolve(ctx, "common:github-pat"); err != nil {
		t.Fatalf("resolve with another vault missing: %v", err)
	}
	if _, err := v.Resolve(ctx, "dev:x"); !errors.Is(err, plugin.ErrNotInitialized) {
		t.Fatalf("resolve in the missing vault: %v", err)
	}
	if list, err := v.List(ctx); err != nil || len(list) != 1 {
		t.Fatalf("list with one vault missing: %v %v", list, err)
	}
	v = NewVaults(New("dev", store(t, "dev"), Exposure{All: true}, missing))
	if _, err := v.List(ctx); !errors.Is(err, plugin.ErrNotInitialized) {
		t.Fatalf("list with no vault: %v", err)
	}
}
