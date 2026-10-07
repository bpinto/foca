package static

import (
	"context"
	"errors"
	"strings"
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
	names := []string{"common:github-pat", "dev:github-pat", "common:prod-db", "common:missing", "other:github-pat", "github-pat"}
	rs, errs, err := v.Resolve(ctx, names)
	if err != nil {
		t.Fatal(err)
	}
	for i, vault := range []string{"common", "dev"} {
		if errs[i] != nil || rs[i].Ref.ID != names[i] || rs[i].Ref.Vault != vault {
			t.Fatalf("resolve %s = %+v, %v", names[i], rs[i], errs[i])
		}
		res, err := v.Serve(ctx, rs[i], nil)
		if err != nil || string(res.Value) != "github-pat@"+vault {
			t.Fatalf("serve %s = %q, %v", names[i], res.Value, err)
		}
	}
	if !errors.Is(errs[2], plugin.ErrNotExposed) {
		t.Fatalf("unexposed secret: %v", errs[2])
	}
	for _, i := range []int{3, 4, 5} {
		if !errors.Is(errs[i], plugin.ErrNotFound) || errors.Is(errs[i], plugin.ErrNotExposed) {
			t.Fatalf("%s: %v", names[i], errs[i])
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
	if _, errs, err := v.Resolve(ctx, []string{"common:github-pat"}); err != nil || errs[0] != nil {
		t.Fatalf("resolve with another vault missing: %v %v", errs, err)
	}
	if _, _, err := v.Resolve(ctx, []string{"common:github-pat", "dev:x"}); !errors.Is(err, plugin.ErrNotInitialized) {
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

// A request unseals each data key once, however many names it carries, and
// only the keys of the vaults it names.
func TestVaultsUnsealEachKeyOncePerRequest(t *testing.T) {
	unseals := map[string]int{}
	dek := func(v string) DEKFunc {
		return func(context.Context) ([]byte, func(), error) {
			unseals[v]++
			return nil, func() {}, nil
		}
	}
	v := NewVaults(
		New("a", store(t, "a", "github-pat", "npm-token"), Exposure{All: true}, dek("a")),
		New("b", store(t, "b", "prod-db"), Exposure{All: true}, dek("b")),
		New("c", store(t, "c"), Exposure{All: true}, dek("c")),
	)
	names := []string{"a:github-pat", "a:npm-token", "b:prod-db", "a:x", "b:y", "a:z"}
	if _, _, err := v.Resolve(context.Background(), names); err != nil {
		t.Fatal(err)
	}
	if unseals["a"] != 1 || unseals["b"] != 1 || unseals["c"] != 0 {
		t.Fatalf("unseals %v for one request of %d names", unseals, len(names))
	}
}

// A realm picks which secret it asks for, so no two secrets it may read are
// shown alike in a prompt. With several vaults, a display name carries its
// vault; one that another secret in the vault also shows carries its full
// name. A secret the instance can't read never counts.
func TestPromptNamesTellSecretsApart(t *testing.T) {
	ctx := context.Background()
	named := func(vault string, metas ...plugin.SecretMeta) *memory.Store {
		s := memory.New()
		for _, m := range metas {
			s.Put(ctx, nil, m, plugin.SecretValue{Bytes: []byte(m.ID + "@" + vault)})
		}
		return s
	}
	common := named("common", plugin.SecretMeta{ID: "github-pat", DisplayName: "GitHub PAT"},
		plugin.SecretMeta{ID: "gh-bot", DisplayName: "GitHub PAT"},
		plugin.SecretMeta{ID: "npm-token", DisplayName: "npm token"},
		plugin.SecretMeta{ID: "prod-npm", DisplayName: "npm token"},
		plugin.SecretMeta{ID: "x", DisplayName: "common:y"}, plugin.SecretMeta{ID: "y"})
	dev := named("dev", plugin.SecretMeta{ID: "github-pat", DisplayName: "GitHub PAT"})
	expose := Exposure{IDs: []string{"github-pat", "gh-bot", "npm-token", "x", "y"}}
	display := func(v *Vaults, names ...string) []string {
		rs, errs, err := v.Resolve(ctx, names)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(rs))
		for i := range rs {
			if errs[i] != nil {
				t.Fatalf("%s: %v", names[i], errs[i])
			}
			out[i] = rs[i].Ref.Display
		}
		return out
	}
	one := NewVaults(New("common", common, expose, nil))
	got := display(one, "common:github-pat", "common:gh-bot", "common:npm-token", "common:x", "common:y")
	want := []string{"GitHub PAT (common:github-pat)", "GitHub PAT (common:gh-bot)", "npm token", "common:y (common:x)", "common:y"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("one vault:\n got %q\nwant %q", got, want)
	}
	two := NewVaults(New("common", common, expose, nil), New("dev", dev, Exposure{All: true}, nil))
	got = display(two, "dev:github-pat", "common:npm-token", "common:github-pat")
	want = []string{"GitHub PAT (dev)", "npm token (common)", "GitHub PAT (common:github-pat)"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("two vaults:\n got %q\nwant %q", got, want)
	}
}
