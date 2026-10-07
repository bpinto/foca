package static

import (
	"context"
	"errors"
	"testing"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/store/memory"
)

func seeded(t *testing.T) *memory.Store {
	t.Helper()
	s := memory.New()
	ctx := context.Background()
	s.Put(ctx, nil, plugin.SecretMeta{ID: "github-pat", DisplayName: "GitHub PAT"}, plugin.SecretValue{Bytes: []byte("ghp_x")})
	s.Put(ctx, nil, plugin.SecretMeta{ID: "npm-token"}, plugin.SecretValue{Bytes: []byte("npm_y")})
	s.Put(ctx, nil, plugin.SecretMeta{ID: "prod-db"}, plugin.SecretValue{Bytes: []byte("pw")})
	return s
}

func TestExposureFiltersListResolveAndServe(t *testing.T) {
	ctx := context.Background()
	p := New("common", seeded(t), Exposure{IDs: []string{"github-pat", "npm-token"}}, nil)

	list, err := p.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	rs, errs, err := p.Resolve(ctx, []string{"github-pat", "prod-db", "missing"})
	if err != nil || len(rs) != 3 || len(errs) != 3 {
		t.Fatalf("resolve = %+v %v, %v", rs, errs, err)
	}
	if r := rs[0]; errs[0] != nil || r.Ref.Display != "GitHub PAT" {
		t.Fatalf("resolve = %+v, %v", r, errs[0])
	}
	res, err := p.Serve(ctx, rs[0], nil)
	if err != nil || string(res.Value) != "ghp_x" {
		t.Fatalf("serve = %q, %v", res.Value, err)
	}

	if err := errs[1]; !errors.Is(err, plugin.ErrNotFound) || !errors.Is(err, plugin.ErrNotExposed) {
		t.Fatalf("unexposed secret: %v", err)
	}
	if err := errs[2]; !errors.Is(err, plugin.ErrNotFound) || errors.Is(err, plugin.ErrNotExposed) {
		t.Fatalf("missing secret: %v", err)
	}
	// Serving an unexposed resource directly is still refused.
	if _, err := p.Serve(ctx, plugin.Resource{Ref: plugin.ResourceRef{ID: "prod-db"}}, nil); !errors.Is(err, plugin.ErrNotExposed) {
		t.Fatalf("serve of unexposed: %v", err)
	}
}

// A request unseals the data key once, however many names it carries.
func TestResolveUnsealsOncePerRequest(t *testing.T) {
	unseals := 0
	dek := func(context.Context) ([]byte, func(), error) {
		unseals++
		return nil, func() {}, nil
	}
	p := New("v", seeded(t), Exposure{All: true}, dek)
	names := []string{"github-pat", "npm-token", "prod-db", "a", "b", "c"}
	if _, _, err := p.Resolve(context.Background(), names); err != nil {
		t.Fatal(err)
	}
	if unseals != 1 {
		t.Fatalf("%d unseals for one request of %d names", unseals, len(names))
	}
}

func TestSecretsRejectParams(t *testing.T) {
	p := New("v", seeded(t), Exposure{All: true}, nil)
	if _, err := p.Validate(context.Background(), plugin.Resource{}, map[string]string{"x": "y"}); err == nil {
		t.Fatal("params accepted")
	}
}
