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
	s.Put(ctx, nil, plugin.SecretMeta{ID: "github-pat", DisplayName: "GitHub PAT", Tags: []string{"github"}}, plugin.SecretValue{Bytes: []byte("ghp_x")})
	s.Put(ctx, nil, plugin.SecretMeta{ID: "npm-token", Tags: []string{"npm"}}, plugin.SecretValue{Bytes: []byte("npm_y")})
	s.Put(ctx, nil, plugin.SecretMeta{ID: "prod-db"}, plugin.SecretValue{Bytes: []byte("pw")})
	return s
}

func TestExposureFiltersListResolveAndServe(t *testing.T) {
	ctx := context.Background()
	p := New("common", seeded(t), Exposure{IDs: []string{"github-pat"}, Tags: []string{"npm"}}, nil)

	list, err := p.List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	r, err := p.Resolve(ctx, "github-pat")
	if err != nil || r.Ref.Display != "GitHub PAT" {
		t.Fatalf("resolve = %+v, %v", r, err)
	}
	res, err := p.Serve(ctx, r, nil)
	if err != nil || string(res.Value) != "ghp_x" {
		t.Fatalf("serve = %q, %v", res.Value, err)
	}

	_, err = p.Resolve(ctx, "prod-db")
	if !errors.Is(err, plugin.ErrNotFound) || !errors.Is(err, plugin.ErrNotExposed) {
		t.Fatalf("unexposed secret: %v", err)
	}
	_, err = p.Resolve(ctx, "missing")
	if !errors.Is(err, plugin.ErrNotFound) || errors.Is(err, plugin.ErrNotExposed) {
		t.Fatalf("missing secret: %v", err)
	}
	// Serving an unexposed resource directly is still refused.
	if _, err := p.Serve(ctx, plugin.Resource{Ref: plugin.ResourceRef{ID: "prod-db"}}, nil); !errors.Is(err, plugin.ErrNotExposed) {
		t.Fatalf("serve of unexposed: %v", err)
	}
}

func TestSecretsRejectParams(t *testing.T) {
	p := New("v", seeded(t), Exposure{All: true}, nil)
	if _, err := p.Validate(context.Background(), plugin.Resource{}, map[string]string{"x": "y"}); err == nil {
		t.Fatal("params accepted")
	}
}
