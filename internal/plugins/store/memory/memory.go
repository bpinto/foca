// Package memory is an in-memory secret store. Nothing survives a restart;
// it exists for tests.
package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/bpinto/foca/internal/plugin"
)

type Store struct {
	mu      sync.Mutex
	entries map[string]entry
	now     func() time.Time
}

type entry struct {
	meta  plugin.SecretMeta
	value []byte
}

func New() *Store {
	return &Store{entries: map[string]entry{}, now: time.Now}
}

func (s *Store) List(_ context.Context, _ []byte) ([]plugin.SecretMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]plugin.SecretMeta, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, copyMeta(e.meta))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) Read(_ context.Context, _ []byte, id string) (plugin.SecretMeta, plugin.SecretValue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return plugin.SecretMeta{}, plugin.SecretValue{}, plugin.ErrNotFound
	}
	return copyMeta(e.meta), plugin.SecretValue{Bytes: append([]byte(nil), e.value...)}, nil
}

// Put stores a copy of v; the caller still owns and should zero v.
func (s *Store) Put(_ context.Context, _ []byte, meta plugin.SecretMeta, v plugin.SecretValue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	if old, ok := s.entries[meta.ID]; ok {
		meta.Created = old.meta.Created
		meta.Updated = now
		zero(old.value)
	} else {
		meta.Created = now
	}
	s.entries[meta.ID] = entry{meta: copyMeta(meta), value: append([]byte(nil), v.Bytes...)}
	return nil
}

func (s *Store) Delete(_ context.Context, _ []byte, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[id]
	if !ok {
		return plugin.ErrNotFound
	}
	zero(e.value)
	delete(s.entries, id)
	return nil
}

func copyMeta(m plugin.SecretMeta) plugin.SecretMeta {
	m.Tags = append([]string(nil), m.Tags...)
	return m
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
