package core

import (
	"bytes"
	"context"
	"testing"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/protocol"
)

// A read whose answer couldn't fit in one message is refused before the
// value is recorded as served: the client could never have read it.
func TestReadThatCantBeAnsweredIsRefusedNotServed(t *testing.T) {
	h := newHarness(t, fake.Approve, fake.Approve)
	big := bytes.Repeat([]byte{0xff}, 800<<10) // 1.07 MB as base64
	h.store.Put(context.Background(), nil, plugin.SecretMeta{ID: "npm-token"}, plugin.SecretValue{Bytes: big})
	got, err := h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:github-pat", "common:npm-token"})
	if got != nil || code(err) != protocol.CodeInvalidParams {
		t.Fatalf("got %d values, %v", len(got), err)
	}
	evs := h.sink.Events()
	wantTypes(t, evs, "approval.granted:ok", "secret.read:error", "secret.read:error")
	for _, e := range evs[1:] {
		if e.Reason != "response_too_large" || e.Approval == nil {
			t.Fatalf("read recorded as %+v", e)
		}
	}
	// Up to the limit, it is served.
	h.store.Put(context.Background(), nil, plugin.SecretMeta{ID: "npm-token"}, plugin.SecretValue{Bytes: big[:600<<10]})
	if got, err := h.svc.ReadSecrets(context.Background(), h.call(), []string{"common:npm-token"}); err != nil || len(got[0].Value) != 600<<10 {
		t.Fatalf("600 KiB value: %v", err)
	}
}
