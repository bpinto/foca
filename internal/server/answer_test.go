//go:build linux

package server

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/protocol"
)

// A value that escaping would blow up past one message goes as base64 and
// arrives whole, and its read is recorded as served.
func TestControlCharacterValueArrivesAsBase64(t *testing.T) {
	e := start(t, hostRealm, nil)
	e.auth.Default = fake.Approve
	v := bytes.Repeat([]byte{1}, 180<<10) // six times that as escaped utf8
	e.store.Put(context.Background(), nil, plugin.SecretMeta{ID: "ctl"}, plugin.SecretValue{Bytes: v})
	var res protocol.SecretReadResult
	if err := dial(t, e.paths.ClientSocket("dev")).Call(ctx(t), protocol.MethodSecretRead, protocol.SecretReadParams{Names: []string{"dev:ctl"}}, &res); err != nil {
		t.Fatal(err)
	}
	got, err := protocol.DecodeValue(res.Secrets[0].Value, res.Secrets[0].Encoding)
	if err != nil || res.Secrets[0].Encoding != protocol.EncodingBase64 || !bytes.Equal(got, v) {
		t.Fatalf("%s, %d bytes, %v", res.Secrets[0].Encoding, len(got), err)
	}
	served := false
	for _, ev := range e.sink.Events() {
		served = served || ev.Type == audit.TypeSecretRead && ev.Outcome == audit.OutcomeOK
	}
	if !served {
		t.Fatal("read not recorded as served")
	}
}

// Request ids are strings or integers; anything else is refused, answered
// with a null id, and recorded.
func TestRequestIDsMustBeStringsOrIntegers(t *testing.T) {
	e := start(t, hostRealm, nil)
	c := dial(t, e.paths.ClientSocket("dev"))
	for _, id := range []string{`{"a":1}`, `[1]`, `true`, `null`, `1.5`, `1e999`} {
		c.WriteRaw([]byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"server.hello"}`))
		line, err := c.ReadRaw()
		if err != nil || !strings.Contains(string(line), `"id":null`) || !strings.Contains(string(line), `"code":-32600`) {
			t.Fatalf("id %s: %s %v", id, line, err)
		}
	}
	// Coalesced: the first is written in full, the rest counted.
	waitFor(t, func() bool { return hasReject(e.sink, "invalid_request") })
	c.WriteRaw([]byte(`{"jsonrpc":"2.0","id":"x-1","method":"server.hello"}`))
	if line, err := c.ReadRaw(); err != nil || !strings.Contains(string(line), `"id":"x-1","result"`) {
		t.Fatalf("string id: %s %v", line, err)
	}
}
