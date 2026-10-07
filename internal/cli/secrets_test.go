package cli

import (
	"bytes"
	"errors"
	"testing"

	"github.com/bpinto/foca/internal/protocol"
)

// Values the service sent but the CLI won't return, because nobody asked
// for them or the answer is refused, are zeroed, not left for the GC.
func TestValuesNotReturnedAreZeroed(t *testing.T) {
	var made [][]byte
	decodeValue = func(v, enc string) ([]byte, error) {
		if enc != "utf8" {
			return nil, errors.New("bad encoding")
		}
		b := []byte(v)
		made = append(made, b)
		return b, nil
	}
	t.Cleanup(func() { decodeValue = protocol.DecodeValue })
	zeroed := func(b []byte) bool { return !bytes.ContainsFunc(b, func(r rune) bool { return r != 0 }) }
	val := func(name, v, enc string) protocol.SecretOut {
		return protocol.SecretOut{Name: name, Value: v, Encoding: enc}
	}

	// An extra value is zeroed; the one asked for is returned.
	out, err := collectSecrets([]string{"v:a"}, []protocol.SecretOut{val("v:a", "aaa", "utf8"), val("v:b", "bbb", "utf8")})
	if err != nil || string(out[0].Value) != "aaa" || !zeroed(made[1]) {
		t.Fatalf("extra value: %v %q", err, made)
	}
	// A later value that can't be decoded, a repeated name or a missing
	// one refuses the whole answer, and what was decoded is zeroed.
	for name, got := range map[string][]protocol.SecretOut{
		"undecodable": {val("v:a", "aaa", "utf8"), val("v:b", "bbb", "bogus")},
		"repeated":    {val("v:a", "aaa", "utf8"), val("v:b", "bbb", "utf8"), val("v:a", "ccc", "utf8")},
		"missing":     {val("v:a", "aaa", "utf8")},
	} {
		made = nil
		if _, err := collectSecrets([]string{"v:a", "v:b"}, got); err == nil {
			t.Fatalf("%s: accepted", name)
		}
		for _, b := range made {
			if !zeroed(b) {
				t.Fatalf("%s: %q left behind", name, b)
			}
		}
	}
}
