package protocol

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeParamsIsStrict(t *testing.T) {
	var p SecretReadParams
	if err := DecodeParams([]byte(`{"names":["a"],"min_protocol":1,"client":{"pid":3}}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.Names[0] != "a" || p.MinProtocol != 1 || p.Client.PID != 3 {
		t.Fatalf("decoded %+v", p)
	}
	for _, bad := range []string{
		`{"names":["a"],"scope":"instance"}`,                 // unknown top-level field
		`{"names":["a"],"client":{"uid":0,"verified":true}}`, // unknown client field
		`{"names":["a"]} {"x":1}`,
	} {
		if err := DecodeParams([]byte(bad), &p); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	var empty SecretListParams
	if err := DecodeParams(nil, &empty); err != nil {
		t.Fatalf("empty params: %v", err)
	}
}

func TestReadMessageLimit(t *testing.T) {
	ok := strings.Repeat("a", MaxMessage) + "\n"
	r := bufio.NewReaderSize(strings.NewReader(ok+"next\n"), 4096)
	m, err := ReadMessage(r)
	if err != nil || len(m) != MaxMessage {
		t.Fatalf("max-size message: %d, %v", len(m), err)
	}
	if m, _ := ReadMessage(r); string(m) != "next" {
		t.Fatalf("following message %q", m)
	}
	big := strings.Repeat("a", MaxMessage+1) + "\n"
	if _, err := ReadMessage(bufio.NewReaderSize(strings.NewReader(big), 4096)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized: %v", err)
	}
}

func TestValueEncodingRoundTrip(t *testing.T) {
	for _, in := range [][]byte{[]byte("ghp_abc"), {0xff, 0x00, 0x10}} {
		v, enc := EncodeValue(in)
		out, err := DecodeValue(v, enc)
		if err != nil || !bytes.Equal(in, out) {
			t.Fatalf("%x -> %q/%s -> %x, %v", in, v, enc, out, err)
		}
	}
	if _, err := DecodeValue("x", "rot13"); err == nil {
		t.Fatal("unknown encoding accepted")
	}
}

// An id is echoed in the answer, so only what JSON-RPC 2.0 recommends is
// taken: a string or an integer, and a short one.
func TestRequestIDsAreStringsOrIntegers(t *testing.T) {
	for _, id := range []string{`1`, `-7`, `0`, `9223372036854775807`, `"a"`, `"` + strings.Repeat("x", MaxID-2) + `"`} {
		req, err := DecodeRequest([]byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"secret.list"}`))
		if err != nil || string(req.ID) != id {
			t.Errorf("id %s refused: %v", id, err)
		}
	}
	for _, id := range []string{`null`, `{}`, `{"a":1}`, `[1]`, `true`, `1.5`, `1e3`, `1e999`, `9223372036854775808`,
		`"` + strings.Repeat("x", MaxID-1) + `"`} {
		req, err := DecodeRequest([]byte(`{"jsonrpc":"2.0","id":` + id + `,"method":"secret.list"}`))
		if err == nil || req.ID != nil {
			t.Errorf("id %s accepted: %s", id, req.ID)
		}
	}
	// No id at all is a notification, not an error.
	if req, err := DecodeRequest([]byte(`{"jsonrpc":"2.0","method":"secret.list"}`)); err != nil || req.ID != nil {
		t.Fatalf("notification: %v", err)
	}
}

// Marshal leaves <, > and & alone, also inside raw results: escaped, each
// would take six bytes.
func TestMarshalDoesNotEscapeHTML(t *testing.T) {
	b, err := Marshal(Response{JSONRPC: "2.0", ID: json.RawMessage(`1`), Result: json.RawMessage(`{"v":"<&>"}`)})
	if err != nil || string(b) != `{"jsonrpc":"2.0","id":1,"result":{"v":"<&>"}}` {
		t.Fatalf("%s %v", b, err)
	}
}

// ValueLen is what the encoder writes, byte for byte, so a response can be
// measured before it is built.
func TestValueLenMatchesTheEncoder(t *testing.T) {
	var cases [][]byte
	for c := 0; c < 256; c++ {
		cases = append(cases, []byte{byte(c)}, bytes.Repeat([]byte{byte(c)}, 7))
	}
	cases = append(cases, nil, []byte("ghp_abc"), []byte("\u00e9\u2028\u2029\ufffd\u65e5\u672c"), []byte("<a&b>\x7f"),
		[]byte{0xe2, 0x80}, []byte("tab\tnew\nline\"\\"))
	for _, b := range cases {
		v, enc := EncodeValue(b)
		out, err := Marshal(v)
		if err != nil || len(out) != ValueLen(b) {
			t.Errorf("%q: ValueLen %d, encoded %d (%s)", b, ValueLen(b), len(out), enc)
		}
		if back, err := DecodeValue(v, enc); err != nil || !bytes.Equal(back, b) {
			t.Errorf("%q: round trip %q %v", b, back, err)
		}
	}
}

// A value that escaping would blow up goes as base64: 180 KiB of control
// characters would take six times that as utf8, more than one message.
func TestEncodeValuePicksTheShorterForm(t *testing.T) {
	ctl := bytes.Repeat([]byte{1}, 180<<10)
	if _, enc := EncodeValue(ctl); enc != EncodingBase64 || ValueLen(ctl) > MaxResult {
		t.Fatalf("control characters: %s, %d bytes", enc, ValueLen(ctl))
	}
	if _, enc := EncodeValue([]byte("ghp_abc\n")); enc != EncodingUTF8 {
		t.Fatalf("plain text went as %s", enc)
	}
	// Each form costs its own length plus quotes; utf8 wins ties.
	for _, b := range [][]byte{[]byte("<<<>>>&&&"), []byte("a\x01"), []byte("\x01\x01\x01\x01")} {
		v, enc := EncodeValue(b)
		u, _ := Marshal(string(b))
		if want := min(len(u), base64.StdEncoding.EncodedLen(len(b))+2); ValueLen(b) != want {
			t.Errorf("%q: %s %q is %d bytes, the shorter form %d", b, enc, v, ValueLen(b), want)
		}
	}
}

// The measured length of a secret.read result is what the encoder writes.
func TestSecretReadLenMatchesTheEncoder(t *testing.T) {
	names := []string{"dev:a", "dev:b", "dev:c"}
	values := [][]byte{[]byte("ghp_<x>"), {0xff, 0}, bytes.Repeat([]byte{2}, 100)}
	r := SecretReadResult{}
	for i := range names {
		v, enc := EncodeValue(values[i])
		r.Secrets = append(r.Secrets, SecretOut{Name: names[i], Value: v, Encoding: enc})
	}
	if b, _ := Marshal(r); len(b) != SecretReadLen(names, values) {
		t.Fatalf("SecretReadLen %d, encoded %d", SecretReadLen(names, values), len(b))
	}
}

// encoding/json alone accepts these, reading them in ways another parser
// might not. They must all be refused.
func TestParamsRejectCaseMismatchAndDuplicates(t *testing.T) {
	bad := map[string]string{
		"case mismatch":          `{"Names":["a"]}`,
		"duplicate key":          `{"names":["a"],"names":["b"]}`,
		"nested case mismatch":   `{"names":["a"],"client":{"PID":1}}`,
		"nested duplicate":       `{"names":["a"],"client":{"pid":1,"pid":2}}`,
		"duplicate in parents":   `{"names":["a"],"client":{"parents":[{"exe":"/a","exe":"/b"}]}}`,
		"case in embedded field": `{"names":["a"],"Min_Protocol":1}`,
		"guest field smuggled":   `{"names":["a"],"Guest_Verified":{}}`,
	}
	for name, raw := range bad {
		var p SecretReadParams
		if err := DecodeParams(json.RawMessage(raw), &p); err == nil {
			t.Errorf("%s: %s accepted", name, raw)
		}
	}
	var p SecretReadParams
	if err := DecodeParams(json.RawMessage(`{"names":["a"],"min_protocol":1,"client":{"pid":1,"parents":[{"exe":"/a"}]}}`), &p); err != nil {
		t.Fatalf("valid params refused: %v", err)
	}
}

func TestRequestEnvelopeRejectsDuplicates(t *testing.T) {
	for _, raw := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"secret.list","method":"secret.read"}`,
		`{"jsonrpc":"2.0","id":1,"Method":"secret.read"}`,
		`{"jsonrpc":"2.0","id":1,"method":"secret.read","params":{"a":1,"a":2}}`,
	} {
		if _, err := DecodeRequest([]byte(raw)); err == nil {
			t.Errorf("%s accepted", raw)
		}
	}
	req, err := DecodeRequest([]byte(`{"jsonrpc":"2.0","id":"x","method":"secret.read","params":{"names":["a"]}}`))
	if err != nil || req.Method != "secret.read" || string(req.ID) != `"x"` {
		t.Fatalf("valid request: %+v %v", req, err)
	}
}

// Two parsers must never read different params out of one action.run: a
// repeated param name is refused, not resolved to its last value.
func TestActionRunParamsAreStrict(t *testing.T) {
	var p ActionRunParams
	if err := DecodeParams([]byte(`{"name":"aws","params":{"profile":"dev-admin"}}`), &p); err != nil || p.Params["profile"] != "dev-admin" {
		t.Fatalf("%v %+v", err, p)
	}
	for _, bad := range []string{
		`{"name":"aws","params":{"profile":"dev-admin","profile":"prod-admin"}}`,
		`{"name":"aws","params":{"profile":1}}`,
		`{"name":"aws","command":"/bin/sh"}`,
		`{"Name":"aws"}`,
	} {
		var p ActionRunParams
		if err := DecodeParams([]byte(bad), &p); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}

// The measured length of an action.run result is what the encoder writes,
// with stdout withheld, empty or present.
func TestActionRunLenMatchesTheEncoder(t *testing.T) {
	for _, c := range []struct {
		stdout, stderr []byte
	}{{nil, nil}, {[]byte{}, nil}, {[]byte("out\n"), nil}, {nil, []byte("warn")}, {[]byte{0xff}, []byte("e\x01")}} {
		r := ActionRunResult{ExitCode: 3}
		if c.stdout != nil {
			r.Stdout, r.StdoutEncoding = EncodeValue(c.stdout)
		}
		if len(c.stderr) > 0 {
			r.StderrTail, r.StderrEncoding = EncodeValue(c.stderr)
		}
		if b, _ := Marshal(r); len(b) != ActionRunLen(3, c.stdout, c.stderr) {
			t.Errorf("%q %q: ActionRunLen %d, encoded %d (%s)", c.stdout, c.stderr, ActionRunLen(3, c.stdout, c.stderr), len(b), b)
		}
	}
}
