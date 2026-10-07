package format

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// Golden output: the exact bytes each format writes.
func TestJSONGolden(t *testing.T) {
	cases := []struct {
		name    string
		secrets []Secret
		want    string
	}{
		{"one", []Secret{{"github-pat", []byte("ghp_x")}},
			`{"github-pat":"ghp_x"}` + "\n"},
		{"order kept", []Secret{{"b", []byte("2")}, {"a", []byte("1")}},
			`{"b":"2","a":"1"}` + "\n"},
		{"escaping", []Secret{{"q", []byte("a\"b\\c\nd\te<f>&\u2028")}},
			`{"q":"a\"b\\c\nd\te<f>&\u2028"}` + "\n"},
		{"binary", []Secret{{"cert", []byte{0xff, 0x00, 0x01}}, {"t", []byte("x")}},
			`{"cert":{"base64":"/wAB"},"t":"x"}` + "\n"},
		{"empty", nil, "{}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := JSON(&buf, tc.secrets); err != nil {
				t.Fatal(err)
			}
			if buf.String() != tc.want {
				t.Fatalf("got  %s\nwant %s", buf.String(), tc.want)
			}
			var v map[string]any
			if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
				t.Fatalf("not valid JSON: %v", err)
			}
		})
	}
}

func TestEnvGolden(t *testing.T) {
	var buf bytes.Buffer
	secrets := []Secret{{"github-pat", []byte("ghp_x")}, {"url", []byte(`postgres://u:p@h/db?x="y" $HOME`)}}
	if err := Env(&buf, secrets, []string{"GITHUB_TOKEN", "DATABASE_URL"}); err != nil {
		t.Fatal(err)
	}
	want := "GITHUB_TOKEN=ghp_x\nDATABASE_URL=postgres://u:p@h/db?x=\"y\" $HOME\n"
	if buf.String() != want {
		t.Fatalf("got %q\nwant %q", buf.String(), want)
	}
}

// A value that would end up split over lines, or altered, is refused with
// no partial output.
func TestEnvRefusesWhatItCantHold(t *testing.T) {
	for _, v := range [][]byte{[]byte("a\nB=evil"), []byte("a\rb"), {'a', 0, 'b'}, {0xff}} {
		var buf bytes.Buffer
		err := Env(&buf, []Secret{{"ok", []byte("fine")}, {"bad", v}}, []string{"OK", "BAD"})
		if err == nil || !strings.Contains(err.Error(), "--format json") {
			t.Fatalf("%q: %v", v, err)
		}
		if buf.Len() != 0 {
			t.Fatalf("partial output %q", buf.String())
		}
	}
	for _, name := range []string{"", "1X", "A-B", "A B", "A=B"} {
		if err := Env(&bytes.Buffer{}, []Secret{{"s", []byte("v")}}, []string{name}); err == nil {
			t.Fatalf("variable %q accepted", name)
		}
	}
	// A reader keeps one of the two, so the other would be lost unseen.
	var buf bytes.Buffer
	err := Env(&buf, []Secret{{"a", []byte("1")}, {"b", []byte("2")}}, []string{"X", "X"})
	if err == nil || !strings.Contains(err.Error(), "set twice") || buf.Len() != 0 {
		t.Fatalf("variable named twice: %v, %q", err, buf.String())
	}
}

func TestEnvVar(t *testing.T) {
	if got := EnvVar("github-pat"); got != "GITHUB_PAT" {
		t.Fatal(got)
	}
	if got := EnvVar("npm_token-2"); got != "NPM_TOKEN_2" {
		t.Fatal(got)
	}
	// The vault is left out of the name.
	if got := EnvVar("common:github-pat"); got != "GITHUB_PAT" {
		t.Fatal(got)
	}
	if ValidEnvVar(EnvVar("1password")) {
		t.Fatal("leading digit accepted")
	}
}

func TestRawWritesExactBytes(t *testing.T) {
	var buf bytes.Buffer
	v := []byte{0, 'a', '\n', 0xff}
	Raw(&buf, Secret{"x", v})
	if !bytes.Equal(buf.Bytes(), v) {
		t.Fatalf("%x", buf.Bytes())
	}
}
