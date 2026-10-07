// Package format writes secret values for `foca get`. Each formatter
// writes to w once everything is checked, so a value that can't be written
// safely produces an error and no partial output.
package format

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Secret is one named value. The caller owns Value and zeroes it.
type Secret struct {
	Name  string
	Value []byte
}

// Names lists the formats `get --format` accepts.
var Names = []string{"raw", "json", "env"}

var envVarPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// EnvVar derives a variable name from a secret's name, leaving out its
// vault: common:github-pat → GITHUB_PAT.
func EnvVar(secret string) string {
	if _, id, ok := strings.Cut(secret, ":"); ok {
		secret = id
	}
	return strings.ToUpper(strings.ReplaceAll(secret, "-", "_"))
}

// ValidEnvVar reports whether s can be an environment variable name.
func ValidEnvVar(s string) bool { return envVarPattern.MatchString(s) }

// Raw writes a single value exactly as stored, with nothing added.
func Raw(w io.Writer, s Secret) error {
	_, err := w.Write(s.Value)
	return err
}

// JSON writes one object keyed by secret name, in the order given:
//
//	{"github-pat":"ghp_…","cert":{"base64":"MIIC…"}}
//
// UTF-8 values are JSON strings. Other values can't be JSON strings without
// being altered, so they are an object holding the base64 encoding.
func JSON(w io.Writer, secrets []Secret) error {
	var buf bytes.Buffer
	defer zero(buf.Bytes())
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	buf.WriteByte('{')
	for i, s := range secrets {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := enc.Encode(s.Name); err != nil {
			return err
		}
		trimNewline(&buf)
		buf.WriteByte(':')
		if utf8.Valid(s.Value) {
			if err := enc.Encode(string(s.Value)); err != nil {
				return err
			}
		} else {
			buf.WriteString(`{"base64":`)
			if err := enc.Encode(base64.StdEncoding.EncodeToString(s.Value)); err != nil {
				return err
			}
			trimNewline(&buf)
			buf.WriteByte('}')
		}
		trimNewline(&buf)
	}
	buf.WriteString("}\n")
	_, err := w.Write(buf.Bytes())
	return err
}

// Env writes NAME=value lines in the format `docker run --env-file` reads:
// the value is everything after the first = up to the line break, taken as
// is, with no quoting, escapes or expansion. A value that contains a line
// break, a NUL or invalid UTF-8 can't be written that way and is refused.
//
// Other readers of NAME=value files don't read them this way: a shell that
// sources the file runs $(…) and backticks and splits on spaces, systemd's
// EnvironmentFile and dotenv parsers interpret quotes, backslashes and
// surrounding whitespace. The output is only for readers that take values
// raw. vars[i] is the variable name for secrets[i]; each may appear once.
func Env(w io.Writer, secrets []Secret, vars []string) error {
	if len(vars) != len(secrets) {
		return errors.New("format: one variable name per secret")
	}
	var buf bytes.Buffer
	defer zero(buf.Bytes())
	seen := map[string]bool{}
	for i, s := range secrets {
		if !ValidEnvVar(vars[i]) {
			return fmt.Errorf("%q is not a valid variable name", vars[i])
		}
		// Readers keep either the first or the last, so one value would be lost.
		if seen[vars[i]] {
			return fmt.Errorf("variable %s is set twice", vars[i])
		}
		seen[vars[i]] = true
		if bytes.ContainsAny(s.Value, "\n\r\x00") || !utf8.Valid(s.Value) {
			return fmt.Errorf("secret %s contains a line break, NUL or non-UTF-8 bytes, which the env format can't hold; use --format json", s.Name)
		}
		buf.WriteString(vars[i])
		buf.WriteByte('=')
		buf.Write(s.Value)
		buf.WriteByte('\n')
	}
	_, err := w.Write(buf.Bytes())
	return err
}

func trimNewline(b *bytes.Buffer) {
	if n := b.Len(); n > 0 && b.Bytes()[n-1] == '\n' {
		b.Truncate(n - 1)
	}
}

func zero(b []byte) {
	b = b[:cap(b)]
	for i := range b {
		b[i] = 0
	}
}
