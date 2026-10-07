package action

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"
	"unicode"
	"unicode/utf8"
)

// ValidateOutput checks stdout against the action's output format. Nothing
// is returned to the caller unless it passes.
func ValidateOutput(format string, b []byte) error {
	switch format {
	case FormatNone:
		return nil
	case FormatText:
		if !utf8.Valid(b) {
			return errors.New("not valid UTF-8")
		}
		for _, r := range string(b) {
			if r != '\n' && r != '\t' && r != '\r' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) {
				return errors.New("contains a control or format character")
			}
		}
		return nil
	case FormatJSON:
		if !json.Valid(b) {
			return errors.New("not valid JSON")
		}
		return nil
	case FormatAWSCredProc:
		return awsCredentialProcess(b)
	}
	return fmt.Errorf("unknown output format %q", format)
}

// awsCredentialProcess checks the shape the AWS SDKs expect from a
// credential_process: version 1, both keys, and an RFC 3339 expiration if
// there is one.
func awsCredentialProcess(b []byte) error {
	var v struct {
		Version         *int    `json:"Version"`
		AccessKeyID     *string `json:"AccessKeyId"`
		SecretAccessKey *string `json:"SecretAccessKey"`
		SessionToken    *string `json:"SessionToken"`
		Expiration      *string `json:"Expiration"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&v); err != nil {
		return fmt.Errorf("not a JSON object: %v", err)
	}
	if d.More() {
		return errors.New("more than one JSON value")
	}
	switch {
	case v.Version == nil || *v.Version != 1:
		return errors.New("Version must be 1")
	case v.AccessKeyID == nil || *v.AccessKeyID == "":
		return errors.New("AccessKeyId is missing")
	case v.SecretAccessKey == nil || *v.SecretAccessKey == "":
		return errors.New("SecretAccessKey is missing")
	case v.SessionToken != nil && *v.SessionToken == "":
		return errors.New("SessionToken is empty")
	}
	if v.Expiration != nil {
		if _, err := time.Parse(time.RFC3339, *v.Expiration); err != nil {
			return errors.New("Expiration is not an RFC 3339 time")
		}
	}
	return nil
}

// Masker replaces secret values, and their base64, hex, URL-encoded and
// JSON-escaped forms, with [hidden:<id>]. It is best effort (design §11.1): a command
// that re-encodes a secret some other way gets it past.
type Masker struct {
	needles []needle
	longest int
}

type needle struct {
	b    []byte
	mark []byte
}

// NewMasker masks the given values, by secret id. It keeps its own copies;
// Zero clears them.
func NewMasker(values map[string][]byte) *Masker {
	m := &Masker{}
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		v := values[id]
		if len(v) == 0 {
			continue
		}
		mark := []byte("[hidden:" + id + "]")
		for _, enc := range encodings(v) {
			if len(enc) == 0 || m.has(enc) {
				continue
			}
			m.needles = append(m.needles, needle{b: enc, mark: mark})
			m.longest = max(m.longest, len(enc))
		}
	}
	// Longest first, so where several match at the same byte the mark is
	// that of the longest, not of a shorter encoding of another secret.
	sort.SliceStable(m.needles, func(i, j int) bool { return len(m.needles[i].b) > len(m.needles[j].b) })
	return m
}

// encodings are the forms of v that are masked.
func encodings(v []byte) [][]byte {
	out := [][]byte{append([]byte(nil), v...)}
	for _, e := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		out = append(out, []byte(e.EncodeToString(v)))
	}
	h := hex.EncodeToString(v)
	out = append(out, []byte(h), bytes.ToUpper([]byte(h)))
	out = append(out, []byte(url.QueryEscape(string(v))), []byte(url.PathEscape(string(v))))
	// The body of a JSON string, as encoders commonly write it: with and
	// without Go's escaping of & < >, and with / written \/ as some do.
	for _, html := range []bool{true, false} {
		var b bytes.Buffer
		e := json.NewEncoder(&b)
		e.SetEscapeHTML(html)
		if e.Encode(string(v)) != nil {
			continue
		}
		s := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
		s = s[1 : len(s)-1]
		out = append(out, bytes.Clone(s), bytes.ReplaceAll(s, []byte("/"), []byte(`\/`)))
		clear(b.Bytes())
	}
	return out
}

// Active reports whether there is anything to mask.
func (m *Masker) Active() bool { return m != nil && len(m.needles) > 0 }

// Window is how many bytes before a tail Mask needs to see, so that any
// secret reaching into the tail is seen whole.
func (m *Masker) Window() int {
	if !m.Active() {
		return 0
	}
	return m.longest - 1
}

// Mask returns b with every occurrence replaced.
func (m *Masker) Mask(b []byte) []byte { return m.maskFrom(b, 0) }

// MaskTail masks b and returns what follows its first len(b)-keep bytes.
// b should hold the last keep+Window() bytes of a stream: a secret that
// reaches into the tail then lies wholly inside b and is replaced, and the
// partial secret that may start b is dropped with the prefix.
func (m *Masker) MaskTail(b []byte, keep int) []byte {
	return m.maskFrom(b, max(0, len(b)-keep))
}

// maskFrom masks b and keeps the output from offset start of b on. A
// replaced range that begins before start but ends after it is kept, as
// its mark.
//
// Every match of every form is found before anything is replaced, and
// overlapping matches are merged into one range: replacing one secret first
// would leave the part of another that overlaps it in the clear. A merged
// range gets the mark of the match that starts first, the longest if
// several do.
func (m *Masker) maskFrom(b []byte, start int) []byte {
	if !m.Active() {
		return append([]byte(nil), b[start:]...)
	}
	type span struct{ from, to, n int }
	var spans []span
	for i, n := range m.needles {
		for off := 0; ; {
			j := bytes.Index(b[off:], n.b)
			if j < 0 {
				break
			}
			spans = append(spans, span{off + j, off + j + len(n.b), i})
			off += j + 1
		}
	}
	// Needles are longest first, so a stable sort keeps the longest match
	// first among those starting at the same byte.
	sort.SliceStable(spans, func(i, j int) bool { return spans[i].from < spans[j].from })

	out := make([]byte, 0, len(b)-start)
	at := 0
	for i := 0; i < len(spans); {
		s := spans[i]
		for i++; i < len(spans) && spans[i].from < s.to; i++ {
			s.to = max(s.to, spans[i].to)
		}
		if s.from > start {
			out = append(out, b[max(at, start):s.from]...)
		}
		if s.to > start {
			out = append(out, m.needles[s.n].mark...)
		}
		at = s.to
	}
	return append(out, b[max(at, start):]...)
}

func (m *Masker) has(b []byte) bool {
	for _, n := range m.needles {
		if bytes.Equal(n.b, b) {
			return true
		}
	}
	return false
}

// Zero clears the masker's copies of the values.
func (m *Masker) Zero() {
	if m == nil {
		return
	}
	for _, n := range m.needles {
		for i := range n.b {
			n.b[i] = 0
		}
	}
	m.needles = nil
}
