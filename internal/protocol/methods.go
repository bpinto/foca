package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/bpinto/foca/internal/identity"
)

// Method names.
const (
	MethodHello        = "server.hello"
	MethodSecretList   = "secret.list"
	MethodSecretRead   = "secret.read"
	MethodGrantsStatus = "grants.status"
	MethodGrantsDrop   = "grants.drop"
	MethodActionList   = "action.list"
	MethodActionRun    = "action.run"
)

// Common fields every request may carry. Embedded in each params type so
// strict decoding accepts them.
type Common struct {
	MinProtocol int                  `json:"min_protocol,omitempty"`
	Client      *identity.ClientInfo `json:"client,omitempty"`
}

func (c Common) Base() Common { return c }

// Params is implemented by every params type.
type Params interface{ Base() Common }

type HelloParams struct {
	Common
	Protocol int `json:"protocol"`
}

type HelloResult struct {
	Protocol      int            `json:"protocol"`
	Instance      string         `json:"instance"`
	Realm         identity.Realm `json:"realm"`
	ServerVersion string         `json:"server_version"`
	Features      []string       `json:"features"`
}

type SecretListParams struct {
	Common
}

type SecretInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Description string `json:"description,omitempty"`
}

type SecretListResult struct {
	Secrets []SecretInfo `json:"secrets"`
}

type SecretReadParams struct {
	Common
	Names []string `json:"names"`
}

type SecretOut struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Encoding string `json:"encoding"` // utf8 | base64
}

type SecretReadResult struct {
	Secrets []SecretOut `json:"secrets"`
}

const (
	EncodingUTF8   = "utf8"
	EncodingBase64 = "base64"
)

// EncodeValue picks utf8 for valid UTF-8, unless escaping would make it
// longer on the wire than base64 (control characters take six bytes each),
// and base64 otherwise.
func EncodeValue(b []byte) (value, encoding string) {
	if valueEncoding(b) == EncodingUTF8 {
		return string(b), EncodingUTF8
	}
	return base64.StdEncoding.EncodeToString(b), EncodingBase64
}

func valueEncoding(b []byte) string {
	if utf8.Valid(b) && jsonStringLen(b) <= base64.StdEncoding.EncodedLen(len(b))+2 {
		return EncodingUTF8
	}
	return EncodingBase64
}

// ValueLen is how many bytes the value EncodeValue gives for b takes in a
// message, quotes included. It copies nothing, so a secret value can be
// measured before anything is decided about serving it.
func ValueLen(b []byte) int {
	if valueEncoding(b) == EncodingUTF8 {
		return jsonStringLen(b)
	}
	return base64.StdEncoding.EncodedLen(len(b)) + 2
}

// jsonStringLen is the length of b as a JSON string written by Marshal:
// quotes, two-byte escapes for " \ and the common control characters,
// \u00XX for the others, and \u2028, \u2029 and \ufffd (for each invalid
// byte) in six. TestValueLenMatchesTheEncoder holds it to encoding/json.
func jsonStringLen(b []byte) int {
	n := 2
	for i := 0; i < len(b); {
		c := b[i]
		if c < utf8.RuneSelf {
			switch {
			case c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t':
				n += 2
			case c < 0x20:
				n += 6
			default:
				n++
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 || r == '\u2028' || r == '\u2029' {
			n += 6
		} else {
			n += size
		}
		i += size
	}
	return n
}

// SecretReadLen is the length of the encoded secret.read result for these
// names and values, measured without copying a value.
func SecretReadLen(names []string, values [][]byte) int {
	r := SecretReadResult{Secrets: make([]SecretOut, len(names))}
	n := 0
	for i := range names {
		// Value "" stands in for the value: it encodes as two quotes.
		r.Secrets[i] = SecretOut{Name: names[i], Encoding: valueEncoding(values[i])}
		n += ValueLen(values[i]) - 2
	}
	b, err := Marshal(r)
	if err != nil {
		return MaxMessage + 1
	}
	return len(b) + n
}

// DecodeValue reverses EncodeValue.
func DecodeValue(value, encoding string) ([]byte, error) {
	switch encoding {
	case "", EncodingUTF8:
		if !utf8.ValidString(value) {
			return nil, errors.New("value is not valid UTF-8")
		}
		return []byte(value), nil
	case EncodingBase64:
		return base64.StdEncoding.DecodeString(value)
	default:
		return nil, fmt.Errorf("unknown encoding %q", encoding)
	}
}

type GrantsStatusParams struct {
	Common
}

// GrantInfo is one of the caller's live reuse grants.
type GrantInfo struct {
	Name string `json:"name"`
	// Kind is "secret" or "action"; Params, for an action, are the values
	// the grant covers.
	Kind       string            `json:"kind,omitempty"`
	Params     map[string]string `json:"params,omitempty"`
	Scope      string            `json:"scope"`
	ApprovalID string            `json:"approval_id"`
	ExpiresAt  time.Time         `json:"expires_at"`
}

type GrantsStatusResult struct {
	Grants []GrantInfo `json:"grants"`
}

// GrantsDropParams drops the caller's grants for Names, or all of them.
type GrantsDropParams struct {
	Common
	Names []string `json:"names,omitempty"`
}

type GrantsDropResult struct {
	Dropped int `json:"dropped"`
}

type ActionListParams struct {
	Common
}

// ParamSchema describes one parameter an action needs.
type ParamSchema struct {
	Name             string   `json:"name"`
	Description      string   `json:"description,omitempty"`
	Allowed          []string `json:"allowed,omitempty"`
	Pattern          string   `json:"pattern,omitempty"`
	AllowLeadingDash bool     `json:"allow_leading_dash,omitempty"`
}

type ActionInfo struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Params      []ParamSchema `json:"params"`
}

type ActionListResult struct {
	Actions []ActionInfo `json:"actions"`
}

type ActionRunParams struct {
	Common
	Name   string            `json:"name"`
	Params map[string]string `json:"params,omitempty"`
}

// ActionRunResult is how the action's command exited. Stdout is left out
// when it is withheld: a non-zero exit without return_on_failure.
type ActionRunResult struct {
	ExitCode       int    `json:"exit_code"`
	Stdout         string `json:"stdout,omitempty"`
	StdoutEncoding string `json:"stdout_encoding,omitempty"`
	StderrTail     string `json:"stderr_tail,omitempty"`
	StderrEncoding string `json:"stderr_encoding,omitempty"`
}

// ActionRunLen is the length of the encoded action.run result, measured
// without copying the output. A nil stdout is one that is withheld.
func ActionRunLen(exitCode int, stdout, stderrTail []byte) int {
	r := ActionRunResult{ExitCode: exitCode}
	n := 0
	// Empty strings are left out, so each part adds its key too.
	if stdout != nil {
		r.StdoutEncoding = valueEncoding(stdout)
		if len(stdout) > 0 {
			n += len(`,"stdout":`) + ValueLen(stdout)
		}
	}
	if len(stderrTail) > 0 {
		r.StderrEncoding = valueEncoding(stderrTail)
		n += len(`,"stderr_tail":`) + ValueLen(stderrTail)
	}
	b, err := Marshal(r)
	if err != nil {
		return MaxMessage + 1
	}
	return len(b) + n
}
