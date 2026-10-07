// Package helper adapts an external helper executable to foca's plugin
// interfaces (design §5, D2). It is used where a platform API needs a
// language other than Go; in practice that is foca-darwin, a Swift binary
// for Touch ID, the Keychain and macOS sleep and lock events.
//
// Protocol v1: the helper is run as `<path> <kind>`. One-shot kinds read
// one JSON request on stdin and write one JSON response on stdout:
//
//	stdin : {"v":1,"op":"approve","params":{…}}
//	stdout: {"v":1,"ok":true,"result":{…}}
//	     or {"v":1,"ok":false,"error":{"code":"denied","message":"…"}}
//
// The events kind is long-lived: see Events. Logs go to stderr.
package helper

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/protocol"
)

// Protocol is the helper protocol version this adapter speaks.
const Protocol = 1

// Kinds a helper can implement. Each is the helper's first argument.
const (
	KindInfo          = "info"
	KindAuthenticator = "authenticator"
	KindKeyProtector  = "key-protector"
	KindEvents        = "events"
)

// Error codes a helper may answer with.
const (
	CodeDenied      = "denied"      // the user refused
	CodeUnavailable = "unavailable" // no prompt or store can be used right now
	CodeTimeout     = "timeout"     // the helper's own deadline passed
	CodeCancelled   = "cancelled"   // stopped by SIGTERM or by the system
	CodeNotFound    = "not_found"   // no such key
	CodeExists      = "exists"      // a key already exists; never overwritten
	CodeMismatch    = "mismatch"    // sealed data doesn't belong to this vault
	CodeBadRequest  = "bad_request" // malformed request, unknown op or version
	CodeInternal    = "internal"
)

// Limits on what a helper may send back.
const (
	maxResponse  = 64 << 10
	maxStderr    = 4 << 10
	defaultGrace = 2 * time.Second
)

// Config says which executable to trust and how.
type Config struct {
	// Path is absolute and comes from host config; PATH is never searched.
	Path string
	// SHA256, if set, pins the file's content (hex).
	SHA256 string
	// Home is the helper's HOME. Empty means this process's HOME.
	Home string
	// Grace is how long a helper has to exit after SIGTERM before SIGKILL.
	Grace time.Duration
	Log   *slog.Logger
}

// Helper runs one trusted helper executable.
type Helper struct {
	cfg   Config
	kinds []string
}

// Error is a helper's error answer.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "helper: " + e.Code
	}
	return "helper: " + e.Code + ": " + e.Message
}

// Is lets errors.Is match on the code alone.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Message == "" && t.Code == e.Code
}

// Open checks the helper file and asks it which kinds it implements. Every
// kind in need must be among them.
func Open(ctx context.Context, cfg Config, need ...string) (*Helper, error) {
	if cfg.Home == "" {
		cfg.Home = os.Getenv("HOME")
	}
	if cfg.Grace <= 0 {
		cfg.Grace = defaultGrace
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	cfg.SHA256 = strings.ToLower(cfg.SHA256)
	h := &Helper{cfg: cfg}
	var info struct {
		Kinds   []string `json:"kinds"`
		Version string   `json:"version,omitempty"`
	}
	ictx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := h.call(ictx, KindInfo, "info", struct{}{}, &info); err != nil {
		return nil, fmt.Errorf("helper %s: info: %w", cfg.Path, err)
	}
	for _, k := range need {
		if !slices.Contains(info.Kinds, k) {
			return nil, fmt.Errorf("helper %s doesn't implement %q (it offers %s)", cfg.Path, k, strings.Join(info.Kinds, ", "))
		}
	}
	h.kinds = info.Kinds
	return h, nil
}

// Path is the configured helper path.
func (h *Helper) Path() string { return h.cfg.Path }

// check runs the trust checks: absolute path, owner and mode of the file
// and every directory above it, and the optional pin. It runs before every
// spawn, so a helper replaced after start-up is refused too. It returns the
// resolved path, which is what gets run.
func (h *Helper) check() (string, error) {
	resolved, err := fsutil.CheckTrustedFile(h.cfg.Path)
	if err != nil {
		return "", fmt.Errorf("helper not trusted: %w", err)
	}
	if h.cfg.SHA256 == "" {
		return resolved, nil
	}
	f, err := os.Open(resolved)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	want, err := hex.DecodeString(h.cfg.SHA256)
	if err != nil || subtle.ConstantTimeCompare(sum.Sum(nil), want) != 1 {
		return "", fmt.Errorf("helper not trusted: %s doesn't match its sha256 pin", resolved)
	}
	return resolved, nil
}

// env is everything the helper gets from us: no caller data, no secrets.
func (h *Helper) env() []string {
	env := []string{"HOME=" + h.cfg.Home, fmt.Sprintf("FOCA_HELPER_PROTOCOL=%d", Protocol)}
	if lang := os.Getenv("LANG"); lang != "" {
		env = append(env, "LANG="+lang)
	}
	return env
}

// command builds the helper's process. When ctx ends it gets SIGTERM, and
// SIGKILL if it hasn't exited after the grace period.
func (h *Helper) command(ctx context.Context, kind string) (*exec.Cmd, error) {
	path, err := h.check()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, path, kind)
	cmd.Env = h.env()
	cmd.Dir = "/"
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = h.cfg.Grace
	return cmd, nil
}

type request struct {
	V      int    `json:"v"`
	Op     string `json:"op"`
	Params any    `json:"params"`
}

type response struct {
	V      int             `json:"v"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message,omitempty"`
	} `json:"error,omitempty"`
}

// call runs one request. When ctx ends the helper gets SIGTERM, then SIGKILL
// after the grace period, and call returns ctx's error.
func (h *Helper) call(ctx context.Context, kind, op string, params, result any) error {
	req, err := json.Marshal(request{V: Protocol, Op: op, Params: params})
	if err != nil {
		return err
	}
	defer zero(req)
	return h.exchange(ctx, kind, req, result)
}

// exchange sends raw request bytes; tests use it for malformed requests.
func (h *Helper) exchange(ctx context.Context, kind string, req []byte, result any) error {
	cmd, err := h.command(ctx, kind)
	if err != nil {
		return err
	}
	stdout := &capped{max: maxResponse}
	stderr := &capped{max: maxStderr}
	defer stdout.zero()
	cmd.Stdin = bytes.NewReader(req)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()
	if s := strings.TrimSpace(stderr.String()); s != "" {
		h.cfg.Log.Debug("helper stderr", "kind", kind, "text", s)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("helper %s: %w", kind, ctx.Err())
	}
	if stdout.over {
		return fmt.Errorf("helper %s: response over %d bytes", kind, maxResponse)
	}
	if stdout.Len() == 0 {
		if runErr != nil {
			return fmt.Errorf("helper %s failed: %v%s", kind, runErr, tail(stderr))
		}
		return fmt.Errorf("helper %s: no response", kind)
	}
	if err := decodeResponse(stdout.Bytes(), result); err != nil {
		return fmt.Errorf("helper %s: %w", kind, err)
	}
	// A success counts only from a helper that also exited cleanly: one
	// that answered and then crashed or failed is an error, never an
	// approval. Error answers keep their meaning whatever the exit status.
	if runErr != nil {
		return fmt.Errorf("helper %s answered but then failed: %v%s", kind, runErr, tail(stderr))
	}
	return nil
}

func decodeResponse(b []byte, result any) error {
	b = bytes.TrimSpace(b)
	if err := protocol.CheckStrict(b, reflect.TypeOf(response{})); err != nil {
		return fmt.Errorf("malformed response: %w", err)
	}
	var r response
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return fmt.Errorf("malformed response: %w", err)
	}
	if r.V != Protocol {
		return fmt.Errorf("protocol version %d, want %d", r.V, Protocol)
	}
	if !r.OK {
		if r.Error == nil || r.Error.Code == "" {
			return errors.New("malformed response: ok is false with no error code")
		}
		return &Error{Code: r.Error.Code, Message: clean(r.Error.Message)}
	}
	if r.Error != nil {
		return errors.New("malformed response: ok is true with an error")
	}
	if result == nil {
		return nil
	}
	if len(r.Result) == 0 {
		r.Result = []byte("{}")
	}
	defer zero(r.Result)
	if err := protocol.CheckStrict(r.Result, reflect.TypeOf(result).Elem()); err != nil {
		return fmt.Errorf("malformed result: %w", err)
	}
	rd := json.NewDecoder(bytes.NewReader(r.Result))
	rd.DisallowUnknownFields()
	if err := rd.Decode(result); err != nil {
		return fmt.Errorf("malformed result: %w", err)
	}
	return nil
}

// capped is a buffer that stops growing at max and remembers that it did.
// It doesn't embed bytes.Buffer: io.Copy would use the buffer's ReadFrom
// and bypass the cap.
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); len(p) > room {
		c.over = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *capped) Len() int       { return c.buf.Len() }
func (c *capped) Bytes() []byte  { return c.buf.Bytes() }
func (c *capped) String() string { return c.buf.String() }

// zero clears the buffer, spare capacity included. Copies left behind by
// growth are not reached; zeroing is best effort (design §12.4).
func (c *capped) zero() {
	b := c.buf.Bytes()
	zero(b[:cap(b)])
}

func tail(stderr *capped) string {
	s := strings.TrimSpace(stderr.String())
	if s == "" {
		return ""
	}
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	return ": " + clean(s)
}

// clean bounds helper text before it reaches logs or audit.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		if b.Len() >= 256 {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
