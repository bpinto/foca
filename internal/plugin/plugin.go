// Package plugin defines the interfaces every pluggable part of foca
// implements. Each kind ships a fake or in-memory implementation for tests.
package plugin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/identity"
)

var (
	// ErrUnavailable: the authenticator can't show a prompt right now.
	ErrUnavailable = errors.New("authenticator unavailable")
	// ErrNotFound: no such resource.
	ErrNotFound = errors.New("not found")
	// ErrNotExposed: the resource exists but this instance may not see it.
	// It matches ErrNotFound so callers can't tell the two apart.
	ErrNotExposed = fmt.Errorf("%w: not exposed to this instance", ErrNotFound)
	// ErrExists: a resource with this id already exists.
	ErrExists = errors.New("already exists")
	// ErrNotInitialized: the vault has not been created yet (foca init).
	ErrNotInitialized = errors.New("vault not initialized")
)

// NotInitialized is ErrNotInitialized for a named vault.
type NotInitialized struct{ Vault string }

func (e NotInitialized) Error() string        { return "vault " + e.Vault + " is not initialized" }
func (e NotInitialized) Is(target error) bool { return target == ErrNotInitialized }

// ---- Authenticator ----

type ResourceRef struct {
	Kind    string // "secret" | "action"
	ID      string
	Display string // trusted display name from the host
	// Vault is the vault a secret is in, as named by its ID, "<vault>:<id>"
	// (package secretname). Audit events name it.
	Vault string
}

// Requester carries the three identity levels side by side, never merged.
type Requester struct {
	Peer          identity.VerifiedPeer
	GuestVerified *identity.GuestInfo  // set only by a verified relay
	Reported      *identity.ClientInfo // the client's own claim
}

type ApprovalRequest struct {
	ID        string
	Instance  string
	Realm     identity.Realm
	Operation string
	Resources []ResourceRef
	Params    map[string]string
	Requester Requester
	// Prompt is the full reason text, built by the core from trusted
	// templates. Authenticators show it verbatim and never build their own.
	Prompt  string
	Timeout time.Duration
}

type ApprovalResult struct {
	Approved bool
	Method   string // e.g. "biometry", "polkit-auth_self"
	Detail   string // free text for audit only
}

type Authenticator interface {
	Name() string
	// Available reports whether a prompt can be shown right now, without
	// showing any UI.
	Available(ctx context.Context) (ok bool, reason string)
	// Approve shows the prompt. A denial is Approved=false with a nil error.
	// It returns ErrUnavailable if no prompt could be shown and ctx.Err()
	// when the deadline passes.
	Approve(ctx context.Context, req ApprovalRequest) (ApprovalResult, error)
}

// ---- Key protector ----

type KeyRef struct {
	Vault   string
	VaultID string
}

type KeyProtector interface {
	Name() string
	Seal(ctx context.Context, ref KeyRef, dek []byte) (sealed []byte, err error)
	Unseal(ctx context.Context, ref KeyRef, sealed []byte) (dek []byte, err error)
	Destroy(ctx context.Context, ref KeyRef, sealed []byte) error
}

// DEKFunc returns a vault's data key and a function that zeroes and releases
// it. Stores that don't encrypt (the in-memory test store) need none, so a
// nil DEKFunc stands for "no key".
type DEKFunc func(ctx context.Context) (dek []byte, release func(), err error)

// ---- Secret store ----

type SecretMeta struct {
	ID          string    `json:"id"`
	DisplayName string    `json:"display_name,omitempty"`
	Description string    `json:"description,omitempty"`
	Created     time.Time `json:"created"`
	Updated     time.Time `json:"updated,omitempty"`
}

// Display is the name shown to the user: the display name, else the id.
func (m SecretMeta) Display() string {
	if m.DisplayName != "" {
		return m.DisplayName
	}
	return m.ID
}

// SecretValue holds secret bytes. It is never a string so it can be zeroed.
type SecretValue struct {
	Bytes []byte
}

// Zero overwrites the value in place.
func (v *SecretValue) Zero() {
	for i := range v.Bytes {
		v.Bytes[i] = 0
	}
	v.Bytes = nil
}

// SecretStore holds encrypted values and their metadata. dek is the vault's
// data key; stores that don't encrypt (the in-memory test store) ignore it.
// Read returns a copy the caller owns and must zero.
type SecretStore interface {
	List(ctx context.Context, dek []byte) ([]SecretMeta, error)
	Read(ctx context.Context, dek []byte, id string) (SecretMeta, SecretValue, error)
	Put(ctx context.Context, dek []byte, meta SecretMeta, v SecretValue) error
	Delete(ctx context.Context, dek []byte, id string) error
}

// ---- Provider ----

type Resource struct {
	Ref         ResourceRef
	Description string
	// Params is an action's parameter schema, for action.list.
	Params []ParamInfo
	// Uses lists the secrets an action reads on the host (env_secrets),
	// resolved for the calling instance. The prompt and audit name them.
	Uses []ResourceRef
}

// ParamInfo describes one parameter a caller must supply.
type ParamInfo struct {
	Name             string
	Description      string
	Allowed          []string
	Pattern          string
	AllowLeadingDash bool
}

type Result struct {
	Value []byte // owned by the caller, who must zero it
	// Run is set by action providers, also alongside an error when the
	// command ran but its result can't be returned.
	Run *RunInfo
}

// UseError: an action uses a secret the calling instance can't read. Err
// is ErrNotFound or ErrNotExposed.
type UseError struct {
	Secret string
	Err    error
}

func (e *UseError) Error() string {
	return fmt.Sprintf("uses secret %s: %v", e.Secret, e.Err)
}

func (e *UseError) Unwrap() error { return e.Err }

// Reasons an action's run fails, as RunError.Reason. Each is the audit
// reason too.
const (
	RunTimeout          = "timeout"
	RunCancelled        = "cancelled"
	RunOutputTooLarge   = "output_too_large"
	RunOutputInvalid    = "output_invalid"
	RunCommandUntrusted = "command_untrusted"
	RunStartFailed      = "start_failed"
	RunSecretUnreadable = "secret_unreadable"
)

// RunError is an action that failed to run, or whose result can't be
// returned.
type RunError struct {
	Reason string
	Err    error
}

func (e *RunError) Error() string { return e.Reason + ": " + e.Err.Error() }
func (e *RunError) Unwrap() error { return e.Err }

// RunInfo is how an action's command ran. Value holds stdout when it is
// returned.
type RunInfo struct {
	// ExitCode is -1 when the command was killed by a signal or never ran.
	ExitCode    int
	Duration    time.Duration
	StdoutBytes int64
	StderrBytes int64
	// StderrSHA256 is empty when the action uses secrets: a hash of
	// output that may hold one would let anyone with the audit log test
	// guesses of it.
	StderrSHA256 string
	// StderrTail is the end of stderr (masked when masking is on), for the
	// caller. It is never logged.
	StderrTail []byte
	// StdoutReturned is false when stdout is withheld: a non-zero exit
	// without return_on_failure.
	StdoutReturned bool
	Masked         bool
	TimedOut       bool
}

// Provider defines what a credential is and how an approved request is
// answered. One provider instance is bound to one foca instance, so it
// already knows that instance's exposure rules.
type Provider interface {
	Kind() string
	List(ctx context.Context) ([]Resource, error)
	// Resolve looks up every name of one request at once, in order, so the
	// request costs one read of the store however many names it carries.
	// errs[i] is ErrNotFound (or ErrNotExposed) for an unknown name; err is
	// a failure of the lookup itself.
	Resolve(ctx context.Context, ids []string) (rs []Resource, errs []error, err error)
	Validate(ctx context.Context, r Resource, params map[string]string) (map[string]string, error)
	// Serve is only ever called by the core after a successful approval.
	Serve(ctx context.Context, r Resource, params map[string]string) (Result, error)
}

// ---- Platform events ----

type EventKind string

const (
	// Sleep, ScreenLock and SessionEnd wipe every grant.
	EventSleep      EventKind = "sleep"
	EventScreenLock EventKind = "screen-lock"
	EventSessionEnd EventKind = "session-end"
	// Ready means the source is subscribed and will report the events
	// above. Until a source sends it, and again after Run returns, reuse
	// is off (design D13).
	EventReady EventKind = "ready"
)

type PlatformEvent struct {
	Kind   EventKind
	At     time.Time
	Source string
	// Done, if set, is closed by the core once it has handled the event:
	// for a sleep, once grants are wiped and the lock is recorded. A source
	// that can hold sleep back (logind's inhibitor, the helper's ack) lets
	// the machine sleep only then, or after HandledWait.
	Done chan struct{}
}

// HandledWait bounds how long a source holds sleep back for the core. It
// stays under the 5 s that logind and macOS allow a delay anyway.
const HandledWait = 4 * time.Second

// Handled closes Done, if set. Only the core calls it, once per event.
func (e PlatformEvent) Handled() {
	if e.Done != nil {
		close(e.Done)
	}
}

// WaitHandled returns once the core has handled e, max has passed or ctx
// has ended, whichever comes first.
func (e PlatformEvent) WaitHandled(ctx context.Context, max time.Duration) {
	if e.Done == nil {
		return
	}
	t := time.NewTimer(max)
	defer t.Stop()
	select {
	case <-e.Done:
	case <-t.C:
	case <-ctx.Done():
	}
}

// PlatformEvents reports sleep, screen lock and session end, so the service
// can wipe grants. Run blocks until ctx ends or the source fails; any return
// while ctx is still live counts as a failure.
type PlatformEvents interface {
	Name() string
	Run(ctx context.Context, out chan<- PlatformEvent) error
}

// ---- Peer identifier ----

// PeerIdentifier reports the connecting process from kernel data. It fills
// everything except Opaque and Realm, which come from instance config.
type PeerIdentifier interface {
	Identify(conn *net.UnixConn) (identity.VerifiedPeer, error)
}

// ---- Audit sink ----

type AuditSink interface {
	// Append must make the event durable before returning.
	Append(ctx context.Context, e *audit.Event) (seq uint64, err error)
	Query(ctx context.Context, f audit.Filter, p audit.Page) (events []audit.Event, next uint64, err error)
	Subscribe(ctx context.Context, f audit.Filter, fromSeq uint64) (<-chan audit.Event, error)
	Close() error
}
