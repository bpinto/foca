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
	Method   string // e.g. "biometry"
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
}

type Result struct {
	Value []byte // owned by the caller, who must zero it
}

// Provider defines what a credential is and how an approved request is
// answered. One provider instance is bound to one foca instance, so it
// already knows that instance's exposure rules.
type Provider interface {
	Kind() string
	List(ctx context.Context) ([]Resource, error)
	// Resolve returns ErrNotFound (or ErrNotExposed) for unknown names.
	Resolve(ctx context.Context, id string) (Resource, error)
	Validate(ctx context.Context, r Resource, params map[string]string) (map[string]string, error)
	// Serve is only ever called by the core after a successful approval.
	Serve(ctx context.Context, r Resource, params map[string]string) (Result, error)
}

// ---- Platform events ----

type EventKind string

const (
	EventSleep      EventKind = "sleep"
	EventScreenLock EventKind = "screen-lock"
	EventSessionEnd EventKind = "session-end"
)

type PlatformEvent struct {
	Kind   EventKind
	At     time.Time
	Source string
}

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
