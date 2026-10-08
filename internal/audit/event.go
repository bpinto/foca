// Package audit defines the versioned audit event format and its sinks.
//
// Events never contain secret values, action output or key material.
package audit

import (
	"time"

	"github.com/bpinto/foca/internal/identity"
)

// Version is the event format version. Bump only on incompatible changes.
const Version = 1

// Event types.
const (
	TypeServerStart     = "server.start"
	TypeServerStop      = "server.stop"
	TypeConfigLoad      = "config.load"
	TypeApprovalGranted = "approval.granted"
	TypeApprovalDenied  = "approval.denied"
	TypeApprovalReused  = "approval.reused"
	TypeApprovalTimeout = "approval.timeout"
	TypeSecretList      = "secret.list"
	TypeActionList      = "action.list"
	TypeActionRun       = "action.run"
	TypeSecretRead      = "secret.read"
	TypeSecretAdd       = "secret.add"
	TypeSecretUpdate    = "secret.update"
	TypeSecretRemove    = "secret.remove"
	TypeVaultInit       = "vault.init"
	TypeVaultRecover    = "vault.recover"
	TypeVaultRekey      = "vault.rekey"
	TypeConfigReload    = "config.reload"
	TypeLock            = "lock"
	TypeRequestRejected = "request.rejected"
	TypeGrantsDrop      = "grants.drop"
)

// Outcomes.
const (
	OutcomeOK       = "ok"
	OutcomeDenied   = "denied"
	OutcomeError    = "error"
	OutcomeNotFound = "not_found"
	OutcomeRejected = "rejected"
)

// Origins: where a request entered.
const (
	OriginClientSocket = "client-socket"
	OriginHostCLI      = "host-cli"
)

// Approval modes.
const (
	ModeFresh  = "fresh"
	ModeReused = "reused"
	ModeNone   = "none"
)

type Event struct {
	V         int       `json:"v"`
	Seq       uint64    `json:"seq"`
	ID        string    `json:"id"`
	TS        time.Time `json:"ts"`
	Instance  string    `json:"instance,omitempty"`
	Vault     string    `json:"vault,omitempty"`
	Type      string    `json:"type"`
	Outcome   string    `json:"outcome"`
	Reason    string    `json:"reason,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	Origin    string    `json:"origin,omitempty"` // client-socket | host-cli
	// Resource is set on per-resource events; Resources on approval events
	// that cover a batch.
	Resource  *Resource  `json:"resource,omitempty"`
	Resources []Resource `json:"resources,omitempty"`
	// Uses lists the secrets an action reads on the host (env_secrets).
	Uses     []Resource        `json:"uses,omitempty"`
	Params   map[string]string `json:"params,omitempty"`
	Approval *Approval         `json:"approval,omitempty"`
	Peer     *Peer             `json:"peer,omitempty"`
	Client   *Client           `json:"client,omitempty"`
	Error    *ErrorInfo        `json:"error,omitempty"`
	// Run says how an action's command ran. Never its output.
	Run *Run `json:"run,omitempty"`
	// Count is what the event itself counts: the grants a lock or
	// grants.drop removed, the secrets a secret.list returned.
	Count int `json:"count,omitempty"`
	// Coalesced is set only on an event that stands for a burst of others
	// like it (design §9.6).
	Coalesced *Coalesced `json:"coalesced,omitempty"`
}

// Coalesced says how many events were folded into one, and which event,
// written in full, they followed.
type Coalesced struct {
	Count    int    `json:"count"`
	AfterSeq uint64 `json:"after_seq"`
	// Reasons counts the folded events by their own reason, when reasons
	// that a realm must not tell apart share one window (design §9.6).
	Reasons map[string]int `json:"reasons,omitempty"`
}

// Run is an action's process, without its output (design §8.1): stdout is
// never logged, and stderr only as its length and, for actions that use no
// secrets, its sha256.
type Run struct {
	ExitCode       int    `json:"exit_code"`
	DurationMS     int64  `json:"duration_ms"`
	StdoutBytes    int64  `json:"stdout_bytes"`
	StdoutReturned bool   `json:"stdout_returned"`
	StderrBytes    int64  `json:"stderr_bytes"`
	StderrSHA256   string `json:"stderr_sha256,omitempty"`
	Masked         bool   `json:"masked,omitempty"`
	TimedOut       bool   `json:"timed_out,omitempty"`
}

type Resource struct {
	Kind string `json:"kind"` // secret | action
	ID   string `json:"id"`
}

type Approval struct {
	ID            string     `json:"id,omitempty"`
	Mode          string     `json:"mode"`
	Authenticator string     `json:"authenticator,omitempty"`
	Method        string     `json:"method,omitempty"`
	Scope         string     `json:"scope,omitempty"`
	ScopeKey      *ScopeKey  `json:"scope_key,omitempty"`
	GrantedAt     *time.Time `json:"granted_at,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	PromptText    string     `json:"prompt_text,omitempty"`
}

// Peer holds kernel-verified identity only.
type Peer struct {
	Verified *identity.VerifiedPeer `json:"verified"`
}

// Client holds identity that did not come from the host kernel. Each level is
// kept in its own field and never merged into Peer.
type Client struct {
	GuestVerified *identity.GuestInfo  `json:"guest_verified,omitempty"`
	Reported      *identity.ClientInfo `json:"reported,omitempty"`
}

type ErrorInfo struct {
	Code    string `json:"code"`
	Message string `json:"message,omitempty"`
}

// ScopeKey is the exact key a grant was made for. Each component records who
// vouched for it, so a UI can show what a reuse was matched on.
type ScopeKey struct {
	Instance    string   `json:"instance"`
	Connection  *KeyPart `json:"connection,omitempty"`
	PeerSession *KeyPart `json:"peer_session,omitempty"`
}

type KeyPart struct {
	Value string `json:"value"`
	By    string `json:"by"` // "host": the host kernel
}

// Types lists every event type foca records, Outcomes and Modes every
// outcome and approval mode; foca events accepts only these as filters.
var (
	Types = []string{
		TypeServerStart, TypeServerStop, TypeConfigLoad, TypeConfigReload,
		TypeApprovalGranted, TypeApprovalDenied, TypeApprovalReused, TypeApprovalTimeout,
		TypeSecretList, TypeSecretRead, TypeActionList, TypeActionRun,
		TypeSecretAdd, TypeSecretUpdate, TypeSecretRemove, TypeVaultInit, TypeVaultRecover, TypeVaultRekey,
		TypeGrantsDrop, TypeLock, TypeRequestRejected,
	}
	Outcomes = []string{OutcomeOK, OutcomeDenied, OutcomeError, OutcomeNotFound, OutcomeRejected}
	Modes    = []string{ModeFresh, ModeReused, ModeNone}
)

// Resource kinds.
const (
	KindSecret = "secret"
	KindAction = "action"
)
