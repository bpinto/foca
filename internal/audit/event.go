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
	TypeSecretRead      = "secret.read"
	TypeSecretAdd       = "secret.add"
	TypeSecretUpdate    = "secret.update"
	TypeSecretRemove    = "secret.remove"
	TypeVaultInit       = "vault.init"
	TypeConfigReload    = "config.reload"
	TypeLock            = "lock"
	TypeRequestRejected = "request.rejected"
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
	Resource  *Resource         `json:"resource,omitempty"`
	Resources []Resource        `json:"resources,omitempty"`
	Params    map[string]string `json:"params,omitempty"`
	Approval  *Approval         `json:"approval,omitempty"`
	Peer      *Peer             `json:"peer,omitempty"`
	Client    *Client           `json:"client,omitempty"`
	Error     *ErrorInfo        `json:"error,omitempty"`
	Count     int               `json:"count,omitempty"`
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
