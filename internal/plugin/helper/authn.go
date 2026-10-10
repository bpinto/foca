package helper

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bpinto/foca/internal/plugin"
)

// Authenticator asks the helper to show the approval prompt (Touch ID on
// macOS). The prompt text is the core's, shown verbatim.
type Authenticator struct {
	h    *Helper
	name string
	// fallback allows the device password when biometry fails or is
	// unavailable. Off by default (design §17).
	fallback bool
}

func NewAuthenticator(h *Helper, name string, allowPasswordFallback bool) *Authenticator {
	return &Authenticator{h: h, name: name, fallback: allowPasswordFallback}
}

func (a *Authenticator) Name() string { return a.name }

type availableParams struct {
	AllowPasswordFallback bool `json:"allow_password_fallback"`
}

type availableResult struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
}

// Available asks without showing any UI.
func (a *Authenticator) Available(ctx context.Context) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var r availableResult
	if err := a.h.call(ctx, KindAuthenticator, "available", availableParams{a.fallback}, &r); err != nil {
		return false, err.Error()
	}
	if !r.Available && r.Reason == "" {
		r.Reason = "the helper can't show a prompt"
	}
	return r.Available, r.Reason
}

type approveParams struct {
	Reason                string `json:"reason"`
	TimeoutMS             int64  `json:"timeout_ms"`
	AllowPasswordFallback bool   `json:"allow_password_fallback"`
}

type approveResult struct {
	Approved bool   `json:"approved"`
	Method   string `json:"method,omitempty"`
}

// errHelperTimeout is the helper's own deadline, or the system taking the
// prompt down. Both are a timeout to the core, not a denial.
var errHelperTimeout = fmt.Errorf("helper: prompt ended without an answer: %w", context.DeadlineExceeded)

func (a *Authenticator) Approve(ctx context.Context, req plugin.ApprovalRequest) (plugin.ApprovalResult, error) {
	timeout := req.Timeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = time.Until(dl)
	}
	if timeout <= 0 {
		return plugin.ApprovalResult{}, context.DeadlineExceeded
	}
	p := approveParams{Reason: req.Prompt, TimeoutMS: timeout.Milliseconds(), AllowPasswordFallback: a.fallback}
	var r approveResult
	err := a.h.call(ctx, KindAuthenticator, "approve", p, &r)
	if err == nil {
		return plugin.ApprovalResult{Approved: r.Approved, Method: clean(r.Method)}, nil
	}
	var he *Error
	if !errors.As(err, &he) {
		return plugin.ApprovalResult{}, err
	}
	switch he.Code {
	case CodeDenied:
		return plugin.ApprovalResult{Approved: false, Detail: he.Message}, nil
	case CodeUnavailable:
		return plugin.ApprovalResult{}, fmt.Errorf("%w: %s", plugin.ErrUnavailable, he.Message)
	case CodeTimeout, CodeCancelled:
		return plugin.ApprovalResult{}, errHelperTimeout
	default:
		return plugin.ApprovalResult{}, err
	}
}
