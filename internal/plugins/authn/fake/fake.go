// Package fake is a scripted authenticator for tests. It must never be
// selectable from config in a production build (see internal/wiring).
package fake

import (
	"context"
	"errors"
	"sync"

	"github.com/bpinto/foca/internal/plugin"
)

type Decision int

const (
	Approve Decision = iota
	Deny
	// Hang blocks until the request's context ends, like a prompt nobody
	// answers.
	Hang
	Fail
)

// Authenticator answers each prompt with the next scripted decision, then
// with Default once the script runs out.
type Authenticator struct {
	mu          sync.Mutex
	script      []Decision
	Default     Decision
	unavailable bool
	requests    []plugin.ApprovalRequest
	// Started, if set, receives each request when its prompt "opens".
	Started chan plugin.ApprovalRequest
}

func New(script ...Decision) *Authenticator {
	return &Authenticator{script: script, Default: Deny}
}

func (a *Authenticator) Name() string { return "fake" }

func (a *Authenticator) SetUnavailable(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.unavailable = v
}

func (a *Authenticator) Available(context.Context) (bool, string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.unavailable {
		return false, "fake authenticator set unavailable"
	}
	return true, ""
}

// Requests returns every prompt shown so far.
func (a *Authenticator) Requests() []plugin.ApprovalRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]plugin.ApprovalRequest(nil), a.requests...)
}

func (a *Authenticator) Approve(ctx context.Context, req plugin.ApprovalRequest) (plugin.ApprovalResult, error) {
	a.mu.Lock()
	if a.unavailable {
		a.mu.Unlock()
		return plugin.ApprovalResult{}, plugin.ErrUnavailable
	}
	a.requests = append(a.requests, req)
	d := a.Default
	if len(a.script) > 0 {
		d, a.script = a.script[0], a.script[1:]
	}
	started := a.Started
	a.mu.Unlock()

	if started != nil {
		started <- req
	}
	switch d {
	case Approve:
		return plugin.ApprovalResult{Approved: true, Method: "fake"}, nil
	case Hang:
		<-ctx.Done()
		return plugin.ApprovalResult{}, ctx.Err()
	case Fail:
		return plugin.ApprovalResult{}, errors.New("fake authenticator failure")
	default:
		return plugin.ApprovalResult{Approved: false, Method: "fake"}, nil
	}
}
