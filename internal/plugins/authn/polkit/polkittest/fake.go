package polkittest

import (
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// Answer is how the fake answers an interactive check.
type Answer int

const (
	Approve Answer = iota
	Deny           // authentication failed
	Dismiss        // the user closed the dialog
	NoAgent        // no agent took the challenge
	Hang           // nobody answers until the check is cancelled
	Keep           // approved, and polkit keeps the authorization
	Fail           // a D-Bus error
)

// Subject is polkit's (sa{sv}) subject.
type Subject struct {
	Kind    string
	Details map[string]dbus.Variant
}

// Result is CheckAuthorization's (bba{ss}) answer.
type Result struct {
	Authorized bool
	Challenge  bool
	Details    map[string]string
}

// Action is one entry of EnumerateActions.
type Action struct {
	ID, Description, Message, Vendor, VendorURL, Icon string
	Any, Inactive, Active                             uint32
	Annotations                                       map[string]string
}

// Check is one CheckAuthorization call the fake received.
type Check struct {
	Sender   string
	Subject  Subject
	ActionID string
	Details  map[string]string
	Flags    uint32
	CancelID string
}

// Fake owns org.freedesktop.PolicyKit1 on a private bus. Interactive checks
// get the next scripted answer, then Default; checks without interaction
// get PreCheck.
type Fake struct {
	mu        sync.Mutex
	Actions   []Action
	PreCheck  Result
	Default   Answer
	script    []Answer
	checks    []Check
	cancelled []string
	revoked   []string
	pending   map[string]chan struct{}
	// Started receives each interactive check as it starts, if set.
	Started chan Check
	// Translations replace each action's message for a locale, as an
	// xml:lang message in its file would.
	Translations map[string]string
}

// StartFake starts the fake authority on the bus at addr. Its action is
// installed as the policy describes, for owners, and the pre-check says
// auth_self.
func StartFake(t testing.TB, addr string, message, owners string) *Fake {
	t.Helper()
	conn := Connect(t, addr)
	f := &Fake{
		Actions: []Action{{
			ID: "io.github.bpinto.foca.approve", Message: message, Active: 1,
			Annotations: map[string]string{"org.freedesktop.policykit.owner": owners},
		}},
		PreCheck: Result{Challenge: true, Details: map[string]string{"polkit.result": "auth_self"}},
		Default:  Deny,
		pending:  map[string]chan struct{}{},
	}
	if err := conn.Export(fakeMethods{f}, "/org/freedesktop/PolicyKit1/Authority", "org.freedesktop.PolicyKit1.Authority"); err != nil {
		t.Fatal(err)
	}
	if r, err := conn.RequestName("org.freedesktop.PolicyKit1", dbus.NameFlagDoNotQueue); err != nil || r != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("request name: %v %v", r, err)
	}
	return f
}

// Script sets the answers to the next interactive checks.
func (f *Fake) Script(answers ...Answer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.script = answers
}

// Set changes the fake's state under its lock.
func (f *Fake) Set(fn func(f *Fake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// Checks returns every CheckAuthorization call so far.
func (f *Fake) Checks() []Check {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Check(nil), f.checks...)
}

// Cancelled returns the cancellation ids of CancelCheckAuthorization calls.
func (f *Fake) Cancelled() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cancelled...)
}

// Revoked returns the temporary authorizations revoked.
func (f *Fake) Revoked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.revoked...)
}

type fakeMethods struct{ f *Fake }

func (m fakeMethods) EnumerateActions(locale string) ([]Action, *dbus.Error) {
	m.f.mu.Lock()
	defer m.f.mu.Unlock()
	out := append([]Action(nil), m.f.Actions...)
	if msg, ok := m.f.Translations[locale]; ok {
		for i := range out {
			out[i].Message = msg
		}
	}
	return out, nil
}

func (m fakeMethods) CheckAuthorization(sender dbus.Sender, subject Subject, actionID string, details map[string]string, flags uint32, cancelID string) (Result, *dbus.Error) {
	f := m.f
	f.mu.Lock()
	c := Check{Sender: string(sender), Subject: subject, ActionID: actionID, Details: details, Flags: flags, CancelID: cancelID}
	f.checks = append(f.checks, c)
	if flags&1 == 0 {
		r := f.PreCheck
		f.mu.Unlock()
		return r, nil
	}
	a := f.Default
	if len(f.script) > 0 {
		a, f.script = f.script[0], f.script[1:]
	}
	cancel := make(chan struct{})
	f.pending[cancelID] = cancel
	started := f.Started
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		delete(f.pending, cancelID)
		f.mu.Unlock()
	}()
	if started != nil {
		started <- c
	}

	switch a {
	case Approve:
		return Result{Authorized: true, Details: map[string]string{}}, nil
	case Deny:
		return Result{Details: map[string]string{}}, nil
	case Dismiss:
		return Result{Details: map[string]string{"polkit.dismissed": "true"}}, nil
	case NoAgent:
		return Result{Challenge: true, Details: map[string]string{"polkit.result": "auth_self"}}, nil
	case Keep:
		return Result{Authorized: true, Details: map[string]string{
			"polkit.retains_authorization_after_challenge": "true", "polkit.temporary_authorization_id": "tmpauthz7",
		}}, nil
	case Hang:
		select {
		case <-cancel:
			return Result{}, dbus.NewError("org.freedesktop.PolicyKit1.Error.Cancelled", []any{"cancelled"})
		case <-time.After(30 * time.Second):
			return Result{Details: map[string]string{}}, nil
		}
	default:
		return Result{}, dbus.NewError("org.freedesktop.PolicyKit1.Error.Failed", []any{"scripted failure"})
	}
}

func (m fakeMethods) CancelCheckAuthorization(id string) *dbus.Error {
	f := m.f
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelled = append(f.cancelled, id)
	if c, ok := f.pending[id]; ok {
		close(c)
		delete(f.pending, id)
	}
	return nil
}

func (m fakeMethods) RevokeTemporaryAuthorizationById(id string) *dbus.Error {
	m.f.mu.Lock()
	defer m.f.mu.Unlock()
	m.f.revoked = append(m.f.revoked, id)
	return nil
}

// Open reports how many interactive checks are still waiting for an
// answer.
func (f *Fake) Open() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pending)
}
