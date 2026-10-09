// Package polkit asks for approval through polkit, the authority Linux
// desktops use for their "Authentication Required" dialogs (design §4.1).
//
// foca checks one action, ActionID, for its own process. The session's
// authentication agent shows the core's prompt text through the action's
// message and asks for the user's password, or whatever the PAM stack
// behind the agent accepts. polkit itself confirms the answer; an agent can
// only pass it on.
//
// polkit is trusted only as far as it is checked. Before every prompt the
// action must be installed as PolicyFile writes it, with no translated
// message an agent could show instead, and polkit must say it
// would really ask: an action that a rule answers "yes" to, or whose
// approval polkit keeps for later, is refused. Reuse is the job of foca's
// own grants (design §9.5), which a platform event can wipe.
//
// Like logind, only the bus's name owner is trusted: the system bus lets
// only polkitd own org.freedesktop.PolicyKit1, and sysbus makes sure the
// bus is the system's.
package polkit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/sysbus"
)

const (
	// ActionID is the polkit action every approval checks.
	ActionID = "io.github.bpinto.foca.approve"
	// Message frames the core's prompt text, as macOS frames it with
	// "<app> is trying to". polkit fills $(reason) from the request's
	// details in a single pass, so a "$(" in the reason is shown as it is.
	Message = "foca is trying to $(reason)"

	busName        = "org.freedesktop.PolicyKit1"
	authorityPath  = dbus.ObjectPath("/org/freedesktop/PolicyKit1/Authority")
	authorityIface = "org.freedesktop.PolicyKit1.Authority"
	ownerKey       = "org.freedesktop.policykit.owner"

	// allowUserInteraction is CheckAuthorization's only flag.
	allowUserInteraction = uint32(1)
	errCancelled         = "org.freedesktop.PolicyKit1.Error.Cancelled"
)

// cancelGrace bounds how long a timed-out prompt waits for polkit to take
// the dialog down and answer.
const cancelGrace = 2 * time.Second

// Authenticator shows each prompt through polkit.
type Authenticator struct {
	// Dial connects to the system bus; tests point it at a private one.
	Dial func() (*dbus.Conn, error)
	// UID and User name this process's user, which the action's owner
	// annotation must list: polkit passes details (the prompt text) only
	// from an action's owners.
	UID  int
	User string
}

func New() *Authenticator {
	a := &Authenticator{Dial: sysbus.Connect, UID: os.Getuid()}
	if u, err := user.LookupId(strconv.Itoa(a.UID)); err == nil {
		a.User = u.Username
	}
	return a
}

func (a *Authenticator) Name() string { return "polkit" }

// subject is polkit's (sa{sv}) subject.
type subject struct {
	Kind    string
	Details map[string]dbus.Variant
}

// authResult is CheckAuthorization's (bba{ss}) answer.
type authResult struct {
	Authorized bool
	Challenge  bool
	Details    map[string]string
}

// actionDesc is one entry of EnumerateActions: (ssssssuuua{ss}).
type actionDesc struct {
	ID, Description, Message, Vendor, VendorURL, Icon string
	Any, Inactive, Active                             uint32
	Annotations                                       map[string]string
}

// session is one connection to polkit, with foca's own process as the
// subject.
type session struct {
	conn    *dbus.Conn
	obj     dbus.BusObject
	subject subject
}

func (a *Authenticator) open() (*session, error) {
	conn, err := a.Dial()
	if err != nil {
		return nil, fmt.Errorf("polkit: connect to the system bus: %w", err)
	}
	names := conn.Names()
	if len(names) == 0 {
		conn.Close()
		return nil, errors.New("polkit: no unique name on the system bus")
	}
	// polkit resolves the bus name to this process through the bus, so
	// it can't be confused by a pid that is reused.
	return &session{
		conn:    conn,
		obj:     conn.Object(busName, authorityPath),
		subject: subject{Kind: "system-bus-name", Details: map[string]dbus.Variant{"name": dbus.MakeVariant(names[0])}},
	}, nil
}

// Available checks the action and asks polkit what it would require, with
// no interaction, so no UI is shown.
func (a *Authenticator) Available(ctx context.Context) (bool, string) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	s, err := a.open()
	if err != nil {
		return false, err.Error()
	}
	defer s.conn.Close()
	if _, err := a.ready(ctx, s, nil); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// ready checks that the action is installed as foca needs it and that
// polkit would ask the user, and returns what polkit will ask for
// ("auth_self" or "auth_admin", or "" from a polkit too old to say). Its
// errors are reasons no prompt can be shown.
func (a *Authenticator) ready(ctx context.Context, s *session, details map[string]string) (string, error) {
	var d actionDesc
	for _, locale := range locales() {
		var actions []actionDesc
		if err := s.obj.CallWithContext(ctx, authorityIface+".EnumerateActions", 0, locale).Store(&actions); err != nil {
			return "", fmt.Errorf("polkit: not running: %w", err)
		}
		i := slices.IndexFunc(actions, func(d actionDesc) bool { return d.ID == ActionID })
		if i < 0 {
			return "", fmt.Errorf("polkit: action %s is not installed; see `foca polkit-policy`", ActionID)
		}
		d = actions[i]
		if d.Message != Message {
			in := "as written"
			if locale != "" {
				in = "in locale " + strconv.Quote(locale)
			}
			return "", fmt.Errorf("polkit: action %s has the message %q %s, not %q, so the prompt would not show what is asked; reinstall it from `foca polkit-policy`", ActionID, d.Message, in, Message)
		}
	}
	if !a.owns(d.Annotations[ownerKey]) {
		return "", fmt.Errorf("polkit: action %s doesn't list this user (uid %d) in %s, so polkit won't show foca's prompt text; reinstall it from `foca polkit-policy`", ActionID, a.UID, ownerKey)
	}

	if details == nil {
		details = map[string]string{}
	}
	var r authResult
	if err := s.obj.CallWithContext(ctx, authorityIface+".CheckAuthorization", 0, s.subject, ActionID, details, uint32(0), "").Store(&r); err != nil {
		return "", fmt.Errorf("polkit: check %s: %w", ActionID, err)
	}
	switch {
	case r.Authorized:
		// A rule says yes, or an earlier approval was kept: polkit would
		// approve without anyone seeing the prompt.
		return "", fmt.Errorf("polkit: %s is allowed without asking (a rule says yes, or polkit kept an earlier approval); foca only uses an action polkit asks for every time", ActionID)
	case !r.Challenge:
		return "", fmt.Errorf("polkit: %s is refused here; polkit asks only in an active local session", ActionID)
	}
	// polkit before 127 doesn't name the requirement. A challenge it won't
	// retain is then still auth_self or auth_admin, just not which.
	need := r.Details["polkit.result"]
	switch {
	case r.Details["polkit.retains_authorization_after_challenge"] != "":
		return "", fmt.Errorf("polkit: %s would keep the approval for later (a *_keep default or rule); foca only uses an action polkit asks for every time", ActionID)
	case need != "" && need != "auth_self" && need != "auth_admin":
		return "", fmt.Errorf("polkit: %s asks for %q; foca needs auth_self or auth_admin", ActionID, need)
	}
	return need, nil
}

// locales are the ones the action's message is checked in, "" being the
// message as written. polkit gives an agent the message in the agent's own
// locale (its LANG, or en_US.UTF-8 without one), where a translation in the
// action file would replace foca's text. foca can't see an agent's locale,
// so it checks its own and that default.
func locales() []string {
	ls := []string{"", "C", "en_US.UTF-8"}
	for _, k := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := os.Getenv(k); v != "" && !slices.Contains(ls, v) {
			ls = append(ls, v)
		}
	}
	return ls
}

// method names how polkit asked, when it said.
func method(need string) string {
	if need == "" {
		return "polkit"
	}
	return "polkit-" + need
}

// owns reports whether the owner annotation lists this user, by name or
// uid.
func (a *Authenticator) owns(owners string) bool {
	for _, o := range strings.Fields(owners) {
		id, ok := strings.CutPrefix(o, "unix-user:")
		if ok && (id == strconv.Itoa(a.UID) || (a.User != "" && id == a.User)) {
			return true
		}
	}
	return false
}

// escape writes the prompt text for agents that read markup. Some show
// the message as Pango markup or Qt rich text, where a "<" in a param value
// could open a tag that hides the text after it; others show plain text.
// "<", ">" and "&" become \u003c, \u003e and \u0026, as JSON writes
// them, which every agent shows alike, as text. "&lt;" would read as "<" in
// one agent and as itself in another. A param value can't fake an escape:
// it is quoted, so its own backslashes show doubled.
func escape(prompt string) string { return markup.Replace(prompt) }

var markup = strings.NewReplacer("<", `\u003c`, ">", `\u003e`, "&", `\u0026`)

// errNoAnswer is the prompt ending without an answer that foca didn't
// cause: a timeout to the core, not a denial.
var errNoAnswer = fmt.Errorf("polkit: prompt ended without an answer: %w", context.DeadlineExceeded)

func (a *Authenticator) Approve(ctx context.Context, req plugin.ApprovalRequest) (plugin.ApprovalResult, error) {
	s, err := a.open()
	if err != nil {
		return plugin.ApprovalResult{}, fmt.Errorf("%w: %v", plugin.ErrUnavailable, err)
	}
	defer s.conn.Close()
	details := map[string]string{"reason": escape(req.Prompt)}
	// Checked again for this prompt: the action, rules or session may
	// have changed since Available.
	need, err := a.ready(ctx, s, details)
	if err != nil {
		if ctx.Err() != nil {
			return plugin.ApprovalResult{}, ctx.Err()
		}
		return plugin.ApprovalResult{}, fmt.Errorf("%w: %v", plugin.ErrUnavailable, err)
	}

	call := s.obj.Go(authorityIface+".CheckAuthorization", 0, make(chan *dbus.Call, 1),
		s.subject, ActionID, details, allowUserInteraction, req.ID)
	select {
	case <-call.Done:
	case <-ctx.Done():
		// Take the dialog down. Only this connection may cancel its own
		// check, by the id it gave.
		cctx, cancel := context.WithTimeout(context.Background(), cancelGrace)
		s.obj.CallWithContext(cctx, authorityIface+".CancelCheckAuthorization", 0, req.ID)
		select {
		case <-call.Done:
		case <-cctx.Done():
		}
		cancel()
		return plugin.ApprovalResult{}, ctx.Err()
	}

	var r authResult
	if err := call.Store(&r); err != nil {
		var de dbus.Error
		if errors.As(err, &de) && de.Name == errCancelled {
			return plugin.ApprovalResult{}, errNoAnswer
		}
		return plugin.ApprovalResult{}, fmt.Errorf("polkit: check %s: %w", ActionID, err)
	}
	switch {
	case r.Authorized && r.Details["polkit.temporary_authorization_id"] != "":
		// polkit kept this approval, or used one it had kept. Either way
		// it could answer for the next prompt without asking: drop it and
		// fail closed.
		cctx, cancel := context.WithTimeout(context.Background(), cancelGrace)
		s.obj.CallWithContext(cctx, authorityIface+".RevokeTemporaryAuthorizationById", 0, r.Details["polkit.temporary_authorization_id"])
		cancel()
		return plugin.ApprovalResult{}, fmt.Errorf("polkit: %s was approved with an authorization polkit keeps; foca refuses it", ActionID)
	case r.Authorized:
		return plugin.ApprovalResult{Approved: true, Method: method(need)}, nil
	case r.Challenge:
		// polkit still wants a challenge: no agent took it.
		return plugin.ApprovalResult{}, fmt.Errorf("%w: no polkit authentication agent is running for this session", plugin.ErrUnavailable)
	case r.Details["polkit.dismissed"] != "":
		return plugin.ApprovalResult{Method: method(need), Detail: "dismissed"}, nil
	default:
		return plugin.ApprovalResult{Method: method(need), Detail: "authentication failed"}, nil
	}
}

// ownerName is what an owner annotation may hold: a user name or uid.
var ownerName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$`)

// PolicyFile is the action file foca needs, for polkit's actions directory
// (/usr/share/polkit-1/actions on most systems). owners are the users who
// run foca, by name or uid: polkit shows the prompt text only for them.
func PolicyFile(owners ...string) ([]byte, error) {
	if len(owners) == 0 {
		return nil, errors.New("polkit: the policy needs at least one owner")
	}
	list := make([]string, len(owners))
	for i, o := range owners {
		if !ownerName.MatchString(o) {
			return nil, fmt.Errorf("polkit: %q is not a user name or uid", o)
		}
		list[i] = "unix-user:" + o
	}
	return fmt.Appendf(nil, policyTemplate, ActionID, Message, ownerKey, strings.Join(list, " ")), nil
}

// The defaults ask the user of an active local session for their own
// password every time. auth_admin also works; the *_keep forms and "yes"
// are refused at the first prompt.
const policyTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>foca</vendor>
  <vendor_url>https://github.com/bpinto/foca</vendor_url>
  <action id="%s">
    <description>Approve a foca request</description>
    <message>%s</message>
    <defaults>
      <allow_any>no</allow_any>
      <allow_inactive>no</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
    <annotate key="%s">%s</annotate>
  </action>
</policyconfig>
`
