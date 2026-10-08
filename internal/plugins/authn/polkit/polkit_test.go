package polkit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugin/authntest"
	"github.com/bpinto/foca/internal/plugins/authn/polkit/polkittest"
)

const testUser = "foca-test"

func newAuth(addr string) *Authenticator {
	return &Authenticator{Dial: func() (*dbus.Conn, error) { return dbus.Connect(addr) }, UID: os.Getuid(), User: testUser}
}

func owner() string { return "unix-user:" + testUser }

func fake(t *testing.T) (*Authenticator, *polkittest.Fake) {
	t.Helper()
	addr := polkittest.Bus(t)
	return newAuth(addr), polkittest.StartFake(t, addr, Message, owner())
}

func request(prompt string) plugin.ApprovalRequest {
	return plugin.ApprovalRequest{ID: "01JREQUEST", Prompt: prompt, Timeout: time.Minute}
}

// waitFor polls until cond holds, for at most 3 s.
func waitFor(cond func() bool) bool {
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return cond()
}

func TestConformanceFakeAuthority(t *testing.T) {
	authntest.Run(t, func(t *testing.T) authntest.Harness {
		a, f := fake(t)
		return authntest.Harness{
			Authenticator: a,
			Can:           []authntest.Answer{authntest.Approve, authntest.Deny, authntest.Ignore, authntest.Unavailable},
			Answer: func(ans authntest.Answer) {
				f.Script(map[authntest.Answer]polkittest.Answer{
					authntest.Approve: polkittest.Approve, authntest.Deny: polkittest.Deny,
					authntest.Ignore: polkittest.Hang, authntest.Unavailable: polkittest.NoAgent,
				}[ans])
			},
			Shown: func() []string {
				var shown []string
				for _, c := range f.Checks() {
					if c.Flags&1 != 0 {
						shown = append(shown, strings.Replace(Message, "$(reason)", c.Details["reason"], 1))
					}
				}
				return shown
			},
			Shows:     escape,
			TakenDown: func() bool { return waitFor(func() bool { return f.Open() == 0 }) },
			Grace:     cancelGrace,
		}
	})
}

// The real polkitd can't be told to approve (it takes an agent's answer
// only from uid 0), so the suite's approval test skips here.
func TestConformanceRealPolkitd(t *testing.T) {
	authntest.Run(t, func(t *testing.T) authntest.Harness {
		addr := polkittest.Bus(t)
		pol, err := PolicyFile(strconv.Itoa(os.Getuid()))
		if err != nil {
			t.Fatal(err)
		}
		polkittest.StartPolkitd(t, addr, pol, nil, polkittest.Session{Active: true})
		var agent *polkittest.Agent
		return authntest.Harness{
			Authenticator: newAuth(addr),
			Can:           []authntest.Answer{authntest.Deny, authntest.Ignore, authntest.Unavailable},
			Answer: func(ans authntest.Answer) {
				if ans == authntest.Unavailable {
					return // no agent
				}
				agent = polkittest.RegisterAgent(t, addr, os.Getpid())
				agent.Hold(ans == authntest.Ignore)
			},
			Shown: func() []string {
				if agent == nil {
					return nil
				}
				var shown []string
				for _, b := range agent.Begun() {
					shown = append(shown, b.Message)
				}
				return shown
			},
			Shows:     escape,
			TakenDown: func() bool { return agent == nil || waitFor(func() bool { return agent.Open() == 0 }) },
			Grace:     cancelGrace,
		}
	})
}

// Each prompt checks the action for this process, by its bus name, with the
// prompt text as the one detail, after a check without interaction.
func TestApproveAsksPolkitForThisProcess(t *testing.T) {
	a, f := fake(t)
	f.Script(polkittest.Approve)
	res, err := a.Approve(context.Background(), request("let gh use GitHub PAT."))
	if err != nil || !res.Approved || res.Method != "polkit-auth_self" {
		t.Fatalf("got %+v %v", res, err)
	}
	checks := f.Checks()
	if len(checks) != 2 {
		t.Fatalf("%d checks, want a pre-check and the prompt", len(checks))
	}
	for i, c := range checks {
		name, _ := c.Subject.Details["name"].Value().(string)
		if c.Subject.Kind != "system-bus-name" || name != c.Sender || len(c.Subject.Details) != 1 {
			t.Errorf("check %d: subject %+v, sender %s: want this connection's bus name", i, c.Subject, c.Sender)
		}
		if c.ActionID != ActionID || len(c.Details) != 1 || c.Details["reason"] != "let gh use GitHub PAT." {
			t.Errorf("check %d: action %s details %v", i, c.ActionID, c.Details)
		}
	}
	if checks[0].Flags != 0 || checks[1].Flags != allowUserInteraction || checks[1].CancelID != "01JREQUEST" {
		t.Errorf("flags %d then %d, cancel id %q", checks[0].Flags, checks[1].Flags, checks[1].CancelID)
	}
}

func TestAnswersMapAsTheCoreExpects(t *testing.T) {
	cases := []struct {
		answer   polkittest.Answer
		approved bool
		detail   string
		err      func(error) bool
	}{
		{polkittest.Approve, true, "", nil},
		{polkittest.Deny, false, "authentication failed", nil},
		{polkittest.Dismiss, false, "dismissed", nil},
		{polkittest.NoAgent, false, "", func(err error) bool { return errors.Is(err, plugin.ErrUnavailable) }},
		// Neither a denial nor "unavailable": the core records an
		// authenticator error.
		{polkittest.Fail, false, "", func(err error) bool {
			return err != nil && !errors.Is(err, plugin.ErrUnavailable) && !errors.Is(err, context.DeadlineExceeded)
		}},
	}
	for _, c := range cases {
		a, f := fake(t)
		f.Script(c.answer)
		res, err := a.Approve(context.Background(), request("let a program use A."))
		if c.err == nil && err != nil || c.err != nil && !c.err(err) {
			t.Errorf("answer %d: error %v", c.answer, err)
		}
		if res.Approved != c.approved || res.Detail != c.detail {
			t.Errorf("answer %d: got %+v", c.answer, res)
		}
	}
}

// An approval polkit keeps could answer the next prompt without anyone
// seeing it. It is revoked and refused.
func TestApprovalPolkitKeepsIsRevokedAndRefused(t *testing.T) {
	a, f := fake(t)
	f.Script(polkittest.Keep)
	res, err := a.Approve(context.Background(), request("let a program use A."))
	if err == nil || res.Approved {
		t.Fatalf("got %+v %v, want an error", res, err)
	}
	if r := f.Revoked(); len(r) != 1 || r[0] != "tmpauthz7" {
		t.Fatalf("revoked %v", r)
	}
}

// When polkit would not ask (a rule says yes, an approval is kept, the
// session can't be asked, or it would keep the next approval), nothing is
// shown and the request can't be approved.
func TestRefusedWithoutAPromptWhenPolkitWouldNotAsk(t *testing.T) {
	cases := map[string]polkittest.Result{
		"authorized":     {Authorized: true, Details: map[string]string{}},
		"kept":           {Authorized: true, Details: map[string]string{"polkit.temporary_authorization_id": "x"}},
		"refused":        {Details: map[string]string{}},
		"auth_self_keep": {Challenge: true, Details: map[string]string{"polkit.result": "auth_self_keep", "polkit.retains_authorization_after_challenge": "1"}},
		"retains":        {Challenge: true, Details: map[string]string{"polkit.result": "auth_self", "polkit.retains_authorization_after_challenge": "1"}},
		"unknown":        {Challenge: true, Details: map[string]string{"polkit.result": "auth_other"}},
	}
	for name, pre := range cases {
		a, f := fake(t)
		f.Set(func(f *polkittest.Fake) { f.PreCheck = pre })
		f.Script(polkittest.Approve)
		if ok, why := a.Available(context.Background()); ok || why == "" {
			t.Errorf("%s: available %v %q", name, ok, why)
		}
		res, err := a.Approve(context.Background(), request("let a program use A."))
		if res.Approved || !errors.Is(err, plugin.ErrUnavailable) {
			t.Errorf("%s: got %+v %v, want ErrUnavailable", name, res, err)
		}
		for _, c := range f.Checks() {
			if c.Flags != 0 {
				t.Errorf("%s: a prompt was shown", name)
			}
		}
	}
}

func TestAuthAdminIsAccepted(t *testing.T) {
	a, f := fake(t)
	f.Set(func(f *polkittest.Fake) {
		f.PreCheck = polkittest.Result{Challenge: true, Details: map[string]string{"polkit.result": "auth_admin"}}
	})
	f.Script(polkittest.Approve)
	res, err := a.Approve(context.Background(), request("let a program use A."))
	if err != nil || !res.Approved || res.Method != "polkit-auth_admin" {
		t.Fatalf("got %+v %v", res, err)
	}
}

// polkit before 127 doesn't say what it asks for. A challenge it won't keep
// is still asked every time, so it is accepted, without naming the kind.
func TestOlderPolkitWithoutAResultIsAccepted(t *testing.T) {
	a, f := fake(t)
	f.Set(func(f *polkittest.Fake) {
		f.PreCheck = polkittest.Result{Challenge: true, Details: map[string]string{}}
	})
	f.Script(polkittest.Approve, polkittest.Dismiss)
	res, err := a.Approve(context.Background(), request("let a program use A."))
	if err != nil || !res.Approved || res.Method != "polkit" {
		t.Fatalf("got %+v %v", res, err)
	}
	res, err = a.Approve(context.Background(), request("let a program use A."))
	if err != nil || res.Approved || res.Method != "polkit" || res.Detail != "dismissed" {
		t.Fatalf("got %+v %v", res, err)
	}
	// Retained is refused whether or not polkit names the kind.
	f.Set(func(f *polkittest.Fake) {
		f.PreCheck = polkittest.Result{Challenge: true, Details: map[string]string{"polkit.retains_authorization_after_challenge": "1"}}
	})
	if ok, why := a.Available(context.Background()); ok || !strings.Contains(why, "keep") {
		t.Fatalf("available %v %q", ok, why)
	}
}

// The action must show foca's text, and polkit passes that text only from
// the action's owners, so both are checked before anything is asked.
func TestActionMustBeInstalledAsFocaNeedsIt(t *testing.T) {
	uid := strconv.Itoa(os.Getuid())
	cases := []struct {
		name    string
		actions func([]polkittest.Action) []polkittest.Action
		ok      bool
	}{
		{"as installed", func(a []polkittest.Action) []polkittest.Action { return a }, true},
		{"missing", func([]polkittest.Action) []polkittest.Action { return nil }, false},
		{"other message", func(a []polkittest.Action) []polkittest.Action {
			a[0].Message = "Authentication is required"
			return a
		}, false},
		{"no owner", func(a []polkittest.Action) []polkittest.Action {
			a[0].Annotations = nil
			return a
		}, false},
		{"another owner", func(a []polkittest.Action) []polkittest.Action {
			a[0].Annotations["org.freedesktop.policykit.owner"] = "unix-user:root unix-group:" + testUser
			return a
		}, false},
		{"owner by uid among others", func(a []polkittest.Action) []polkittest.Action {
			a[0].Annotations["org.freedesktop.policykit.owner"] = "unix-user:root unix-user:" + uid
			return a
		}, true},
	}
	for _, c := range cases {
		a, f := fake(t)
		f.Set(func(f *polkittest.Fake) { f.Actions = c.actions(f.Actions) })
		ok, why := a.Available(context.Background())
		if ok != c.ok {
			t.Errorf("%s: available %v %q", c.name, ok, why)
		}
		if !ok && len(f.Checks()) > 0 {
			t.Errorf("%s: checked before refusing", c.name)
		}
	}
}

// A translated message would replace foca's text for an agent in that
// locale, so the message is checked in each locale an agent likely uses:
// C, the agent library's default en_US.UTF-8, and the service's own.
func TestTranslatedMessageIsRefused(t *testing.T) {
	cases := []struct {
		locale, env, value string
		ok                 bool
	}{
		{"en_US.UTF-8", "", "", false},
		{"C", "", "", false},
		{"de_DE.UTF-8", "LANG", "de_DE.UTF-8", false},
		{"fr_FR.UTF-8", "LC_MESSAGES", "fr_FR.UTF-8", false},
		{"pt_BR.UTF-8", "LC_ALL", "pt_BR.UTF-8", false},
		// Only the text matters: the same message under a locale is fine.
		{"en_US.UTF-8", "", "", true},
	}
	for _, c := range cases {
		for _, k := range []string{"LANG", "LC_ALL", "LC_MESSAGES"} {
			t.Setenv(k, "")
		}
		if c.env != "" {
			t.Setenv(c.env, c.value)
		}
		a, f := fake(t)
		msg := "Approve a routine system update"
		if c.ok {
			msg = Message
		}
		f.Set(func(f *polkittest.Fake) { f.Translations = map[string]string{c.locale: msg} })
		f.Script(polkittest.Approve)
		ok, why := a.Available(context.Background())
		res, err := a.Approve(context.Background(), request("let a program use A."))
		if ok != c.ok || res.Approved != c.ok {
			t.Errorf("%s: available %v %q, approve %+v %v", c.locale, ok, why, res, err)
		}
		if !c.ok && (!errors.Is(err, plugin.ErrUnavailable) || len(f.Checks()) > 0) {
			t.Errorf("%s: %v, %d checks", c.locale, err, len(f.Checks()))
		}
	}
}

func TestTimeoutCancelsTheCheck(t *testing.T) {
	a, f := fake(t)
	f.Script(polkittest.Hang)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := a.Approve(ctx, request("let a program use A."))
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if c := f.Cancelled(); len(c) != 1 || c[0] != "01JREQUEST" {
		t.Fatalf("cancelled %v", c)
	}
}

func TestNoPolkitIsUnavailable(t *testing.T) {
	a := newAuth(polkittest.Bus(t))
	if ok, why := a.Available(context.Background()); ok || !strings.Contains(why, "not running") {
		t.Fatalf("available %v %q", ok, why)
	}
	if _, err := a.Approve(context.Background(), request("x.")); !errors.Is(err, plugin.ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
	a.Dial = func() (*dbus.Conn, error) { return nil, errors.New("no bus") }
	if _, err := a.Approve(context.Background(), request("x.")); !errors.Is(err, plugin.ErrUnavailable) {
		t.Fatalf("got %v", err)
	}
}

func TestPolicyFile(t *testing.T) {
	b, err := PolicyFile("bruno", "1000")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`<action id="io.github.bpinto.foca.approve">`,
		`<message>foca is trying to $(reason)</message>`,
		`<allow_any>no</allow_any>`, `<allow_inactive>no</allow_inactive>`, `<allow_active>auth_self</allow_active>`,
		`<annotate key="org.freedesktop.policykit.owner">unix-user:bruno unix-user:1000</annotate>`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("policy lacks %s", want)
		}
	}
	for _, bad := range [][]string{nil, {""}, {"a b"}, {"<x>"}, {"unix-user:x"}, {"-x"}} {
		if _, err := PolicyFile(bad...); err == nil {
			t.Errorf("owners %q accepted", bad)
		}
	}
}

// ---- against the real polkitd ----

func realPolkitd(t *testing.T, rules map[string]string, s polkittest.Session, owners ...string) (*Authenticator, string) {
	t.Helper()
	addr := polkittest.Bus(t)
	if owners == nil {
		owners = []string{strconv.Itoa(os.Getuid())}
	}
	pol, err := PolicyFile(owners...)
	if err != nil {
		t.Fatal(err)
	}
	polkittest.StartPolkitd(t, addr, pol, rules, s)
	return newAuth(addr), addr
}

func rule(result string) map[string]string {
	return map[string]string{"50-test.rules": `polkit.addRule(function(action, subject) {
  if (action.id == "io.github.bpinto.foca.approve") return polkit.Result.` + result + `;
});`}
}

// Rules and sessions that would let a request through without the user, or
// keep the approval, are refused before any prompt.
func TestRealPolkitdRefusesWhatWouldNotAsk(t *testing.T) {
	cases := map[string]struct {
		rules   map[string]string
		session polkittest.Session
	}{
		"rule says yes":    {rule("YES"), polkittest.Session{Active: true}},
		"rule keeps":       {rule("AUTH_SELF_KEEP"), polkittest.Session{Active: true}},
		"rule keeps admin": {rule("AUTH_ADMIN_KEEP"), polkittest.Session{Active: true}},
		"rule says no":     {rule("NO"), polkittest.Session{Active: true}},
		"inactive session": {nil, polkittest.Session{}},
		"remote session":   {nil, polkittest.Session{Active: true, Remote: true}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a, addr := realPolkitd(t, c.rules, c.session)
			agent := polkittest.RegisterAgent(t, addr, os.Getpid())
			if ok, why := a.Available(context.Background()); ok {
				t.Fatalf("available")
			} else {
				t.Log(why)
			}
			res, err := a.Approve(context.Background(), request("let a program use A."))
			if res.Approved || !errors.Is(err, plugin.ErrUnavailable) {
				t.Fatalf("got %+v %v", res, err)
			}
			if b := agent.Begun(); len(b) > 0 {
				t.Fatalf("prompted: %+v", b)
			}
		})
	}
}

func TestRealPolkitdAuthAdmin(t *testing.T) {
	a, addr := realPolkitd(t, rule("AUTH_ADMIN"), polkittest.Session{Active: true})
	polkittest.RegisterAgent(t, addr, os.Getpid())
	res, err := a.Approve(context.Background(), request("let a program use A."))
	// polkit before 127 doesn't say it asked for auth_admin.
	if err != nil || res.Approved || (res.Method != "polkit-auth_admin" && res.Method != "polkit") || res.Detail != "dismissed" {
		t.Fatalf("got %+v %v", res, err)
	}
}

// polkit refuses details (the prompt text) from a caller the action doesn't
// list as an owner, which is why the policy names the user.
func TestRealPolkitdNeedsTheOwnerForThePromptText(t *testing.T) {
	a, addr := realPolkitd(t, nil, polkittest.Session{Active: true}, "root")
	if ok, why := a.Available(context.Background()); ok || !strings.Contains(why, "owner") {
		t.Fatalf("available %v %q", ok, why)
	}
	conn := polkittest.Connect(t, addr)
	s := subject{Kind: "system-bus-name", Details: map[string]dbus.Variant{"name": dbus.MakeVariant(conn.Names()[0])}}
	var r authResult
	err := conn.Object(busName, authorityPath).Call(authorityIface+".CheckAuthorization", 0,
		s, ActionID, map[string]string{"reason": "x"}, uint32(0), "").Store(&r)
	if err == nil || !strings.Contains(err.Error(), "Only trusted callers") {
		t.Fatalf("polkit took details from a non-owner: %+v %v", r, err)
	}
}

// polkit shows an agent the action's message in the agent's own locale, so
// a translated message would replace foca's text, and with it everything
// the prompt says. The message is checked in the locales an agent uses: the
// service's own, and the agent library's default, en_US.UTF-8.
func TestRealPolkitdTranslatedMessageIsRefused(t *testing.T) {
	for _, c := range []struct{ name, lang, xmlLang, agent string }{
		{"agent default", "", "en_US", "en_US.UTF-8"},
		{"session language", "de_DE.UTF-8", "de", "de_DE.UTF-8"},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("LANG", c.lang)
			t.Setenv("LC_ALL", "")
			t.Setenv("LC_MESSAGES", "")
			pol, err := PolicyFile(strconv.Itoa(os.Getuid()))
			if err != nil {
				t.Fatal(err)
			}
			pol = bytes.Replace(pol, []byte("    <defaults>"),
				[]byte(`    <message xml:lang="`+c.xmlLang+`">Approve a routine system update</message>`+"\n    <defaults>"), 1)
			addr := polkittest.Bus(t)
			polkittest.StartPolkitd(t, addr, pol, nil, polkittest.Session{Active: true})
			agent := polkittest.RegisterAgentIn(t, addr, os.Getpid(), c.agent)
			a := newAuth(addr)
			ok, why := a.Available(context.Background())
			res, err := a.Approve(context.Background(), request("let a program use A."))
			if b := agent.Begun(); len(b) > 0 {
				t.Fatalf("the agent was shown %q", b[0].Message)
			}
			if ok || !strings.Contains(why, "Approve a routine system update") {
				t.Fatalf("available %v %q", ok, why)
			}
			if res.Approved || !errors.Is(err, plugin.ErrUnavailable) {
				t.Fatalf("got %+v %v, want ErrUnavailable", res, err)
			}
		})
	}
}

// Some agents read the message as markup, so a "<" in a param value could
// open a tag that hides the rest of the prompt. polkit is given "<", ">" and
// "&" as escapes every agent shows as text.
func TestMarkupInThePromptReachesPolkitEscaped(t *testing.T) {
	a, f := fake(t)
	f.Script(polkittest.Approve)
	prompt := `run "List PRs" with repo="a<span size='1'>b</span> & c".`
	if _, err := a.Approve(context.Background(), request(prompt)); err != nil {
		t.Fatal(err)
	}
	want := `run "List PRs" with repo="a\u003cspan size='1'\u003eb\u003c/span\u003e \u0026 c".`
	checks := f.Checks()
	if len(checks) != 2 {
		t.Fatalf("%d checks", len(checks))
	}
	for _, c := range checks {
		if got := c.Details["reason"]; got != want {
			t.Fatalf("reason %q, want %q", got, want)
		}
	}
}
