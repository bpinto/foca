package core

import (
	"crypto/ed25519"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/policy"
)

// guestRig is a rig whose instance has a guest relay, so guest-session
// applies. The foca CLI and shells are skipped on prompts.
func guestRig(t *testing.T, p policy.Policy, decisions ...fake.Decision) *rig {
	r := newRig(t, all(p), decisions...)
	r.inst.GuestRelay = make(ed25519.PublicKey, ed25519.PublicKeySize)
	r.svc.opts.SkipAncestors = []string{"foca", "bash"}
	return r
}

// relayed is a call that arrived through the relay: the host sees the
// forwarded connection (ssh, session sid:10:100), the relay names a foca CLI
// in guest session gsession, run by bash, run by gh, run by claude.
func (r *rig) relayed(conn, gsession string) Call {
	c := r.from(conn, "sid:10:100")
	c.Guest = &identity.GuestInfo{
		PID: 812, StartTime: 5, UID: 1000, PIDStable: true, Session: gsession, Name: "foca",
		Parents: []identity.Proc{{PID: 800, Name: "bash"}, {PID: 790, Name: "gh"}, {PID: 700, Name: "claude"}},
	}
	return c
}

func TestGuestSessionReusesOnlyOnItsWholeKey(t *testing.T) {
	base := func(r *rig) Call { return r.relayed("c1", "sid:780:1") }
	cases := []struct {
		name  string
		next  func(r *rig) Call
		reuse bool
	}{
		{"same guest session, another connection", func(r *rig) Call { return r.relayed("c2", "sid:780:1") }, true},
		{"other guest session", func(r *rig) Call { return r.relayed("c1", "sid:781:1") }, false},
		{"recycled guest sid, other leader start", func(r *rig) Call { return r.relayed("c1", "sid:780:2") }, false},
		{"other forwarded connection", func(r *rig) Call {
			c := base(r)
			c.Peer.Session = "sid:11:100"
			return c
		}, false},
		{"guest pid not pinned", func(r *rig) Call { c := base(r); c.Guest.PIDStable = false; return c }, false},
		{"host pid not pinned", func(r *rig) Call { c := base(r); c.Peer.PIDStable = false; return c }, false},
		{"no guest session", func(r *rig) Call { return r.relayed("c1", "") }, false},
		{"no guest identity", func(r *rig) Call { c := base(r); c.Guest = nil; return c }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := guestRig(t, reuse(time.Hour, policy.ScopeGuestSession), fake.Approve, fake.Approve)
			if err := r.read(t, base(r), "github-pat"); err != nil {
				t.Fatal(err)
			}
			if err := r.read(t, tc.next(r), "github-pat"); err != nil {
				t.Fatal(err)
			}
			if reused := r.prompts() == 1; reused != tc.reuse {
				t.Fatalf("reused = %v, want %v", reused, tc.reuse)
			}
		})
	}
}

// Only an instance whose config names a relay takes guest identity for a
// key, whatever a call carries.
func TestGuestScopeNeedsTheInstancesRelay(t *testing.T) {
	r := guestRig(t, reuse(time.Hour, policy.ScopeGuestSession), fake.Approve, fake.Approve)
	r.inst.GuestRelay = nil
	r.read(t, r.relayed("c1", "sid:780:1"), "github-pat")
	r.read(t, r.relayed("c1", "sid:780:1"), "github-pat")
	if r.prompts() != 2 || r.grantCount() != 0 {
		t.Fatalf("%d prompts, %d grants without a relay", r.prompts(), r.grantCount())
	}
}

// The grant records each key component with who vouched for it.
func TestGuestSessionGrantRecordsItsKey(t *testing.T) {
	r := guestRig(t, reuse(15*time.Minute, policy.ScopeGuestSession), fake.Approve)
	if err := r.read(t, r.relayed("c1", "sid:780:1"), "github-pat"); err != nil {
		t.Fatal(err)
	}
	if p := r.auth.Requests()[0].Prompt; !strings.Contains(p, "15m, this session") {
		t.Fatalf("prompt %q", p)
	}
	ev := r.events(audit.TypeApprovalGranted)[0]
	k := ev.Approval.ScopeKey
	if ev.Approval.Scope != "guest-session" || k.PeerSession == nil || k.PeerSession.Value != "sid:10:100" || k.PeerSession.By != "host" ||
		k.GuestSession == nil || k.GuestSession.Value != "sid:780:1" || k.GuestSession.By != "guest" {
		t.Fatalf("scope key %+v", k)
	}
	if ev.Client == nil || ev.Client.GuestVerified == nil || ev.Client.GuestVerified.PID != 812 {
		t.Fatalf("client %+v", ev.Client)
	}
}

// Every guest name is one the process gave itself, so each carries the mark,
// and the skip list applies by name: foca and bash are passed over.
func TestGuestNamesAreMarkedAndSkippedByName(t *testing.T) {
	r := guestRig(t, policy.Policy{Kind: policy.EveryTime}, fake.Approve)
	r.read(t, r.relayed("c1", "sid:780:1"), "github-pat")
	if p := r.auth.Requests()[0].Prompt; p != "share:\n🔑 GitHub PAT\n🖥️ VM dev\n👤 gh "+UnsealedMark+" via claude "+UnsealedMark {
		t.Fatalf("prompt %q", p)
	}
}

func guestPrompt(t *testing.T, g identity.GuestInfo) string {
	t.Helper()
	vm := identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"}
	p, ok := BuildPrompt(PromptInput{Operation: "secret.read", Realm: vm, Resources: refs("GitHub PAT"),
		Requester:  plugin.Requester{Peer: identity.VerifiedPeer{Exe: "/usr/bin/ssh", Opaque: true, Realm: vm}, GuestVerified: &g},
		ShowClient: true, Skip: []string{"bash", "zsh", "tmux", "foca"}})
	if !ok {
		t.Fatal("prompt too long")
	}
	return p
}

// guestFrom is a caller in a chain of comm names, its terminal's session led
// by the process at index leader.
func guestFrom(leader int, names ...string) identity.GuestInfo {
	g := identity.GuestInfo{PID: 10, StartTime: 1, PIDStable: true, Name: names[0]}
	for i, n := range names[1:] {
		g.Parents = append(g.Parents, identity.Proc{PID: 11 + i, StartTime: 1, Name: n})
	}
	g.Session = "sid:" + strconv.Itoa(10+leader) + ":1"
	return g
}

// What runs the terminal (a tmux server, sshd, systemd) never names the
// requester: the chain ends at the shell that owns the terminal, and that
// shell is named when nothing else is left.
func TestGuestChainEndsAtTheTerminal(t *testing.T) {
	cases := []struct {
		g    identity.GuestInfo
		want string
	}{
		{guestFrom(3, "foca", "bash", "claude", "zsh", "tmux: server", "systemd"), "share:\n🔑 GitHub PAT\n🖥️ VM dev\n👤 claude ⚠"},
		{guestFrom(1, "foca", "zsh", "tmux: server", "systemd"), "share:\n🔑 GitHub PAT\n🖥️ VM dev\n👤 zsh ⚠"},
		{guestFrom(0, "foca", "systemd"), "share:\n🔑 GitHub PAT\n🖥️ VM dev\n👤 foca ⚠"},
	}
	for _, tc := range cases {
		if got := guestPrompt(t, tc.g); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
	// A leader matched by pid alone could be a later process: no cut, and
	// no shell named in place of a program.
	g := guestFrom(1, "foca", "zsh", "tmux: server", "systemd")
	g.Session = "sid:11:2"
	if got := guestPrompt(t, g); got != "share:\n🔑 GitHub PAT\n🖥️ VM dev\n👤 tmuxserver ⚠ via systemd ⚠" {
		t.Errorf("leader with another start time: %q", got)
	}
}

func TestCommNamesMarkWhatTheKernelCut(t *testing.T) {
	cases := map[string]string{
		"git-credential-":  "git-credential-…",
		"gh":               "gh",
		".claude-wrapped":  "claude",
		".terraform-wrap":  "terraform",
		".terraform-wr":    ".terraform-wr",
		".kubectl-wrappe":  "kubectl",
		".a-very-long-nam": ".a-very-long-nam…",
		"x…y⚠z":            "xyz", // the marks are foca's alone
	}
	for in, want := range cases {
		if got, _ := commName(in); got != want {
			t.Errorf("commName(%q) = %q, want %q", in, got, want)
		}
	}
	g := guestFrom(2, "foca", "git-credential-", "zsh")
	if got := guestPrompt(t, g); got != "share:\n🔑 GitHub PAT\n🖥️ VM dev\n👤 git-credential-… ⚠" {
		t.Errorf("prompt %q", got)
	}
}
