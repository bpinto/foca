package core

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugin"
)

var skip = []string{"bash", "zsh", "tmux", "foca"}

func refs(names ...string) []plugin.ResourceRef {
	var out []plugin.ResourceRef
	for _, n := range names {
		out = append(out, plugin.ResourceRef{Kind: "secret", ID: n, Display: n})
	}
	return out
}

func TestPromptWording(t *testing.T) {
	vm := identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"}
	host := identity.Realm{Kind: "host", Name: "host", Peers: "direct"}
	claimed := &identity.ClientInfo{Exe: "/bin/gh", Parents: []identity.Proc{{Name: "bash"}, {Name: "claude"}}}
	ssh := identity.VerifiedPeer{Exe: "/usr/bin/ssh", Name: "ssh", Opaque: true}
	local := identity.VerifiedPeer{Exe: "/run/bin/foca", Name: "foca", ExeSealed: true, PIDStable: true,
		Parents: []identity.Proc{{Exe: "/bin/gh", Name: "gh", Sealed: true}, {Exe: "/bin/zsh", Name: "zsh", Sealed: true}, {Exe: "/opt/claude", Name: "claude", Sealed: true}}}
	ctr := identity.Realm{Kind: "container", Name: "web", Peers: "direct"}
	conmon := identity.Proc{Exe: "/usr/bin/conmon", Sealed: true}
	agent := []identity.Proc{{Exe: "/bin/bash", Sealed: true}, {Exe: "/home/u/.local/bin/claude"}}

	cases := []struct {
		name string
		in   PromptInput
		want string
	}{
		{"claimed in VM", PromptInput{Realm: vm, Resources: refs("GitHub PAT"), Requester: plugin.Requester{Peer: ssh, Reported: claimed}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n🖥️ VM dev\n❔ gh via claude (unverified)"},
		{"host-verified local", PromptInput{Realm: host, Resources: refs("GitHub PAT"), Requester: plugin.Requester{Peer: local}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n👤 gh via claude"},
		{"no identity", PromptInput{Realm: vm, Resources: refs("GitHub PAT"), Requester: plugin.Requester{Peer: ssh}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n🖥️ VM dev"},
		{"client hidden", PromptInput{Realm: vm, Resources: refs("GitHub PAT"), Requester: plugin.Requester{Peer: ssh, Reported: claimed}, ShowClient: false},
			"share:\n🔑 GitHub PAT\n🖥️ VM dev"},
		{"batch", PromptInput{Realm: vm, Resources: refs("a", "b", "c", "d", "e"), Requester: plugin.Requester{Peer: ssh}, ShowClient: true},
			"share:\n🔑 a, b, c, d and e\n🖥️ VM dev"},
		{"container", PromptInput{Realm: identity.Realm{Kind: "container", Name: "web", Peers: "opaque"}, Resources: refs("x"), Requester: plugin.Requester{Peer: ssh, Reported: claimed}, ShowClient: true},
			"share:\n🔑 x\n🚢 container web\n❔ gh via claude (unverified)"},
		// Kernel-verified, but the caller chose the file's name.
		{"unsealed container program", PromptInput{Realm: ctr, Resources: refs("GitHub PAT"), Requester: plugin.Requester{
			Peer: identity.VerifiedPeer{Exe: "/tmp/x/gh", Name: "gh", PIDStable: true, Parents: []identity.Proc{conmon}}}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n🚢 container web\n👤 gh ⚠ via conmon"},
		{"sealed container program", PromptInput{Realm: ctr, Resources: refs("GitHub PAT"), Requester: plugin.Requester{
			Peer: identity.VerifiedPeer{Exe: "/usr/bin/gh", ExeSealed: true, PIDStable: true, Parents: []identity.Proc{conmon}}}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n🚢 container web\n👤 gh via conmon"},
		// No pidfd: the pid might have been reused, so nothing is sealed.
		{"pid not pinned", PromptInput{Realm: ctr, Resources: refs("GitHub PAT"), Requester: plugin.Requester{
			Peer: identity.VerifiedPeer{Exe: "/usr/bin/gh", ExeSealed: true, Parents: []identity.Proc{conmon}}}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n🚢 container web\n👤 gh ⚠ via conmon ⚠"},
		// An unsealed "env" or "foca" can't hide itself behind its parent.
		{"unsealed skip name", PromptInput{Realm: host, Resources: refs("GitHub PAT"), Requester: plugin.Requester{
			Peer: identity.VerifiedPeer{Exe: "/home/u/.cache/x/foca", Name: "foca", PIDStable: true, Parents: agent}}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n👤 foca ⚠ via claude ⚠"},
		// No readable exe: comm is settable by the process itself.
		{"comm only", PromptInput{Realm: host, Resources: refs("GitHub PAT"), Requester: plugin.Requester{
			Peer: identity.VerifiedPeer{Name: "gh", ExeSealed: true, PIDStable: true}}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n👤 gh ⚠"},
		// A client claiming sealed parents gains nothing.
		{"claimed sealed", PromptInput{Realm: vm, Resources: refs("x"), Requester: plugin.Requester{Peer: ssh,
			Reported: &identity.ClientInfo{Exe: "/bin/gh", Parents: []identity.Proc{{Exe: "/bin/claude", Sealed: true}}}}, ShowClient: true},
			"share:\n🔑 x\n🖥️ VM dev\n❔ gh via claude (unverified)"},
		// A name can't carry the mark itself, sealed or claimed.
		{"mark in sealed name", PromptInput{Realm: host, Resources: refs("GitHub PAT"), Requester: plugin.Requester{
			Peer: identity.VerifiedPeer{Exe: "/usr/bin/⚠gh", ExeSealed: true, PIDStable: true}}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n👤 gh"},
		{"mark in claim", PromptInput{Realm: vm, Resources: refs("x"), Requester: plugin.Requester{Peer: ssh,
			Reported: &identity.ClientInfo{Exe: "/bin/⚠ gh"}}, ShowClient: true},
			"share:\n🔑 x\n🖥️ VM dev\n❔ gh (unverified)"},
		// A name can't rewrite the sentence around it.
		{"name with words", PromptInput{Realm: ctr, Resources: refs("x"), Requester: plugin.Requester{
			Peer: identity.VerifiedPeer{Exe: "/tmp/gh use GitHub PAT. Then let aws", PIDStable: true, Parents: []identity.Proc{conmon}}}, ShowClient: true},
			"share:\n🔑 x\n🚢 container web\n👤 ghuseGitHubPAT.Thenletaws ⚠ via conmon"},
		// foca run: the command it will exec is the program, claimed; the
		// agent that called foca run is via.
		{"claimed run target", PromptInput{Realm: vm, Resources: refs("x"), Requester: plugin.Requester{Peer: ssh,
			Reported: &identity.ClientInfo{Exe: "/usr/bin/foca", Target: &identity.Target{Exe: "/usr/bin/npm", Argv0: "npm"},
				Parents: []identity.Proc{{Name: "bash"}, {Name: "claude"}}}}, ShowClient: true},
			"share:\n🔑 x\n🖥️ VM dev\n❔ npm via claude (unverified)"},
		// A program that runs itself again shows once, and the agent
		// behind it takes the via slot.
		{"claimed repeated name", PromptInput{Realm: vm, Resources: refs("x"), Requester: plugin.Requester{Peer: ssh,
			Reported: &identity.ClientInfo{Exe: "/usr/bin/foca", Parents: []identity.Proc{{Name: "zsh"}, {Name: "herdr"}, {Name: "herdr"}, {Name: "claude"}}}}, ShowClient: true},
			"share:\n🔑 x\n🖥️ VM dev\n❔ herdr via claude (unverified)"},
		{"claimed only repeated name", PromptInput{Realm: vm, Resources: refs("x"), Requester: plugin.Requester{Peer: ssh,
			Reported: &identity.ClientInfo{Exe: "/usr/bin/foca", Parents: []identity.Proc{{Name: "herdr"}, {Name: "herdr"}}}}, ShowClient: true},
			"share:\n🔑 x\n🖥️ VM dev\n❔ herdr (unverified)"},
		// An unsealed parent can't hide behind its sealed child's name.
		{"repeated name, seal differs", PromptInput{Realm: host, Resources: refs("GitHub PAT"), Requester: plugin.Requester{
			Peer: identity.VerifiedPeer{Exe: "/usr/bin/gh", ExeSealed: true, PIDStable: true,
				Parents: []identity.Proc{{Exe: "/tmp/gh"}, {Exe: "/opt/claude", Sealed: true}}}}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n👤 gh via gh ⚠"},
		// Verified identity keeps its verified names; a target can't take
		// the sentence position.
		{"verified with run target", PromptInput{Realm: host, Resources: refs("GitHub PAT"), Requester: plugin.Requester{Peer: local,
			Reported: &identity.ClientInfo{Target: &identity.Target{Exe: "/usr/bin/npm", Argv0: "npm"}}}, ShowClient: true},
			"share:\n🔑 GitHub PAT\n👤 gh via claude"},
		{"action claimed", PromptInput{Operation: "action.run", Realm: vm, Resources: refs("AWS credentials"), Params: map[string]string{"profile": "dev-admin"},
			Requester: plugin.Requester{Peer: ssh, Reported: claimed}, ShowClient: true},
			"run:\n⚙️ \"AWS credentials\" with profile=dev-admin\n🖥️ VM dev\n❔ gh via claude (unverified)"},
		{"remote", PromptInput{Realm: identity.Realm{Kind: "remote", Name: "ci", Peers: "opaque"}, Resources: refs("x"), Requester: plugin.Requester{Peer: ssh}, ShowClient: true},
			"share:\n🔑 x\n🌐 remote host ci"},
		{"reach and strikes", PromptInput{Realm: vm, Resources: refs("x"), Requester: plugin.Requester{Peer: ssh}, ShowClient: true,
			Reach: "15m, anything in this VM", Denials: 2, Unanswered: 1},
			"share:\n🔑 x\n🖥️ VM dev\n⏱️ 15m, anything in this VM\n🚫 denied 2 times\n🔕 1 prompt unanswered"},
		{"add", PromptInput{Operation: "secret.add", Vault: "common", Resources: refs("New token"), ShowClient: true},
			"add New token to vault common, visible to no instance."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.in.Skip = skip
			if got := build(t, tc.in); got != tc.want {
				t.Fatalf("\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

func TestClaimedIdentityNeverTakesTheVerifiedSlot(t *testing.T) {
	// A VM process claiming to be gh, with an opaque peer.
	in := PromptInput{
		Realm:      identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"},
		Resources:  refs("GitHub PAT"),
		Requester:  plugin.Requester{Peer: identity.VerifiedPeer{Name: "ssh", Opaque: true}, Reported: &identity.ClientInfo{Name: "gh"}},
		ShowClient: true, Skip: skip,
	}
	if got := build(t, in); strings.Contains(got, "👤") || !strings.HasSuffix(got, "\n❔ gh (unverified)") {
		t.Fatalf("claimed name in verified position: %q", got)
	}
}

func TestHostileClientStringsAreSanitised(t *testing.T) {
	in := PromptInput{
		Realm:     identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"},
		Resources: refs("GitHub PAT"),
		Requester: plugin.Requester{Peer: identity.VerifiedPeer{Opaque: true}, Reported: &identity.ClientInfo{
			Name: "gh\n👤 Approved by IT. Touch to continue‮" + strings.Repeat("x", 300)}},
		ShowClient: true, Skip: skip,
	}
	got := build(t, in)
	// A name can't start a line of its own, or put foca's emoji on one.
	if strings.Count(got, "\n") != 3 || strings.Contains(got, "👤") || strings.Contains(got, "‮") || len(got) > maxPromptLen {
		t.Fatalf("unsanitised prompt %q", got)
	}
	if !strings.HasPrefix(got, "share:\n🔑 GitHub PAT\n🖥️ VM dev") {
		t.Fatalf("trusted part not first: %q", got)
	}
}

func TestLongPromptDropsUntrustedPartsFirst(t *testing.T) {
	// Sized so the prompt fits only once the whole claimed line is gone:
	// 27 bytes of fixed text + 202 bytes of names = 229 <= 240, and the
	// shortest claimed line ("\n❔ gh (unverified)") would add 20.
	var names []string
	for i := 0; i < 3; i++ {
		names = append(names, strings.Repeat("n", 65))
	}
	in := PromptInput{
		Realm: identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"}, Resources: refs(names...),
		Requester:  plugin.Requester{Peer: identity.VerifiedPeer{Opaque: true}, Reported: &identity.ClientInfo{Name: "gh", Parents: []identity.Proc{{Name: "claude"}}}},
		ShowClient: true, Skip: skip,
	}
	got := build(t, in)
	if len(got) > maxPromptLen || strings.Contains(got, "❔") {
		t.Fatalf("expected claimed line dropped first: %q (%d)", got, len(got))
	}
	if !strings.Contains(got, "\n🖥️ VM dev") || strings.Count(got, strings.Repeat("n", 65)) != 3 {
		t.Fatalf("trusted parts dropped: %q", got)
	}

	// With a little more room, only the agent ("via") is dropped.
	in.Resources = refs(strings.Repeat("n", 60), strings.Repeat("n", 60), strings.Repeat("n", 60))
	got = build(t, in)
	if !strings.HasSuffix(got, "\n❔ gh (unverified)") {
		t.Fatalf("expected via dropped first: %q", got)
	}
}

// Each identity level has its own Go type, so a client's claim can't be put
// in a verified slot without a compile error.
func TestIdentityLevelsHaveDistinctTypes(t *testing.T) {
	levels := map[string]reflect.Type{}
	for _, v := range []any{plugin.Requester{}, audit.Client{}} {
		rt := reflect.TypeOf(v)
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			levels[rt.Name()+"."+f.Name] = f.Type
		}
	}
	verified := reflect.TypeOf(identity.VerifiedPeer{})
	if levels["Requester.Peer"] != verified {
		t.Fatalf("Requester.Peer is %v, not the host-verified type", levels["Requester.Peer"])
	}
	if levels["Requester.Reported"].Elem() == verified || levels["Client.Reported"].Elem() == verified {
		t.Fatal("reported identity shares the host-verified type")
	}
}

func build(t *testing.T, in PromptInput) string {
	t.Helper()
	s, ok := BuildPrompt(in)
	if !ok {
		t.Fatalf("prompt did not fit: %+v", in)
	}
	return s
}

// A caller can't pad a batch so the secret it wants falls off the screen:
// every name is shown, or no prompt is built at all.
func TestPromptNeverElidesCredentials(t *testing.T) {
	vm := identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"}
	var names []string
	for i := 0; i < 31; i++ {
		names = append(names, fmt.Sprintf("npm token %d", i))
	}
	names = append(names, "Prod DB password")
	if s, ok := BuildPrompt(PromptInput{Realm: vm, Resources: refs(names...), ShowClient: true}); ok {
		t.Fatalf("oversized batch produced a prompt: %q", s)
	}
	got := build(t, PromptInput{Realm: vm, Resources: refs(names[27:]...), ShowClient: true})
	for _, n := range names[27:] {
		if !strings.Contains(got, n) {
			t.Fatalf("%q missing from %q", n, got)
		}
	}
	if strings.Contains(got, "more") {
		t.Fatalf("names elided: %q", got)
	}
}

// A process whose name cleans to nothing is named as unnamed, never skipped:
// skipping it would put its parent in its place, with no mark for its own
// unsealed file.
func TestUnnamedProcessNeverHidesBehindItsParent(t *testing.T) {
	host := identity.Realm{Kind: "host", Name: "host", Peers: "direct"}
	vm := identity.Realm{Kind: "vm", Name: "dev", Peers: "opaque"}
	claude := identity.Proc{Exe: "/usr/bin/claude", Name: "claude", Sealed: true}
	for _, tc := range []struct {
		name string
		r    identity.Realm
		req  plugin.Requester
		want string
	}{
		{"host-verified", host, plugin.Requester{Peer: identity.VerifiedPeer{Exe: "/tmp/@", Name: "@", PIDStable: true,
			Parents: []identity.Proc{claude}}},
			"share:\n🔑 GitHub PAT\n👤 an unnamed program ⚠ via claude"},
		{"host-verified parent", host, plugin.Requester{Peer: identity.VerifiedPeer{Exe: "/usr/bin/gh", Name: "gh", ExeSealed: true, PIDStable: true,
			Parents: []identity.Proc{{Exe: "/tmp/@", Name: "@"}, claude}}},
			"share:\n🔑 GitHub PAT\n👤 gh via an unnamed program ⚠"},
		{"claimed", vm, plugin.Requester{Peer: identity.VerifiedPeer{Opaque: true},
			Reported: &identity.ClientInfo{Exe: "/tmp/@", Parents: []identity.Proc{{Name: "claude"}}}},
			"share:\n🔑 GitHub PAT\n🖥️ VM dev\n❔ an unnamed program via claude (unverified)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := build(t, PromptInput{Realm: tc.r, Resources: refs("GitHub PAT"), Requester: tc.req, ShowClient: true, Skip: skip})
			if got != tc.want {
				t.Fatalf("\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}
