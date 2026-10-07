package identity

import (
	"strings"
	"testing"
)

func TestCleanStripsControlAndBoundsSize(t *testing.T) {
	c := ClientInfo{
		Name: "gh\x1b[31m\nfake",
		Exe:  strings.Repeat("a", 2*MaxClientString),
	}
	for i := 0; i < 20; i++ {
		c.Parents = append(c.Parents, Proc{PID: i, Name: "p\r"})
	}
	got := c.Clean()
	if got.Name != "gh[31mfake" {
		t.Fatalf("control chars not stripped: %q", got.Name)
	}
	if len(got.Exe) != MaxClientString {
		t.Fatalf("exe not bounded: %d", len(got.Exe))
	}
	if len(got.Parents) != MaxClientParents || got.Parents[0].Name != "p" {
		t.Fatalf("parents not bounded/cleaned: %+v", got.Parents)
	}
	if c.Parents[0].Name != "p\r" {
		t.Fatal("Clean mutated its receiver's parents")
	}

	// Format characters (bidi overrides, zero-width) are stripped too, so a
	// later UI can't be made to render a claim backwards or hide part of it.
	c = ClientInfo{Cwd: "/home/‮gnp.exe", Hostname: "d​ev", Parents: []Proc{{Name: "gh", Sealed: true}}}
	got = c.Clean()
	if got.Cwd != "/home/gnp.exe" || got.Hostname != "dev" {
		t.Fatalf("format chars kept: %q %q", got.Cwd, got.Hostname)
	}
	if got.Parents[0].Sealed {
		t.Fatal("a client vouched for its own parent's file")
	}

	// The run target is a claim like the rest, cleaned the same way and
	// without touching the receiver's copy.
	c = ClientInfo{Target: &Target{Exe: "/bin/‮np\x1bm" + strings.Repeat("a", 2*MaxClientString), Argv0: "npm\n"}}
	got = c.Clean()
	if got.Target == c.Target || got.Target.Argv0 != "npm" || len(got.Target.Exe) != MaxClientString ||
		!strings.HasPrefix(got.Target.Exe, "/bin/npmaaa") {
		t.Fatalf("target not cleaned: %+v", got.Target)
	}
	if c.Target.Argv0 != "npm\n" {
		t.Fatal("Clean mutated its receiver's target")
	}
	if got := (ClientInfo{Target: &Target{Argv0: "\x1b"}}).Clean(); got.Target != nil {
		t.Fatalf("empty target kept: %+v", got.Target)
	}
}

// A client can't vouch for its own files: whatever it claims, its parents
// are never sealed once cleaned, so the audit log never records a claim as
// sealed (design §4.1.1).
func TestCleanNeverKeepsAClaimedSeal(t *testing.T) {
	c := ClientInfo{Exe: "/bin/gh", Parents: []Proc{{Exe: "/bin/claude", Sealed: true}, {Exe: "/bin/zsh", Sealed: true}}}
	for _, p := range c.Clean().Parents {
		if p.Sealed {
			t.Fatalf("claimed parent %s kept its seal", p.Exe)
		}
	}
}

func TestDisplayName(t *testing.T) {
	cases := map[string]string{
		"/nix/store/abc-gh-2.0/bin/gh":        "gh",
		"claude":                              "claude",
		"/usr/bin/" + strings.Repeat("x", 50): strings.Repeat("x", 32),
		"evil‮name":                           "evilname",
		"":                                    "",
		"/nix/store/x-claude-code/bin/.claude-wrapped": "claude",
		"..gh-wrapped-wrapped":                         "gh",
		".-wrapped":                                    ".-wrapped",
		// Nothing a name holds can add words or look-alike letters.
		"/tmp/x/gh use GitHub PAT. Then let aws": "ghuseGitHubPAT.Thenletaws",
		"g\u04bb":                                "g",
		"⚠ gh":                                   "gh",
		"g++":                                    "g++",
		"Google Chrome Helper (GPU)":             "GoogleChromeHelperGPU",
	}
	for in, want := range cases {
		if got := DisplayName(in, 32); got != want {
			t.Errorf("DisplayName(%q) = %q, want %q", in, got, want)
		}
	}
}
