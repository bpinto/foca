package core

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/bpinto/foca/internal/action"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugin"
)

// Prompt text is a verb phrase; the authenticator frames it (macOS shows
// "<app> is trying to <phrase>"). Every part is either trusted host data or
// a sanitised name placed according to how it was verified (design §4.1.1).

const (
	maxPromptLen = 240
	maxNameLen   = 32
)

// PromptInput is everything the prompt may draw on.
type PromptInput struct {
	Operation string // "secret.read" | "secret.add"
	Realm     identity.Realm
	Vault     string
	Resources []plugin.ResourceRef
	Requester plugin.Requester
	// ShowClient=false leaves out program and agent names entirely.
	ShowClient bool
	Skip       []string
	// VisibleTo is every realm that will see the secret after a secret.add
	// or secret.update, or that uses the vault for vault.init.
	VisibleTo []identity.Realm
	// Hidden, for secret.remove, is every realm that sees the secret now and
	// won't afterwards.
	Hidden []identity.Realm
	// Reach, if approving creates a grant, says how far it reaches
	// (policy.Reach). Denials is how many times this was denied recently,
	// and Unanswered how many of the instance's recent prompts timed out or
	// were cancelled. All are trusted and never dropped.
	Reach      string
	Denials    int
	Unanswered int
	// Params are an action's validated params, and Uses the secrets it
	// reads on the host. Both are trusted and never dropped.
	Params map[string]string
	Uses   []plugin.ResourceRef
}

type trust int

const (
	trustNone trust = iota
	trustClaimed
	trustVerified
)

// actor is the program and agent behind a request, with how far it is trusted.
// For verified identity, each name also records whether its file was sealed;
// an unsealed name carries the UnsealedMark.
type actor struct {
	program, via             string
	programSealed, viaSealed bool
	trust                    trust
}

// BuildPrompt returns the reason text, or ok=false if even the trusted parts
// don't fit. Credential names are never elided: "a, b, c and 29 more" would
// let a caller hide the secret it wants behind harmless ones. Callers must
// refuse a request whose prompt doesn't fit, before any prompt is shown.
func BuildPrompt(in PromptInput) (prompt string, ok bool) {
	a := resolveActor(in)
	for _, step := range []func(*actor){
		func(*actor) {},
		func(a *actor) { a.via = "" },
		func(a *actor) { *a = actor{} },
	} {
		step(&a)
		if s := render(in, a) + suffix(in); len(s) <= maxPromptLen {
			return s, true
		}
	}
	return "", false
}

func render(in PromptInput, a actor) string {
	realm := realmPhrase(in.Realm)
	switch in.Operation {
	case "secret.add":
		names := listNames(in.Resources)
		return fmt.Sprintf("add %s to vault %s, %s.", names, in.Vault, visiblePhrase(in.VisibleTo))
	case "secret.update":
		return fmt.Sprintf("change %s in vault %s, %s.", listNames(in.Resources), in.Vault, visiblePhrase(in.VisibleTo))
	case "secret.remove":
		return fmt.Sprintf("remove %s from vault %s%s.", listNames(in.Resources), in.Vault, hiddenPhrase(", hiding it from ", in.Hidden))
	case "vault.init":
		users := ""
		if len(in.VisibleTo) > 0 {
			users = " for " + realmList(in.VisibleTo)
		}
		return fmt.Sprintf("create vault %s%s.", in.Vault, users)
	case "vault.recover":
		users := ""
		if len(in.VisibleTo) > 0 {
			users = " for " + realmList(in.VisibleTo)
		}
		return fmt.Sprintf("seal vault %s's key again with %s using its recovery key%s.", in.Vault, in.Params["protector"], strings.Replace(users, " for ", ", for ", 1))
	case "vault.rekey":
		users := ""
		if len(in.VisibleTo) > 0 {
			users = ", for " + realmList(in.VisibleTo)
		}
		return fmt.Sprintf("encrypt vault %s again under a new key, sealed with %s%s.", in.Vault, in.Params["protector"], users)
	case "action.run":
		what := runPhrase(in)
		switch a.trust {
		case trustVerified:
			return fmt.Sprintf("run %s for %s%s%s.", what, named(a.program, a.programSealed), realm, viaPhrase(named(a.via, a.viaSealed)))
		case trustClaimed:
			return fmt.Sprintf("run %s%s. %s claims: %s%s.", what, realm, claimant(in.Realm), a.program, plainVia(a.via))
		default:
			return fmt.Sprintf("run %s%s.", what, realm)
		}
	default: // secret.read
		creds := listNames(in.Resources)
		switch a.trust {
		case trustVerified:
			return fmt.Sprintf("let %s use %s%s%s.", named(a.program, a.programSealed), creds, realm, viaPhrase(named(a.via, a.viaSealed)))
		case trustClaimed:
			return fmt.Sprintf("let a program use %s%s. %s claims: %s%s.",
				creds, realm, claimant(in.Realm), a.program, plainVia(a.via))
		default:
			return fmt.Sprintf("let a program use %s%s.", creds, realm)
		}
	}
}

// resolveActor picks the identity source by trust level. Claimed data never
// reaches the "let X use" position; that slot is only for kernel-verified
// identity (host kernel for direct realms, guest kernel via the relay).
func resolveActor(in PromptInput) actor {
	if !in.ShowClient {
		return actor{}
	}
	skip := map[string]bool{}
	for _, s := range in.Skip {
		skip[s] = true
	}
	r := in.Requester
	switch {
	case !r.Peer.Opaque:
		chain := append([]identity.Proc{{Exe: r.Peer.Exe, Name: r.Peer.Name, Sealed: r.Peer.ExeSealed}}, r.Peer.Parents...)
		if !r.Peer.PIDStable {
			// The pid may name a later process; no name is certain.
			for i := range chain {
				chain[i].Sealed = false
			}
		}
		return pick(chain, skip, trustVerified, how{})
	case r.GuestVerified != nil:
		// The realm's kernel vouches for each process, but every name is
		// one the process gave itself (comm), so none is sealed and each
		// carries the mark. The skip list applies by name: a process that
		// calls itself bash to hide could as well call itself gh.
		chain, leader := guestChain(*r.GuestVerified)
		return pick(chain, skip, trustVerified, how{byName: true, comm: true, leader: leader})
	case r.Reported != nil:
		return pick(clientChain(*r.Reported), skip, trustClaimed, how{byName: true})
	}
	return actor{}
}

// guestChain is the caller and its parents as the relay read them: names
// only, never sealed. It ends at the leader of the caller's terminal
// session, the shell that owns the terminal: what is above it (a tmux
// server, sshd, systemd) runs the terminal, not the request. leader says
// whether the leader is in the chain; if not, the whole chain is kept.
func guestChain(g identity.GuestInfo) (chain []identity.Proc, leader bool) {
	chain = append([]identity.Proc{{PID: g.PID, StartTime: g.StartTime, Name: g.Name}}, g.Parents...)
	for i := range chain {
		chain[i].Exe, chain[i].Sealed = "", false
	}
	var sid int
	var start uint64
	if _, err := fmt.Sscanf(g.Session, "sid:%d:%d", &sid, &start); err != nil {
		return chain, false
	}
	for i, p := range chain {
		// The start time too: a pid alone could be a later process.
		if p.PID == sid && p.StartTime == start {
			return chain[:i+1], true
		}
	}
	return chain, false
}

// clientChain is the claimed caller and its parents, after the command it
// says it will run, if any: for `foca run` that command is the program that
// gets the values. Neither kernel can vouch for a process not yet started,
// so the target only ever appears in a claim.
func clientChain(c identity.ClientInfo) []identity.Proc {
	chain := append([]identity.Proc{{Exe: c.Exe, Name: c.Name}}, c.Parents...)
	if c.Target != nil {
		chain = append([]identity.Proc{{Exe: c.Target.Exe, Name: c.Target.Argv0}}, chain...)
	}
	for i := range chain {
		chain[i].Sealed = false // claims are never sealed, whatever they say
	}
	return chain
}

// how says how pick reads a chain.
type how struct {
	// byName applies the skip list to names whatever the seal, for chains
	// where every name was chosen by the process itself.
	byName bool
	// comm: names are comm, which the kernel cuts to 15 bytes (commName).
	comm bool
	// leader: the chain ends at its terminal's session leader, which is
	// named if every process in it is skipped. "zsh" then says the request
	// was typed in a shell, not made through a program.
	leader bool
}

// pick returns the first two processes in the chain that aren't shells,
// multiplexers or foca itself: the program and the agent behind it.
//
// For host-verified chains only sealed entries are skipped. An unsealed
// file's name was chosen by whoever wrote it, so a program named "env" or
// "foca" in the caller's own directory can't hide itself and put its parent
// in the prompt instead.
func pick(chain []identity.Proc, skip map[string]bool, t trust, h how) actor {
	type entry struct {
		name   string
		sealed bool
	}
	var got []entry
	last := entry{}
	for _, p := range chain {
		n, bare := identity.DisplayName(p.Name, maxNameLen), ""
		if e := identity.DisplayName(p.Exe, maxNameLen); e != "" {
			n = e
		}
		bare = n
		if h.comm {
			n, bare = commName(p.Name)
		}
		if bare == "" {
			// A name that cleans to nothing is never skipped: it is on no
			// skip list, and skipping it would put the next process in its
			// place (an unsealed "/tmp/@" would show as its sealed parent).
			n = unnamed
		}
		e := entry{n, p.Sealed && p.Exe != ""}
		last = e
		if skip[bare] && (p.Sealed || h.byName) {
			continue
		}
		// "herdr via herdr" says nothing the first name doesn't: a program
		// that runs itself again shows once. Only an exact match, seal
		// included, so an unsealed parent can't hide behind its sealed child.
		if len(got) == 1 && e == got[0] {
			continue
		}
		got = append(got, e)
		if len(got) == 2 {
			break
		}
	}
	if len(got) == 0 && h.leader && last.name != "" {
		got = append(got, last)
	}
	switch len(got) {
	case 0:
		return actor{}
	case 1:
		return actor{program: got[0].name, programSealed: got[0].sealed, trust: t}
	default:
		return actor{program: got[0].name, programSealed: got[0].sealed, via: got[1].name, viaSealed: got[1].sealed, trust: t}
	}
}

// unnamed stands for a process whose name cleans to nothing. It has spaces,
// which no sanitised name has, so no process can pass for it.
const unnamed = "an unnamed program"

// commLen is how much of a name the kernel keeps in comm.
const commLen = 15

// CutMark follows a name the kernel may have cut short. Like UnsealedMark it
// is added after sanitising, so no process can put it in its own name.
const CutMark = "…"

// commName is the label for a name read from comm, and the bare name the
// skip list is matched on. A name of the full 15 bytes may have been cut, so
// its label gets CutMark (a name exactly that long gets it too). A Nix
// wrapper whose "-wrapped" suffix was cut is still unwrapped: the cut fell
// in the suffix, so the name before it is whole.
func commName(comm string) (label, bare string) {
	s, cut := comm, len(comm) >= commLen
	if cut && strings.HasPrefix(s, ".") {
		const suffix = "-wrapped"
		if strings.HasSuffix(s, suffix) {
			cut = false // whole; DisplayName unwraps it
		} else {
			for k := len(suffix) - 1; k >= 2; k-- {
				if strings.HasSuffix(s, suffix[:k]) {
					s, cut = s[1:len(s)-k], false
					break
				}
			}
		}
	}
	bare = identity.DisplayName(s, maxNameLen)
	if cut && bare != "" {
		return bare + CutMark, bare
	}
	return bare, bare
}

// UnsealedMark follows a verified name whose file isn't sealed: the
// kernel vouches for the process, but the caller could have chosen the name.
// DisplayName strips the mark from every name, so only foca can add it.
const UnsealedMark = identity.UnsealedMark

// named marks a verified name whose file is not sealed.
func named(name string, sealed bool) string {
	if name == "" || sealed {
		return name
	}
	return name + " " + UnsealedMark
}

func listNames(rs []plugin.ResourceRef) string {
	names := make([]string, len(rs))
	for i, r := range rs {
		n := r.Display
		if n == "" {
			n = r.ID
		}
		names[i] = n
	}
	switch len(names) {
	case 0:
		return "nothing"
	case 1:
		return names[0]
	default:
		return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
}

// runPhrase names an action as the host describes it, with the values it
// runs with and the secrets it reads on the host:
// `"List PRs" with repo=foca/foca (uses GitHub PAT)`.
func runPhrase(in PromptInput) string {
	s := strconv.Quote(listNames(in.Resources))
	if len(in.Params) > 0 {
		s += " with " + action.DescribeParams(in.Params)
	}
	if len(in.Uses) > 0 {
		s += " (uses " + listNames(in.Uses) + ")"
	}
	return s
}

func visiblePhrase(rs []identity.Realm) string {
	if len(rs) == 0 {
		return "visible to no instance"
	}
	return "visible in " + realmList(rs)
}

func hiddenPhrase(lead string, rs []identity.Realm) string {
	if len(rs) == 0 {
		return ""
	}
	return lead + realmList(rs)
}

// realmList names realms as "VM dev, VM work and host laptop".
func realmList(rs []identity.Realm) string {
	labels := make([]string, len(rs))
	for i, r := range rs {
		if n := r.Noun(); n != "" {
			labels[i] = n + " " + r.Name
		} else {
			labels[i] = "host " + r.Name
		}
	}
	if len(labels) == 1 {
		return labels[0]
	}
	return strings.Join(labels[:len(labels)-1], ", ") + " and " + labels[len(labels)-1]
}

func realmPhrase(r identity.Realm) string {
	if n := r.Noun(); n != "" {
		return fmt.Sprintf(" in %s %s", n, r.Name)
	}
	return ""
}

func claimant(r identity.Realm) string {
	n := r.Noun()
	if n == "" {
		return "Client"
	}
	return strings.ToUpper(n[:1]) + n[1:]
}

func viaPhrase(v string) string {
	if v == "" {
		return ""
	}
	return ", via " + v
}

func plainVia(v string) string {
	if v == "" {
		return ""
	}
	return " via " + v
}

// suffix is the trusted text after the sentence: how far approving reaches,
// how often this was denied lately, and how many of the instance's prompts
// went unanswered.
func suffix(in PromptInput) string {
	s := ""
	if in.Reach != "" {
		s += " " + in.Reach
	}
	switch {
	case in.Denials == 1:
		s += " (denied once)"
	case in.Denials > 1:
		s += fmt.Sprintf(" (denied %d times)", in.Denials)
	}
	if in.Unanswered > 0 {
		s += fmt.Sprintf(" (%d unanswered)", in.Unanswered)
	}
	return s
}
