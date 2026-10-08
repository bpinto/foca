// Package identity holds the value types that describe who is asking.
//
// Verified and reported identity are deliberately different types so they can
// never be mixed by accident: VerifiedPeer is only ever produced by a peer
// identifier from kernel data, ClientInfo only ever comes from request bytes.
package identity

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
)

// Realm describes the isolated environment an instance serves.
type Realm struct {
	Kind  string `json:"kind"`  // host | vm | container | remote
	Name  string `json:"name"`  // shown in prompts and audit
	Peers string `json:"peers"` // direct | opaque
	// ContainerID is only ever set by the Linux peer identifier, for a
	// direct container realm: the container the peer runs in, from its
	// cgroup. Empty when no runtime's id is found there.
	ContainerID string `json:"container_id,omitempty"`
}

const (
	RealmHost      = "host"
	RealmVM        = "vm"
	RealmContainer = "container"
	RealmRemote    = "remote"

	PeersDirect = "direct"
	PeersOpaque = "opaque"
)

// Noun is the word used for the realm in prompt text.
func (r Realm) Noun() string {
	switch r.Kind {
	case RealmVM:
		return "VM"
	case RealmContainer:
		return "container"
	case RealmRemote:
		return "remote host"
	default:
		return ""
	}
}

// Proc is one process as seen by whoever filled it in.
type Proc struct {
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start_time,omitempty"`
	Exe       string `json:"exe,omitempty"`
	Name      string `json:"name,omitempty"`
	// Sealed means the program file and every directory above it are
	// owned by root and not writable by others, so the caller could not
	// have chosen its name or content. Only a verifier sets it; it is
	// cleared on client-reported data.
	Sealed bool `json:"sealed,omitempty"`
}

// VerifiedPeer is the connecting process as reported by the host kernel.
type VerifiedPeer struct {
	Source    string `json:"source"`
	UID       int    `json:"uid"`
	GID       int    `json:"gid"`
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start_time,omitempty"`
	Exe       string `json:"exe,omitempty"`
	// ExeSealed: see Proc.Sealed. An unsealed exe's name was chosen by
	// whoever wrote the file, so the prompt never states it as fact.
	ExeSealed bool `json:"exe_sealed"`
	// PIDStable means the kernel pinned the process (a pidfd), so nothing
	// read about it can belong to a later process that reused the pid.
	// Without it, names are never treated as sealed, and session-scoped
	// reuse must not apply.
	PIDStable bool   `json:"pid_stable"`
	Name      string `json:"name,omitempty"`
	Session   string `json:"session,omitempty"`
	// Parents is the host-verified ancestor chain, nearest first. Only
	// meaningful for direct realms; for opaque peers it describes the proxy.
	Parents []Proc `json:"parents,omitempty"`
	Opaque  bool   `json:"opaque"`
	Realm   Realm  `json:"realm"`
}

// ClientInfo is identity data supplied by a client about itself. It is never
// trusted for any decision.
type ClientInfo struct {
	PID      int    `json:"pid,omitempty"`
	PPID     int    `json:"ppid,omitempty"`
	UID      int    `json:"uid,omitempty"`
	Exe      string `json:"exe,omitempty"`
	Name     string `json:"name,omitempty"`
	Argv0    string `json:"argv0,omitempty"`
	Cwd      string `json:"cwd,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Session  string `json:"session,omitempty"`
	Tool     string `json:"tool,omitempty"`
	// Parents is the client's ancestor chain, nearest first.
	Parents []Proc `json:"parents,omitempty"`
	// Target is the command the client will start with what it reads
	// (foca run), or nil.
	Target *Target `json:"target,omitempty"`
}

// Target is the command `foca run` is about to exec (design §4.1.1): its
// resolved path and the base name of its argv[0]. The other arguments are
// never sent; they may hold anything.
type Target struct {
	Exe   string `json:"exe,omitempty"`
	Argv0 string `json:"argv0,omitempty"`
}

// GuestInfo is a caller's identity as read from a realm's own kernel by the
// guest relay (design §14). It is a separate type from ClientInfo, with no
// conversion helpers, so a client's claim can never be stored as guest
// verified by accident: the assignment doesn't compile.
//
// It carries no exe: the relay runs as its own user, and Linux shows another
// user's /proc/<pid>/exe only to a process with CAP_SYS_PTRACE, which the
// relay doesn't hold. Names are comm, which a process sets itself, so no
// name here is ever sealed.
type GuestInfo struct {
	Source    string `json:"source,omitempty"`
	PID       int    `json:"pid"`
	StartTime uint64 `json:"start_time,omitempty"`
	UID       int    `json:"uid"`
	GID       int    `json:"gid"`
	// PIDStable: the VM kernel pinned the process (a pidfd), as for
	// VerifiedPeer. Without it no guest-* scope applies.
	PIDStable bool   `json:"pid_stable"`
	Name      string `json:"name,omitempty"`
	Session   string `json:"session,omitempty"`
	// Parents is the ancestor chain, nearest first, as the relay read it:
	// pids, start times and names only.
	Parents []Proc `json:"parents,omitempty"`
}

// Clean returns a copy with control characters removed and sizes bounded,
// as for ClientInfo, or an error if it can't describe a process or claims
// more than the relay can read.
func (g GuestInfo) Clean() (GuestInfo, error) {
	if g.PID <= 0 {
		return g, errors.New("guest_verified: pid must be positive")
	}
	if g.UID < 0 || g.GID < 0 {
		return g, errors.New("guest_verified: uid and gid must not be negative")
	}
	if len(g.Parents) > MaxClientParents {
		return g, fmt.Errorf("guest_verified: at most %d parents", MaxClientParents)
	}
	g.Source = cleanString(g.Source, MaxClientString)
	g.Name = cleanString(g.Name, MaxClientString)
	g.Session = cleanString(g.Session, MaxClientString)
	parents := make([]Proc, len(g.Parents))
	for i, p := range g.Parents {
		if p.Exe != "" || p.Sealed {
			return g, errors.New("guest_verified: the relay reads no exe, so a parent can't have one or be sealed")
		}
		p.Name = cleanString(p.Name, MaxClientString)
		parents[i] = p
	}
	if len(parents) == 0 {
		parents = nil
	}
	g.Parents = parents
	return g, nil
}

// Limits applied to client-reported data before it is stored anywhere.
const (
	MaxClientString  = 512
	MaxClientParents = 8
)

// Clean returns a copy with control characters removed and sizes bounded.
func (c ClientInfo) Clean() ClientInfo {
	c.Exe = cleanString(c.Exe, MaxClientString)
	c.Name = cleanString(c.Name, MaxClientString)
	c.Argv0 = cleanString(c.Argv0, MaxClientString)
	c.Cwd = cleanString(c.Cwd, MaxClientString)
	c.Hostname = cleanString(c.Hostname, MaxClientString)
	c.Session = cleanString(c.Session, MaxClientString)
	c.Tool = cleanString(c.Tool, MaxClientString)
	if len(c.Parents) > MaxClientParents {
		c.Parents = c.Parents[:MaxClientParents]
	}
	parents := make([]Proc, len(c.Parents))
	for i, p := range c.Parents {
		p.Exe = cleanString(p.Exe, MaxClientString)
		p.Name = cleanString(p.Name, MaxClientString)
		p.Sealed = false // a client can't vouch for its own files
		parents[i] = p
	}
	if len(parents) == 0 {
		parents = nil
	}
	c.Parents = parents
	if c.Target != nil {
		t := Target{Exe: cleanString(c.Target.Exe, MaxClientString), Argv0: cleanString(c.Target.Argv0, MaxClientString)}
		c.Target = &t
		if t == (Target{}) {
			c.Target = nil
		}
	}
	return c
}

func cleanString(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		// Cf covers bidi overrides and zero-width characters that could
		// make a later UI render misleading text.
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == unicode.ReplacementChar {
			continue
		}
		if b.Len()+len(string(r)) > max {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// UnsealedMark flags a verified name whose file the caller could have written.
// It is reserved: DisplayName removes it from every name, so no process can
// fake it or blur its meaning.
const UnsealedMark = "⚠"

// DisplayName reduces a process name or path to a short label for prompts:
// basename only, Nix wrapper names unwrapped (".claude-wrapped" → "claude"),
// at most max characters, and only ASCII letters, digits and "._+-". Anything
// else is dropped, so a name can't add words, punctuation or look-alike
// letters to the sentence it sits in ("gh use GitHub PAT. Then let aws"
// becomes "ghuseGitHubPAT.Thenletaws"), nor carry the UnsealedMark.
func DisplayName(s string, max int) string {
	s = filepath.Base(cleanString(s, MaxClientString))
	if s == "." || s == "/" {
		return ""
	}
	for strings.HasPrefix(s, ".") && strings.HasSuffix(s, "-wrapped") && len(s) > len(".-wrapped") {
		s = strings.TrimSuffix(strings.TrimPrefix(s, "."), "-wrapped")
	}
	var b strings.Builder
	for _, r := range s {
		if b.Len() == max {
			break
		}
		if nameChar(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func nameChar(r rune) bool {
	return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || strings.ContainsRune("._+-", r)
}
