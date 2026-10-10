package cli

import (
	"fmt"
	"path/filepath"

	"github.com/alecthomas/kong"
)

// place is where the CLI seems to run: on a host (a host config exists), in
// a realm (a socket was handed in, and there's no host config), both, or
// neither. It only adds a note to a host command's error in a realm. Access
// is the service's to decide: a socket refuses host-only methods, and host
// commands need the host's config and keys.
type place struct {
	host  bool
	realm string // what says this is a realm: FOCA_SOCK or ~/.foca.sock
}

func (g *Globals) where(e *Env) place {
	var p place
	if paths, err := g.paths(e); err == nil && exists(paths.Config) {
		p.host = true
	}
	if e.Getenv("FOCA_SOCK") != "" {
		p.realm = "FOCA_SOCK"
	} else if home := e.Getenv("HOME"); home != "" && exists(filepath.Join(home, ".foca.sock")) {
		p.realm = "~/.foca.sock"
	}
	return p
}

func (p place) onlyRealm() bool { return !p.host && p.realm != "" }

// misplaced is the note for a host command that failed in what looks like
// a realm, where it can't find the host's config or data.
func misplaced(kctx *kong.Context, p place) string {
	n := kctx.Selected()
	for n != nil && n.Parent != nil && n.Parent.Type != kong.ApplicationNode {
		n = n.Parent
	}
	if n == nil || n.Group == nil || n.Group.Key != "host" || !p.onlyRealm() {
		return ""
	}
	return fmt.Sprintf("%s is a host command, and this looks like a realm (%s, no host config): run it on the host", n.Name, p.realm)
}
