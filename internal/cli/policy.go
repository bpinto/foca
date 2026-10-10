package cli

import (
	"errors"
	"fmt"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/bpinto/foca/internal/action"
	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/plugins/authn/polkit"
	"github.com/bpinto/foca/internal/policy"
	"github.com/bpinto/foca/internal/protocol"
	"github.com/bpinto/foca/internal/secretname"
	"github.com/bpinto/foca/internal/svcctl"
)

// ---- lock ----

type LockCmd struct{}

// Run makes the service wipe now: every grant is dropped, so the next access
// asks again. Tightening needs no approval.
func (LockCmd) Run(g *Globals, e *Env) error {
	paths, err := g.paths(e)
	if err != nil {
		return err
	}
	pids, _, err := g.signalServices(e, paths, syscall.SIGUSR1)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.Stderr, "lock requested (pid %s): every reuse grant is dropped\n", pidList(pids))
	return nil
}

// ---- policy explain ----

type PolicyCmd struct {
	Explain PolicyExplainCmd `cmd:"" help:"Show the effective approval policy, in plain words."`
}

type PolicyExplainCmd struct {
	Names []string `arg:"" optional:"" help:"Secrets (<vault>:<secret>) and actions to explain (default: every secret with its own policy, and every action)."`
}

// Run reads only the config, so a policy can be checked before anything is
// approved (design §9.1, safeguard 6). The wording is the same as the
// prompt's.
func (c *PolicyExplainCmd) Run(g *Globals, e *Env) error {
	cfg, _, err := g.load(e)
	if err != nil {
		return err
	}
	instances := cfg.Instances
	if name := g.instanceName(e); name != "" {
		inst, ok := cfg.Instance(name)
		if !ok {
			return fmt.Errorf("no instance %q in %s", name, cfg.Path)
		}
		instances = []config.Instance{inst}
	}

	events := cfg.PlatformEventsName()
	reuse := events != "none"
	if reuse {
		fmt.Fprintf(e.Stdout, "Platform events: %s. Reuse applies only while it reports sleep and screen lock; otherwise every access asks.\n", events)
	} else {
		fmt.Fprintln(e.Stdout, "Platform events: none. Grants can't be wiped on sleep or lock, so reuse is off and every access asks.")
	}

	var ids, actionIDs []string
	for _, n := range c.Names {
		// A name that names an action is explained as the action.
		if cfg.Actions[n] != nil {
			actionIDs = append(actionIDs, n)
			continue
		}
		if _, _, ok := secretname.Split(n); !ok {
			return fmt.Errorf("invalid name %q: name secrets <vault>:<secret>, or name an action", n)
		}
		ids = append(ids, n)
	}
	if len(c.Names) == 0 {
		for id := range cfg.SecretPolicies {
			ids = append(ids, id)
		}
		sort.Strings(ids)
	}
	for _, inst := range instances {
		noun := "vault"
		if len(inst.Vaults()) > 1 {
			noun = "vaults"
		}
		fmt.Fprintf(e.Stdout, "\nInstance %s (%s), %s %s\n", inst.Name, realmLabel(inst), noun, strings.Join(inst.Vaults(), ", "))
		w := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
		describe := func(name string) string {
			p := cfg.SecretPolicy(inst, name)
			if !reuse {
				p = policy.Policy{Kind: policy.EveryTime}
			}
			return policy.Describe(p, inst.Realm)
		}
		if len(c.Names) == 0 {
			for _, v := range inst.Vaults() {
				if inst.Expose[v].All {
					fmt.Fprintf(w, "  any other secret in %s\t%s\n", v, describe(secretname.Join(v, "")))
				}
			}
		}
		for _, name := range ids {
			vault, id, _ := secretname.Split(name)
			if !inst.Exposes(vault, id) {
				if len(c.Names) > 0 {
					fmt.Fprintf(w, "  %s\tnot exposed to this instance\n", name)
				}
				continue
			}
			fmt.Fprintf(w, "  %s\t%s\n", name, describe(name))
		}
		shown := inst.Actions
		if len(c.Names) > 0 {
			shown = actionIDs
		}
		for _, id := range shown {
			if !slices.Contains(inst.Actions, id) {
				fmt.Fprintf(w, "  action %s\tnot offered to this instance\n", id)
				continue
			}
			p := cfg.ActionPolicy(inst, id)
			if !reuse {
				p = policy.Policy{Kind: policy.EveryTime}
			}
			fmt.Fprintf(w, "  action %s\t%s\n", id, policy.Describe(p, inst.Realm))
		}
		w.Flush()
	}
	return nil
}

func realmLabel(inst config.Instance) string {
	if n := inst.Realm.Noun(); n != "" {
		return n + " " + inst.Realm.Name
	}
	return "host " + inst.Realm.Name
}

// ---- grants ----

type GrantsCmd struct {
	Drop   bool     `help:"Drop grants instead of listing them: the named ones, or all of yours. With --host, any grant, by APPROVAL_ID or APPROVAL_ID/NAME."`
	Host   bool     `help:"On the host: list every live grant of every running service, whoever it belongs to."`
	Format string   `short:"f" enum:"table,json" default:"table" help:"With --host: table, or json (one object per instance)."`
	Names  []string `arg:"" optional:"" help:"Secrets or actions whose grants to drop (with --drop); with --host, approval ids."`
}

// Run lists or drops the caller's own reuse grants. Dropping is tightening,
// so it never needs approval. --host reads the services' snapshots instead.
func (c *GrantsCmd) Run(g *Globals, e *Env) error {
	if c.Host {
		if c.Drop {
			return c.hostDrop(g, e)
		}
		if len(c.Names) > 0 {
			return fmt.Errorf("names only apply with --drop")
		}
		return c.host(g, e)
	}
	if c.Format != "table" {
		return fmt.Errorf("--format only applies with --host")
	}
	if len(c.Names) > 0 && !c.Drop {
		return fmt.Errorf("names only apply with --drop")
	}
	cl, err := g.dial(e)
	if err != nil {
		return err
	}
	defer cl.Close()
	common := protocol.Common{Client: reported()}
	if c.Drop {
		var res protocol.GrantsDropResult
		if err := cl.Call(background(), protocol.MethodGrantsDrop, protocol.GrantsDropParams{Common: common, Names: c.Names}, &res); err != nil {
			return err
		}
		fmt.Fprintf(e.Stderr, "dropped %d grant(s)\n", res.Dropped)
		return nil
	}
	var res protocol.GrantsStatusResult
	if err := cl.Call(background(), protocol.MethodGrantsStatus, protocol.GrantsStatusParams{Common: common}, &res); err != nil {
		return err
	}
	if len(res.Grants) == 0 {
		fmt.Fprintln(e.Stderr, "no live grants: the next read asks for approval")
		return nil
	}
	w := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSCOPE\tEXPIRES")
	for _, gr := range res.Grants {
		name := gr.Name
		if gr.Kind == "action" {
			name = "action " + name
			if len(gr.Params) > 0 {
				name += " (" + action.DescribeParams(gr.Params) + ")"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", clean(name), clean(gr.Scope), gr.ExpiresAt.Local().Format(time.DateTime))
	}
	return w.Flush()
}

// PolkitPolicyCmd prints the action file for polkit's actions directory.
// It names the users who run foca: polkit shows foca's prompt text only for
// an action's owners.
type PolkitPolicyCmd struct {
	Users []string `arg:"" optional:"" help:"Users who run foca, by name or uid (default: you)."`
}

func (c *PolkitPolicyCmd) Run(g *Globals, e *Env) error {
	users := c.Users
	if len(users) == 0 {
		u, err := user.Current()
		if err != nil {
			return fmt.Errorf("can't tell who you are (%v); name the users", err)
		}
		users = []string{u.Username}
	}
	b, err := polkit.PolicyFile(users...)
	if err != nil {
		return err
	}
	_, err = e.Stdout.Write(b)
	return err
}

// hostGrants is one instance in `foca grants --host -f json`.
type hostGrants struct {
	Instance string `json:"instance"`
	// Running is false when no verified service holds the instance's pid
	// file; its snapshot, if any, isn't trusted then (design §8.6).
	Running   bool           `json:"running"`
	Reuse     bool           `json:"reuse"`
	WrittenAt *time.Time     `json:"written_at,omitempty"`
	Grants    []svcctl.Grant `json:"grants"`
	Error     string         `json:"error,omitempty"`
}

// host lists the live grants of every running service, or of --instance,
// from the snapshots they keep (design §8.6). Like events, it takes the
// instance only from the flag, so a FOCA_INSTANCE left set can't hide one.
func (c *GrantsCmd) host(g *Globals, e *Env) error {
	paths, err := g.paths(e)
	if err != nil {
		return err
	}
	out, failed, err := hostSnapshots(g, paths)
	if err != nil {
		return err
	}
	if c.Format == "json" {
		for _, h := range out {
			if err := writeJSONLine(e.Stdout, h); err != nil {
				return err
			}
		}
	} else if err := printHostGrants(e, out); err != nil {
		return err
	}
	if failed == len(out) {
		return fmt.Errorf("no grants could be read")
	}
	return nil
}

// hostSnapshots reads the grants of every running service, or of
// --instance, and how many of them couldn't be read.
func hostSnapshots(g *Globals, paths config.Paths) ([]hostGrants, int, error) {
	var names []string
	if g.Instance != "" {
		if !config.ValidName(g.Instance) {
			return nil, 0, fmt.Errorf("--instance %q is not an instance name", g.Instance)
		}
		names = []string{g.Instance}
	} else {
		files, err := paths.PIDFiles()
		if err != nil {
			return nil, 0, err
		}
		for _, f := range files {
			names = append(names, filepath.Base(filepath.Dir(f)))
		}
		sort.Strings(names)
	}
	if len(names) == 0 {
		return nil, 0, fmt.Errorf("%w (no pid file in %s)", svcctl.ErrNotRunning, paths.RuntimeDir)
	}
	now := time.Now()
	out := make([]hostGrants, 0, len(names))
	failed := 0
	for _, name := range names {
		h := hostGrants{Instance: name, Grants: []svcctl.Grant{}}
		s, err := svcctl.ReadGrants(paths.PIDFile(name), paths.GrantsFile(name), now)
		switch {
		case errors.Is(err, svcctl.ErrNotRunning):
			h.Error = err.Error()
		case err != nil:
			h.Running, h.Error = true, err.Error()
		default:
			h.Running, h.Reuse = true, s.Reuse
			h.WrittenAt = &s.WrittenAt
			if len(s.Grants) > 0 {
				h.Grants = s.Grants
			}
		}
		if h.Error != "" {
			failed++
		}
		out = append(out, h)
	}
	return out, failed, nil
}

// dropWait is how long foca grants --host --drop waits for the service to
// show the grants gone.
var dropWait = 5 * time.Second

// hostDrop asks the services holding the named grants to drop them (design
// §8.6): a request in the instance's private drop directory, then SIGUSR2,
// since a signal carries no data. Tightening, so no approval. It reports a
// drop only once the service's snapshot shows it.
func (c *GrantsCmd) hostDrop(g *Globals, e *Env) error {
	if len(c.Names) == 0 {
		return fmt.Errorf("name the grants to drop by approval id (APPROVAL_ID or APPROVAL_ID/NAME, as foca grants --host -f json shows them); foca lock drops them all")
	}
	if c.Format != "table" {
		return fmt.Errorf("--format only applies to listing")
	}
	var targets []svcctl.DropTarget
	for _, arg := range c.Names {
		id, name, _ := strings.Cut(arg, "/")
		t := svcctl.DropTarget{ApprovalID: id}
		if name != "" {
			t.Kind, t.Name = "action", name
			if strings.Contains(name, ":") {
				t.Kind = "secret"
			}
		}
		if err := t.Check(); err != nil {
			return fmt.Errorf("%s: %w", clean(arg), err)
		}
		targets = append(targets, t)
	}
	paths, err := g.paths(e)
	if err != nil {
		return err
	}
	snaps, _, err := hostSnapshots(g, paths)
	if err != nil {
		return err
	}
	// Each target goes to the instance whose snapshot holds it.
	byInstance := map[string][]svcctl.DropTarget{}
	var order []string
	matched := 0
	for _, t := range targets {
		found := false
		for _, h := range snaps {
			n := 0
			for _, gr := range h.Grants {
				if dropMatches(t, gr) {
					n++
				}
			}
			if !h.Running || n == 0 {
				continue
			}
			matched += n
			if byInstance[h.Instance] == nil {
				order = append(order, h.Instance)
			}
			byInstance[h.Instance] = append(byInstance[h.Instance], t)
			found = true
		}
		if !found {
			return fmt.Errorf("no live grant %s (see foca grants --host)", clean(t.ApprovalID+slashName(t)))
		}
	}
	for _, inst := range order {
		if err := svcctl.WriteDropRequest(paths.DropDir(inst), byInstance[inst]); err != nil {
			return err
		}
		if _, err := svcctl.Signal(paths.PIDFile(inst), syscall.SIGUSR2); err != nil {
			return err
		}
	}
	// Wait for every snapshot to show its grants gone.
	deadline := time.Now().Add(dropWait)
	for _, inst := range order {
		for {
			s, err := svcctl.ReadGrants(paths.PIDFile(inst), paths.GrantsFile(inst), time.Now())
			if err == nil && !slices.ContainsFunc(s.Grants, func(gr svcctl.Grant) bool {
				return slices.ContainsFunc(byInstance[inst], func(t svcctl.DropTarget) bool { return dropMatches(t, gr) })
			}) {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("instance %s hasn't shown the grants dropped after %s; see its service's log", inst, dropWait)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	fmt.Fprintf(e.Stderr, "dropped %d grant(s); the next access asks again\n", matched)
	return nil
}

func dropMatches(t svcctl.DropTarget, g svcctl.Grant) bool {
	return t.ApprovalID == g.ApprovalID && (t.Kind == "" || t.Kind == g.Kind && t.Name == g.Name)
}

func slashName(t svcctl.DropTarget) string {
	if t.Name == "" {
		return ""
	}
	return "/" + t.Name
}

// printHostGrants writes the table, then what it leaves out: instances with
// no grants on one line, then any that couldn't be read or can't reuse.
// The notes come after the table so they don't land above it.
func printHostGrants(e *Env, out []hostGrants) error {
	w := tabwriter.NewWriter(e.Stdout, 0, 4, 2, ' ', 0)
	header := false
	var idle, notes []string
	for _, h := range out {
		switch {
		case h.Error != "":
			notes = append(notes, h.Instance+": "+clean(h.Error))
			continue
		case !h.Reuse:
			notes = append(notes, h.Instance+": reuse is off (no platform events), so every access asks")
		case len(h.Grants) == 0:
			idle = append(idle, h.Instance)
		}
		for _, gr := range h.Grants {
			if !header {
				fmt.Fprintln(w, "INSTANCE\tNAME\tSCOPE\tFOR\tEXPIRES")
				header = true
			}
			name := gr.Name
			if gr.Kind == "action" {
				name = "action " + name
				if len(gr.Params) > 0 {
					name += " (" + action.DescribeParams(gr.Params) + ")"
				}
			}
			expires := gr.ExpiresAt.Local().Format(time.DateTime)
			if gr.Quiet {
				expires += " (quiet)"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", h.Instance, clean(name), clean(gr.Scope), clean(scopeHolder(gr.ScopeKey)), expires)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if len(idle) > 0 {
		fmt.Fprintln(e.Stderr, "no live grants: "+strings.Join(idle, ", "))
	}
	for _, n := range notes {
		fmt.Fprintln(e.Stderr, n)
	}
	return nil
}

// scopeHolder names what a grant is keyed on: a peer's session or one
// connection.
func scopeHolder(k *audit.ScopeKey) string {
	switch {
	case k == nil:
		return "-"
	case k.PeerSession != nil:
		return "session " + k.PeerSession.Value
	case k.Connection != nil:
		return "connection " + k.Connection.Value
	}
	return "-"
}
