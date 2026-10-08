package cli

import (
	"fmt"
	"os/user"
	"slices"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/bpinto/foca/internal/action"
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
	pid, err := svcctl.Signal(paths.PIDFile(), syscall.SIGUSR1)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.Stderr, "lock requested (pid %d): every reuse grant is dropped\n", pid)
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
// approved (design §9.1, safeguard 7). The wording is the same as the
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
	Drop  bool     `help:"Drop grants instead of listing them: the named ones, or all of yours."`
	Names []string `arg:"" optional:"" help:"Secrets or actions whose grants to drop (with --drop)."`
}

// Run lists or drops the caller's own reuse grants. Dropping is tightening,
// so it never needs approval.
func (c *GrantsCmd) Run(g *Globals, e *Env) error {
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
