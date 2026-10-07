package config

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bpinto/foca/internal/policy"
)

// knownAuthenticators are the names [authenticators.<name>.policy] may use.
// Only the configured authenticator's entry applies; the others are allowed
// so a config can switch authenticators without losing their settings.
var knownAuthenticators = map[string]bool{
	"touchid": true, "polkit": true, "fake": true,
}

// parsePolicy reads one level. A missing table is Unset ("no opinion").
func parsePolicy(r *rawPolicy) (policy.Policy, error) {
	if r == nil {
		return policy.Policy{}, nil
	}
	switch r.Approval {
	case "every-time":
		if r.Window != nil || r.Scope != "" {
			return policy.Policy{}, errors.New(`approval = "every-time" takes no window or scope`)
		}
		return policy.Policy{Kind: policy.EveryTime}, nil
	case "reuse":
		if r.Window == nil {
			return policy.Policy{}, errors.New(`approval = "reuse" needs a window`)
		}
		w := r.Window.Duration
		if w < policy.MinReuseWindow || w > policy.MaxReuseWindow {
			return policy.Policy{}, fmt.Errorf("window %s is outside %s..%s", w, policy.MinReuseWindow, policy.MaxReuseWindow)
		}
		p := policy.Policy{Kind: policy.Reuse, Window: w}
		if r.Scope != "" {
			s, err := policy.ParseScope(r.Scope)
			if err != nil {
				return policy.Policy{}, err
			}
			p.Scope = s
		}
		return p, nil
	case "":
		return policy.Policy{}, errors.New(`approval is required ("every-time" or "reuse")`)
	default:
		return policy.Policy{}, fmt.Errorf(`approval must be "every-time" or "reuse", got %q`, r.Approval)
	}
}

// checkGuestScopes refuses guest-* scopes on instances without the guest
// relay. Such a scope is never widened to peer-session in its place (design
// §9.1, safeguard 2). The relay isn't built yet, so no instance
// has one and every guest-* scope is an error.
func (c *Config) checkGuestScopes() []error {
	var errs []error
	check := func(where string, p policy.Policy, applies []Instance) {
		if p.Kind != policy.Reuse || !p.Scope.NeedsRelay() {
			return
		}
		names := make([]string, len(applies))
		for i, inst := range applies {
			names[i] = inst.Name
		}
		if len(names) == 0 {
			return
		}
		errs = append(errs, fmt.Errorf("%s: scope %q needs the guest relay (design §14), which %s doesn't have; it is never replaced by a wider scope",
			where, p.Scope, strings.Join(names, ", ")))
	}
	for _, inst := range c.Instances {
		check("instances."+inst.Name+".policy", inst.Policy, []Instance{inst})
	}
	for _, v := range sortedKeys(c.VaultPolicies) {
		var users []Instance
		for _, inst := range c.Instances {
			if _, ok := inst.Expose[v]; ok {
				users = append(users, inst)
			}
		}
		check("vaults."+v+".policy", c.VaultPolicies[v], users)
	}
	for _, id := range sortedKeys(c.SecretPolicies) {
		check("secrets."+id+".policy", c.SecretPolicies[id], c.Instances)
	}
	if p, ok := c.AuthenticatorPolicies[c.Plugins.Authenticator]; ok {
		check("authenticators."+c.Plugins.Authenticator+".policy", p, c.Instances)
	}
	return errs
}

// SecretPolicy folds every level that applies when inst reads the secret
// named name, "<vault>:<id>" (design §9.2): instance, vault, secret, the configured authenticator, and
// the floor in code. It does not know whether platform events are healthy;
// the service turns the result into EveryTime when they aren't.
func (c *Config) SecretPolicy(inst Instance, name string) policy.Policy {
	// "<vault>:" is any secret of the vault, for policy explain.
	vault, _, _ := strings.Cut(name, ":")
	return policy.Effective(
		inst.Policy,
		c.VaultPolicies[vault],
		c.SecretPolicies[name],
		c.AuthenticatorPolicies[c.Plugins.Authenticator],
	)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
