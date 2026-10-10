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

// ActionPolicy is the policy for inst running action id (design §11.1): the
// action's own levels (instance, action, the configured authenticator, the
// floor) met with the policy of every secret it uses, so a strict secret
// can't be loosened by putting it inside an action. Vault levels count only
// through those secrets.
func (c *Config) ActionPolicy(inst Instance, id string) policy.Policy {
	p := policy.Effective(
		inst.Policy,
		c.ActionPolicies[id],
		c.AuthenticatorPolicies[c.Plugins.Authenticator],
	)
	if s := c.Actions[id]; s != nil {
		for _, sid := range s.SecretIDs() {
			p = policy.Meet(p, c.SecretPolicy(inst, sid))
		}
	}
	return p
}
