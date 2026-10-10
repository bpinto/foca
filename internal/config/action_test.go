package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/policy"
)

// actionsConfig is the design's example (§7.1, §11), on Linux paths.
const actionsConfig = `
version = 1
[plugins]
authenticator = "fake"
secret_store = "memory"
[vaults.common]
[instances.dev]
realm   = { kind = "vm" }
expose  = ["common:github-pat", "common:npm-token"]
actions = ["aws-creds", "aws-sso-login", "gh-pr-list"]
[instances.work]
realm   = { kind = "vm" }
expose  = ["common:*"]
[instances.host]
expose  = ["common:github-pat"]
actions = "*"

[actions.aws-creds]
description = "AWS credentials for a profile via granted"
command     = "/run/current-system/sw/bin/granted"
args        = ["credential-process", "--profile", "{profile}"]
timeout     = "60s"
output      = { format = "aws-credential-process", max_bytes = 65536 }
env         = { HOME = "/home/bruno", PATH = "/usr/bin:/bin" }
  [actions.aws-creds.params.profile]
  allowed = ["dev-admin", "staging-readonly"]
  [actions.aws-creds.policy]
  approval = "reuse"
  window   = "15m"
  scope    = "peer-session"

[actions.aws-sso-login]
command = "/run/current-system/sw/bin/granted"
args    = ["sso", "login", "--sso-start-url", "https://example.awsapps.com/start"]
timeout = "5m"

[actions.gh-pr-list]
command      = "/run/current-system/sw/bin/gh"
args         = ["pr", "list", "--repo", "{repo}"]
env_secrets  = { GH_TOKEN = "common:github-pat" }
  [actions.gh-pr-list.params.repo]
  pattern = "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
`

func TestActionsParseLikeTheDesignExample(t *testing.T) {
	c, err := Parse([]byte(actionsConfig))
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := c.Instance("dev")
	work, _ := c.Instance("work")
	host, _ := c.Instance("host")
	if !slices.Equal(dev.Actions, []string{"aws-creds", "aws-sso-login", "gh-pr-list"}) || work.Actions != nil ||
		!slices.Equal(host.Actions, dev.Actions) {
		t.Fatalf("offered: dev %v, work %v, host %v", dev.Actions, work.Actions, host.Actions)
	}
	aws := c.Actions["aws-creds"]
	if aws.Timeout != time.Minute || aws.Format != "aws-credential-process" || aws.MaxBytes != 65536 || aws.Mask {
		t.Fatalf("aws-creds %+v", aws)
	}
	sso := c.Actions["aws-sso-login"]
	if sso.Timeout != 5*time.Minute || sso.MaxBytes != 64<<10 {
		t.Fatalf("aws-sso-login %+v", sso)
	}
	// Masking is on by default once an action uses secrets.
	if gh := c.Actions["gh-pr-list"]; !gh.Mask || gh.EnvSecrets["GH_TOKEN"] != "common:github-pat" {
		t.Fatalf("gh-pr-list %+v", gh)
	}
}

func TestActionRejections(t *testing.T) {
	base := minimal + `
[actions.a]
command = "/bin/true"
`
	cases := map[string]struct{ cfg, want string }{
		"no command":            {minimal + "\n[actions.a]\nargs = []\n", "actions.a: command is required"},
		"relative command":      {strings.Replace(base, "/bin/true", "true", 1), "absolute path"},
		"undeclared param":      {base + `args = ["{x}"]` + "\n", "{x} is not declared"},
		"unused param":          {base + "[actions.a.params.x]\nallowed = [\"1\"]\n", "params.x is declared but no argument uses it"},
		"unknown action key":    {base + "shell = true\n", "unknown keys: actions.a.shell"},
		"unknown param key":     {base + "args = [\"{x}\"]\n[actions.a.params.x]\nregex = \".*\"\n", "unknown keys"},
		"timeout 0":             {base + "timeout = \"0s\"\n", "timeout must not be 0"},
		"timeout too long":      {base + "timeout = \"2h\"\n", "timeout 2h0m0s is outside"},
		"max_bytes 0":           {base + "output = { max_bytes = 0 }\n", "max_bytes must not be 0"},
		"unknown format":        {base + "output = { format = \"xml\" }\n", "output.format"},
		"mask without secrets":  {base + "mask_output = true\n", "mask_output only applies with env_secrets"},
		"unbalanced pattern":    {base + "args = [\"{x}\"]\n[actions.a.params.x]\npattern = \"[a-z]+)|(.*\"\n", "params.x: pattern"},
		"bad action id":         {minimal + "\n[actions.AWS]\ncommand = \"/bin/true\"\n", "id \"AWS\" must match"},
		"undeclared action":     {strings.Replace(minimal, `realm = { kind = "vm" }`, `realm = { kind = "vm" }`+"\nactions = [\"nope\"]", 1), `action "nope" is not declared`},
		"star in list":          {strings.Replace(base, `realm = { kind = "vm" }`, `realm = { kind = "vm" }`+"\nactions = [\"*\", \"a\"]", 1), `use actions = "*"`},
		"bad actions value":     {strings.Replace(base, `realm = { kind = "vm" }`, `realm = { kind = "vm" }`+"\nactions = \"all\"", 1), `actions must be "*" or a list`},
		"action policy invalid": {base + "[actions.a.policy]\napproval = \"reuse\"\n", "actions.a.policy: approval = \"reuse\" needs a window"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(tc.cfg))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want error containing %q", err, tc.want)
			}
		})
	}
}

// An action offered to an instance can't use a secret that the instance's
// expose list leaves out.
func TestActionSecretsMustBeExposed(t *testing.T) {
	cfg := strings.Replace(actionsConfig, `expose  = ["common:github-pat", "common:npm-token"]`, `expose  = ["common:npm-token"]`, 1)
	_, err := Parse([]byte(cfg))
	if err == nil || !strings.Contains(err.Error(), `instances.dev: action "gh-pr-list" uses secret "common:github-pat", which the instance's expose list leaves out`) {
		t.Fatalf("got %v", err)
	}
	// In a vault read whole, only the run can tell whether the secret exists.
	cfg = strings.Replace(actionsConfig, `expose  = ["common:github-pat", "common:npm-token"]`, `expose  = ["common:*"]`, 1)
	if _, err := Parse([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
}

// A strict secret can't be loosened by putting it inside an action, and an
// action's reuse needs an opt-in at a level of its own (design §11.1).
func TestActionPolicyMeetsItsSecrets(t *testing.T) {
	cfg := actionsConfig + `
[instances.dev.policy]
approval = "reuse"
window   = "30m"
scope    = "peer-session"
[vaults.common.policy]
approval = "reuse"
window   = "2h"
[secrets."common:github-pat".policy]
approval = "every-time"
`
	c, err := Parse([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	dev, _ := c.Instance("dev")
	host, _ := c.Instance("host")
	want := policy.Policy{Kind: policy.Reuse, Window: 15 * time.Minute, Scope: policy.ScopePeerSession}
	if got := c.ActionPolicy(dev, "aws-creds"); got != want {
		t.Errorf("aws-creds: %v, want %v", got, want)
	}
	if got := c.ActionPolicy(dev, "gh-pr-list"); got.Kind != policy.EveryTime {
		t.Errorf("gh-pr-list uses an every-time secret: %v", got)
	}
	// The vault's reuse level only counts through the secrets an action
	// uses; with nothing at the action's own levels, it asks every time.
	if got := c.ActionPolicy(host, "aws-sso-login"); got.Kind != policy.EveryTime {
		t.Errorf("aws-sso-login on host: %v", got)
	}
	cfg = strings.Replace(cfg, "[secrets.\"common:github-pat\".policy]\napproval = \"every-time\"\n", "[actions.gh-pr-list.policy]\napproval = \"reuse\"\nwindow = \"8h\"\n", 1)
	if c, err = Parse([]byte(cfg)); err != nil {
		t.Fatal(err)
	}
	dev, _ = c.Instance("dev")
	want = policy.Policy{Kind: policy.Reuse, Window: 30 * time.Minute, Scope: policy.ScopePeerSession}
	if got := c.ActionPolicy(dev, "gh-pr-list"); got != want {
		t.Errorf("gh-pr-list folds instance 30m, action 8h, secret (vault 2h): %v, want %v", got, want)
	}
}
