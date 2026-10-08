<div align="center">

# 🦭 foca

**Approval-gated credentials for your VMs, containers and coding agents.**

[![test](https://github.com/bpinto/foca/actions/workflows/test.yml/badge.svg)](https://github.com/bpinto/foca/actions/workflows/test.yml)
[![release](https://img.shields.io/github/v/release/bpinto/foca)](https://github.com/bpinto/foca/releases/latest)
[![platforms](https://img.shields.io/badge/platforms-macOS%20%7C%20Linux-lightgrey)](#install)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

[Install](#install) · [Quick start](#quick-start) · [Commands](#commands) · [Actions](#actions) · [Security](#security-model) · [Design](docs/design.md) · [For agents](AGENTS.md)

</div>

---

foca is a small service, like `ssh-agent`, that hands secrets from your machine to the
processes, microVMs and containers that need them. **Nothing is handed out silently**:
each access asks for your approval, the prompt says exactly who is asking for what, and
every attempt lands in an audit log.

> **foca** is trying to let **gh** use **GitHub PAT** in **VM dev**, via **claude**.
> Approving allows reuse for 15m by anything in VM dev.

## Why foca

- 🔐 **Every access approved.** Touch ID on macOS, your desktop's polkit password dialog on
  Linux. Every time, unless your config opts in to a reuse window. Stricter settings
  always win, and reuse is capped at 8 hours.
- 🧭 **Prompts you can trust.** A program is named as fact only when a kernel vouches for
  it. What a VM merely claims is labelled as a claim, and nothing a caller sends can add
  words to the prompt.
- 🧱 **One realm, one socket.** Each VM or container gets its own socket and, by default,
  its own vault and key. A realm can't see, or even detect, another realm's secrets.
- ⚙️ **Host commands, not just tokens.** Declare actions such as "AWS credentials via
  `granted`" in config. A VM runs them by name with checked parameters, and the secrets
  they use never leave the host.
- 🌙 **Locks with your screen.** Sleep, screen lock and log-out drop every grant at once.
- 📜 **Everything recorded.** A versioned JSONL audit log of every request, approved or
  not, that `foca events` can query and follow live. Never values, output or keys.
- 🛡️ **Fails closed.** If it can't verify, prompt or record, it refuses.

## How it works

```
 Host (Mac or Linux)                                 microVM "dev"
┌─────────────────────────────────────────┐         ┌────────────────────────────┐
│ foca serve                              │         │                            │
│  ├─ dev/client.sock  ◄──────────────────┼── ssh ──┤  ~/.foca.sock  ◄── foca    │
│  ├─ vaults/dev.fcv   (AES-256-GCM)      │ Remote  │                    get     │
│  ├─ audit.jsonl                         │ Forward │                    run     │
│  └─ approval: Touch ID · polkit         │         │                    exec    │
└─────────────────────────────────────────┘         └────────────────────────────┘
```

A request names a secret or an action. The service resolves it from host config, works
out the policy, asks for approval (or reuses a live grant), records the decision, serves
the value or runs the command, and records the outcome before anything is returned.

## Install

Download the archive for your platform from the
[latest release](https://github.com/bpinto/foca/releases/latest) and put its contents on
your `PATH`:

| Platform | Archive |
|---|---|
| macOS (Apple silicon) | `foca-darwin-arm64.tar.gz` |
| Linux (x86-64) | `foca-linux-amd64.tar.gz` |
| Linux (ARM64) | `foca-linux-arm64.tar.gz` |

```sh
curl -fsSL https://github.com/bpinto/foca/releases/latest/download/foca-darwin-arm64.tar.gz \
  | tar -xz -C ~/.local/bin
```

On macOS the archive holds `foca` and `foca-darwin`, the small signed helper for Touch ID,
the Keychain and sleep events. Keep the two in the same directory: `foca` only runs the
helper it was released with.

Every release includes `SHA256SUMS` for checking the archives.

<details>
<summary><b>Nix</b></summary>

`nix profile install github:bpinto/foca`, or use the modules. On a NixOS host the module
installs foca's polkit action, gives its users the TPM and restricts ptrace; the home-manager
module writes the config from Nix, checks it with foca at build time, and runs the service, as
systemd user units on Linux and launchd agents on macOS:

```nix
# flake inputs: foca.url = "github:bpinto/foca";
# NixOS
imports = [ foca.nixosModules.default ];
services.foca = { enable = true; users = [ "alice" ]; };

# home-manager
imports = [ foca.homeManagerModules.default ];
services.foca = {
  enable = true;
  settings = {
    plugins = { authenticator = "polkit"; key_protector = "tpm"; };
    instances.dev.realm.kind = "vm";
  };
};
```

In a VM, `foca.nixosModules.guest` installs the client and sets `kernel.yama.ptrace_scope`.
On macOS (Apple silicon) the package is the release archive, installed as it is: its helper
is signed and pinned into `foca`, so Nix must not strip or sign it again. Use `touchid` and
`keychain` there.

</details>

## Quick start

**1. Configure** `~/.config/foca/config.toml` on the host:

```toml
version = 1

[plugins]
authenticator = "touchid"         # Linux: "polkit" (below)
key_protector = "keychain"        # Linux: "tpm"

[instances.dev]                   # one per realm; this one is a VM
realm = { kind = "vm" }
```

On Linux, use `authenticator = "polkit"` and `key_protector = "tpm"`: each vault key is sealed
to the machine's TPM and bound to the Secure Boot state and keys (PCR 7), so the vault opens
only on this machine, with Secure Boot on and its keys unchanged. foca refuses PCR 7 with
Secure Boot off; listing more PCRs in `[key_protectors.tpm] pcrs` binds to more of what boots
(design §4.2.1). You need access to `/dev/tpmrm0` (usually the `tss` group). polkit needs
foca's action installed once:

```sh
foca polkit-policy | sudo tee /usr/share/polkit-1/actions/io.github.bpinto.foca.policy
```

**2. Create a vault, add a secret, start the service:**

```sh
foca init --recovery              # creates the vault; its key goes to the Keychain or TPM
foca add dev:github-pat           # in vault dev; value from a hidden prompt or stdin
foca serve                        # run it under launchd or systemd for daily use
```

`--recovery` also makes a recovery key and prints it once, on stdout: copy it down and keep it
away from this machine (`foca init --recovery | pass insert -m foca/dev` keeps it in a
password manager). After a firmware or Secure Boot change the TPM won't release the vault
key, and `foca recover` uses the recovery key to seal it again. On Linux, `init` requires it.

**3. Forward the socket into the VM** (`~/.ssh/config` on the host):

```
Host dev
  RemoteForward /home/me/.foca.sock /path/to/runtime/foca/dev/client.sock
  StreamLocalBindUnlink yes
```

The socket is in `$XDG_RUNTIME_DIR/foca/<instance>/`, or `$TMPDIR/foca-<uid>/<instance>/`.

**4. Use it from the VM:**

```sh
foca get dev:github-pat | gh auth login --with-token
foca run -e GH_TOKEN=dev:github-pat -- gh pr list
```

## Commands

| Command | Runs on | What it does |
|---|---|---|
| `foca serve [--only <instance>…]` | host | Run the service for every instance in the config, or some of them |
| `foca init` · `add` · `edit` · `remove` | host | Manage vaults and secrets, each approved |
| `foca recover` | host | Seal a vault's key again with its recovery key, after a firmware or Secure Boot change |
| `foca rekey` | host | Encrypt a vault again under a new key and recovery key, so the old recovery key and copies of the old file open nothing in it from then on (a copy still holds the secrets as they were) |
| `foca reload` · `stop` | host | Reload the config, or stop the service |
| `foca lock` | host | Drop every reuse grant now |
| `foca policy explain [names…]` | host | What the config allows, in the prompt's own words |
| `foca config check [file]` | host | Check a config file as `serve` would |
| `foca events query` · `follow` | host | Search the audit log, or follow it live |
| `foca list` | anywhere | Names and descriptions you can read, never values |
| `foca get <names…>` | anywhere | Values to a pipe or file: `-f raw\|json\|env`, `-o FILE` |
| `foca run -e VAR=name -- cmd` | anywhere | Run a command with secrets in its environment |
| `foca actions` | anywhere | Actions you can run, with their parameters |
| `foca exec <action> -p k=v` | anywhere | Run a host action and pass on its output and exit code |
| `foca grants [--drop]` | anywhere | List or drop your reuse grants |

Several secrets in one `get` or `run` take one approval. `get` won't write a secret to a
terminal. `-f env` writes `NAME=value` lines for `docker run --env-file`, values taken raw;
never `source` it in a shell or use it as a systemd `EnvironmentFile`. On the host, `-i <instance>` picks a socket when there are several.

## Audit log

Every request, approved or not, is one JSON line in `audit.jsonl` in the data directory.
`foca events` reads it as JSON lines:

```sh
foca events query --type secret.read --since 24h          # up to 100; --limit up to 500
foca events query -i dev --outcome denied --after-seq 1042  # the next page
foca events follow --resource secret:common:github-pat    # new events, live, until ^C
foca events follow --from-seq 1                           # everything stored, then live
```

When more events match than `--limit`, `query` ends with `{"next_after_seq": N}`. The log
rotates by size, and rotated files are kept up to a limit:

```toml
[audit]
max_file_size_mib = 16            # 1-1024
keep_files        = 16            # rotated files kept, 1-1000
```

## Actions

Actions are host commands declared in full in config. A realm can only run the actions
its instance is offered, by name, filling in declared parameters:

```toml
[instances.dev]
realm   = { kind = "vm" }
actions = ["aws-creds"]

[actions.aws-creds]
description = "AWS credentials"
command     = "/opt/homebrew/bin/granted"
args        = ["credential-process", "--profile", "{profile}"]
output      = { format = "aws-credential-process" }
env         = { HOME = "/Users/me", PATH = "/usr/bin:/bin" }
  [actions.aws-creds.params.profile]
  allowed = ["dev-admin", "staging-readonly"]
```

Then in the VM's `~/.aws/config`:

```ini
credential_process = foca exec aws-creds --param profile=dev-admin
```

- **No shell.** `{profile}` fills exactly one argument; there is nothing to inject into.
- **Checked parameters.** Every value must be `allowed` or fully match a `pattern`, and
  values starting with `-` are refused unless permitted.
- **Clean, bounded runs.** Only the configured environment, stdin from `/dev/null`, a
  timeout that kills the whole process group, and a cap on output.
- **Secrets stay home.** `env_secrets = { GH_TOKEN = "dev:github-pat" }` gives a secret to the
  command on the host. The prompt names it, and it is masked out of the output.

<details>
<summary><b>Reuse policies</b></summary>

By default every access asks. Allow reuse at any level, and the strictest wins:

```toml
[instances.dev.policy]       # also [vaults.<name>.policy], [actions.<id>.policy]
approval = "reuse"           #   and [authenticators.<name>.policy]
window   = "30m"

[secrets."common:prod-db".policy]
approval = "every-time"      # always asks, whatever the other levels say
```

Run `foca policy explain` to check what a config means before approving anything.

</details>

<details>
<summary><b>Sharing a vault between realms</b></summary>

Each instance reads a private vault named after it by default. `expose` lists what it reads
instead, from any number of vaults: `"<vault>:*"` for all of one, `"<vault>:<secret>"` for one
secret. A shared vault is declared in `[vaults]`:

```toml
[vaults.common]

[instances.dev]
realm  = { kind = "vm" }
expose = ["dev:*", "common:github-pat", "common:npm-token"]

[instances.work]
realm  = { kind = "vm" }
expose = ["common:*"]
```

A secret outside `expose` looks exactly like one that doesn't exist. A secret is always named
with its vault, `common:github-pat`, in requests, config, prompts and the audit log, so two
vaults can hold the same name.

</details>

<details>
<summary><b>Verified identity inside a VM</b></summary>

Over a forwarded socket the host only sees `ssh`, so the program inside the VM is shown as
a claim (`VM claims: gh via claude`). Run the optional guest relay inside the VM and the
prompt names the program as verified by the VM's kernel, which also enables reuse scoped
to one VM session or one program. See
[design §14](docs/design.md#14-guest-verified-identity-the-guest-relay-optional).

</details>

## Security model

**foca defends against** a VM or agent reading secrets without you knowing, one realm
reaching another's secrets, arbitrary host command execution, a realm managing the host,
policy being loosened from inside a realm, prompt floods, and secrets left reusable on an
unattended machine.

**It doesn't defend against** a secret after you approve it (the realm has it then), you
approving blindly, or malware running as your user on the host. Full threat model:
[design §12](docs/design.md#12-threat-model).

## Documentation

- [**Design**](docs/design.md): architecture, protocol, config, policy and threat model
- [**AGENTS.md**](AGENTS.md): detailed reference for AI agents using or working on foca
- [**CONTRIBUTING.md**](CONTRIBUTING.md): how to contribute

## Development

```sh
nix develop                       # Go, gopls, socat, dbus, polkit, bubblewrap, swtpm
go test ./...                     # everything that runs on Linux
go test -tags foca_testing ./...  # + end-to-end tests with a fake authenticator
nix flake check                   # the Nix package and modules
scripts/build-darwin.sh           # macOS build with the signed, pinned helper
```

## License

foca is released under the [MIT License](LICENSE). Contributions are welcome; see
[CONTRIBUTING.md](CONTRIBUTING.md).
