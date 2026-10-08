# AGENTS.md

Detailed reference for AI agents. Part 1 is for agents that **use** foca to get credentials
inside a VM, container or host shell. Part 2 is for agents that **work on** this repository.
The human overview is [README.md](README.md); the full specification is
[docs/design.md](docs/design.md).

---

# Part 1: using foca

## What to expect

- Every `get`, `run` and `exec` may show the user a Touch ID prompt and **block until they
  answer** (60 s by default). Don't set short timeouts around foca calls.
- The prompt names your program and the credential, so ask for exactly what the task needs,
  in one call. Several names in one `get` or `run` are **one** prompt.
- A denial is the user's decision. Don't retry it: repeated denials are refused without a
  prompt for 2 s, then 8 s, then 30 s, and three unapproved prompts put the whole realm on a
  cooldown (30 s, then 2 min, then 5 min). Tell the user what you needed and why instead.
- Values never belong in your output, logs, files you commit, or command arguments. Pipe
  them, or put them in a child's environment with `foca run`.
- foca never prompts in the terminal when stdin or stderr isn't a TTY. A missing input is an
  error naming the flag to use, never a hang.

## Finding the socket

In order: `--socket PATH`, `$FOCA_SOCK`, `--instance NAME` / `$FOCA_INSTANCE` (host only:
that instance's socket in the runtime directory), `~/.foca.sock` (the usual forwarded
socket in a realm), then the only instance in the host config. "service not running (no
socket at …)" means none of these is listening.

## Discovering what you may use

```sh
foca list        # NAME  DESCRIPTION — names you can read; never values
foca actions     # NAME  DESCRIPTION  PARAMS — e.g. profile=dev-admin|staging-readonly
```

Neither needs approval, but both are audited. A secret or action you can't see behaves
exactly like one that doesn't exist (`not_found`).

## Reading secrets

```sh
foca get common:github-pat | tool --token-stdin           # raw: exactly one value, bytes as stored
foca get -f json common:github-pat dev:cert            # {"common:github-pat":"ghp_…","dev:cert":{"base64":"MIIC…"}}
foca get -f env GH_TOKEN=common:github-pat dev:npm-token  # GH_TOKEN=…\nNPM_TOKEN=…
foca get -o ./token common:github-pat                  # new 0600 file, renamed into place
foca run -e GH_TOKEN=common:github-pat -e dev:npm-token -- npm publish
```

- A secret is always named with its vault: `<vault>:<secret>`, as `foca list` shows it. The
  vault matches `[a-z0-9][a-z0-9-]{0,31}`, the secret `[A-Za-z0-9_-]{1,128}`. At most 32
  per request.
- `raw` takes exactly one name. `json` writes non-UTF-8 values as `{"base64": …}`. `env`
  writes `NAME=value` lines for `docker run --env-file`, which takes each value raw to the end
  of the line; it refuses values with a line break, NUL or invalid UTF-8, and a variable named
  twice. Never `source` or `eval` it in a shell (it would run `$(…)`), and don't use it as a
  systemd `EnvironmentFile` (which interprets quotes, backslashes and spaces).
- A bare name in `-f env` or `run -e` becomes its upper-cased variable, vault left out:
  `dev:npm-token` → `NPM_TOKEN`.
- `get` refuses to write to a terminal; redirect stdout or use `-o`. `-o` refuses symlinks,
  directories and devices. A redirect to a file others may read (umask 022) gets a warning:
  prefer `-o`, which makes the file 0600.
- `run` replaces itself with the command (`execve`), so its exit code is the command's.

## Running actions

```sh
foca exec aws-creds -p profile=dev-admin        # also --param name=value
```

- stdout is the action's stdout; stderr gets the last 4 KiB of its stderr; the exit code is
  the action's (1 if it was outside 0–255). On a non-zero exit stdout is withheld unless the
  host set `return_on_failure`. Like `get`, `exec` won't write output to a terminal: pipe
  or redirect stdout (an action with no output runs anywhere).
- Every declared param is required, and no others are accepted. Values must match the
  host's `allowed` list or `pattern`, at most 256 bytes, no control, format or separator
  characters but a plain space, and not starting with `-` unless the host allows it. You
  can't choose the command, arguments or environment.
- Secrets an action uses stay on the host; any that show up in its output read
  `[hidden:<id>]`.
- AWS: `credential_process = foca exec aws-creds --param profile=dev-admin`.

## Grants

If the host allows reuse, one approval covers later requests for a while (the prompt says
for how long and for whom). An action's grant covers only the parameter values it was
approved with.

```sh
foca grants                     # NAME  SCOPE  EXPIRES
foca grants --drop [names…]     # drop yours, all or by name; never needs approval
```

## Errors

The CLI prints `foca: <name>: <message>` on stderr and exits 1 (2 for a usage error).

| Name | Code | Meaning | What to do |
|---|---|---|---|
| `denied` | -32001 | the user refused, or a recent denial or cooldown is still running | stop; tell the user what you needed |
| `not_found` | -32002 | no such secret or action here, or an action uses a secret this realm can't read | check `foca list` / `foca actions` |
| `not_initialized` | -32003 | the vault hasn't been created | the user runs `foca init` on the host |
| `auth_unavailable` | -32004 | no prompt can be shown (no GUI session, no Touch ID) | ask the user |
| `timeout` | -32005 | nobody answered the prompt, or the action timed out | ask the user before trying again |
| `busy` | -32006 | too many prompts queued, too many requests (30, then 5/s), or 4 actions already running | wait a few seconds |
| `audit_failed` | -32007 | the host couldn't record the request, so it refused | tell the user |
| `param_rejected` | -32008 | an action param is unknown, missing or fails its check | fix the params; see `foca actions` |
| `forbidden_on_socket` | -32010 | a host-only operation (add, init, …) | only the user can do this, on the host |
| `protocol_unsupported` | -32011 | the client needs a newer server | update foca on the host |
| `invalid_params` | -32602 | malformed request, or names that don't fit one prompt | split or fix the request |

## Talking to the socket directly

Newline-delimited JSON-RPC 2.0 over the Unix socket; messages at most 1 MiB; keys
snake_case, case-sensitive, unique; unknown fields are refused. Requests run in order, at
most 4 waiting per connection. Every request may carry `min_protocol` and `client` (your
own, unverified description of yourself).

| Method | Params | Result |
|---|---|---|
| `server.hello` | `{protocol: 1}` | `{protocol, instance, realm, server_version, features}` |
| `secret.list` | `{}` | `{secrets: [{name, display_name?, description?}]}` |
| `secret.read` | `{names: [...]}` | `{secrets: [{name, value, encoding: "utf8"\|"base64"}]}` |
| `action.list` | `{}` | `{actions: [{name, description?, params: [{name, description?, allowed?, pattern?, allow_leading_dash?}]}]}` |
| `action.run` | `{name, params?: {k: v}}` | `{exit_code, stdout?, stdout_encoding?, stderr_tail?, stderr_encoding?}` |
| `grants.status` | `{}` | `{grants: [{name, kind, params?, scope, approval_id, expires_at}]}` |
| `grants.drop` | `{names?: [...]}` | `{dropped}` |

Errors carry `error.data = {name, request_id}`; `request_id` finds the audit record.

```sh
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"secret.list","params":{}}' \
  | socat - UNIX-CONNECT:$HOME/.foca.sock
```

---

# Part 2: working on foca

## Ground rules

- **Read [docs/design.md](docs/design.md) first.** It is the accepted specification, and
  describes the code as it is: §16 lists the tests behind each security property, §17 what
  isn't built or verified yet. A change that refines the design updates it.
- **Fail closed.** If something can't be verified, prompted for or recorded, refuse.
  Nothing is returned before its audit record is written.
- **Trusted and untrusted data never mix.** `identity.VerifiedPeer` comes only from the
  kernel, `ClientInfo` only from request bytes, `GuestInfo` only from the relay; they are
  separate types on purpose. Prompt text is built only from trusted fields, and untrusted
  names are sanitised (`identity.DisplayName`).
- **Secrets are `[]byte`, zeroed after use.** Never a `string` where avoidable, never in
  argv, logs or audit events.
- **Strict everywhere.** Config rejects unknown keys and out-of-range values (never clamps
  silently); the protocol rejects unknown, duplicate or case-variant keys.
- **No cgo.** macOS APIs go through the `foca-darwin` helper over stdio.
- **Boundaries are tested.** `internal/client` must not import service-side packages
  (`client/boundary_test.go`); the CLI's UI stack (`huh`) stays out of `internal/server`.
- **Test-only plugins** (the `fake` authenticator) exist only in builds tagged
  `foca_testing`. Never make them reachable otherwise.

## Layout

```
cmd/foca/                 main: runs internal/cli
internal/protocol/        wire types, JSON-RPC framing, strict decoding, error codes
internal/client/          socket client; imports no service code
internal/cli/             every command (kong; huh for interactive forms)
internal/server/          sockets, peer admission, dispatch (conn.go)
internal/server/core/     the pipeline: resolve → policy → grants → prompt → audit → serve
internal/server/wiring/   config → plugins; test-only plugins behind foca_testing
internal/config/          TOML loading and validation, policy folding, paths
internal/policy/          the "stricter wins" lattice and its plain-language wording
internal/action/          action specs: param checks, argv templates, output formats, masking
internal/plugin/          plugin interfaces; helper/ is the stdio helper adapter
internal/plugins/         authn/fake, store/{memory,vaultfile}, keyprot/file,
                          provider/{static,command}, peer (linux, darwin), events/logind
internal/audit/           event types (v1), JSONL and memory sinks
internal/identity/        verified, guest and reported identity types
internal/fsutil/          trusted-file checks, private dirs, atomic writes, locks
internal/svcctl/          serve.pid, the instance lock, and verified signalling (reload, lock, stop)
helpers/darwin/           foca-darwin (Swift): Touch ID, Keychain, sleep and lock events
```

## Build and test

```sh
nix develop                                             # dev shell: go, gopls, socat, dbus
go test ./...                                           # all Linux tests
go test -tags foca_testing ./...                        # + CLI end-to-end and binary tests
CGO_ENABLED=1 go test -race ./...                       # race detector (gcc from the shell)
GOOS=darwin GOARCH=arm64 go vet ./...                   # darwin code compiles and vets
gofmt -l internal cmd                                   # must print nothing
```

On a Mac: `scripts/build-darwin.sh`, then `FOCA_HELPER=$PWD/bin/foca-darwin go test
./internal/plugin/helper/...` runs the helper conformance suite; add
`FOCA_HELPER_INTERACTIVE=1` and `-run Interactive` for the Touch ID and screen-lock tests,
which need a person at the Mac. CI runs the Linux
matrix and the macOS suite on every push (`.github/workflows/test.yml`).

## Releases

`.github/workflows/release.yml` runs after `test` passes for a push, and builds through
`scripts/build-linux.sh` and `scripts/build-darwin.sh` (which pins the signed helper into
`foca`):

- every commit on `main` replaces the assets of the rolling `tip` pre-release, versioned
  `<next patch>-tip.<commit date, UTC, YYYYMMDD>+<sha>`; an older commit never
  replaces a newer one;
- a `vX.Y.Z` tag publishes that release.

Assets: `foca-darwin-arm64.tar.gz` (`foca` and `foca-darwin`), `foca-linux-amd64.tar.gz`,
`foca-linux-arm64.tar.gz` and `SHA256SUMS`. Never ship a `foca` built any other way on
macOS: without the build script it has no helper pin and runs no helper. The
`MACOS_CERT_P12`, `MACOS_CERT_PASSWORD` and `MACOS_SIGN_IDENTITY` secrets sign the helper
with a Developer ID; without them it is signed ad hoc.

## Conventions

- Match the surrounding code: short comments that say *why*, plain words, no clever
  abstractions.
- Test names state the behaviour they prove (`TestHangUpDuringRunKillsTheGroup`). Security
  properties get a test that fails if the protection is removed.
- Every audit-visible behaviour is asserted on the recorded events, not just the response.
- A new security property gets a row in design §16 naming its tests.
- Workflows pin every action to a full commit SHA, its version in a comment: a moved tag
  can't change what CI runs, and CI holds the signing secrets and write access.
