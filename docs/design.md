# foca — design

Status: **accepted**, and partly built (§17). This document is the specification foca is
built to; a change to the code that changes the design updates it too. §16 lists the tests
that hold each security property, and §17 what isn't built or verified yet.

foca is a small per-instance service, similar to `ssh-agent`. It hands credentials from a
host (the owner's Mac) to processes and microVMs. Each access needs a deliberate user approval
and is recorded. It replaces two things in the current setup:

- a static-token manager whose socket is forwarded into the VMs;
- **aws-cred-broker**, a Mac-side script that runs `granted` behind Touch ID so AWS SSO
  credentials reach the VMs.

foca is an original implementation; no third-party code is ported into it.

---

## 1. Goals and non-goals

Goals

1. One tool for **static secrets** and **pre-approved host commands**, with each varying piece
   behind a plugin interface.
2. **All core logic builds and tests on Linux** (this VM). Only the small macOS-specific plugins
   need a Mac to build or test.
3. **Most-secure defaults.** Every access gets a fresh approval unless host config explicitly
   allows reuse.
4. **One instance per realm** (VM, container, host). Each instance has its own socket and, by
   default, its own vault, key-protector entry and
   audit log. No VM can reach another VM's secrets.
5. **Every access recorded** as versioned structured events, ready for a later UI
   (`foca events query` / `follow`, §8.5).

Non-goals for now: the UI itself, syncing between machines, sharing between users, Windows.

---

## 2. Target environment

```
 Mac (host)                                              microVM "dev"
 ┌──────────────────────────────────────────┐            ┌──────────────────────────────┐
 │ launchd agent: foca serve                │            │                              │
 │   --instance dev                         │   SSH      │  ~/.foca.sock  ◄── CLI       │
 │   ├─ client.sock  (0600, dir 0700) ◄─────┼─RemoteFwd──┤  (forwarded by ssh)          │
 │   ├─ serve.pid    (host CLI signals it)  │            │  foca get / run / exec       │
 │   ├─ vault.fcv    (encrypted)            │            └──────────────────────────────┘
 │   ├─ audit.jsonl                         │
 │   └─ helper: foca-darwin (Swift)         │            microVM "work": own instance,
 │        Touch ID · Keychain · sleep/lock  │            own socket, own vault, own key
 └──────────────────────────────────────────┘
```

- A VM client only ever talks to its forwarded socket. It cannot start, configure or manage
  anything on the host.
- With SSH `RemoteForward`, the process that connects on the host is the **`ssh` client**, not
  the process in the VM. Host-side peer identity therefore identifies "the ssh connection for
  VM X". Anything about the real process inside the VM is **client-reported** and unverified
  (§8.3).
- Today each VM has two forwarded sockets (static tokens and the AWS broker). After
  migration, a single forwarded socket replaces both: `~/.foca.sock` by default, or
  `$FOCA_SOCK`.

---

## 2.1 Realms: VMs are one case of many

Nothing in the core is VM-specific. Each instance serves exactly one **realm**, the
isolated environment its callers live in. The rules for separation stay the same: one
instance, socket, vault, DEK and key-protector entry per realm.

| Realm kind | How callers reach the socket | What the host kernel sees as the peer | Best identity available |
|---|---|---|---|
| `host` | the socket directly, on the host | the real process | **host-verified** |
| `container`, Linux host (docker, podman, nspawn, bubblewrap) | socket bind-mounted into the container | the **real process**: SO_PEERCRED translates pid and uid across namespaces | **host-verified**, plus the container id from `/proc/<pid>/cgroup` |
| `vm` (microVM over ssh, or later vsock) | forwarded socket | a proxy (`ssh`) | guest-verified with the relay (§14), else claimed |
| `container`, macOS host (Docker Desktop, OrbStack, Apple `container`) | socket shared into the runtime's Linux VM | a proxy (the runtime's file-sharing or forwarding process) | guest-verified with the relay (§14), else claimed |
| `remote` (later: another machine over ssh) | forwarded socket | `ssh` | guest-verified with the relay, else claimed |

**Two consequences shape the design.**

- **Direct vs opaque peers.** A peer is *opaque* when the process the host kernel reports is a
  proxy, not the caller. That is the case for ssh, VM file-sharing daemons and socat. For an
  opaque peer, host-verified identity names the proxy, and so the realm as a whole. It never
  names the program.

  Whether a realm is opaque is **declared** in config (`[realm] peers = "direct" | "opaque"`),
  never guessed. For `direct`, an extra safeguard applies: a peer whose exe basename is in
  `opaque_peers` is refused. The default is `ssh`, `sshd`, `sshd-session`, `socat`, `nc`,
  `ncat` and `systemd-socket-proxyd`. macOS container runtimes' proxies join the list once
  they are checked on a Mac. Until then such a realm must list its runtime's proxy;
  without it, connections fail closed (below), never misattributed. On macOS a `container`
  realm can't be declared `direct` at all: config loading refuses it.
  It is not reinterpreted, so a misconfigured socket can't put "let ssh use…" on the
  prompt. The reverse holds for `opaque`: the peer's exe basename (Nix wrappers unwrapped,
  never `comm`) must be in `opaque_peers`, or the connection is refused as
  `direct_peer_on_opaque_realm`. A host process on a VM's socket is therefore never prompted
  as "in VM dev". This is a guard against mistakes, not against same-user code, which can run
  a real proxy.

  Setting `opaque_peers` replaces the default list rather than adding to it, so a config that
  needs another proxy lists the defaults it still wants too. Entries are bare program names
  as foca shows them (`ssh`, not `/usr/bin/ssh` or `.ssh-wrapped`); config loading refuses
  any other form, since it would never match.
- **The relay is generic.** `foca relay` runs inside whatever boundary the host can't see
  into, whether a VM, a container inside a macOS runtime VM or a remote host. It works the same
  way in each. Linux containers on a Linux host don't need it, because the host already sees
  the real process.

Prompts name the realm by kind and name: `in VM dev`, `in container web`. Host-local requests
have no realm phrase.

---

## 3. Architecture overview

One Go binary, `foca`:

- `foca serve` runs the service for one instance.
- All other subcommands are the CLI. The same binary is cross-compiled for `linux/arm64` (the
  VMs) and `darwin/arm64` (the host).

One small Swift binary, `foca-darwin`, wraps the macOS APIs Go can't reach without cgo:
LocalAuthentication, Keychain, and the IOKit / DistributedNotificationCenter sleep and lock
events.

```
           ┌──────────── foca serve (one process, many instances) ───────────────┐
 client ──►│ listener ─► peer identifier ─► JSON-RPC dispatch                    │
 socket    │ (one per instance)               │                                  │
           │                                  ▼                                  │
 host CLI ─┼─ files + signals          request pipeline (core)                   │
           │   resolve resource ─► validate params ─► effective policy ─►        │
           │   reuse grant? ──no──► authenticator.Approve ─► audit approval ─►   │
           │   provider.Serve ─► audit outcome ─► respond ─► zero buffers        │
           │                                                                     │
           │ providers: static(secret store) · command      grants: in-memory    │
           │ key protector ─ DEK seal/unseal               platform events ─► wipe│
           │ audit sink: jsonl (later sqlite)                                    │
           └─────────────────────────────────────────────────────────────────────┘
```

### 3.1 Request pipeline

This sequence is the heart of the system. It is pure Go behind interfaces and is fully
testable on Linux with fakes.

1. **Accept.** Get the `VerifiedPeer` from the connection (§4.6). Reject it if its uid is not
   the service's uid.
2. **Decode** the JSON-RPC request. Management methods are refused: they don't exist on any
   socket (§6.2).
3. **Resolve** each named resource (`secret:<vault>:<id>` or `action:<id>`) through its provider.
   Unknown names fail with `not_found`, which is still audited. Callers send **names only**,
   never definitions.
4. **Validate parameters** against the host-declared constraints (actions only).
5. **Compute the effective policy** by folding all applicable levels with "stricter wins" (§9).
6. **Check reuse grants.** If the policy allows reuse and a live grant matches
   `(resource, scope key)`, mark the approval `reused`. Otherwise call `Authenticator.Approve`
   with a prompt that lists every resource in the request. The prompt queue is serialised per
   instance (§9.6).
7. **Audit the approval decision.** Events: `approval.granted`, `approval.denied` or
   `approval.reused`. If the audit write fails, the request is **denied** (fail closed).
8. **Serve.** The provider returns a value or runs the action.
9. **Audit the outcome** (`secret.read` / `action.run`, `ok` / `error`). If this audit write
   fails, the value is **not** returned.
10. **Respond, then zero** plaintext buffers. This is best effort in Go (§12.4).

---

## 4. Plugin interfaces

These are Go interfaces in `internal/plugin`. Context, errors and small value types are
omitted here for brevity. Every kind ships a fake or in-memory implementation that the tests
use.

### 4.1 Authenticator: "prove the user is present and approves this access"

```go
type Authenticator interface {
    Name() string                                   // "touchid", "polkit", "fake"
    Available(ctx) (ok bool, reason string)         // can a prompt be shown right now? no UI
    Approve(ctx, ApprovalRequest) (ApprovalResult, error)
}

type ApprovalRequest struct {
    ID        string         // ULID, also used in audit
    Instance  string         // trusted: from host config
    Operation string         // "secret.read" | "action.run" | host CLI op ("secret.add", …)
    Resources []ResourceRef  // trusted: resolved by the host
    Params    map[string]string // action params after validation (trusted: allowlisted)
    Requester RequesterSummary  // verified peer + client-reported info, labelled as such
    Timeout   time.Duration
}
type ApprovalResult struct {
    Approved bool
    Method   string     // e.g. "biometry", "password"
    Detail   string     // free text for audit, never shown as trusted
}
```

- **The daemon builds prompt text only from trusted fields**: instance, operation, resolved
  resource names and validated params. Example:
  `foca [dev]: read common:github-pat (via ssh forward)`. Callers can't supply a reason string,
  because a caller-chosen reason could put a reassuring lie on the prompt.
- **The requesting process is shown on the prompt, labelled by trust level.** Only
  `guest-verified:` comes from the optional guest relay (§14). `<Realm> claims:` (e.g. `VM claims:`) is the client's own,
  unverified claim. Untrusted names are cut down to a short basename of ASCII letters, digits
  and `._+-`, so they can't add words to the sentence. When the text is too long, they are
  dropped before any trusted field. `[approval] prompt_show_client = false`
  hides them. Exact wording: §4.1.1.
- Implementations: `touchid` (helper), `fake` (test builds only, D12), and later `polkit`.

#### 4.1.1 Prompt format

A good prompt answers three questions in one sentence: **which program**, **which
credential**, and **on whose behalf**. macOS adds `"<process name>" is trying to` in front of
the reason text itself, so the reason is a verb phrase. The helper must therefore show up as
`foca`, not `foca-darwin`. It carries an embedded `Info.plist` (`CFBundleName = foca`) for
that; whether the dialog uses it or the executable name is still to be confirmed on a Mac.
macOS also ends the text with its own full stop, so the helper drops the reason's last one.

**Slots and where they come from**

| Slot | Meaning | Source | Trust |
|---|---|---|---|
| `{instance}` | which VM | host config | trusted |
| `{credentials}` | display names of the secrets, or the action's description | host (vault metadata / config) | trusted |
| `{reach}` | reuse sentence, if approving creates a grant (§9.1, safeguard 6) | host policy | trusted |
| `{program}` | who will receive or use the value | `credential_process`/`get`: the CLI's parent; `run`: the command being run, when the identity is claimed | guest-verified via relay, else client-reported |
| `{via}` | the agent or harness behind it | nearest ancestor in the parent chain that isn't a shell or foca. Skipped names are configurable: `[approval] skip_ancestors`, default `sh bash zsh fish nu dash ksh tmux screen sshd sshd-session login su sudo env nix direnv foca` | same as `{program}` |

To support this:

- The CLI sends a short parent chain in `client`: up to 8 hops, each with exe, name, pid and
  start time.
- For `run` it also sends the resolved target path and argv.
- The relay reads the same chain from the VM kernel. For `run`, if the caller's exe hash
  matches the genuine foca CLI, the relay treats that process's argv from
  `/proc/<pid>/cmdline` as guest-verified too. That gives a verified target command for `run`.

**Names.** A process is named by its exe basename (falling back to `comm`). Nix wrapper names
are unwrapped, so `.claude-wrapped` becomes `claude`; on a Nix system, `wrapProgram` would
otherwise put that form into almost every prompt.

**Sealed names.** The kernel vouches for the process, not for its file's name: anyone who can
write a file can call it `gh`, and `comm` can be set to anything. So a verified name is stated
as fact only when the exe is **sealed**: the running file and every directory above it, seen
from the process's own root (`/proc/<pid>/root`), are owned by root and not writable by group
or others. A sticky directory only its group can write, such as `/nix/store`, passes; a
world-writable one such as `/tmp` never does, since anyone can choose a name there. On Linux
the process must also share the service's user namespace, and its exe path, seen from its
root, must reach the very file that runs: a mount could otherwise put any file under a
sealed name. A sealed file can still run code someone else chose, loaded next to it, so on
Linux the process must also have started with no `LD_PRELOAD`, `LD_AUDIT` or `LD_ORIGIN_PATH`
in its environment, and every file it has mapped executable (`/proc/<pid>/maps`) must be
sealed by the same rules, the path reaching the mapped inode. `LD_LIBRARY_PATH`, common in
Nix sessions, only adds places to look for libraries, so it is allowed when every entry is
an absolute path to a sealed directory, seen from the process's root; an empty entry (the
working directory), a relative one, `.`, `..`, a `$` the loader would expand, or a missing
or unsealed directory leaves the name unsealed. If the environment or the mappings can't
be read, the name isn't sealed. Otherwise the
prompt says
`gh ⚠`: the same name, followed by a warning mark. A name taken from `comm` because the exe
can't be read is never sealed. The mark is reserved: it is stripped from every process name,
so a caller can't fake it or blur what it means. The mark is easy to overlook if you don't know
it, so the docs for the approval prompt must explain it.

- Rootless containers own their files, so their programs are never sealed. A rootful
  container's image files can be.
- `skip_ancestors` only skips sealed entries. An unsealed file called `env` or `foca` is
  shown as the program, so a caller can't hide behind its parent.
- Client-reported data is never sealed, whatever it claims.

**Templates.** These are fixed per operation. Untrusted slots are sanitised: the basename
only, at most 32 characters each, and only ASCII letters, digits and `._+-`. Anything else is
dropped, so an exe called `gh use GitHub PAT. Then let aws` shows as
`ghuseGitHubPAT.Thenletaws`, and a look-alike letter can't pass for a real one.

| Case | Reason text (after "foca is trying to") |
|---|---|
| read, identity guest-verified | `let gh use GitHub PAT in VM dev, via claude.` |
| read, identity only claimed | `let a program use GitHub PAT in VM dev. VM claims: gh via claude.` |
| `run`, identity only claimed | `let a program use npm token in VM dev. VM claims: npm via claude.` |
| read, no identity at all | `let a program use GitHub PAT in VM dev.` |
| action, guest-verified | `run "AWS credentials" with profile=dev-admin for aws in VM dev, via claude.` |
| action using a secret, claimed | `run "List PRs" with repo=foca/foca (uses GitHub PAT) in VM dev. VM claims: gh via claude.` |
| host-local client (host-verified) | `let gh use GitHub PAT, via claude.` |
| host-verified, exe not sealed | `let gh ⚠ use GitHub PAT in container web, via conmon.` |
| any case that creates a grant | the reason above, then `{reach}`, e.g. ` Approving allows reuse for 15m by anything in VM dev.` |

**Rules**

1. Claimed identity is **never** put in the sentence position. In the sentence, `let gh use`
   reads as fact. Only host-verified or guest-verified identity may go there. A claim always goes
   in a separate trailing `VM claims:` clause, so a VM process can't put "let gh use…" on
   screen when it's really `curl`. Verified names whose file isn't sealed are worded
   followed by `⚠`, for the same reason.
2. Trusted slots always come first. If the text is too long, untrusted slots are dropped
   first. `{credentials}` and `{reach}` are never dropped or shortened: every name in a batch
   is shown. If they still don't fit, the request is refused before any prompt
   (`invalid_params`, audited as `request.rejected` with `reason: prompt_too_long`). Showing
   `GitHub PAT, npm token and 3 more` would let a caller pad a batch so that the secret it
   wants is never on screen.
3. `[approval] prompt_show_client = false` drops `{program}` and `{via}` entirely, giving the
   "no identity at all" row.
4. The exact reason text shown is stored in the `approval.*` audit event (`prompt_text`), so
   what you approved can always be looked up later.

### 4.2 Key protector: "keep the vault's data key safe"

The vault is encrypted with a random 256-bit **data encryption key (DEK)**. A key protector
*seals* and *unseals* that DEK. This one interface fits a stored secret (Keychain, libsecret,
kernel keyring), a wrapping key (Secure Enclave, TPM) and a file (tests).

```go
type KeyProtector interface {
    Name() string
    Seal(ctx, ref KeyRef, dek []byte) (sealed []byte, err error) // store or wrap
    Unseal(ctx, ref KeyRef, sealed []byte) (dek []byte, err error)
    Destroy(ctx, ref KeyRef, sealed []byte) error
}
type KeyRef struct {
    Vault     string  // vault name, e.g. "common"
    VaultID   string  // random id written into the vault header at init
}
```

- `sealed` is stored in the vault header as a key slot. For Keychain it is just the item's
  account name. For Secure Enclave or TPM it is the wrapped DEK.
- Keychain account = `foca:<vault>:<vault-id>`. Every vault gets its own entry, and
  initialising a scratch vault can never overwrite another one. The account is keyed by a
  stable id, not the file path, so moving the file doesn't strand the key.
- Implementations: `file` (KEK in a 0600 file; refused unless config sets
  `insecure_file_protector = true`), `keychain` (helper, §5), and later `secure-enclave`,
  `tpm`, `libsecret`, `keyring`.

### 4.3 Secret store: "hold encrypted values and their metadata"

```go
type SecretStore interface {
    Init(ctx, dek []byte, header VaultHeader) error
    Header(ctx) (VaultHeader, error)                  // plaintext header: key slots, ids
    List(ctx, dek []byte) ([]SecretMeta, error)       // decrypts metadata only
    Read(ctx, dek []byte, id string) (SecretValue, error) // decrypts exactly one entry
    Put(ctx, dek []byte, meta SecretMeta, v SecretValue) error
    Delete(ctx, dek []byte, id string) error
}
type SecretMeta struct {
    ID, DisplayName, Description string
    Created, Updated time.Time
}
type SecretValue struct{ Bytes []byte }   // []byte, never string, so it can be zeroed
```

- `memory` (tests), `vault-file` (§10), later `1password` / Keychain items.
- The store holds **no policy**. Policy lives only in host config (D6).

### 4.4 Provider: "what a credential is and how a request is answered"

```go
type Provider interface {
    Kind() string                                       // "secret", "action"
    List(ctx) ([]ResourceInfo, error)                   // what callers may name
    Resolve(ctx, ids []string) ([]Resource, []error, error) // one store read per request
    Validate(ctx, r Resource, params map[string]string) (map[string]string, error)
    Serve(ctx, r Resource, params map[string]string) (Result, error) // after approval only
}
```

- `static` exposes vault secrets as `secret:<vault>:<id>`: a `Provider` per vault, filtered by
  an instance's exposure, and `Vaults` over every vault the instance reads. A name says which
  vault it is read from, and `Serve` decrypts one entry there.
- `Resolve` takes every name of a request at once, so a request unseals each vault's DEK and
  reads its metadata once however many names it carries. Unknown names get a per-name
  `not_found` (or `not_exposed`, which matches it), and so do names in a vault the instance
  doesn't read. A name in a vault not created yet is `not_initialized`.
- `command` exposes config-declared actions as `action:<id>` (§11). Its `Resolve` also
  resolves the secrets an action uses (`env_secrets`) in the calling instance's vaults, under
  its exposure, so the prompt and audit can name them (`Resource.Uses`).
- Later: `oauth-refresh`.
- `Serve` is only ever called by the core after a successful approval. Providers never see raw
  RPC input, only validated parameters.

### 4.5 Platform events: "lock on sleep or screen lock"

```go
type PlatformEvents interface {
    Name() string
    Run(ctx, out chan<- PlatformEvent) error   // blocks; returns on ctx cancel or failure
}
type PlatformEvent struct{ Kind EventKind; At time.Time; Source string }
// EventKind: Sleep, ScreenLock, SessionEnd (each wipes),
//            Ready (the source is subscribed; reuse may apply from now on)
```

- `logind` (Linux; D-Bus `PrepareForSleep`, session `Lock` / `LockedHint`, and
  `SessionRemoved` for the service user's own sessions), `darwin` (helper streaming JSON lines:
  IOKit system-will-sleep, the `com.apple.screenIsLocked` notification and a fast-user-switch
  away as screen lock, log-out or shutdown as session end), `none`, and `fake` (test builds
  only). `auto` is `logind` on Linux, `darwin` on macOS
  and `none` elsewhere.
- `logind` matches only signals sent by `org.freedesktop.login1`, so another process on the bus
  can't fake an event. It reads the name's unique owner once, after subscribing to
  `NameOwnerChanged` for it, and any change of owner (logind restarting or going away) ends
  the source with an error: the core wipes, and the source starts again with the new owner.
  It dials the system bus at `/run/dbus/system_bus_socket` only, never at
  `DBUS_SYSTEM_BUS_ADDRESS`, and refuses it unless `SO_PEERCRED` says root opened it: the
  name's owner is only as trustworthy as the bus daemon.
  `logind` takes a `delay` sleep inhibitor and releases it only once the core
  has wiped the grants and recorded the lock, or after 4 s, so suspend waits for the wipe; if
  polkit refuses one, the sleep signal still arrives and the watchdog (§9.5) is the backstop.
  It holds at most one: a wake takes a new one and closes any still held.
- Waking and unlocking are not reported: they clear nothing and restore nothing, and the next
  access after a lock always asks. A source only uses wake internally, e.g. logind takes its
  delay inhibitor again for the next suspend.
- Reuse starts only after the source sends `Ready`. If the source fails or stops, the core
  **wipes and disables reuse** until it is ready again (D13), and restarts it with backoff
  (1 s doubling to 30 s).

### 4.6 Peer identifier: "who connected"

```go
type PeerIdentifier interface {
    Identify(conn *net.UnixConn) (VerifiedPeer, error)
}
type VerifiedPeer struct {
    UID, GID int
    PID      int
    StartTime uint64  // process start time; (PID, StartTime) detects pid reuse
    Exe      string   // resolved executable path
    Name     string   // comm / p_comm
    Session  string   // durable session key (see below)
    Source   string   // "SO_PEERCRED", "LOCAL_PEERCRED+LOCAL_PEERPID"
    Opaque   bool     // realm declares peers = "opaque" (§2.1): this is a proxy, not the caller
    Realm    RealmRef // {kind, name} from config; for Linux containers also
                      // ContainerID from /proc/<pid>/cgroup (host-verified)
}
```

- **Linux**: `SO_PEERCRED`; `SO_PEERPIDFD` where available, so pid reuse can't
  confuse it; `/proc/<pid>/exe`, `comm`, `stat` (sid). Pure Go via `golang.org/x/sys/unix`.
  Only a kernel that doesn't know `SO_PEERPIDFD` (it answers `ENOPROTOOPT`) falls back to
  checking the start time; any other error refuses the peer, which may already be gone.
  - Sealing (§4.1.1) also reads `/proc/<pid>/environ` and `/proc/<pid>/maps`, after the
    pidfd is taken and before it is checked, like everything else. Each file and
    directory check is kept for the rest of the identification, keyed by the process's
    mount namespace and root, so the peer and its parents share the work for the
    libraries they all map and the `LD_LIBRARY_PATH` directories they all name. Overlayfs
    shows the underlying file's device in `maps`, which stat doesn't report, so there the
    inode number alone must match.
  - The identifier also reads `/proc/<pid>/cgroup`, pinned the same way, for the container
    id; the server keeps it only on a direct `container` realm. Only the shapes docker,
    podman, containerd and CRI-O give a container's cgroup count: `docker-<id>.scope`,
    `libpod-<id>.scope`, `crio-<id>.scope`, `cri-containerd-<id>.scope`, `libpod-<id>`,
    `crio-<id>`, `/docker/<id>` and `/kubepods/…/pod<uid>/<id>`, where the id is 64
    lowercase hex digits. A path naming two takes the outer one, since that is the
    container the host runs, and cgroup v1 hierarchies that disagree give none. The id is
    audited (§8.1), never shown in a prompt: the realm's name already says which
    container it is.
- **macOS**: `LOCAL_PEERCRED`, plus `LOCAL_PEERTOKEN` rather than `LOCAL_PEERPID`.
  The audit token carries a pid version as well as the pid, so after reading process
  information (path from `proc_info(PROC_PIDPATHINFO)`, `kinfo_proc`, `getsid`) the identifier
  confirms the version still matches, through `proc_info(PROC_PIDUNIQIDENTIFIERINFO)`. The
  version also changes on exec, so a pid reused or an exec during identification is refused
  like a process that changed. The token describes the peer as it is when read, not as it
  was when it connected, so like a Linux pidfd it can't reveal an exec that came before
  identification (§12.4, "Exec after connect"). If the version can't be read, the peer is handled like Linux without a pidfd (below). Also
  pure Go behind a `darwin` build tag, so it compiles anywhere but is only tested on a Mac.
  - The path is the one the kernel finds for the running file (what `proc_pidpath` reports).
    The exec path in `kern.procargs2` can't be used: it sits in the process's own memory,
    which the process can rewrite at any time without changing its pid version. Any symlinks
    on the path are followed one component at a time: the exe is the file reached, and it is
    sealed only if every directory passed through, including those reached through a
    symlink, is sealed. Whoever could rewrite a link on the way could have chosen the name
    too.
  - Nothing checks for code loaded next to the program. Another process's environment is
    readable in pure Go only through `kern.procargs2`, which is the process's own memory and
    so rewritable by whatever was loaded, and listing its loaded images needs its task port.
    A sealed name on macOS therefore doesn't rule out `DYLD_INSERT_LIBRARIES` (§12.4).
- **Pid pinning.** `VerifiedPeer.PIDStable` is true only when the kernel pinned the process
  (a pidfd, or a confirmed pid version). Without it, the pid could have been reused before the
  first read and the two reads would agree on the wrong process. Then no name is treated as
  sealed (§4.1.1), and no grant is made or reused by session for that peer (§9.5).
- The session key uses a "durable session" walk. Starting from the peer's session, climb to
  the nearest ancestor session that **has a controlling terminal**. Agent harnesses start each
  command with `setsid()` and no terminal, so their commands collapse into the terminal
  session they were started from, while separate terminals stay separate.
  - If no terminal session is found within 8 hops, the peer's **own** session is used, so the
    fallback is always the narrowest choice.
  - Climbing "until sid 1" would merge every ssh login on Linux into sshd's session, because
    daemons there are not in session 1.
  - The key includes the leader's start time (`sid:<n>:<start>`), so a recycled sid never
    matches an older session. If the peer's own session leader has exited, the key is the
    peer itself (`pid:<pid>:<start>`), never a bare sid.

### 4.7 Audit sink: "record every access"

```go
type AuditSink interface {
    Append(ctx, Event) (seq uint64, err error)   // must be durable before return
    Query(ctx, Filter, Page) ([]Event, Cursor, error)
    Subscribe(ctx, Filter, fromSeq uint64) (<-chan Event, error)
}
```

- `jsonl`, `memory` (tests), later `sqlite`. A pure-Go driver keeps the build
  cgo-free.
- `Query` and `Subscribe` are part of the interface from the start, before anything uses
  them. That way the sinks are built to support them.

---

## 5. Plugin mechanism and language

### D1: Go for the core and CLI

- Go builds and tests natively in this Linux VM and cross-compiles to darwin with no SDK.
- The VMs already run Go tooling; one binary serves both host and VM.
- It produces a single static binary for the VMs, and there is a mature `x/sys/unix` for peer
  credentials on both OSes.
- Rejected: **Swift**, which made our previous attempt macOS-only to test. **Rust** would
  work but adds a toolchain and gives up Go's simple cross-compiling for
  pieces.

### D2: Hybrid plugins — compiled-in Go interfaces, plus stdio helpers for non-Go platform APIs. No cgo.

All plugin kinds are Go interfaces. Pure-Go implementations are compiled in, using build tags
where they are OS-specific: Linux and darwin peer identifier, logind, file protector, vault
store, providers, audit. A generic **helper adapter** implements `Authenticator`,
`KeyProtector` and `PlatformEvents` by talking JSON over stdio to an external executable. It
is used only where a platform API needs a non-Go language. In practice that means one Swift
binary, `foca-darwin`.

| Concern | Helper executables | Compiled-in (cgo + build tags) |
|---|---|---|
| Linux testability | Core has no cgo. The helper adapter is tested on Linux against a fake helper written in Go. | Core still testable on Linux, since darwin files are excluded, but the darwin build needs a Mac SDK. |
| Cross-compiling from the VM | `CGO_ENABLED=0` builds every Go binary for both OSes. | darwin daemon must be built on a Mac. |
| **Keychain identity** | Keychain item ACLs attach to the code identity of the process that creates and reads the item. Ad-hoc signing makes that the binary's hash. The helper is small and rarely changes, so its identity is stable across core releases. | The identity is the whole daemon, so every core rebuild (and every Nix bump) changes it. That brings back "allow access" prompts or strands the item. |
| Touch ID UI | Helper runs as a child of the launchd agent, inside the user's GUI session. | Same. |
| Trust | Daemon must trust an extra executable. Mitigated: a path fixed at build or install time, ownership and mode checks, a sha256 pin built into foca (below). | Nothing extra to trust. |
| Latency | One process spawn per approval or unseal, about 5–30 ms. Negligible next to a human Touch ID touch (~1 s). Events helper is long-lived. | In-process. |
| Failure modes | Helper missing, crashing or a protocol-version mismatch. Each fails closed with a clear error. | Fewer moving parts. |
| Versioning | Helper protocol is versioned (`v`), and an `info` op reports capabilities. | n/a |

**Helper trust rules**

1. The path is fixed when foca is built or installed, never configured: the path built in
   with `-ldflags -X` (a package can set its install path), else `foca-darwin` in the
   directory of the running `foca`, symlinks resolved. `PATH` is never searched. Anyone who
   can write that directory can already replace `foca` itself.
2. At start-up and before each spawn, the file and every directory on the way to it must be
   owned by root or the service user and must not be group- or world-writable. The path is
   walked one component at a time, so that includes the directories a symlink sits in and
   those it leads through. A sticky directory such as `/tmp` passes, but a symlink in it
   must be the user's or root's. Nix store paths pass this check. Config files, action
   commands and foca's own directories are checked the same way.
3. A sha256 pin, built into foca with `-ldflags -X`, is required: a foca built without one
   runs no helper. It is checked before each spawn; on a mismatch the helper doesn't run.
   `scripts/build-darwin.sh` builds the helper, signs it (ad-hoc, or with
   `FOCA_SIGN_IDENTITY`), hashes the signed file and builds foca with the pin. Signing comes
   before hashing because it rewrites the file.
4. Minimal environment: `HOME`, `LANG`, `FOCA_HELPER_PROTOCOL=1`. No caller data except
   sanitised prompt text.
5. Hard per-call timeout. The daemon sends SIGTERM, and the helper calls
   `LAContext.invalidate()`. That takes the dialog down in about 50 ms. The
   helper then answers `cancelled`, and SIGKILL follows after a short grace period.
   LocalAuthentication tells a user cancel (`-2`) from an app cancel (`-9`). The two map to
   `denied` and `timeout`, so the audit log can separate them.

**Helper protocol v1.** One JSON object on stdin, one on stdout, logs on stderr. This is the
same idea as git credential helpers, but JSON. Every one-shot kind, `info` included, uses the
same envelope. Requests and responses are decoded strictly: an unknown field, a wrong `v` or
an unknown op is an error (`bad_request`), never ignored.

```
$ foca-darwin authenticator          # subcommand = plugin kind
stdin : {"v":1,"op":"approve","params":{"reason":"…","timeout_ms":60000,"allow_password_fallback":false}}
stdout: {"v":1,"ok":true,"result":{"approved":true,"method":"biometry"}}
     or {"v":1,"ok":false,"error":{"code":"denied","message":"…"}}

$ foca-darwin info            op info → {"kinds":["authenticator","key-protector","events"],"version":"0.1.0"}
$ foca-darwin authenticator   op available {allow_password_fallback} → {available, reason}  (no UI)
                              op approve   {reason, timeout_ms, allow_password_fallback} → {approved, method}
$ foca-darwin key-protector   ops seal {vault, vault_id, dek} → {sealed}
                                   unseal {vault, vault_id, sealed} → {dek}
                                   destroy {vault, vault_id, sealed?} → {}      (bytes are base64)
$ foca-darwin events          long-lived (below)
```

- Error codes: `denied` (the user refused), `unavailable`, `timeout` (the helper's own
  deadline), `cancelled` (SIGTERM, or the system took the prompt down), `not_found`,
  `exists`, `mismatch`, `bad_request`, `internal`. The adapter maps `denied` to a denial,
  `unavailable` to `auth_unavailable`, and `timeout` or `cancelled` to a timeout. Anything it
  can't read (a crash, a malformed or oversized response, another protocol version) is an
  error, never an approval. A success answer counts only if the helper also exits 0; one
  followed by a crash or a non-zero exit is an error.
- The service runs `info` at start-up and refuses a helper that lacks a kind the config uses.
- Keychain entries are generic passwords, service `foca`, account `foca:<vault>:<vault-id>`.
  `sealed` is the account name. A seal never overwrites an existing entry (`exists`), and an
  unseal or destroy whose `sealed` names another vault's entry is refused (`mismatch`), so an
  edited vault header can't borrow another vault's key.
- `events` reads `{"v":1,"op":"subscribe","params":{}}`, then writes
  `{"v":1,"seq":N,"event":"ready|sleep|screen-lock|session-end"}` lines. The service answers a
  sleep with `{"v":1,"op":"ack","params":{"seq":N}}` once the core has wiped the grants and
  recorded the lock, or after 4 s, and the helper lets the machine sleep only then, or after
  5 s. It exits when stdin closes or on
  SIGTERM. A malformed line, an unknown event, a seq that doesn't increase or the helper
  exiting ends the source, so the core wipes and turns reuse off until it is back (§4.5).

The Go repo includes a **conformance test suite** for helpers. It runs on Linux against a
Go fake helper, and on a Mac with `FOCA_HELPER=/path/to/foca-darwin go test
./internal/plugin/helper/...`.

The DEK crosses a parent/child pipe on unseal. Pipes are private to the two processes; see §12
for why that is acceptable.

**Keychain and Secure Enclave constraints** (known platform behaviour, still to be verified on
a Mac):

- Any `SecAccessControl`-gated Keychain item, and any persistent Secure Enclave key, needs
  the `keychain-access-groups` entitlement. That needs a provisioning profile, which can only
  be embedded in a signed `.app` bundle, and only that bundle's main executable may use it.
- Under ad-hoc signing the Keychain protector is therefore a **plain** generic-password item,
  with Touch ID enforced by our own LAContext check. Its access rule names the helper's code
  identity, so a rebuilt ad-hoc helper is asked once ("Always Allow") before it can read an
  older entry. With a Developer ID the rule follows the signing identity, and helper updates
  don't ask.
- A later Secure Enclave protector would need `foca-darwin` shipped as the main
  executable of a signed `.app`. The helper model makes that possible without touching the Go
  daemon, which is one more reason for D2.

---

## 6. Wire protocol

### D5: JSON-RPC 2.0, newline-delimited, over a Unix stream socket

This framing is simple and easy to debug with `socat`. Keys are
snake_case. Maximum message size is 1 MiB. One connection may carry many requests, handled in
order. There are no server-to-client notifications.

- A request's `id` is a string or an integer (int64), at most 64 bytes as written; anything
  else (`null`, an object, `1e999`) is refused as an invalid request. A request without an
  `id` is a notification, which is refused and recorded but gets no answer.
- Messages are encoded without escaping `<`, `>` and `&`, which `encoding/json` would turn
  into six bytes each, so a message that fits still fits once re-encoded.
- Every answer fits in one message. The bound on ids leaves results a known budget, and a
  `secret.read` or `action.run` whose result would exceed it is refused before anything is
  recorded as served (§6.4, §11).

The first call on a connection should be `server.hello`:

```json
→ {"jsonrpc":"2.0","id":1,"method":"server.hello",
   "params":{"protocol":1,"client":{ "...client-reported identity, §8.3..." }}}
← {"jsonrpc":"2.0","id":1,"result":{"protocol":1,"instance":"dev","server_version":"0.1.0","features":["secret.read","action.run"]}}
```

A connection can send `client` once in `hello`, or per request in `params.client` to override
it (for example, `run` reporting the target command).

**Version skew fails closed.**

- Requests may carry `min_protocol`. If the server is older, it refuses the request.
- The server decodes params with unknown fields **disallowed**. Silently dropping a field the
  client relies on for enforcement would fail open.
- Keys are **case-sensitive and unique**, in the envelope and in params. Go's `encoding/json`
  alone matches keys without regard to case and keeps the last duplicate, so two parsers (the
  relay and the host, say) could read the same bytes differently: `"Guest_Verified"` would
  slip past a relay looking for `guest_verified`. A type-guided check refuses such input
  before decoding.

### 6.1 Methods on the client socket

| Method | Approval | Notes |
|---|---|---|
| `server.hello` | no | version negotiation, capabilities |
| `secret.list` | no (D16) | metadata only; audited as `secret.list` |
| `secret.read` `{names:[…]}` | **yes** | batch: one prompt lists every name (D15) |
| `action.list` | no (D16) | names, descriptions, parameter schemas; audited as `action.list` |
| `action.run` `{name, params}` | **yes** | runs one host-declared action; `{exit_code, stdout, stdout_encoding, stderr_tail, stderr_encoding}` (§11) |
| `grants.status` | no | caller's live reuse grants (none by default): the ones a request from this caller would reuse; not audited, since it changes nothing and returns no secret material; `foca grants` |
| `grants.drop` `{names?}` | no | drop caller's grants, all or by name; tightening is always allowed; audited as `grants.drop`; `foca grants --drop` |

Nothing on the socket changes state on the host. Management method names sent to it, such
as `secret.add`, `vault.init` or `server.shutdown`, return `-32010 forbidden_on_socket` and
are audited, so a realm that tries them shows up in the log.

### 6.2 D4: One socket per instance; management is host CLI only

Each instance has exactly **one** socket, `client.sock`, and that is the file forwarded into
its realm. There is **no management socket**. Management is done by the `foca` CLI on
the host, working directly on host files:

| Host CLI operation | How | Approval |
|---|---|---|
| `init`, `add`, `edit`, `remove` (`reset` is reserved, not built) | takes an exclusive `flock` on the vault, asks through the configured authenticator, unseals the DEK through the key protector, writes atomically, appends the audit event | **yes** |
| `lock` (wipe now) | sends `SIGUSR1` to the service | no (tightening) |
| `reload` (config) | checks the config, then sends `SIGHUP`; a config that fails validation keeps the old one. A good one replaces the running service: open connections close and pending approvals are cancelled | no |
| `stop` | sends `SIGTERM`, or uses launchctl / systemctl | no |
| `events` | reads the audit log (§8.5) | no |

- **The service is read-only on vaults.** It re-reads a vault when the file's identity, size
  or mtime changes, so the CLI's edits apply to the next request. A bug in the service can't
  corrupt or plant secrets.
- **Signals go only to a verified service.** The CLI finds the service through
  `$RUNTIME/foca/serve.pid` (0600, inside the 0700 runtime dir). Before signalling, it
  pins the process (a pidfd on Linux, its pid version on macOS, checked again just before
  `kill`), matches its start time, and checks that its executable is foca and that it runs
  as the same uid.
- **Concurrent writers.** The CLI and the service both append to the audit log. Each append
  takes an exclusive `flock` and reads the last `seq` under the lock, so sequence numbers stay
  unique across processes.
- **Reads on the host still go through a client socket**, of an instance whose realm is
  `host`. Approval policy, grants, the prompt queue and wipes then live in one place. The CLI
  never serves secret values from the vault itself.

**Why no admin socket.** Against processes running as the same user, an admin socket protects
nothing: they can call it just as they can run the CLI, and approval is required either way.
Its only job would be keeping management away from realms. Having no management socket does
that without depending on which file gets forwarded, and it shrinks the attack surface to a
socket that can't change anything.

Client sockets sit in per-instance runtime directories, which are mode 0700.

### 6.3 Errors

| Code | Name | Meaning |
|---|---|---|
| -32700 / -32600 / -32601 / -32602 | standard | parse / invalid request / no method / invalid params |
| -32001 | `denied` | user denied, or authenticator failed |
| -32002 | `not_found` | unknown secret or action |
| -32003 | `not_initialized` | vault missing |
| -32004 | `auth_unavailable` | no prompt possible here (e.g. no GUI session) |
| -32005 | `timeout` | approval or action timed out |
| -32006 | `busy` | approval queue full (§9.6) |
| -32007 | `audit_failed` | could not record; request refused |
| -32008 | `param_rejected` | action parameter failed constraints |
| -32010 | `forbidden_on_socket` | a management method sent to a socket; management is host CLI only |
| -32011 | `protocol_unsupported` | the request's `min_protocol` is newer than the server |

`error.data` carries `{"name": "...", "request_id": "..."}`; the `request_id` finds the audit
row. It never carries the event's `seq`: one log serves every instance, so a realm that saw seqs
could follow what other realms do.

### 6.4 Secret values on the wire

`secret.read` returns `{"secrets":[{"name":"common:github-pat","value":"…","encoding":"utf8"}]}`.
Non-UTF-8 values use `"encoding":"base64"`, and so do UTF-8 values that escaping would make
longer than base64 (control characters take six bytes each as JSON). Values whose answer
wouldn't fit in one message are refused with `invalid_params` ("read fewer at a time") after
approval and before anything is served; each read is recorded as `secret.read` with outcome
`error` and `reason: response_too_large`. Clients write values only to a pipe, a file (0600),
or a child's environment. The CLI refuses to write a value to a TTY.

- `get --output FILE` checks the destination before asking the service: it must be a new
  file in an existing directory, or an existing regular file of the user's, never a symlink,
  directory or device. The value goes into a new 0600 file that is renamed into place, so a
  hard link to the old file, or a reader that already has it open, never sees it.
- `get` without `--output` to a regular file that group or others may read (a shell
  redirect under umask 022) warns on stderr, suggesting `--output` or `umask 077`. The user
  chose the file, so it isn't refused.
- A socket the CLI finds through the runtime directory (`--instance`, or the only instance
  in the config) must be served by the same user. The CLI checks the server's uid from the
  kernel (`SO_PEERCRED`, `LOCAL_PEERCRED`) before sending anything, so a socket someone else
  left there is refused. A socket given by `--socket` or `FOCA_SOCK`, or the forwarded
  `~/.foca.sock` in a realm, is taken as given.

---

## 7. Configuration

### D6: TOML, host-owned, one file per service, the only source of policy

TOML is commented and human-editable, and Nix generates it natively with
`pkgs.formats.toml`. The config file is the **only** place policy, actions and exposure are
defined. Vaults hold values and descriptive metadata only. Nothing from a caller is ever
treated as config (rule 3).

**Load-time checks.** If any check fails, the service refuses to start. On a reload
(`SIGHUP`), the old config is kept.

- The file must be owned by the service user and not writable by group or other.
- Unknown keys are errors, so typos fail loudly. Keys are matched exactly, case included:
  `[Plugins]` or `Approval = …` is an unknown key, not another spelling of a known one.
- Durations parse as Go durations and must be within limits (§9.4). The service rejects
  out-of-range values; it never clamps them silently.
- Actions must use absolute command paths, every placeholder must be declared and every
  declared param used (§11). An offered action's command must pass the helper trust check at
  start-up.
- The exposure rules in §7.1 hold. For example, a vault can't be shared by accident.
- `touchid`, `keychain` and `platform_events = "darwin"` are refused on any OS but macOS
  (test builds excepted, so the fake helper can stand in on Linux).

### 7.1 Instances, vaults and exposure (D20)

Three kinds of named objects, configured separately:

- **Instance**: one per realm. It owns its own client socket, its realm
  description, instance-level policy, and **what the realm can see**.
- **Vault**: an encrypted secret store. It has its own DEK, key-protector entry and file.
- **Action**: a host command definition (§11), defined once and referenced by instances.

How much is shared is a **user preference**, not built into the architecture:

| Preference | Config | Effect |
|---|---|---|
| **Separate per realm** (default, most secure) | no `expose`: each instance reads its own vault, named after the instance | a realm can only ever see its own vault; different DEK, different Keychain entry |
| **Partly shared** | `dev` reads `["dev:*", "common:github-pat"]`, `work` reads `["common:*"]` | private secrets stay in each realm's vault; common tokens are managed in one place, and each realm reads only what it lists |
| **Everything to everything** | one vault, every instance `expose = ["common:*"]` and `actions = "*"` | single source; each realm still has its own socket, so prompts and audit still say *which* realm asked |

**Defaults and safeguards**

1. **No `expose` means a private vault.** An instance without one reads all of a private
   vault named after itself, as if it had `expose = ["<name>:*"]`.
2. **`expose` names every vault.** Each entry is `"<vault>:*"` (all of it) or
   `"<vault>:<secret>"`. The vaults an instance reads are exactly the ones its list names.
   A vault other than the instance's own private one must be declared in `[vaults]`, so a
   typo can't create a vault, and an entry that repeats or overlaps another is an error.
3. **Sharing is never implicit.** If another instance reads a vault that an instance has
   implicitly, through having no `expose`, that is a config error: the instance must say what
   it reads. This stops a copy-pasted vault name from silently sharing everything.
4. **Exposure only narrows, and only config decides it.** A secret outside `expose` is
   reported as `not_found` to that instance, exactly like a secret that doesn't exist.
   Requests for it are audited as `not_found` with `reason: not_exposed`, so the host can see
   the attempt while the realm can't learn the secret exists. Bursts of them share a
   coalescing window with unknown names (§9.6), so not even whether an event was written tells
   them apart. Nothing stored in a vault takes
   part in exposure: a vault edit can never change who reads a secret.
5. **A secret is named by its vault.** Its full name is `<vault>:<id>`, everywhere: realms
   ask for `common:github-pat`, and prompts, grants, policy (`[secrets."common:github-pat"]`),
   `env_secrets` and the audit log use the same name. Two vaults can hold the same id; they
   are two secrets, and no name ever stands for either. A realm sees the names of the vaults
   it reads, and nothing of the others. Moving a secret to another vault changes its name.
6. **Actions are opt-in per instance.** `actions = ["aws-creds"]` lists them; `"*"` is
   allowed but must be written. No `actions` key means no actions.
7. **Policy still folds "stricter wins"**, with a vault level, the vault the secret is in,
   and an instance level (§9.2). Sharing a vault never loosens a secret's policy in any realm.
8. **Host CLI operations name the vault** through the secret's full name
   (`foca add common:npm-token`). The **approval prompt** for an add, edit or
   remove names every realm that reads the secret, e.g. `add npm token to vault common,
   visible in VM dev and VM work.`, and the event records them in `params.visible_to` (or
   `hidden_from` for a remove). CLI output shows the same.
9. **One socket forwarded to many realms is possible, but discouraged.** The host can't tell
   those realms apart, so prompts and audit can't say which one asked. Sharing a vault between
   separate instances gives the same "everything everywhere" result without losing that.

**Processes (D3, revised).** A single `foca serve` may host many instances. Possible
setups:

- **One process for all instances.** This is the default. One prompt queue serialises
  prompts across all realms, events and wipes happen once, and there is one launchd agent.
- **One process per instance.** Run `serve --only <instance>`, or give each process its own
  config. This keeps memory separation between realms as defence in depth. A vault used by
  instances in different processes is refused (each vault has exactly one writer).

**Paths.** Every path can be overridden with an env var or flag.

- Instance and vault names must match `^[a-z0-9][a-z0-9-]{0,31}$`.
- Socket paths are checked at start-up against the `sun_path` limit: 104 bytes on macOS, 108
  on Linux. A long `$TMPDIR` fails with a clear error instead of a truncated bind.

| What | Default | Override |
|---|---|---|
| config | `$XDG_CONFIG_HOME/foca/config.toml` | `--config`, `FOCA_CONFIG` |
| data dir | `$XDG_DATA_HOME/foca/` (`vaults/<vault>.fcv`, `audit.jsonl`) | `--data-dir`, `FOCA_DATA_DIR` |
| runtime dir | `$XDG_RUNTIME_DIR/foca/<instance>/`, else `$TMPDIR/foca-<uid>/<instance>/`, named after the user so no one else can create it first | `--runtime-dir`, `FOCA_RUNTIME_DIR` |
| instance (CLI on the host) | the only one, if there is just one | `--instance`, `FOCA_INSTANCE` |
| client socket (client side) | `~/.foca.sock` if it exists, else the instance's `client.sock` | `--socket`, `FOCA_SOCK` |

Example host config: VMs `dev` and `work` share a `common` vault, `dev` also reads its own
private vault, a Linux-style container `web` reads only its own, and AWS actions are offered
only to `dev`.

```toml
version      = 1
opaque_peers = ["ssh", "sshd", "sshd-session", "socat", "nc", "ncat", "systemd-socket-proxyd"]
                                   # refused on direct realms, required on opaque ones (§2.1)

[plugins]
authenticator   = "touchid"        # touchid | polkit   (fake: test builds only)
key_protector   = "keychain"       # keychain | file | ...
secret_store    = "vault-file"     # the default; memory is for tests
peer_identifier = "auto"           # by OS
platform_events = "auto"           # darwin | logind | none
audit_sink      = "jsonl"

[approval]
prompt_timeout = "60s"
max_queue      = 4                 # pending prompts per service; more -> busy

[limits]                           # per instance (§9.6.1)
max_connections = 32
idle_timeout    = "2m"

[vaults.common]                    # shared, so declared; private vaults need no table

# ---- instances: one per realm ----
[instances.dev]
realm   = { kind = "vm", name = "dev", peers = "opaque" }
expose  = ["dev:*", "common:github-pat", "common:npm-token"]
actions = ["aws-creds", "aws-sso-login"]

[instances.work]
realm   = { kind = "vm", name = "work", peers = "opaque" }
expose  = ["common:*"]

[instances.web]                    # no expose: all of its private vault "web"
realm   = { kind = "container", name = "web", peers = "direct" }

# ---- policy: every table is optional; leaving one out means "no opinion" (§9) ----
[instances.dev.policy]             # instance level
approval = "reuse"
window   = "30m"
scope    = "peer-session"

[vaults.common.policy]             # vault level
approval = "reuse"
window   = "2h"

[authenticators.touchid.policy]    # authenticator level
approval = "reuse"
window   = "1h"

[secrets."common:prod-db-password".policy]  # secret level, by full name
approval = "every-time"

[actions.aws-creds]                # §11
description = "AWS credentials for a profile via granted"
command     = "/etc/profiles/per-user/bruno/bin/granted"
args        = ["credential-process", "--profile", "{profile}"]
timeout     = "60s"
output      = { format = "aws-credential-process", max_bytes = 65536 }
env         = { HOME = "/Users/bruno", PATH = "/usr/bin:/bin" }
  [actions.aws-creds.params.profile]
  allowed = ["dev-admin", "staging-readonly"]
  [actions.aws-creds.policy]
  approval = "reuse"
  window   = "15m"
  scope    = "peer-session"
```

In this example, reading `common:github-pat` from `dev` folds instance 30m, vault 2h and
authenticator 1h, which gives reuse for 30m within `peer-session`. Reading
`common:prod-db-password` from `work` is always every-time, whatever the other levels say.

---

## 8. Audit events and the future events API

### D10: Versioned JSONL events, fail-closed, verified and reported identity strictly separate

Each event is one JSON object per line in `<data-dir>/audit.jsonl`. The file is mode 0600,
rotated by size, and keeps N files. Appending uses `O_APPEND` plus `fsync` before the request
continues.

- A write that fails partway is cut back to the end of the last good event, so a torn line can
  never merge with the next event and hide it.
- A failed `fsync` stops the sink until restart. After one, the kernel may have dropped the
  data and a later `fsync` can still report success. Every request is then refused, as D10
  intends.

### 8.1 Event shape (`v: 1`)

```json
{
  "v": 1,
  "seq": 1042,
  "id": "01J9Z8K3M2Q4…",
  "ts": "2026-10-01T17:02:11.482Z",
  "instance": "dev",
  "vault": "common",
  "type": "secret.read",
  "outcome": "ok",
  "request_id": "01J9Z8K3H…",
  "origin": "client-socket",
  "resource": { "kind": "secret", "id": "common:github-pat" },
  "params": null,
  "approval": {
    "id": "01J9Z8K3J…",
    "mode": "fresh",
    "authenticator": "touchid",
    "method": "biometry",
    "scope": "peer-session",
    "scope_key": { "instance": "dev", "peer_session": { "value": "ssh:4711", "by": "host" } },
    "granted_at": "2026-10-01T17:02:10.901Z",
    "expires_at": null
  },
  "peer": {
    "verified": {
      "source": "LOCAL_PEERCRED+LOCAL_PEERPID",
      "uid": 501, "gid": 20, "pid": 4711,
      "exe": "/usr/bin/ssh", "name": "ssh",
      "session": "sid:4690", "opaque": true,
      "realm": { "kind": "vm", "name": "dev" }
    }
  },
  "client": {
    "reported": {
      "pid": 812, "ppid": 790, "uid": 1000,
      "exe": "/nix/store/…/bin/gh", "name": "gh",
      "argv0": "gh", "cwd": "/home/dev/src/foca",
      "hostname": "dev", "session": "sid:780",
      "tool": "foca/0.1.0 run"
    }
  },
  "error": null
}
```

- **Times** (`ts`, `approval.granted_at`, `approval.expires_at`) are RFC 3339 in UTC, to the
  millisecond, whatever the host's time zone.
- **`peer.verified`** is filled only by the peer identifier, from the kernel. On a direct
  Linux `container` realm, `realm.container_id` is the container the peer runs in, when its
  cgroup names one (§4.6).
- **`client.reported`** is filled only from request data. It is never merged into `verified`,
  never used for authorisation, and always shown as unverified. The CLI fills it with its own
  identity and its parent's. That parent is the interesting process, such as `aws` calling
  `credential_process`. For `run`, `target` holds the command about to be exec'd: its
  resolved path and argv[0]'s base name (`"target": {"exe": "/usr/bin/npm", "argv0": "npm"}`),
  never its other arguments.
- **`approval.mode`** is `fresh`, `reused` or `none`. `none` is for methods that need no
  approval. Reused events point at the original grant's `approval.id`, so a UI can draw "1
  touch → 7 reads".
- **`count`** is what the event itself counts: the grants a `lock` or `grants.drop` removed,
  the secrets a `secret.list` returned. **`coalesced`** appears only on an event that stands
  for a burst of others like it (§9.6), e.g. `"coalesced": {"count": 41, "after_seq": 1042}`:
  how many were folded into it, and the seq of the event, written in full, that they followed.
  Where several reasons share a window (§9.6), it also says how many had each, e.g.
  `"reasons": {"unknown": 30, "not_exposed": 11}`, and its own `reason` is the shared one.
- **`uses`** lists the secrets an action reads on the host (`env_secrets`), on its approval
  and `action.run` events. **`run`** records how the command ran: `exit_code` (-1 if killed by
  a signal), `duration_ms`, `stdout_bytes`, `stdout_returned`, `stderr_bytes`,
  `stderr_sha256`, `masked` and `timed_out`.
- Never logged: secret values, action stdout, action env, and DEKs. Action stderr is logged
  only as length plus sha256, and only as length for an action that uses secrets: a hash of
  output that may hold one would let anyone with the log test guesses of it. A rejected
  param value appears only quoted and cut to 64 bytes inside `error.message`, never in
  `params`, which holds validated values only.

### 8.2 Event types

`server.start` · `server.stop` · `config.load` · `config.reload` · `approval.granted` ·
`approval.denied` · `approval.reused` · `approval.timeout` · `secret.list` · `secret.read` ·
`action.list` · `action.run` · `secret.add` · `secret.update` · `secret.remove` · `vault.init`
· `vault.reset` (reserved for `reset`, not built) · `grants.drop` · `lock` (with `reason`: `sleep`, `screen-lock`,
`session-end`, `shutdown`, `reload`, `manual`, `expired`, `events-unhealthy`, and `count`, the
grants dropped) · `request.rejected`.

`request.rejected` covers every request the socket refuses before it reaches the pipeline,
with `reason` set to `forbidden_on_socket`, `parse_error`, `invalid_request` (including
notifications), `method_not_found`, `invalid_params`, `protocol_unsupported`,
`message_too_large`, `busy`, `rate_limited`, `too_many_running` (§11), `prompt_too_long`,
`denial_backoff`, `prompt_cooldown`, or a connection-level reason (`too_many_connections`,
`too_many_pipelined`, `connection_closed` for requests a client left queued when it hung up,
and the identification refusals of §2.1). The method name a client sent is kept to
method-name characters, at most 64 bytes. Bursts are coalesced (§9.6).

`outcome` is `ok`, `denied`, `error`, `not_found` or `rejected`.

### 8.3 Identity provenance rules

| Field group | Who fills it | Trusted for policy? | Shown in prompt |
|---|---|---|---|
| `peer.verified` | kernel (via peer identifier) | yes (uid check, session scope key) | yes |
| `client.guest_verified` | guest relay, from the VM kernel (§14) | not yet (only to narrow, later) | yes, labelled "guest-verified:" |
| `client.reported` | requesting client | **never** | yes, labelled "<Realm> claims:", sanitised |
| `resource`, `params`, `instance` | host (resolved / validated) | yes | yes |

### 8.4 Versioning

`v` is bumped only for incompatible changes. Adding fields is compatible. Readers must ignore
unknown fields.

### 8.5 Events for the future UI

There is no socket API for events. The audit log is the API, read through the same Go
package the sinks use:

```
foca events query  [--since T] [--until T] [--type T]… [--instance I] [--resource kind:id]
                   [--outcome O] [--mode fresh|reused|none] [--after-seq N] [--limit ≤500]
                   → JSON lines, plus a trailing {"next_after_seq": N} when more remain
foca events follow [same filters] [--from-seq N]
                   → backfill from N, then live, with no gaps (tails the file)
```

A later menu-bar app or TUI runs these commands, or links the `audit` package and reads the
file directly. `--from-seq` lets a viewer backfill and then go live without gaps. The sink
interface keeps `Query` and `Subscribe` (§4.7) so a later SQLite sink fits behind the same
commands.

---

## 9. Approval policy

### D7: A "stricter wins" lattice over four levels, with every-time approval as the default

### 9.1 Shape

Each level holds one `Policy` value, or nothing at all.

```
Policy  = Unset                              -- "no opinion" (table omitted)
        | EveryTime                          -- fresh approval for each access
        | Reuse{window: Duration, scope: Scope}
Scope   = request < connection < guest-program < guest-session < peer-session < instance
                                                                       (narrow → wide)
```

A scope name says **who vouches for it**. No name means different things on different
transports without saying so.

| Scope | A grant is reused only when… | Vouched for by | Needs |
|---|---|---|---|
| `request` | never; it covers this one request (a batch is one request) | — | — |
| `connection` | the same socket connection | host kernel | — |
| `guest-program` | same VM session **and** same requesting program (exe path + sha256) | VM kernel, via the relay | `guest_relay` (§14) |
| `guest-session` | same VM terminal or ssh session (durable session walk inside the VM) | VM kernel, via the relay | `guest_relay` (§14) |
| `peer-session` | same host-side session. **For a forwarded socket this is the whole VM**; for a host-local client it is one terminal session | host kernel | — |
| `instance` | any caller of this instance | — | — (always capped by the code floor, §9.2) |

**Scope safeguards.** These are the rules that keep the three VM-related levels (whole VM,
VM session, VM session + program) from blurring:

1. **Scope keys contain verified data only.** Client-reported fields never go into a scope key.
   There is deliberately no scope built from client-reported session ids.
2. **A scope is never silently widened.** Using `guest-*` on an instance without
   `guest_relay` is a **config error** at load time; it does not fall back to `peer-session`.
   If the relay can't produce an identity for a request (process gone, `/proc` unreadable),
   the request is refused rather than handled under a wider scope.
3. **A grant stores its exact key.** It records each component and who vouched for it, e.g.
   `{instance: dev, peer_session: ssh:4711, guest_session: 780, guest_exe_sha256: …}`. A reuse
   check compares every component; a missing component never counts as a match.
4. **Connections are never multiplexed.** The relay opens one upstream connection for each
   downstream connection, so `connection` scope means the same thing with or without it.
5. **Callers can't choose a scope.** Scope comes only from host config, folded with "stricter
   wins". `grants.drop` is the only thing a caller can do to its grants.
6. **The prompt states how far the approval reaches.** If approving creates a grant, the
   prompt says so in plain words, for example:
   `Approve read common:github-pat? Also allows silent reads for 15m by: anything in VM dev`, or
   `… by: aws (guest-verified) in the same VM session`.
7. **`foca policy explain` shows the same wording.** It runs on the host CLI, reading config only
   and prints the effective policy for every secret and action in that plain-language form,
   so you can check what the config means before anything is approved.
8. **The audit log shows scope and key.** Each grant and reuse event carries `scope` and the
   key components with their trust level, so a later UI can show "1 touch → 7 reads, all from
   VM session 780".

### 9.2 Levels folded together

The order does not matter.

1. instance: `[instances.<name>.policy]`
2. vault: `[vaults.<name>.policy]` of the vault the secret is in (secrets only)
3. resource: `[secrets."<vault>:<id>".policy]` or `[actions.<id>.policy]`
4. authenticator: `[authenticators.<name>.policy]`
5. code floor: `Reuse{window: 8h, scope: peer-session}`. This is the hard cap and is not
   configurable. Even `instance` scope is capped at `peer-session` unless a future decision says
   otherwise.

A `[secrets."<vault>:<id>".policy]` must name a vault in the config, or the config doesn't
load. The secret itself can't be checked without unsealing the vault, so a policy for a secret
that doesn't exist yet has no effect until it is added.

### 9.3 Combining

```
meet(Unset, x)                 = x
meet(EveryTime, x)             = EveryTime
meet(Reuse a, Reuse b)         = Reuse{min(a.window,b.window), narrower(a.scope,b.scope)}
effective = meet(level1, level2, level3) ; if Unset → EveryTime ; then meet(…, code floor)
```

A `Reuse` level may leave out `scope`: it then has no opinion on scope, folds like the widest
one, and the floor caps it at `peer-session`. `window` is required with `reuse`. After the
floor, a window under the minimum or a `request` scope (a grant nothing could reuse) becomes
`EveryTime`; the evaluator only ever narrows.

`meet` is commutative, associative and idempotent, and `meet(x, y) ⊑ x` holds for every `y`.
So **adding a level, or any setting at any level, can never loosen the result**. A
`secrets.X.policy = every-time` can't be undone by an instance-wide 30-minute window, because
`meet(EveryTime, anything) = EveryTime`. The tests check these laws over every small
combination and on random ones, plus table tests of loosening attempts (§16).

What follows:

- With no config, everything is `EveryTime`.
- Opt-in happens wherever reuse is explicitly enabled, and any other level can veto or shorten
  it.
- The vault cannot contain policy or exposure, so a vault edit can't loosen a policy or
  widen who reads a secret (§7.1 rule 4).

### 9.4 Limits (in code)

- `MaxReuseWindow = 8h`, `MinReuseWindow = 1s`. Config values outside this range are
  **rejected** at load time. The evaluator clamps as well, as defence in depth.
- `approval = "every-time"` with a `window` or `scope` set is a config error, and so is
  `approval = "reuse"` without a `window`.
- `[authenticators.<name>.policy]` names a known authenticator. Only the configured one
  applies; the others are allowed so a config can switch authenticators and keep them.

### 9.5 Grants and wipe rules

- A successful fresh approval under a `Reuse` policy creates a grant:
  `{approval_id, resource, scope_key, expires_at = now + window}`. Grants are per resource, so
  approving `github-pat` doesn't cover `npm-token`. An action's grant also covers only the
  validated params it was approved with: approving `aws-creds` with `profile=dev-admin` never
  covers `profile=prod-admin`, and an action grant never covers a read of a secret it uses.
  Host CLI operations never create or reuse grants.
- **Scope keys.** `connection` is keyed on the connection, `peer-session` on the peer's durable
  session (§4.6), and both on the instance. If the caller lacks a component, for example a peer
  whose pid isn't pinned or has no session, that read is `EveryTime`: no grant is made or
  reused, and the prompt promises no reuse.
- **A batch is one approval**, so its uncovered names share one policy: the meet of theirs. The
  `{reach}` sentence is then true for every name on the prompt.
- **Expiry uses wall-clock time, not Go's monotonic clock (D11).** The monotonic clock stops
  during system sleep on both macOS and Linux, so a window measured on it would stretch across
  sleep. A watchdog also compares wall and monotonic elapsed time every 5 s. A jump
  larger than 30 s, either way, is treated as a `sleep` event, as a backstop for missed
  notifications. The same tick drops expired grants and audits `lock` with `reason: expired`.
  A request that could reuse a grant, and `grants.status`, run the same check first, so a
  grant is never reused in the seconds between a missed sleep and the next tick.
- **Unconditional wipe**, whatever the config, on `Sleep`, `ScreenLock`, `SessionEnd`, service
  shutdown, `foca lock` (`SIGUSR1`), the platform-events source becoming unhealthy, or a
  config reload.
  A wipe drops all grants, denial backoff and strikes (§9.6), and audits `lock` with its reason
  and the number of grants dropped. An approval whose prompt was open during a wipe serves its
  request but creates no grant. A wipe that comes while an approval is being recorded waits
  for its grant, then drops and counts it, so `approval.granted` never claims a grant that
  didn't exist.
- **DEK lifetime.** The DEK is unsealed for each request and zeroed when the request ends; it
  is never cached between requests, so a wipe has no key to zero. (Caching it while a grant
  is live would be allowed; it would only save a protector call.) With the Keychain
  protector, unsealing needs no prompt. The user's approval is the Touch ID step itself.
- **If platform events are unavailable** (`none`, or the source is unhealthy), reuse is
  disabled: the effective policy becomes `EveryTime`. Reuse is only safe if we can wipe on
  sleep or lock (D13).

### 9.6 Prompt queue

Only one approval prompt is open per service process at a time, across all its instances. Other requests wait, up to
`max_queue`; beyond that they get `busy`, which is audited. When a queued request reaches the
front, its reuse is re-checked, so concurrent reads coalesce after one touch. This stops a
misbehaving VM from flooding the screen with prompts.

- **Fair share.** With more than one instance, no instance may hold more than half the
  slots (one open prompt plus `max_queue` waiting), so one realm can't keep the others out.
- **Hang-ups cancel.** If a client disconnects while its request waits or its prompt is open,
  the request is cancelled at once. With its prompt open, that is audited as
  `approval.timeout` with `reason: cancelled`. While it waits, no prompt was shown, so it is a
  coalesced `request.rejected` with `reason: cancelled`. Nothing is decrypted for a client that has gone, even if approval
  arrived. Clients must not half-close a connection while they wait for an answer.

**Denials are never cached as "no".** Instead, repeated denials of the same resource for the
same caller (its pinned peer session, else its connection) back off: 2 s, then 8 s, then 30 s
before the next prompt. A request inside that time is refused with `denied` and audited as a
coalesced `request.rejected` (`reason: denial_backoff`); it doesn't wait. The next prompt
shows "(denied once)" or "(denied N times)". An approval resets the count, a denial is
forgotten after 10 minutes, and a wipe resets everything. The prompt slot is held until a
decision is recorded, so a request queued behind a denial meets the backoff, and one queued
behind an approval finds the new grant.

**Unapproved prompts cool the instance down.** Denial backoff is per resource, so a realm
could still keep prompts coming by asking for each of its secrets in turn, and a prompt left to
time out would cost it nothing. So every prompt an instance opens that isn't approved (denied,
timed out, or cancelled by its client while on screen) is a strike against the instance as a
whole, which a realm can't change by forking or reconnecting. After three strikes, the
instance opens no prompt until 30 s after the last one; a fourth makes that 2 min, and every
later one 5 min. A request in that time is refused with `denied` and audited as a coalesced
`request.rejected` (`reason: prompt_cooldown`); it doesn't wait. The next prompt shows
"(N unanswered)" for the timeouts and cancels among the strikes. An approval or a wipe clears
them, and a strike is forgotten after 10 minutes.

**Nothing takes a closing prompt's place.** After a prompt times out or is cancelled, its slot
stays held for 1.5 s before the next queued prompt may open. A realm can't cancel one prompt
just as the user reaches for the sensor and have another appear under their finger. The
service and the host CLI also share a lock, `prompt.lock` in the runtime directory, held while
a prompt is on screen and through that pause. foca never shows two prompts at once, so a
realm's prompt can't open alongside one the user expects from `foca add`. The lock drops when
a process exits, so a host command whose prompt timed out keeps it through the pause before
exiting. Ctrl-C on such a prompt cancels it the same way, then the command waits out the pause;
a second Ctrl-C ends it at once.

**Unapproved events are coalesced in the audit log.** These are the events a realm can cause
without any approval: `request.rejected` (`busy`, `forbidden_on_socket`, refused connections
and so on), `secret.read` with outcome `not_found`, `secret.list`, `action.list`,
`action.run` refused before approval (`not_found`, a secret it uses that the instance can't
read, `param_rejected`), and a `grants.drop` that dropped nothing. A request for which no
prompt was ever shown is one of them too: when no prompt can be shown here (a headless polkit,
a closed laptop) it is a `request.rejected` with `reason: auth_unavailable`, and when its client
left while it waited, one with `reason: cancelled`. Bursts are folded per
**instance, type and reason**, not per peer, because a caller can fork new processes but can't
change its realm. The first event in a 10 s window is written at once and in full, with the
name it asked for. Later ones are counted, and the count is written as one event of the same
type, with `coalesced` set (§8.1), when the next window starts or the service stops. A flood therefore can't bury real events or fill the disk. Events that involve an
approval are **never** coalesced.

- **Reasons a realm must not tell apart share a window.** An unknown name and an unexposed
  one (`unknown`, `not_exposed`) share one, `not_found`, as do an action's unknown and
  unexposed secret (`uses_unreadable_secret`). Whether a probe writes an event then says
  nothing about which it was. The event written in full keeps its own reason, and the count
  says how many of each it folded (`coalesced.reasons`).
- **Nothing is counted while the log fails.** Once a write to the log has failed, every event
  is written in full until one succeeds, so a sink that stopped (D10) refuses these requests
  too, instead of answering them on the strength of an earlier write.

### 9.6.1 Connection limits

A realm can open connections freely through its forwarded socket, and each one can hold up to
1 MiB of unfinished input. `[limits]` bounds this, per instance:

| Key | Default | Range | Effect |
|---|---|---|---|
| `max_connections` | 32 | 1–1024 | further connections are closed before identification and audited as `too_many_connections` |
| `idle_timeout` | `2m` | 5s–1h | a connection that sends no complete request for this long is closed; this also stops byte-by-byte drip feeds. It is lifted while a request is handled, so a slow approval never trips it |

Fixed limits, not configurable:

- **Pipelining.** A connection may send up to 4 requests ahead of the one being handled; one
  more closes it, audited as `too_many_pipelined`. The socket is read while a request is
  handled, so a hang-up is noticed at once even with requests queued: the request in flight
  is cancelled, and the queued ones aren't handled but are audited as `connection_closed`.
- **Writes.** A response the client doesn't take within 10 s closes the connection, so a
  client that stops reading can't hold a slot.
- **Rate.** `secret.read`, `secret.list`, `action.list`, `action.run`, `grants.status` and
  `grants.drop` cost the host work before any approval: an unseal, a metadata decrypt or an
  audit append. Each takes a token from the instance's bucket of 30 requests, refilled at 5 a
  second. A request over it is refused as `busy` before any of that work, audited as
  `rate_limited`.
- **Accept errors.** When accepting fails, as it does once the service is out of file
  descriptors, the next try waits 5 ms, doubling up to 1 s until an accept succeeds, so the
  accept loop never spins.

### 9.7 Batches (D15)

A single `secret.read` naming several secrets, as `run --env A=x --env B=y` does, shows **one**
prompt listing all the names, every one of them (§4.1.1 rule 2). That counts as one access event per secret, all sharing one
`approval.id`. Reuse is still decided per resource: names already covered by grants are left
out of the prompt, and if none remain, no prompt is shown. Those grants are checked again
when the prompt closes: if a wipe or expiry ended one while it was open, its names get a
prompt of their own rather than being reused.

### 9.8 Listing (D16)

`secret.list` and `action.list` return names and descriptions only, never values. They need
no approval but are always audited. Listing is not a read of secret material, and agents need
discoverability. An `[approval] list_requires_approval = true` to make them approval-gated is
planned but not built (§17).

---

## 10. Vault file format

### D8: AES-256-GCM with a random DEK, key slots, per-entry encryption and AAD

```json
{
  "format": "foca-vault", "version": 1,
  "vault_id": "01J…", "vault": "common", "cipher": "aes-256-gcm",
  "key_slots": [
    { "type": "keychain",   "sealed": "<base64>" },
    { "type": "passphrase", "kdf": "argon2id",
      "kdf_params": {"t":3,"m":65536,"p":4}, "salt": "<b64>", "nonce": "<b64>", "wrapped": "<b64>" }
  ],
  "meta":    { "nonce": "<b64>", "ct": "<b64>" },
  "entries": { "<random-entry-id>": { "nonce": "<b64>", "ct": "<b64>" } }
}
```

- **Random DEK, wrapped in key slots** (like LUKS). Changing the protector or the recovery
  passphrase never re-encrypts the data. The data key is never derived from the passphrase
  directly.
- **`meta`** is the encrypted list of `SecretMeta` plus `id → entry-id`. Entry ids are random,
  so the plaintext file doesn't reveal secret names.
- **Per-entry encryption.** Reading one secret decrypts only that one, which keeps less
  plaintext in memory than decrypting the whole vault.
- **AAD** = `format|version|vault_id|vault|<entry-id or "meta">`. Ciphertexts can't be
  swapped between entries or vaults. A vault can be shared by several instances (D20), so
  the header and AAD name the vault, not an instance.
- **Parsed strictly.** The file, and its metadata once decrypted, follow the protocol's
  rules (§6): unknown, duplicate or case-variant keys and trailing data are refused, so no
  two readers can find different contents in the same bytes.
- **A write in doubt is kept.** If the directory `fsync` after the `rename` (below) fails,
  the new file is already the one readers see. The write reports that it may not survive a
  crash, but nothing is rolled back: `init` keeps the protector entry the new file needs.
- **Fresh 96-bit random nonce on every write.** Writes are atomic: temp file in the same
  directory, `fsync`, `rename`, `fsync` the directory. Mode 0600, data dir 0700.
- The passphrase slot is optional and set by `foca init --recovery` through an
  interactive prompt or stdin, never argv. KDF is Argon2id from `golang.org/x/crypto`.

---

## 11. Command provider

### D14: Allowlisted actions — no shell, placeholders that never split or join arguments, constrained parameters, clean environment

- **Actions exist only in host config.** The caller sends `{name, params}`. An unknown name, or
  an action the instance isn't offered, is `not_found`. Unknown, missing or failing params are
  refused with `param_rejected`. Both are audited (coalesced, §9.6) before any prompt.
- **`command` is an absolute, clean path, checked like a helper path** (§5): the file and
  every directory above it owned by root or the user and not group- or world-writable, and the
  file executable. The check runs at start-up for every offered action (the service refuses
  to start otherwise) and again before every run. The resolved path is what runs; `argv[0]`
  is the configured path, so multi-call binaries still see their name. It is run with
  `execve` directly, never through a shell.
- **Placeholders are `{param}` inside `args` elements.** Partial interpolation like
  `--profile={profile}` is allowed because there is no shell. One argv element always stays
  one argv element: substitution never splits or joins words. `{{` and `}}` are literal
  braces; any other brace is a config error.
- **Every declared param is required and used.** A placeholder that isn't declared, or a
  declared param no argument uses, is a config error: an unused param would be on the
  prompt and do nothing. Names match `^[a-z][a-z0-9_]{0,31}$`; an action has at most 16.
- Each parameter must declare exactly one constraint, plus an optional `description`:
  - `allowed = [...]`: exact match.
  - `pattern = "^[a-z0-9-]{1,64}$"`: RE2, always fully matched: the service wraps it as
    `^(?:…)$`, so a missing anchor can't let anything through around the part that matched.
    It must compile on its own first: an unbalanced pattern such as `[a-z]+)|(.*` would
    otherwise close the wrapping group and match anything.
  - Values starting with `-` are refused unless `allow_leading_dash = true`, to stop option
    injection. An `allowed` entry starting with `-` without it is a config error.
  - Whatever the constraint: values are non-empty, at most 256 bytes, valid UTF-8, and hold
    no control, Unicode format or separator characters other than a plain space (newlines,
    NUL, escapes, bidi overrides, line and paragraph separators, no-break and other spaces).
  - Only a leading `-` is refused for every param. Other characters mean something to many
    commands at the start of a value: `@file` (`curl -d @file`, `gh api -F key=@file`, response
    files), `+` and `<`. Inside a larger argument (`--opt=key={value}`), `,` and `=` can add
    sub-options. Give such a param an `allowed` list, or a pattern that refuses them, for
    example `pattern = "[A-Za-z0-9_][A-Za-z0-9_./:-]{0,63}"`.
- **Environment is exactly `env` from config** plus `FOCA_ACTION=<name>` (and `env_secrets`,
  §11.1). Nothing is inherited from the caller or the service, not even `PATH`. stdin is
  `/dev/null` and the working directory is `/`.
- **Limits.**
  - `timeout` (default 60s, 1s–30m): when it passes, the process group gets SIGTERM, then
    SIGKILL 2 s later if the command is still running. The command runs in its own process
    group. After a timeout or a cancel, whatever is left of the group is killed as soon as
    the command exits, children that ignored SIGTERM included. A client that hangs up during
    a run cancels it the same way. After a normal exit, the rest of the group is killed too
    when the action has `env_secrets`, so no child keeps them (§11.1). The group of an
    action without them is left alone, since `granted sso login` may leave a browser running
    in it; a child still holding the command's stdout or stderr gets 2 s before the pipes are
    closed. The group is signalled only while the command is still unreaped, so its id can't
    have been reused by another group. A child that calls `setsid()` or `setpgid()` leaves
    the group and is not killed (§12.4).
  - `output.max_bytes` (default 64 KiB, at most 512 KiB, so a result fits in one message):
    passing it stops the command and the result is `error`.
  - Optional `output.format` validator: `aws-credential-process` (a JSON object with
    `Version` 1, non-empty `AccessKeyId` and `SecretAccessKey`, optional `SessionToken`, and
    an RFC 3339 `Expiration` if present), `json` (one valid JSON value) or `text` (UTF-8 with
    no control characters but tab, CR and LF). It checks stdout on exit 0, after masking. If
    validation fails, the result is `error` and nothing is returned.
  - At most 4 actions per instance are in flight at once, from before their approval until
    their command exits; more are refused as `busy` (`too_many_running`).
- **Result:** `{exit_code, stdout, stdout_encoding, stderr_tail, stderr_encoding}`, with
  `utf8` or `base64` encodings as for secrets, and `stderr_tail` the last 4 KiB. stdout is
  returned only on exit 0, unless `return_on_failure = true`. A timeout is `timeout`; an
  output that is too large or fails its format, a command that fails its trust check or can't
  start, or a secret that can't be read is an error, and nothing is returned. So is a result
  that wouldn't fit in one message (`response_too_large`, an `internal` error to the
  client). The `action.run` event records which (§8.1).
- **Policy.** `[actions.<id>.policy]` is the resource level (§9.2). The action's policy folds
  instance, action and authenticator levels and the floor; then it is met with the policy of
  each secret it uses (§11.1). A grant covers only the params it was approved with (§9.5).
- **CLI.** `foca exec <action> [-p name=value]…` writes stdout to stdout and the stderr tail
  to stderr, and exits with the action's exit code. Like `get`, it refuses to write a non-empty
  stdout to a terminal (the action has run by then; its stderr is still shown). The stderr
  tail and the service's error messages are printed without control or format characters,
  keeping line breaks and tabs.
  `foca actions` lists what the realm is offered. `foca policy explain` shows each instance's
  actions.
- **First targets** (replacing aws-cred-broker):

```toml
[actions.aws-creds]
description = "AWS credentials"
command = "/…/granted"
args    = ["credential-process", "--profile", "{profile}"]
output  = { format = "aws-credential-process" }
  [actions.aws-creds.params.profile]
  allowed = ["dev-admin", "staging-readonly"]

[actions.aws-sso-login]          # opens the browser on the host
command = "/…/granted"
args    = ["sso", "login", "--sso-start-url", "https://example.awsapps.com/start"]
timeout = "5m"
```

VM side `~/.aws/config`:
`credential_process = foca exec aws-creds --param profile=dev-admin`.

### 11.1 Host-side use: secrets that never enter the VM

This is not a separate provider. An action can take vault secrets in its **host-side**
environment, so the VM gets only the result:

```toml
[actions.gh-pr-list]
description  = "List PRs"
command      = "/…/bin/gh"
args         = ["pr", "list", "--repo", "{repo}"]
env_secrets  = { GH_TOKEN = "common:github-pat" }   # vault secret → child env, on the host
mask_output  = true                          # default true when env_secrets is set
  [actions.gh-pr-list.params.repo]
  pattern = "^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"
```

- **The secrets come from the calling instance's vaults, under its exposure.** An action
  can't use a secret the instance couldn't read: such a run is `not_found` and audited as
  `action.run` with `reason: uses_unexposed_secret` (or `uses_unknown_secret`).
  `env_secrets` names each secret in full (`common:github-pat`), so config loading already
  refuses an offered action whose secret the instance's `expose` leaves out; whether a secret
  in a vault the instance reads whole exists is checked at run time.
- The approval prompt and the audit event list both the action and every secret it uses
  (`uses`). The action's policy is met with each secret's policy (§9), so a strict secret
  can't be loosened by putting it inside an action. A vault's policy counts only through
  the secrets an action uses: it never makes an action's reuse opt-in on its own.
- Masking replaces the value, and its base64 (standard and URL alphabets, padded or not),
  hex (either case), URL-encoded (query and path) and JSON-string-escaped (with and without
  escaping `&`, `<` and `>`, and with `/` written as is or as `\/`) forms, with
  `[hidden:<vault>:<id>]` in stdout and stderr. All matches are found before any is replaced;
  matches that overlap, of one secret or of several, are hidden as one range, under the mark
  of the match that starts first. The stderr tail is masked over enough bytes before it that
  a value reaching into the tail is seen whole, so no part of one shows. If
  marks make stdout grow past 512 KiB, the result is refused. Masking is **best effort**: a
  value inside a longer base64 blob at another alignment, or JSON-escaped by an encoder that
  writes other characters as `\u` escapes (every non-ASCII one, say), gets through. A
  host-declared command is trusted not to deliberately re-encode its secrets. The real
  guarantee is that the command and its arguments are fixed by host config.
  `mask_output = true` without `env_secrets` is a config error; `mask_output = false` turns
  masking off.
- Secrets are decrypted only once the run is approved, and only for the life of the command:
  whatever is left of its process group is killed when it exits (§11; a child that leaves
  the group survives, §12.4), and the service's copies are then zeroed. The copy in the
  child's environment block is a Go string, which can't be zeroed (§12.4). A value holding a
  NUL can't be put in an environment variable, and the run fails.

---

## 12. Threat model

### 12.1 Assets

Secret values; the DEK; the ability to run host actions; config integrity; audit integrity.

### 12.2 Actors

- Processes in a VM, including a prompt-injected coding agent.
- A fully compromised VM (root in the guest).
- Other VMs.
- Other processes running as the same user on the host.
- Other local users on the host.
- Someone with physical access to a sleeping or locked Mac.

### 12.3 What foca defends against

- **A VM reading secrets without the user knowing.** By default each read or action needs a
  fresh Touch ID touch, shown with the instance name and resource names. Every attempt, even
  denied or unknown ones, lands in the audit log.
- **Cross-realm access.** By default each instance has its own socket, vault file, DEK and
  Keychain entry. If the user opts in to shared vaults, each realm still sees only its explicit
  `expose` list (§7.1). A realm's socket can only reach its own instance, and an unexposed
  secret is indistinguishable from a missing one.
- **Arbitrary host command execution.** Only config-declared actions with constrained
  parameters run, with no shell and a clean environment. A VM can't supply config, command
  paths or AWS profile definitions. That was the old broker's flaw, and here it is ruled out
  by design.
- **A realm managing the host.** No socket offers management; a realm's socket can't change secrets, policy, config or the service.
- **Loosening policy.** Policy lives only in host config, combines "stricter wins", has an 8 h
  cap in code, and is always wiped on sleep, lock and shutdown.
- **Secrets at rest.** AES-256-GCM vault with per-entry AAD. The DEK is sealed by a platform
  protector and is never stored in plaintext on disk. Secrets never appear in argv or shell
  history.
- **Unattended machine.** Sleep, screen lock and session end wipe grants and the DEK. A
  wall-clock watchdog backs this up.
- **Prompt floods and confusing prompts.** One prompt at a time, across the service and the
  host CLI, a bounded queue, a cooldown for a realm whose prompts go unapproved, a pause
  before a prompt can take a closing one's place, trusted fields first, and unverified fields
  labelled and sanitised.
- **Other local users.** Socket directory 0700, socket 0600, and a uid check on every
  connection. Private directories (runtime, data) must sit below directories no other user
  can write, unless sticky like `/tmp`, so they can't be swapped for an older copy.

### 12.4 What it doesn't defend against

- **A secret after delivery.** Once approved, the value is inside the VM. A compromised VM can
  exfiltrate it. foca makes access deliberate and visible; it does not contain approved
  data.
- **Approved reuse windows.** If config opts in to reuse, anything in the matching scope (for
  `peer-session` on a forwarded socket, that means the whole VM) gets silent access until the
  window ends or a wipe happens. That is why reuse is opt-in.
- **The user approving blindly.** We reduce prompt fatigue with batching and opt-in reuse, but
  we can't stop someone from approving everything.
- **Same-user malware on the host, or root.** Such code can:
  - run the host CLI. Managing secrets (`add`, `edit`, `remove`, `init`, `recover`) still
    needs approval, but changing policy doesn't: the config is the user's own file, so such
    code can edit it (expose a vault to another instance, allow reuse with a long window,
    offer an action) and `foca reload` with no prompt. A reload drops every grant, so under
    the loosened policy a read or action still needs at least one approval, and the reload
    and every access are audited;
  - on macOS, read daemon memory (a debugger). On Linux the service and the host commands
    that unseal a vault (`init`, `add`, `edit`, `remove`) aren't dumpable, so only root can
    attach to them or read their memory, environment or executable through `/proc`. Socket
    clients stay readable: the service identifies them through `/proc`;
  - drive the helper;
  - under ad-hoc signing, read the plain Keychain item holding the DEK, because Touch ID is
    enforced by our code and not by the item (§5).

  This is not a boundary. A Secure Enclave
  protector that needs user presence for every unseal would raise the bar, but needs a signed
  `.app`.
- **Go memory hygiene.** Values are kept as `[]byte` and zeroed after use, but the GC may have
  copied them, and the JSON encoder makes intermediate copies. This is best effort.
- **Children that leave an action's process group.** foca kills what is left of the group
  after a timeout, a cancel, or the exit of an action with `env_secrets` (§11). A child that
  calls `setsid()` or `setpgid()` is no longer in it, and keeps running with whatever
  secrets are in its environment. A host-declared command is trusted not to do that.
- **Client-reported identity.** It can be forged. It is labelled, never trusted, and kept
  separate.
- **Sealed names on Nix.** Any user who can reach the Nix daemon can add a root-owned file with
  any name to `/nix/store`, so on Nix systems "sealed" proves the file wasn't changed, not that
  it is the program its name suggests.
- **Exec after connect.** The peer is read once, when the connection is accepted. A process can
  connect, keep the socket in a forked child, and exec a sealed binary, so the prompt names
  that binary. This holds on Linux and macOS alike: a pidfd and an audit token both follow
  the process across exec. The race is narrow, and only same-uid or direct-realm code can try it.
  Parents are read by pid, without pinning, so their names can change the same way: a parent
  that execs a sealed binary after forking the peer is named as that binary in `via`.
- **Code hidden inside a sealed program.** On Linux a sealed name rules out the loader's
  documented ways in (§4.1.1), but not code that removes its own traces once it runs: a
  library that copies itself into anonymous memory, unmaps its file and blanks its
  environment, or code injected with `ptrace` or `/proc/<pid>/mem`. Doing that takes code
  already running as the user, like the same-user malware above. On macOS nothing
  checks for loaded code: dyld ignores `DYLD_INSERT_LIBRARIES` for platform binaries and
  hardened-runtime programs, but most Homebrew and Nix programs are neither (§4.6).
- **Tampering with the audit log by same-uid code.** It is append-only by convention, with
  sequence numbers. A hash chain is a possible later addition.
- **Rollback** of the vault file to an older version by someone with disk write access.
- **A compromised helper or toolchain.** The checks are path, owner and mode, plus an optional
  pin; supply chain is otherwise out of scope.

---

## 13. Decision records

Format: context → decision → consequences. Short on purpose.

| # | Decision | Why | Consequences |
|---|---|---|---|
| D1 | Go core and CLI | Linux-testable, cross-compiles, one binary for host and VM | Swift only in the darwin helper |
| D2 | Compiled-in interfaces, stdio helpers only for non-Go platform APIs, no cgo | Keeps core testable and cross-compilable, and gives the Keychain a stable identity | One extra trusted binary on macOS, ~10–30 ms per spawn |
| D3 | One process hosts many instances by default; one process per instance is optional | One prompt queue across realms, single wipe; isolation by process remains available | Shared vaults must live in one process |
| D4 | One client socket per instance; management is host CLI only, on files with locks | Nothing a realm can reach changes state; the service is read-only on vaults | Locking for multiple writers; the service reloads changed vaults |
| D5 | JSON-RPC 2.0 NDJSON over Unix socket | Simple, debuggable with `socat` | Hand-written small codec, no framework |
| D6 | TOML host config is the only policy and action source | Declarative, Nix-friendly, reviewable in git; callers send only names | Changing policy means editing config, not running a CLI |
| D7 | Policy lattice, default EveryTime, 8 h cap | Encodes rule 4 exactly; laws can be property-tested | Opting in needs explicit config |
| D8 | Vault: random DEK, key slots, per-entry AES-GCM and AAD | Re-keying without re-encrypting, less plaintext in memory, no swap attacks | Existing tokens are re-added with `foca add` (no importer) |
| D9 | Key protector = seal/unseal of the DEK | One interface for Keychain, SE, TPM, keyring and file | Keychain "seal" is just storing the DEK |
| D10 | JSONL audit v1, fail-closed, verified vs reported split | Records every access and is ready for the UI | An audit disk failure blocks access, on purpose |
| D11 | Wall-clock expiry plus sleep-jump watchdog | Monotonic clocks pause during sleep | Clock changes may wipe early, which is safe |
| D12 | `fake` authenticator compiled only with the `foca_testing` build tag | A config line can never turn approval off in production | Integration tests build a tagged binary |
| D13 | Platform events unhealthy → wipe and EveryTime | Reuse is only safe when we can wipe on sleep or lock | Linux hosts without logind get no reuse |
| D14 | Command provider: no shell, allowlists, clean env | Rules 2 and 3 | Every action is written out in config |
| D15 | One prompt per batch request | `run` with N secrets shouldn't need N touches | Prompt must list all names |
| D16 | Listing needs no approval by default; audited | Names aren't values, and discoverability matters | `list_requires_approval` for the strict case (not built yet) |
| D17 | No auto-spawn; launchd or systemd runs `serve` | VM clients can't spawn on the host anyway; avoids env-inheritance bugs | Host CLI says "service not running" |
| D18 | No ported third-party code | Clean implementation, no notices to carry | Everything is written and tested here |
| D19 | Optional guest relay for guest-verified identity | Lets the prompt show a process the VM kernel vouches for | Needs a dedicated VM user and ssh config |
| D20 | Instances, vaults and actions are separate objects; separate-per-realm by default, sharing explicit | Users choose anything from strict separation to "everything everywhere" without weakening the default | Exposure rules and their config errors must be tested |
| D21 | CLI: `kong` for commands, `charmbracelet/huh` for interactive prompts; secret values read with `golang.org/x/term` | The owner prefers a polished interactive UX. Secret values stay in zeroable `[]byte`, which a `huh` field (a Go string) can't give | Larger dependency tree, also present in the VM copy of the binary; prompts only on a TTY, so agents and scripts never see one |

### D18: No third-party code is ported

foca is written from scratch, so it carries no third-party licence notices.
Dependencies are ordinary Go modules (§15), each under its own licence.

---

## 14. Guest-verified identity: the guest relay (optional)

When a realm's peers are opaque (§2.1), the host can't see the calling process. A VM's
forwarded connection always comes from `ssh`, and a container on macOS reaches the host
through its runtime's proxy. Identity can still be verified **inside the realm**, by a small
relay that is the only thing allowed to reach the upstream socket. The example below is a
VM. For a container, the relay runs as a sidecar process or container user in the same way,
and the upstream socket is mounted only into the relay's mount namespace or for its user.

```
 VM "dev"
 ┌───────────────────────────────────────────────────────────────────────┐
 │  user dev:  gh / aws / agent ──► /run/foca/relay.sock (0666)          │
 │                                         │                             │
 │  user foca:  foca relay ◄───────────────┘  SO_PEERCRED (VM kernel)    │
 │        │   /proc/<pid>/exe + sha256, comm, start time, parent chain   │
 │        ▼                                                              │
 │  /home/foca/.foca.sock  (0600, owner foca) ── ssh fwd ────────────────┼─► host
 └───────────────────────────────────────────────────────────────────────┘
```

**How it works**

- The ssh session that carries the `RemoteForward` logs in to the VM as a dedicated user,
  `foca`. `StreamLocalBindMask 0177` makes the forwarded socket owner-only, so processes
  running as `dev` can't connect to it directly.
- `foca relay` runs as `foca` and listens on a socket that VM users *can* reach. For
  each connection it reads the caller's identity from the **VM kernel**:
  - `SO_PEERCRED`: pid, uid, gid;
  - `/proc/<pid>/exe` and its sha256;
  - `comm`, start time, and the parent chain up to 8 hops.
- The relay forwards each request upstream, replacing `params.client` with a
  `guest_verified` identity. Anything the caller claims about itself is still passed along,
  but stays in `client.reported`.
- The host trusts `guest_verified` only if it arrives on an instance whose config says
  `guest_relay = true`. With that setting, requests **without** `guest_verified` are refused.
  This stops a connection that bypasses the relay from falling back to weaker identity.

**Relay safeguards**

1. **The relay proves itself to the host.** At setup, the relay generates an Ed25519 key pair,
   kept 0600 by the `foca` VM user. Its public key goes into **host config**:
   `guest_relay = { public_key = "ed25519:…" }`. Every upstream connection starts with
   `relay.hello`, in which the relay signs a fresh server nonce, the instance name and the
   connection id. Until that check passes, `guest_verified` data on the connection is not
   accepted. So even if a `dev` process reaches the forwarded socket through a
   misconfiguration (wrong login user, wrong bind mask), it can't pass itself off as the
   relay.
2. **Relay required means relay only.** On an instance with `guest_relay`, a connection
   without a valid `relay.hello` is refused outright and audited as `request.rejected`
   (`reason: relay_required`). It is not downgraded to `client.reported`.
3. **Forged fields are a hard error, never silently dropped.** The relay rejects any
   downstream request that already contains `guest_verified`. It decodes requests with the
   same strict rules as the host (§6) and re-encodes what it forwards; it never edits or scans
   raw bytes. The host rejects
   `guest_verified` on any connection that hasn't passed `relay.hello`.
4. **No pid reuse.** The relay identifies callers by pid **and** start time (pidfd where
   available) and re-checks them just before forwarding. If the process has gone or changed,
   the request is refused.
5. **The relay checks its own setup.** At start it refuses to run unless:
   - its upstream socket is owned by its own user with mode 0600;
   - its key file is 0600;
   - it isn't running as root.

   The host can't check these from outside, so they are a convenience check. The signature
   in (1) is the real guard.
6. **VM hardening.** The guest Nix module sets `kernel.yama.ptrace_scope = 1` or higher
   in the VM, so a `dev` process can't attach to a process in another session and borrow its
   grant.

**What it still doesn't cover:** root in the VM can read the relay key and impersonate it.
`guest-*` scopes and `guest-verified` labels assume an uncompromised VM kernel and root, and the
prompt and docs say so.

**Three trust levels in the audit log and the prompt**

| Level | Source | Holds against |
|---|---|---|
| `peer.verified` | host kernel | anything in any VM (it identifies the VM, not the process) |
| `client.guest_verified` | VM kernel, via the relay | unprivileged VM processes, e.g. a prompt-injected agent running as `dev` |
| `client.reported` | the client itself | nothing; it is informative only |

Root in the VM can impersonate the relay, so `guest_verified` is **not** a boundary against a
compromised guest. The prompt labels it accordingly, e.g.
`guest-verified: /nix/store/…/bin/gh (pid 812)` vs `VM claims: gh`.

**Reuse scopes.** The relay makes `guest-session` and `guest-program` available (§9.1). On an
instance with the relay, they are the recommended reuse scopes. Without the relay, reuse on a
forwarded socket can only be `peer-session`, which means the whole VM, and the prompt says so.

**Possible later use.** Policy could also *narrow* on guest-verified identity. For example,
allow `github-pat` only to an exe whose hash is in an allowlist. That would be an extra
condition on top of approval, never a replacement for it. It is not designed yet.

**Prerequisites.** The guest Nix module creates the `foca` VM user, the ssh match block
and the relay service.

---

## 15. Repository layout

```
cmd/foca/            main: runs internal/cli (serve and every CLI subcommand)
internal/protocol/        wire contract shared by both sides: JSON-RPC framing, method types, error codes
internal/client/          protocol client (CLI, tests, later the relay); must not import service-side code
internal/cli/             CLI commands
internal/server/          listeners, per-connection identification, method dispatch
internal/server/core/     request → approval → audit pipeline, prompt text, prompt queue,
                          grants, denial backoff, wipe controller and watchdog
internal/server/wiring/   config → plugins; test-only plugins gated by the foca_testing tag
internal/plugin/          plugin interfaces
internal/plugin/helper/   helper adapter (authenticator, key protector, events over stdio), the Go fake
                          helper and the conformance suite
internal/darwinproc/      macOS process reads without cgo: audit token, pid version, exe path
internal/policy/          approval-policy lattice: meet, effective policy, the code floor, reach wording
internal/action/          action specs: param checks, argument templates, output formats, masking
internal/plugins/…        authn/fake, store/memory, store/vaultfile, keyprot/file, provider/static,
                          provider/command, peer (linux, darwin), events/logind; later keyprot/*
internal/audit/           event types (v1) + sinks: memory, jsonl
internal/config/          TOML load and validation, paths
internal/identity/        host-verified, guest-verified and reported identity, one distinct type each
internal/fsutil/          trusted-file and private-directory checks, atomic writes, file locks
internal/svcctl/          serve.pid and verified signalling for reload / stop
internal/ids/             sortable ids
internal/format/          output formatters: raw, json, env
helpers/darwin/           Swift package: foca-darwin
flake.nix                 dev shell (go, gopls, socat, dbus for the logind tests; gcc only for `go test -race`)
```

A test, `internal/client/boundary_test.go`, fails if client-side code ever imports
`server`, `plugin(s)`, `audit` or `config`. Code that runs inside a realm can then never link
the vault, keys or plugins.

Dependencies:
- Core: `golang.org/x/sys`, `golang.org/x/crypto`, `BurntSushi/toml`, `godbus/dbus/v5` (logind).
  The ids package is in-house.
- CLI (D21): `alecthomas/kong`, `charmbracelet/huh` (with Lip Gloss) and `golang.org/x/term`.
  These are imported only by `internal/cli`, never by the service packages. A boundary test
  keeps `huh` and its UI stack out of `internal/server`.

**CLI interaction rules (D21)**

- Prompts appear only when stdin **and** stderr are TTYs. Otherwise a missing value is an error
  that names the flag, stdin or `--from-file` alternative, never a hang. Agents and scripts in
  VMs are never prompted.
- Secret values are read only from a no-echo `x/term` prompt, stdin or a file, into `[]byte`
  that is zeroed after use. They are never read from a `huh` field or a flag.
- Prompts draw on stderr, so stdout stays clean for `get`, `--format` and `events` output.

---

## 16. Test gates

Each security property has a test that fails if the protection is removed. These are the
ones to run, and to keep passing, when the code they guard changes. All run on Linux unless
noted; packages are named as in `go test` output (`main` is `cmd/foca`, whose tests and the
`cli` end-to-end ones need `-tags foca_testing`).

| Property | Tests |
|---|---|
| **Pipeline and socket** | |
| approve → read → audit; deny → audit, nothing returned | `core.TestApproveReadAudit`, `server.TestRequestApprovalAuditOverRealSocket`, `core.TestDenyIsAuditedAndReturnsNothing` |
| an audit failure refuses; a torn write never hides the next event | `core.TestAuditFailureRefusesAccess`, `core.TestAddSecretRolledBackWhenAuditFails`, `audit.TestJSONLTornWriteDoesNotSwallowNextEvent`, `audit.TestJSONLFailedSyncLatches` |
| management methods refused and audited; only `client.sock` exists, 0600 in 0700 | `server.TestManagementMethodsRefusedAndAudited`, `server.TestSocketAndDirectoryModes` |
| uid mismatch, wrong kind of peer, and every other refusal audited | `server.TestUIDMismatchIsRefusedAndAudited`, `server.TestNonProxyPeerRefusedOnOpaqueRealm`, `server.TestProxyPeerRefusedOnDirectRealm`, `server.TestEveryRefusedRequestIsAudited` |
| verified, guest-verified and reported identity kept apart | `audit.TestVerifiedAndReportedStaySeparateOnTheWire`, `core.TestIdentityLevelsHaveDistinctTypes` |
| prompts: claims never stated as fact, unsealed names marked, no name elided | `core.TestPromptWording`, `core.TestPromptNeverElidesCredentials`, `core.TestOversizedBatchRefusedBeforePrompting`, `peer.TestMountsCantLendASealedName`, `peer.TestLoadedCodeMustBeSealedToo` |
| a realm can't exhaust the service or flood the log | `server.TestConnectionCapPerInstance`, `core.TestReadsAndListsAreRateLimited`, `core.TestUnapprovedEventsAreCoalesced`, `core.TestTooManyRunningIsBusy` |
| config rejections and file trust | `config.TestRejections`, `config.TestPolicyRejections`, `config.TestLoadChecksFileTrust` |
| test-only plugins unreachable in a production build | `wiring.TestFakeAuthenticatorRefusedInProductionBuild`, `cli.TestServiceDoesNotImportCLIUI` |
| **Vaults, exposure and the host CLI** | |
| a vault shared without explicit `expose` is a config error | `config.TestImplicitPrivateVaultCollisionCountsAsSharing` |
| an unexposed secret looks like `not_found` and is audited; private vaults can't see each other | `core.TestUnexposedLooksLikeMissingButIsAuditedWithReason`, `cli.TestHostCLIAndClientEndToEnd` |
| crypto round trip; AAD swaps and ambiguous files refused | `vaultfile.TestCryptoRoundTrip`, `vaultfile.TestAADSwapRejected`, `vaultfile.TestAmbiguousVaultFilesAreRefused` |
| atomic writes | `fsutil.TestWriteFileAtomicNeverLeavesAPartialFile` |
| no secret in argv; no value written to a terminal | `cli.TestNoSecretInArgv`, `cli.TestGetRefusesTerminalBeforeAsking`, `main.TestBinaryServeGetReloadStop` |
| formatters | `format.TestJSONGolden`, `format.TestEnvGolden`, `format.TestEnvRefusesWhatItCantHold` |
| add, edit and remove name every realm affected | `core.TestAddNamesEveryRealmThatWillSeeTheSecret`, `core.TestEditNamesEveryRealmThatReadsIt`, `core.TestRemoveNamesRealmsThatLoseIt` |
| signals only reach a verified service | `svcctl.TestSignalRefusesUnverifiedProcesses`, `svcctl.TestSignalRefusesOtherUID`, `svcctl.TestPinRefusesAChangedProcess` (macOS) |
| key holders hide their memory | `main.TestBinaryKeyHoldersHideTheirMemory` |
| `--only` never splits a vault; one process per instance | — |
| **Policy, grants and wipes** | |
| lattice laws; no setting loosens; the 8 h cap | `policy.TestLatticeLaws`, `policy.TestEffectiveNeverLoosens`, `policy.TestLooseningAttempts`, `core.TestEightHourCap` |
| a grant key that differs in any component never reuses | `core.TestGrantKeyMismatchNeverReuses` |
| sleep-jump watchdog; a missed sleep caught before reuse | `core.TestSleepJumpWatchdog`, `core.TestMissedSleepIsCaughtBeforeReuse` |
| wipe on every event kind; a wipe during a prompt makes no grant | `core.TestWipeOnEveryEventKind`, `logind.TestLogindReportsEveryEventKind`, `core.TestWipeDuringPromptCreatesNoGrant` |
| unhealthy or no events → every-time; only logind's signals count | `core.TestUnhealthyEventsMeanEveryTime`, `core.TestNoEventsSourceMeansEveryTime`, `logind.TestLogindIgnoresSignalsFromOthers`, `sysbus.TestSystemBusMustBeServedByRoot` |
| cooldown, the pause after a closing prompt, one prompt across processes | `core.TestCooldownAfterThreeUnapprovedPrompts`, `core.TestPromptPauseHoldsTheSlot`, `core.TestPromptLockIsSharedAcrossServices` |
| **Actions** | |
| injection attempts and unknown params refused before any prompt | `action.TestValidateRefusesInjectionAttempts`, `action.TestArgvKeepsOneElementPerTemplateElement`, `command.TestParamsReachArgvWithoutAShell`, `protocol.TestActionRunParamsAreStrict`, `core.TestUnknownActionsAndParamsAreRefusedAndAudited` |
| timeout, cancel and hang-up kill the group | `command.TestTimeoutKillsTheProcessGroup`, `command.TestCancelKillsTheProcessGroup`, `command.TestSecretsActionLeavesNoChildBehind`, `server.TestHangUpDuringRunKillsTheGroup` |
| environment is exactly config; stdin `/dev/null`, cwd `/` | `command.TestEnvironmentIsExactlyConfig`, `command.TestStdinIsDevNullAndCwdIsRoot` |
| output validation | `action.TestValidateOutput`, `command.TestOutputValidation` |
| masked output holds no encoding of a secret | `action.TestMaskTailNeverShowsAPartialSecret`, `action.TestOverlappingSecretsAreMaskedTogether`, `command.TestMaskedOutputContainsNoSecretEncoding` |
| an action can't loosen its secrets; a grant covers only its params | `config.TestActionPolicyMeetsItsSecrets`, `core.TestActionGrantCoversOnlyItsParams` |
| **Authenticators and key protectors** | |
| authenticator conformance (`authntest`) | — |
| polkit shows nothing it can't control | — |
| TPM: round trip, the key never on the bus in clear, a boot change refuses until `recover`, another TPM or storage key can't unseal | — |
| recovery keys shown once; rekey leaves the old keys opening nothing | — |
| helper: strict answers, trust checks, the pin, sleep acked only after the wipe | `helper.TestApproveAnswers`, `helper.TestDecodeResponseIsStrict`, `helper.TestHelperTrustChecks`, `wiring.TestDarwinHelperNeedsABuiltInPin`, `main.TestBinaryHelperPin`, `helper.TestSleepAckedOnlyAfterTheCoreHandledIt`, `main.TestBinaryDarwinHelper` |
| helper conformance and the macOS peer identifier (on a Mac, in CI) | `internal/plugin/helper/conformance_test.go` against the signed `foca-darwin`, `peer.TestDarwinIdentifiesRealPeer`, `peer.TestDarwinPeerThatExecsIsNamedAfterItsNewProgram`, `peer.TestSealedPath` |
| **Events** | |
| paging and filters | — |
| backfill + live with no gaps, across writers and rotations | `audit.TestJSONLSeqUniqueAcrossProcesses` |
| recorded names can't act on the terminal | — |
| **Guest relay** | |
| bad or missing `relay.hello` refused | — |
| forged `guest_verified` rejected on both sides | — |
| no multiplexing | — |
| pid reuse and exited callers refused | — |
| the relay refuses an insecure setup | — |
| reported fields can't overwrite guest-verified ones | — |

---

## 17. Not built or not verified yet

**Not built**

- polkit and the TPM key protector, with `foca recover` and `foca rekey`: on Linux, `serve`
  and the host commands have no real authenticator and run only in `foca_testing` builds.
- Audit log rotation, and `foca events query` and `follow`.
- Nix packaging, and `serve --only` for one process per instance or group.
- The guest relay, guest-verified identity and the `guest-*` scopes, which are a config
  error until then.
- A command that opens a vault with its recovery passphrase: `init --recovery` writes the
  slot, but nothing reads it yet.
- `foca reset` and its `vault.reset` event; `[approval] list_requires_approval` (D16); a
  custom `--format`; the `secure-enclave`, `libsecret` and `keyring` key protectors.
- macOS container runtimes' proxies in the default `opaque_peers` (§2.1).

**Not verified on real hardware or desktops**

- On a Mac: the interactive helper tests (a real Touch ID approve and deny, a screen lock;
  `FOCA_HELPER_INTERACTIVE=1`), whether the dialog says "foca" (§4.1.1), and NSWorkspace
  session notifications under a launchd agent. CI's macOS runner has no Touch ID, so its
  conformance run skips the prompt cases.
- Actions against the real `granted` and `gh`; the AWS targets are tested through config
  and the `aws-credential-process` validator.
- `darwinproc` reaches `getsockopt` and `proc_info` through `unix.Syscall6`, which goes
  through libc's deprecated `syscall()`. It works on current macOS; if Apple removes it,
  those two calls need another route.

---

## 18. Review decisions

Decided in the design review:

1. **Touch ID password fallback:** off by default. Authenticator option
   `allow_password_fallback = true` opts in.
2. **Import from the existing token tool:** not built. Tokens are re-added with
   `foca add`.
3. **Auto-spawn:** not built (D17). launchd or systemd runs one `serve` per instance. Scratch
   instances run `foca serve` in the foreground.
4. **Client process in the prompt:** shown, labelled by trust level (§4.1, §14).
   Guest-verified identity comes from the optional guest relay.
5. **Host-side use:** part of the command provider, not a new provider (§11.1).

6. **Narrowing reuse inside a VM:** there are three explicitly named scopes:
   - `peer-session`: the whole VM, verified by the host;
   - `guest-session`: the same VM session, verified by the relay;
   - `guest-program`: the same VM session and the same program, verified by the relay.

   Scopes are never built from client-reported data, and a scope is never silently widened.
   See the safeguards in §9.1 and §14.
