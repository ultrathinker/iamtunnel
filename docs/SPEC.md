# iamtunnel — design specification

Version 1.48. Status: **accepted by the owner**.

One program in Go. A single source tree builds `iamtunnel.exe` (Windows) and
`iamtunnel` (Linux/macOS). The same binary is **client**, **server**,
**admin** and **gateway**; the role is chosen by a tab in the window or a
subcommand on the console. Nothing is downloaded separately.

Two build variants of the same source (since 1.44, IAMT-439): full, with a
window, and headless — `-tags nogui`. The headless variant drops
`internal/ui` and every file that opens a window, so it carries no cgo at
all and builds on any host. It's what ships on the gateway: the gateway
never opens a window, while the full build on Linux needs eight graphics
libraries loaded before `main` even runs (the dynamic linker), and won't
start at all on a clean server. This is a build variant, not a second
source tree — there is no second half that gets touched less often and
rots; both are built and checked by the CI gates. `iamtunnel version`
always names which build it is, on its third line.

The predecessor project (C#/Avalonia-based) is untouched and unaffected.
iamtunnel is a clean break: its own gateway, its own registration, no
compatibility with the older system.

---

## 1. What the program does

Gives a person **temporary, recorded** SSH access to a Windows (and, since
1.1, Linux/macOS) server behind NAT.

- An admin adds people and their keys, registers machines, and issues
  grants: "person X → machine Y, until time T".
- On the machine, iamtunnel runs in the **server** role: it holds an
  outbound connection to the gateway and opens/closes the "door" — adding
  and removing the gateway's key in `administrators_authorized_keys`.
- A person runs the **client**, sees the machines they're allowed on, and
  connects: the client itself drives the SSH session (the built-in
  `x/crypto/ssh`), with no external `ssh.exe` needed or required to be
  installed.
- The **gateway** (a Linux VPS) is the bastion: an SSH server to the person,
  an SSH client to the machine. It's the only party that ever sees the
  session in plaintext, so it's the one that records it.

## 2. Principles

1. **Autonomy.** One static binary per platform, `CGO_ENABLED=0`, no
   installers, no downloads. `iamtunnel gateway install` on a bare Ubuntu
   host stands up a gateway.
2. **One program, four roles.** One `main`; roles are subcommands and tabs.
3. **Whoever terminates SSH on both ends records it** — the gateway. Neither
   the client nor the machine ever records. A person is **told explicitly**
   about recording on every connection.
4. **The door.** The invariant is stated measurably: *after the gateway
   loses an authorized transport, it cannot open a new connection to the
   machine; a forgotten key line on the machine is inert (layer 0 + layer 1)
   and removed at the first opportunity (layers 2–3).* The residual risk — a
   dead line in the file until the server's next start after a BSOD — is
   accepted and recorded in `THREATS.md`.
5. **No secrets on the client.** A person has their own key. A machine has
   its own registration key. The key the gateway uses to enter a machine
   lives only on the gateway, and only while the door is open.
6. **Every key attempt is tried.** `MaxAuthTries` is explicit (32), the
   callback is pure, identity comes from a successful handshake, and
   `person` in the username must match the key's owner.
7. **No TOFU anywhere.** The gateway's key fingerprint arrives inside the
   registration code and the connection string; machine keys are pinned at
   registration over an authenticated channel.
8. **Design is "Telescope"**, carried over from the predecessor: a serif
   headline as state, monospace captions, hairline rules, zero corner
   radius, one accent color per screen.

## 3. Roles

### 3.1 Client (the `Client` tab / `iamtunnel client …`)

- **First run**: the person pastes the **connection string** the admin gave
  them: `iamtunnel://<host>:<port>/<person>#<sha256 of the gateway host
  key>`. The client pins the gateway's key from the string itself — nothing
  to verify on screen. A changed gateway key is refused with
  `the gateway host-key fingerprint changed`, never a silent re-pin; a new
  string comes from the admin.
- **Several gateways on one machine** (since 1.39, IAMT-429): the client
  keeps a **list** of remembered gateways and the name of the current one.
  Adding a new (host, port, person) triple doesn't need `--replace` — a
  second gateway isn't a threat to the first. The `--replace` guard is
  reserved for what's actually dangerous: the same person on the same
  gateway presenting a **different** host key. Switching gateways asks
  nothing and dials nothing: the key is one per machine and doesn't depend
  on the gateway, and every gateway that already knows the person already
  holds its public half. Gateways don't know about each other — the list is
  a fact about this machine only. Switching wipes everything the previous
  gateway answered (machines, people, grants, sessions, history, held
  commands, the client's own identity, the safety mode and classifier key,
  the audit-journal state, the pairing-window PIN): a stale list under
  buttons that now act on a new gateway would be a real bug, not cosmetics.
- **The person's key**: generated by the client in
  `%LOCALAPPDATA%\iamtunnel\key` (ed25519, no passphrase, owner-only
  permissions), created on first connection. `ssh-agent` and
  `~/.ssh/id_ed25519` are **not** used as sources in this build: the real
  `~/.ssh` is never opened by the client. The person hands the public half
  to the admin (a Copy button).
- **The client directory isn't trusted territory when hit by a privileged
  command** (IAMT-332): client commands accept `--data-dir`, and the
  `client_dir` config key and `IAMTUNNEL_DATA_DIR` are honored — and an
  elevated Windows console running `admin …` often belongs to a different
  account than the one that owns `%LOCALAPPDATA%\iamtunnel`. So reading and
  writing client data files (`key`, `machines.mine`, `known_hosts`, the
  config) go through one contract, `internal/datafile`: a name held by a
  symlink, FIFO or other unusual object is never opened at all (a refusal,
  not a read/write through it); a regular file with **more than one name**
  (a hard link) is refused the same way, both for a new name and for
  reopening an existing one, with the link count read from an already-open
  handle (not a path) so a swap between check and open gains nothing; and a
  file replacement goes through a randomly-named temp file (`O_EXCL`) in the
  same directory rather than a predictable name. This contract defends
  against a directory owned by someone other than the running account, not
  against code already running as that same user — it reads
  `%LOCALAPPDATA%` like any other profile file. Gate 16
  (`scripts/check_rawfileio.go`) keeps this from rotting: a raw pathname I/O
  call bypassing `internal/datafile` fails CI, with an allowlist escape
  hatch that requires a stated reason.

  A layer above the file-name contract checks the directory itself
  (IAMT-333): every command that writes into a client directory checks its
  owner **before the first write**, and if the process is elevated while the
  directory belongs to a different account, it refuses (exit code 4), naming
  the owner and the one escape hatch, `--accept-foreign-data-dir`, for a
  directory the operator has personally verified. A missing directory isn't
  a refusal (first run is legitimate); the process's own account and system
  owners (root; Administrators/SYSTEM/TrustedInstaller on Windows) always
  pass; a non-elevated command skips the check entirely. One exception
  instead of a refusal (IAMT-504): on POSIX, a client or admin verb run via
  `sudo` by the directory's own owner (`SUDO_UID` matches, and the path has
  no foreign links) permanently drops root and runs as that owner, saying so
  on stderr — there's nothing for root to write there, since every write
  belongs to whoever ran sudo. The GUI doesn't do this (a long-lived process
  may later need real rights for the server role); Windows has no
  privilege-drop equivalent, so it keeps the refusal and
  `--accept-foreign-data-dir`.
- `machines.mine` → a list of machines, until when, whether online, whether
  sshd is listening.
- **Connect** speaks SSH itself, via `x/crypto/ssh`
  (`internal/client`); no external `ssh.exe` is ever launched: `pty-req`
  with the real window size, `shell`, I/O forwarding and `exit-status`,
  `window-change` on resize, keepalive every 20 s with 3 misses. The console
  switches to raw mode on Windows. The username is `<person>:<machine>`,
  the port comes from the connection string. An isolated `known_hosts`
  inside `%LOCALAPPDATA%\iamtunnel` is still kept, but only as a local
  record of a verified key, not as a trust source: trust is decided solely
  by the fingerprint pinned from the connection string, and a mismatch
  refuses before any channel opens. The system `~/.ssh/known_hosts` never
  participates.
- The person sees the grant's deadline the moment access is issued; there is
  no live countdown in the client. The gateway ends the session itself on
  expiry or revoke, by its own clock — the client's local clock plays no
  part.
- The client tunnels and forwards nothing. It's a directory and a button.

### 3.2 Server (the `Server` tab / `iamtunnel server …`)

- Holds the machine's registration key and id (created during Set up).
- **Before Start**: checks that `sshd` is running and listening on
  `127.0.0.1:22`. If not, a clear error — the door doesn't open.
- **Start**: `SweepStale` (under a file lock, remove every line with the
  `iamtunnel-door=` prefix, keeping every other line byte-for-byte),
  connect to the gateway with the machine's own key
  (`machine:<id>`), and accept one `iamtunnel-control` channel the gateway
  opens. Start does not call `door.open` and does not write a key to
  `administrators_authorized_keys`. After control is up, the gateway runs
  `door.status`; the machine isn't online until that check succeeds.
- Keepalive in both directions: `keepalive@iamtunnel`, empty payload,
  `want-reply=true`, 20-second interval, three misses. On tunnel loss, a
  live server removes its own line and reconnects with backoff and jitter,
  running `SweepStale` first. Only the gateway ever creates a new
  `door.open`, on a person's reservation via the control channel.
- **One tunnel per machine.** A second server instance on the same machine
  gets `E_MACHINE_ALREADY_ONLINE` from the gateway. A reconnect does NOT
  evict the old connection (PROTOCOL §5): it's accepted only after the old
  one has left the registry — after a silent network drop, that can take up
  to ~60 s (three missed keepalives), during which the machine's attempts
  show up in the journal as `machine.rejected`.
- The handler for a confirmed `door.open` starts the watchdog before
  writing the line, checks the ed25519 key and local ceilings, adds only its
  own door line under a lock, and does a read-back plus ACL set. A
  confirmed `door.close` removes exactly that line, then stops the watchdog
  by its saved handle/PID; a watchdog-stop failure is logged locally and
  doesn't block the close — the line is already gone, and the reply still
  says `removed: true`.
- **Stop** / closing the window / the connection dying: the server removes
  its own line and closes the tunnel. An ordinary stop uses the specific
  parent PID/handle, never an image-name match.
- Local `maxDoorIdle`/`maxDoorHard` cap what `door.open` may request;
  defaults are 15 minutes / 8 hours, and are themselves v1 protocol
  parameters. The server refuses an oversized request and also closes the
  door on its own monotonic limit; its own idle measure is "no tunnel
  bytes", while the gateway closes on exact I/O (§6.4).
- Administrator rights are required — a banner and a UAC relaunch on
  Windows.
- Linux machines are version 1.1, §3.2.1.

#### 3.2.1 Linux machine (1.1)

Everything in §3.2 about Start, keepalive, one tunnel, `door.*`, ceilings
and Stop applies unchanged. Only the platform layer differs:

- **The door file** is `osUser`'s own `authorized_keys` (home directory
  looked up via `getpwnam`, path `<home>/.ssh/authorized_keys`);
  `--key-file` still overrides it. `osUser` on Linux is a local name with no
  `DOMAIN\` prefix. The person logs in with `osUser`'s own rights, not root
  — iamtunnel never grants `sudo`.
- **Preflight check before Start**: sshd is active (`ssh.service`,
  `sshd.service` or `ssh.socket` — Ubuntu 22.10+ starts sshd via socket) and
  `127.0.0.1:22` accepts a connection; `sshd -T -C user=<osUser>` confirms
  `pubkeyauthentication yes` and that `authorizedkeysfile` includes
  `.ssh/authorized_keys` (otherwise refuse, hinting at `--key-file`). If
  not, a clear error — the door doesn't open.
- **Rights**: `enrol`, `server start|stop|status|install|uninstall` all
  require root (euid 0); without it, a refusal with `sudo iamtunnel server
  start` and no silent elevation. In the GUI: a banner and a `pkexec`
  relaunch.
- **Server directory** — personal since 1.4,
  `$XDG_DATA_HOME/iamtunnel/server` (§3.2.2); the machine-wide
  `/var/lib/iamtunnel-machine` (root-owned, `0700`; `machine.key` `0600`)
  is reserved for the impersonal system service — only `server install` and
  `server uninstall` name it. At `enrol`, `osUser` from the invitation must
  be a POSIX name (PROTOCOL §1) and exist locally, or the command refuses
  before writing the machine key. Every machine data-file write
  (`machine.key` on generation, `machine.id`, `enrolment.json`,
  `control.json`) goes through a random-name temp file (`O_EXCL`) in the
  same directory, not a predictable `<name>.tmp` — the same
  `internal/datafile.WriteFileAtomic` engine used everywhere, guarded from
  regression by gate 16.
- **Rules for writing into a directory owned by someone else** (the server
  is root, `~/.ssh` belongs to the person):
  - neither `~/.ssh` nor `authorized_keys` may be a symlink — refused; all
    operations run relative to a directory descriptor (`openat`/`renameat`,
    `O_NOFOLLOW`), so a path swap mid-write can't redirect root's write into
    a foreign file;
  - `~/.ssh` is created if missing: owner `osUser`, `0700`;
  - StrictModes requirements are checked before writing: the home directory,
    `~/.ssh` and the file must be owned by `osUser` or root and not
    group/world-writable. A violation refuses `door.open` with a clear
    message; iamtunnel never fixes home-directory permissions itself
    (otherwise sshd would silently ignore the key while the person only
    sees a login failure);
  - writes: a temp file in the same directory, owner `osUser`, `0600`,
    fsync, `renameat`, read-back; foreign lines preserved byte-for-byte;
    the lock is `flock` on a `door.lock` file in the server's own directory
    (a regular user can't hold it).
- **Watchdog**: a separate process in its own session (`setsid`), started
  before the line is written; it waits for the parent's death via
  `pidfd_open` + `poll`, or on kernels without pidfd, `PR_SET_PDEATHSIG`
  with an immediate `getppid()` check right after arming it. On the
  parent's death it removes the line under lock and journals the machine.
  After a confirmed `door.close`, the server stops the watchdog by its
  saved pidfd, not PID.
- **Autostart**: `server install` writes
  `/etc/systemd/system/iamtunnel-machine.service` (`User=root`,
  `Restart=on-failure`, `KillMode=mixed` — only the server gets SIGTERM and
  removes its own line, `SIGKILL` to the whole group only on a timeout),
  runs `daemon-reload`, `enable --now`; `server uninstall` reverses it.
  Manual `server start` still works.
- **macOS** uses the same Unix door layer; differences (Remote Login via
  launchd, the watchdog via kqueue `EVFILT_PROC`/`NOTE_EXIT`, a
  LaunchDaemon) are covered in §3.2.1's macOS notes and RUNBOOK §1.6.

#### 3.2.2 Several registrations on one machine (1.4)

This follows from §3.4: a registration is a (machine, name) pair, one per
person. A shared workstation two or three people RDP into under their own
domain accounts can run several iamtunnel "servers" side by side — each
their own.

- **The server directory is per-user.** `%LOCALAPPDATA%\iamtunnel\server`
  on Windows, `~/Library/Application Support/iamtunnel/server` on macOS,
  `$XDG_DATA_HOME/iamtunnel/server` on Linux. It holds `machine.key`,
  `machine.id`, `enrolment.json`, the local journal — everything that
  constitutes "my registration". The GATEWAY's own directory stays
  machine-wide: it's one service per host and impersonal. The exception is
  the impersonal system service on Unix (see the last bullet below): it has
  no person, so a personal directory makes no sense for it, and it keeps
  the old machine-wide `/var/lib/iamtunnel-machine` by name.
- **The door line records whose it is.** A second comment on the line
  carries `iamtunnel-owner=<registration name>`. Before 1.4, a machine
  carried exactly one registration, and `SweepStale` could safely claim any
  iamtunnel-tagged line as its own. On Windows, every administrator shares
  one file, `%ProgramData%\ssh\administrators_authorized_keys` — sshd only
  reads that one for all of them — so under the old rule, the second server
  to start would erase the first one's **live** line, dropping that
  person's session mid-work with nothing in any log explaining why: from
  the gateway's side, the machine simply stopped accepting its key. Now
  sweeping only touches lines belonging to its own owner, and `Remove`
  deletes a foreign line by exact id only for the one caller with no owner
  at all (the watchdog, which is impersonal by design); lines with no owner
  tag are treated as pre-1.4 legacy and swept, since such a line can only be
  left behind by a server that no longer exists.
- **Windows autostart is a personal logon task**, one per registration, in
  the Task Scheduler folder `\iamtunnel`. The trigger names the account
  whose logon starts it, the principal is the account it runs as — the same
  person. `InteractiveToken` + `HighestAvailable`: no password is stored
  anywhere; the task takes the session's own token. Every scheduler default
  that would be a defect here is overridden:
  `ExecutionTimeLimit=PT0S` (the default `P3D` would kill a healthy server
  on the third day), both battery settings `false` (otherwise the server
  dies when a laptop is unplugged), `StopOnIdleEnd=false`,
  `DisallowStartOnRemoteAppSession=false` (this product's sessions arrive
  over RDP), `MultipleInstancesPolicy=IgnoreNew`, restart 3×1 min.
  `server uninstall` removes the task but does NOT kill a running server —
  the scheduler has no graceful stop, and a killed server would leave the
  door hanging; the command names `server stop` instead. Windows has no
  machine service for the `server` role and never will: a service has no
  person, and every record it made would be signed by the service.
- **On Unix, autostart stays impersonal.** One system service (a systemd
  unit / LaunchDaemon) running as root, under the machine-wide directory.
  That's correct there: a Linux target is usually headless — no one logs
  into it — so a "logon" autostart would never fire, and the role wants
  root anyway (it writes to the bound account's own `~/.ssh`, and the
  preflight sshd check is system-level). **A named limit:** a Unix host
  with TWO registrations would need its own per-user autostart
  (`systemd --user`, a LaunchAgent) and an unprivileged `server start`;
  neither exists yet.
- **Registration anchor: an elevated start doesn't trust the profile record
  without a second copy** (R4, F-04; THREATS §3.16). A personal directory
  sits where an unprivileged process of the same account can rename the
  directory itself (on Windows, `FILE_DELETE_CHILD` on the parent lets a
  child be renamed regardless of its own locked-down DACL), while the logon
  task runs `server start` elevated and with no human present. So `enrol`
  writes a second copy of the registration's routing facts — host, port,
  fingerprint, machine id — from in-memory values, to
  `%ProgramData%\iamtunnel\anchors\<SID>\enrolment.anchor.json`, a tree
  locked the same way as the machine's data directory; ordinary accounts
  can't rename a child of `%ProgramData%`. An elevated `server start`
  checks the profile record against the anchor before doing anything, and
  proceeds on the checked record; a mismatch or a missing anchor refuses,
  naming the diverging fields and paths. For registrations made before the
  anchor existed, `server install` places it — the one moment the current
  record is trusted (the operator is present and elevated); an existing
  anchor at `install` is only checked, and a mismatch refuses. On Unix, the
  anchor's role is played by ownership of the whole chain: for root (euid
  0), `hardenServerDir` requires every directory from the data directory's
  parent up to `/` to be root-owned and not group/world-writable — ordinary
  `sudo` and the service directory `/var/lib/iamtunnel-machine` pass;
  elevation that preserves the invoking user's `$HOME` (`sudo -E`) refuses
  with a hint; a non-root process isn't bound by this chain at all — there
  is no privilege crossing there.
- **There is no upgrade path from before 1.4.** The old registration lived
  in a machine-wide directory (`%ProgramData%\iamtunnel` on Windows,
  `/var/lib/iamtunnel-machine` on Unix), and 1.4 doesn't look there or
  migrate anything: on an upgraded machine, the person registers again.
  This is deliberate — registration's meaning changed (one per machine,
  now one per (machine, person) pair), and auto-migrating would have to
  guess which of several future registrations the one old one belongs to.
  The old directory is left untouched; no command removes it.
- **There's no isolation between registrations, and none is promised.**
  Windows administrators aren't isolated from each other by the OS's own
  design: any of them can read and rewrite the others' files, including the
  shared key file. No key layout changes that. What 1.4 gives is
  **attribution**: every door line, every journal event, and every gateway
  record names whose registration made it.

### 3.3 Admin (the `Admin` tab / `iamtunnel admin …`)

Every operation is a command to the gateway over SSH (§5.3); the tab and
the console do the same thing.

- people: add / **rename** (grants and goals move to the new name in one
  write, old-name sessions close as on revoke; the key follows the person)
  / remove / keys add|remove / list / **connection-string** (prints the
  §3.1 string for a given person);
- machines: **enrol-code** (prints the §3.4 registration code) / list
  (online, verified, `osUserStatus`, confirmed OS user, door state,
  reservations, tunnelEpoch, whether sshd is listening) / **rename** (label
  only: `id`, grants and journal keep pointing at the same machine) /
  remove / **rekey** (§6.2) / **set-user** / **verify**; `set-user` closes
  the door, resets confirmation, and runs the §3.4 probe again.
- grants: `grant X → Y until T` / **extend** (extending never touches an
  open session; shortening acts as revoke) / revoke (**kills active
  sessions**) / list;
- sessions: active / history (from the event journal) / kill;
- recordings: list / fetch `<id>` (`.cast` and `.txt`);
- gateway: status / fingerprint / **rotate-hostkey** (§6.2) / backup;
- pairing (1.2): pairing start / stop — open or close the pairing window
  for a new admin (below).

**The first admin**: `gateway install` prints a one-time bootstrap token;
the owner, from any machine, runs
`iamtunnel admin claim <host:port#fingerprint:token> --key <pub>` — their
key becomes the first admin's key. The token lives 24 hours, one attempt,
and is journaled.

Since 1.3, `install` prints this token already as one paste-in string
(§3.6), and `gateway status` reprints it while it's still valid and
unspent: a freshly installed gateway shows on screen exactly what needs
pasting into the window on the admin's own machine, and `gateway pair` is
never needed for the FIRST admin at all — the earlier flow could let the
token silently expire in a day with no way to see it again, forcing a
recovery path meant for a different emergency.

**Pairing a new admin (1.2, IAMT-323).** The second and later admins are
appointed with no terminal. A current admin (or the gateway itself,
locally) opens a short **pairing window**: the gateway generates a 6-digit
numeric PIN (leading zeros allowed), the window lives 2 minutes by the
gateway's clock, and at most one window exists at a time (a new start
replaces the active one). On any machine, a person enters the reference
`host:port#<fingerprint>` and PIN in the Admin tab's form; their own client
key becomes the key of a permanent admin — a full `person{role: admin}`
account, not a session. Before 1.3 the gateway named the person from their
key's fingerprint, giving unreadable names; since 1.3 the client supplies
the name in one field, prefilled with the system username. An empty or
taken name becomes `admin`, or `admin2`, `admin3`, and so on. People and
machines can be renamed (`people rename`, `machines rename`), so a bad name
isn't permanent.

Since 1.3 the link and PIN travel as **one string** (§3.6), not two
separate values. Three wrong PINs from one address ban that address for 3
minutes (the same rate-limit mechanism as §6.1, its own counter, counted
strictly by address — a reconnect with a new port doesn't reset it; changing
keys doesn't help; a successful pairing doesn't lift an already-active ban).
Misses are only counted while a window is open; with no window, a
pairing-login attempt looks exactly like an unknown key. The window opens
via `iamtunnel admin pairing start` over the network (prints the PIN,
deadline, and a ready link to hand to the new admin) or `iamtunnel gateway
pair` locally on the gateway; `pairing stop` closes it early (idempotent).
Wire format and refusal codes: PROTOCOL §3.4, §6.

### 3.4 Set up (the tab on an unregistered machine / `iamtunnel enrol <code>`)

The registration code (machine invitation):
`iamtunnel-enrol://<host>:<port>#<sha256 host key>:<secret>`, one-time use.

**Since 1.3 the invitation isn't tied to an OS user, and its TTL is 15
minutes** (was: tied, TTL 24h). The reason: the admin can't know the OS
user or hostname of a machine they haven't touched — that's a fact of the
machine, not of them; the machine reports it itself at step 2. Fifteen
minutes is enough to carry the string to the next machine over, and not
enough for it to sit in a message until evening.

**Since 1.4 the invitation carries exactly one thing — a NAME, chosen by the
admin.** This isn't a return to before-1.3: 1.3 removed two facts only the
machine can know (its hostname, and the `DOMAIN\user` its server runs as).
A name isn't such a fact — it's the admin's own choice: the label they'll
see in the machine list, grant access against, and revoke by. No one else
can make that choice. In short: **the person names, the machine reports,
the gateway verifies** — no one is asked for something they can't know.

**Since 1.4, a registration is a (machine, name) pair, and one physical
machine can carry several — one per person working on it.** This is the
shared workstation two or three engineers RDP into under their own domain
accounts. Each gets their own invitation, their own name, their own data
directory inside their own profile, their own door line, and their own
journal trail. This gives no isolation between them and doesn't promise
any — Windows administrators aren't isolated from each other by the OS's
own design — but it gives **attribution**: every record names whose
registration made it. The name is checked for collision both against
existing machines and against still-live invitations, inside the same
atomic write that creates it.

Registration state machine (each transition is a journal event, each has a
timeout):

1. the machine extracts the gateway's fingerprint from the code and
   connects, **checking the host key automatically**; a mismatch stops
   there, and the code isn't spent;
2. it generates a machine key and sends `enrol` with the secret **and its
   own current OS user** (since 1.3; before that, the OS user came from the
   admin's binding at code issue) → the gateway creates
   `machine{state: enrolled, osUserStatus: pending}` **under the
   invitation's name** (since 1.4; in 1.3 the machine still sent the name
   itself), with `requestedOsUser` from the machine's request, and stores
   its public key; **the secret burns in the same atomic write**.
   `requestedOsUser` is never used for login or admission. The machine may
   still send its hostname, but it's optional and used only to cross-check
   the invitation's name, never to decide anything;

   *Why the machine can be trusted on its word.* It can't claim any name
   for free: the invitation is one-time, lives 15 minutes, and was issued a
   minute ago, so the machine that spent it is the one invited; since 1.4
   the machine doesn't even choose the name — the admin wrote it into the
   invitation — and the claimed OS user stays `requestedOsUser` until the
   gateway confirms it with a **real login** at step 3. A false claim earns
   zero rights. There's deliberately no separate "Accept" step: it would
   check nothing beyond what's already checked, at the cost of one more
   action;
3. the machine raises the tunnel (§5.2), accepts control, and passes the
   initial `door.status`. The gateway captures and pins the sshd host key
   through the target with no user auth, then briefly opens the door and
   runs SSH public-key user-auth as `requestedOsUser` with no shell/exec.
   Only success records `verifiedOsUser: requestedOsUser`, `osUserStatus:
   verified` and `state: verified`; a failure leaves it `enrolled` with
   `osUserStatus: rejected`, closes the temporary door, and admits no
   person;
4. the probe fails (sshd not running) — registration stays `enrolled`, the
   machine shows in lists with that note; retrying the probe is
   `admin machines verify <id>`, or happens automatically on the next
   connection attempt.

A drop at any step leaves only an explicit, repeatable status. The Set up
tab shows the result, including a failed one, until the program restarts.

**Finishing registration means a running autostart, not a process in the
window.** The intended flow ends step 3 with one `Install as a service and
start` button that runs `server install` and `server start` together and
requests elevation itself if needed, without asking the person to relaunch
the program. What actually exists: the GUI has no such button or install
action at all — after registration, the person goes to the Server tab and
presses START, which is still a process that dies at the next reboot.
Autostart is only set from the console (`server install`).

Since 1.4, what gets installed differs by OS, following from the same
(machine, name) decision — details in §3.2.1. In short: on Windows it's a
**personal logon task**, one per registration; on Unix, still one impersonal
system service. So the order on Windows is strict: **`enrol` first, then
`server install`** — the personal autostart is named after the registration
and tied to the account it carries, and neither exists before registration.
On Unix, either order works.

### 3.5 Gateway (`iamtunnel gateway install|uninstall|run|status|backup`), Linux; since 1.1 — Windows and macOS (§3.5.1)

- An SSH server on one port for everyone: people, machines, admins. Default
  port **2222**, configurable via `--port` and in the config file.
- Runs as the `iamtunnel` user, not root; the systemd unit is hardened:
  `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`,
  `NoNewPrivileges=yes`, `ReadWritePaths=/var/lib/iamtunnel`,
  `AmbientCapabilities=` empty (the port is ≥ 1024).
- The `/var/lib/iamtunnel/` directory (`0700`):
  - `state.json` (`0600`) — **only the current facts**: schema, people,
    keys, machines (plus pinned host key, OS user, state), grants, active
    doors and sessions. Written as tmp → fsync → rename → fsync(dir), one
    mutex per process, a lock file against a second `gateway run`. The
    temp file uses a random name (`O_EXCL`), not a predictable path.
  - `events.jsonl` — an **append-only** journal: admin operations, auth
    (success/failure, address, fingerprint), enrol transitions, door
    open/close, session start/stop/drop, host-key mismatches, recording
    deletions, rotation. Rotated by rename, on size (1.14, IAMT-452:
    `64 MiB`, archived as `events-<UTC>.jsonl` next to it, PROTOCOL §1.7).
    Repeated logins by the same key from the same host within `10 minutes`
    fold into one `auth.success` line plus a count; failures fold the same
    way by (host, cause class). Every gateway journal line since 1.14
    carries `prev_hash` — the SHA-256 of the line before it (IAMT-467): a
    changed, removed or inserted line breaks the next line's chain link,
    across rotations too; checked by `gateway verify-journal` and the
    Gateway tab. The chain has no anchor outside the files — it catches
    tampering and hand-editing, but not someone who can rewrite the whole
    file and recompute every hash; that verification says "intact" either
    way, and the check's own output says so.

    This is also the source for the admin's "session history".
    **A journal that isn't being written doesn't stay silent** (1.14,
    IAMT-451). The first failed write (disk full, the file gone read-only,
    fsync failed, a record rejected on validation) puts the gateway's audit
    into a "not writing" state until the first successful write. Until
    then, anything that would leave a trail refuses with
    `E_AUDIT_UNAVAILABLE` — state-changing commands, new sessions, enrol,
    pairing, bootstrap claim; read-only commands (`gateway.status` above
    all) keep working — that's how the operator learns something broke. A
    command whose own record was lost mid-flight still did what it did —
    that can't be undone — and honestly answers `E_AUDIT_UNAVAILABLE`
    "done, but not recorded" instead of "ok". Sessions already in progress
    aren't torn down: their own recording rules apply (§6.5), and a journal
    failure shouldn't become a lever that kills every session on the
    gateway. Visible in three places, none of which depends on the
    journal: the `audit` object in `gateway.status`, an `audit-health.json`
    file in the data directory, and a line in the service journal (stderr)
    on every change.
  - `hostkey` (`0600`), `recordings/` (§6.5).
- `install`: idempotent; user, directories, host key, unit, enable, start,
  print the bootstrap token. A repeated `install` never touches
  `state.json` or `hostkey`.
- `backup`: an atomic snapshot of `state.json` + `events.jsonl` into a
  tarball. Copying the directory on a live process is not a backup.
- `status`: alive or not, version, fingerprint, machines online/verified,
  sessions, disk space.
- Above a threshold, disk space under recordings → **new sessions are
  refused** with a clear message and an event; writing without recording is
  never allowed (principle 3).
- Update: `gateway run` does a graceful drain on SIGTERM — no new
  connections, existing ones get up to their timeout to finish. Since 1.14
  (IAMT-466): the listening port closes right away (a session that just
  landed on an already-accepted connection gets "the gateway is restarting"
  and a `session.drop`); every live session gets a stderr warning that it
  will be closed within 15 seconds — chosen to be shorter than what
  launchd, systemd, and the Windows SCM give a stopping service before they
  force it. `gateway.status` during drain reports `draining:true`, plus
  `version` and `diskPercent`. Shutdown only returns once the very last
  journal line is written.
- `uninstall` (since 1.1, all OSes): stop and remove the service/unit; the
  data directory, `state.json`, the journal, recordings and host key are
  untouched. Install never touches the firewall on any OS — it prints the
  command to open the port.
- `reset` (IAMT-388, all OSes): one command instead of five manual steps —
  stop the service, wipe `state.json`, the bootstrap token, `events.jsonl`,
  `enrol-hmac.key` and `recordings/`, stand up a fresh gateway, and print
  its new bootstrap string (§3.6). The host key is kept — already-handed-out
  connection strings keep matching by fingerprint; `--new-hostkey` replaces
  it too. Without `--yes`, the command names the counted losses (people,
  machines, grants, journal, recordings) and requires `--yes` or a typed
  "yes"; a refusal wipes nothing. Order is a contract: stop the service
  (reversible, frees the state lock) → count losses → confirm → refuse on a
  live console `gateway run` → wipe the exactly-named files → write the new
  journal (the first line is `admin.op` with `result:"reset"`) → a repeated
  `install` with the new claim string.
- `pair` (1.2): open the pairing window locally, print the
  `host:port#<fingerprint>` link and PIN, journal the event. Requires a
  **stopped** `gateway run` — the state file is opened exclusively; a live
  gateway refuses with a hint to stop it first (a live gateway has the
  network-facing `admin pairing start` instead). This is the emergency
  recovery path when every admin key is lost: `systemctl stop
  iamtunnel-gateway` → `gateway pair` → pair in the window → start.

#### 3.5.1 Gateway on Windows and macOS (1.1, IAMT-272)

The gateway's core (protocol, `state.json`, journal, recordings,
backup/restore/rotate-hostkey/status) is one implementation across every
OS. Directories, the service, and rights differ. SIGTERM on Unix and the
Windows service's Stop/Shutdown both lead into the same graceful drain.

- **Windows.** Directory `%ProgramData%\iamtunnel\gateway`, config
  `%ProgramData%\iamtunnel\gateway.json`. `install`/`uninstall` need
  administrator rights. The SCM service `iamtunnel-gateway`: delayed
  autostart, running as the virtual account `NT SERVICE\iamtunnel-gateway`,
  not LocalSystem; recovery restarts three times, 10 seconds apart. The
  service command line is
  `"<exe>" gateway run --data-dir "<dir>" --port <N> --public-host <host>`,
  every argument escaped by Windows' own rules. Directory ACL: inheritance
  off; full access for SYSTEM, Administrators and
  `NT SERVICE\iamtunnel-gateway`; nothing for anyone else. Port hint:
  `New-NetFirewallRule -DisplayName "iamtunnel gateway" -Direction Inbound -Protocol TCP -LocalPort <N> -Action Allow`.
- **macOS.** Directory `/Library/Application Support/iamtunnel/gateway`
  (`0700`), config `/Library/Application Support/iamtunnel/gateway.json`.
  `install`/`uninstall` run as root. A service user `_iamtunnel`: hidden,
  a free system UID below 500, shell `/usr/bin/false`, created via `dscl`.
  The LaunchDaemon `/Library/LaunchDaemons/com.iamtunnel.gateway.plist`
  (owner root:wheel, `0644`): `RunAtLoad`, `KeepAlive`,
  `UserName _iamtunnel`, `ProgramArguments` with
  `gateway run --data-dir … --port … --public-host …`, output to
  `/Library/Logs/iamtunnel/gateway.log`; plist values are XML-escaped.
  Start: `launchctl bootstrap system <plist>`; stop:
  `launchctl bootout system/com.iamtunnel.gateway`. Port hint: about
  Application Firewall; `pf` is never touched.
- **Linux** — as above (systemd); `uninstall` adds:
  `systemctl disable --now`, remove the unit, `daemon-reload`.
- Any OS action (SCM, ACL, dscl, launchctl, systemctl, useradd) goes
  through a seam; production calls panic in the test binary.

### 3.6 One string, one field (1.3)

Everything carried from machine to machine is one string, and everywhere
it's pasted is one field. This is the owner's own decision, made after
walking the whole flow by hand.

**Formats.** The scheme itself says what it is, so the receiving side
understands what was pasted without a human hint:

| String | What it does |
|---|---|
| `iamtunnel-claim://<host>:<port>#<fp>:<token>` | this key becomes the key of the FIRST admin |
| `iamtunnel-pair://<host>:<port>#<fp>:<pin>` | this key becomes the key of another admin |
| `iamtunnel-enrol://<host>:<port>#<fp>:<secret>` | this machine registers with the gateway |
| `iamtunnel://<host>:<port>/<person>#<sha256 host key>` | a person's connection string (unchanged since 1.0, §3.1) |

**The field accepts what a human was handed in another shape.** The parser
strips the wrapper and takes the substance from what was pasted: the whole
ready-made command line `iamtunnel admin pair <ref> <pin>` (exactly what the
gateway prints), a "link space PIN" pair, a bare `host:port#fp` with a value
after it, leading and trailing whitespace and newlines. The reason: the
gateway prints a ready command, a person naturally copies the whole thing,
and before 1.3 the field expected only the bare argument and refused —
while the pairing window lives two minutes, and untangling the input ate
the whole window.

**A preview is mandatory.** The field does nothing on paste alone. Under it
appears "what will happen now" — the action, the gateway's address, and its
fingerprint in words — and only the button acts. This is both protection
against pasting into the wrong window and the only place a person sees the
fingerprint before trusting the gateway (§6.2 — TOFU is absent from every
role; the preview is the moment the fingerprint is checked with human eyes).

**Why the PIN is back in the string, though §6.2 once split them on
purpose.** Before 1.3, the fingerprint and PIN traveled separately,
assuming an attacker who reads one transfer channel but not the other. Real
use showed the second channel never appears — both the link and the PIN
went through one conversation, one screenshot. The rule protected nothing
while doubling the actions on every connection. The owner decided: one
string, everywhere.

In its place — compensations that actually do work:

- lifetimes: 2 minutes for a pairing PIN, **15 minutes** for a machine
  invitation (was 24 hours — the scheme's real weakness), 24 hours for the
  first-admin bootstrap token;
- one-time use: the secret burns in the same atomic state write as the
  result;
- three wrong PINs — a 3-minute address ban (§3.3);
- a preview with the fingerprint before the button, as above;
- anything that just joined is flagged "new" in lists and removable with one
  button.

**Accepted residual risk, stated plainly:** whoever reads the clipboard or
transfer channel during the two-minute window can become a gateway
administrator. This is the price of one field instead of two, accepted by
the owner deliberately. Manual separation stays possible — the gateway
still prints the link and PIN so they can be split — the interface simply
no longer forces it.

## 4. Architecture

```
 person ──ssh──▶ ┌──────────── gateway ─────────┐ ◀──SSH (machine:<id>)── machine
 (iamtunnel,     │ SSH server (x/crypto/ssh)     │        iamtunnel server:
  pinned host    │  auth: pure callback,         │        keepalive 20 s,
  key, isolated  │        MaxAuthTries=32        │        HandleChannelOpen
  known_hosts)   │  ACL: X→Y until T, revoke     │          "iamtunnel-target"
                 │  machine registry: id→ServerConn│        → dial 127.0.0.1:22
                 │  channel iamtunnel-target ────┼──────▶  authorized_keys + watchdog
                 │  SSH client to the machine,   │
                 │    door key, pinned host key  │   iamtunnel admin ──ssh──▶
                 │  recording: .cast + .txt      │   (exec channel, JSON)
                 │  state.json, events.jsonl     │
                 └───────────────────────────────┘
```

### 4.1 Language and dependencies

- Go 1.27, module `iamtunnel`. `CGO_ENABLED=0` everywhere, checked in CI.
- `golang.org/x/crypto/ssh` — vanilla, unforked. Unexported payload structs
  (`ptyRequestMsg`, `windowChangeMsg`, etc.) are redeclared locally.
- `gioui.org` — the GUI, pure Go. `golang.org/x/sys/windows` for Win32.
- **Not used**: gliderlabs/ssh, gorm/sqlite, docker, fsnotify.

### 4.2 Repository layout

```
cmd/iamtunnel/main.go         subcommands; no args on Windows opens the window
internal/gateway/             SSH server, auth, machine registry, proxying
internal/gateway/acl/         grants, deadlines, revoke
internal/gateway/state/       state.json: model, validation, atomic write, migrations
internal/gateway/events/      events.jsonl
internal/gateway/record/      asciicast v2 writer, VT parser → transcript
internal/proto/               JSON exec protocol + version + capabilities
internal/sshx/                shared: payload structs, keepalive, Channel→net.Conn
internal/server/              server role: tunnel, door, timers, watchdog
internal/winkeys/             administrators_authorized_keys + ACL
internal/elevate/             UAC
internal/client/  internal/admin/  internal/config/
internal/ui/design/           Telescope: scale, palette, Poster, Facts, Rule, Tabs, Pulse
internal/ui/                  screens, shot, selftest
test/e2e/                     gateway + a fake machine (its own sshd on x/crypto) + client
docs/                         SPEC, PROTOCOL, THREATS, RUNBOOK, USER
```

### 4.3 Data model (state.json)

- `person{name, role: user|admin, keys[]{fingerprint, pub, added}}`
- `machine{id, name, state: enrolled|verified, machineKey, sshdHostKey?,
  observedSSHDHostKey?, hostKeyStatus: unverified|match|mismatch,
  requestedOsUser, verifiedOsUser?, osUserStatus: pending|verified|rejected,
  door?{id, pubkey, opened, sessions?, closesWhenIdle?, closesAtTheLatest?}}`.
  `closesWhenIdle` is the RFC 3339 idle-close deadline, `closesAtTheLatest`
  the hard deadline; each is optional (absent ≠ zero time), and when
  present must be no earlier than `opened`, with `closesWhenIdle` no later
  than `closesAtTheLatest`. `reservations`, door state and `tunnelEpoch`
  are transient gateway-process state and are never serialized to
  `state.json`. `requestedOsUser` is the unverified value from Set up or
  `machines set-user`; the gateway only ever logs in as `verifiedOsUser`.
  A Windows principal looks like `DOMAIN\name` or `MACHINE\name`; since 1.1
  a Linux/macOS machine uses a local POSIX name
  `^[a-z_][a-z0-9_-]{0,31}$` (PROTOCOL §1). The gateway accepts either
  form; a machine refuses the other OS's form. A successful SSH public-key
  probe proves OpenSSH accepted the key for that account at the moment of
  checking. `hostKeyStatus:mismatch` forbids the door; `admin machines
  list` shows door state, reservations and tunnelEpoch. Five machine
  fields — `observedSSHDHostKey`, `hostKeyStatus`, `requestedOsUser`,
  `verifiedOsUser`, `osUserStatus` — are **stored** since IAMT-91 step 1.
  This is memory of what the gateway learned about the machine, not
  policy: the comparison happens in a live handshake, and these fields
  just let its outcome survive a restart. `hostKeyStatus` and
  `osUserStatus` are closed sets; a missing field means "never checked"
  and is read as `unverified`/`pending` — never as an empty string, which
  belongs to neither set and would silently stop guarding a `mismatch`.
  Defaults are applied at both disk boundaries — parsing and before
  writing — and only where a value is actually missing, so a recorded
  `mismatch` is never overwritten by loading the file. ⚠ Open item:
  `schema` is still 1, and rolling the gateway back to a build older than
  this field silently erases `mismatch` (and `goals`, `pairingPending` and
  other fields added after 1.0) — bumping `schema` on the first field whose
  loss is dangerous, or recording a schema witness in the journal, is a
  decision not yet made (R4 F-07).
- `grant{person, machine, machineKeyFingerprint, until?, caps:
  ["shell"|"exec"]}` — `caps` is interpreted starting in 1.0. `["shell"]`
  keeps the original permission for both an interactive shell and a single
  exec; `["exec"]` allows only a single exec and forbids `pty-req` and
  `shell`. A grant issued with no explicit capability (`--cap` not given)
  gets `["exec"]`: exec is the one kind of access the gateway sees whole
  before it reaches the machine, and so the only one any safety mode can
  act on — it's the default, not `shell`. `["shell"]` remains for backward
  compatibility with already-issued grants.
  `machineKeyFingerprint` is a **required** field: the OpenSSH fingerprint
  of the `machine.machineKey` the grant was issued against. A grant is tied
  to the machine's identity, not its name — a name is a label and can be
  reused. If the machine's key no longer matches this fingerprint, access
  doesn't "wake up silently" — the grant is explicitly revoked, with a
  journal entry. `until` is optional; its absence differs from a zero time.
- root-level `pendingEnrolments[]{name, secretHash, publicKey, expires}`
  (since 1.4, `name` — the name the admin chose) and root-level
  `bootstrapPending?{secretHash, publicKey, expires}` — one-time secrets for
  machine registration (PROTOCOL §3.2) and the first-admin claim (§3.3). A
  name is checked for collision with existing machines and with still-live
  invitations **inside the same transaction** it's created in, and again on
  redemption. `secretHash` is HMAC-SHA-256 under the gateway's own key, not
  the secret itself or a bare hash: reading `state.json` alone can't be used
  to redeem the code. After a successful use, the field is erased in the
  same atomic write — that's what makes the code one-time.
- root-level `pairingPending?{secretHash, expires}` (1.2) — the active
  pairing window for a new admin (PROTOCOL §3.4). Unlike its two neighbors
  it holds no public key: the client arrives with its own permanent key,
  not a derived one. The PIN is 6 digits, `secretHash` the same
  HMAC-SHA-256 scheme; `expires` is 2 minutes from start by the gateway's
  clock, checked at exec time. It's erased by the same atomic write that
  creates the `person{role: admin}`.
- `schema: 1`. A gateway of an older build won't open a state file of a
  newer schema — but that guard only fires on a NUMBER change, not on a
  field being added, and an old build will happily open a newer file and
  silently drop unknown fields on its first rewrite (see the ⚠ note above).
- All times are ISO-8601 with a zone; a missing field ≠ zero; deadline
  pairs are checked for consistency. Names: `[a-z0-9][a-z0-9._-]{0,31}`.

## 5. Protocols

### 5.1 Person → gateway

Username is `<person>:<machine>`; for admin/client commands, just `<person>`.
The full grammar lives in `PROTOCOL.md`, parser under unit tests; colons,
control characters and ambiguous Unicode are all refused.

Auth is public-key only (§6.1). After the handshake: the key's owner must
equal `person`, or refuse; a `person → machine` grant must exist and not
have expired; the machine must be `verified`, online, hold a control
channel of the current epoch, and carry no host-key mismatch. A closed door
creates a reservation; the gateway opens it only on a confirmed
`door.open`. A refusal, timeout, or lost control never opens the target and
gives a single line to the channel, an event, and closes.

For exec without a PTY, the gateway has the full command string before
forwarding and runs it through a text risk classifier. This is a safety net
against an accidental mistake in unwatched automation, **not** a defense
against deliberate misuse — a command is easy to route around with
encoding, a script, or another form of input. An interactive shell is never
classified — it's a byte stream with no honest command boundary. The
owner sets one `risk_action`: `log` only journals both levels, `warn`
(default) also warns for both, `ask` warns yellow and requires human
approval before red, `block` warns yellow and stops red. So an update never
halts running automation on its own, and there is no stopping mode for
yellow. Every non-green exec creates a `session.risk` with the session id, a
scrubbed command, the rule, the reason and the action taken. The warning
sent before the command reaches the machine carries a stable ASCII prefix;
under block this is `The command was stopped and was not executed. Reason:
<reason>. An administrator can change this outcome with "iamtunnel admin
risk mode" or Admin → Live in the window. [iamtunnel] risk=red
rule=<rule> action=block E_COMMAND_BLOCKED`. Color and CR are only added
with a PTY; in exec without one, the line is plain text ending in LF. Block
returns exit-status 126 and never sends the exec at all.

An admin can flip this live with `iamtunnel admin risk mode
[log|warn|ask|block]`; an empty argument only reads the mode. The new
setting applies from the next classification and doesn't end sessions
already running. `source` in the `risk.mode` reply and in `gateway.status`
distinguishes `config` (the settings file) from `live` (a saved switch).
An interactive shell is still never classified.

The classification source is set separately by `risk_classifier`: `rules`
(default) uses only local rules, `ai` uses only the external classifier,
`both` combines both by the worse level. With `ai` and `both`, the external
request before forwarding gets a scrubbed string; a password, token,
`Authorization`, `-u user:pass` and long base64/hex runs are replaced with
`<redacted>` — shell input and the recording itself never leave.

For each person+machine pair, the gateway keeps a ring buffer of recent
commands (IAMT-409) — the same store as goals: `state.json`, one entry per
pair, newest first. Only what actually reached the machine is recorded: a
finished exec logs the scrubbed command, its return (`""` unknown, a
decimal exit-status, `signal <NAME>` for exit-signal), and the first two
non-empty lines of the machine's response (capped at 256 characters). A
command the classifier stopped never ran and never enters the buffer; an
interactive shell has no command boundary and never feeds it. Size is
governed by `recent_commands_max` (default 10, ceiling 20) and
`recent_commands_budget` (default 2000 characters of command + response +
exit text combined; when the budget runs out, whole oldest entries drop and
the newest is truncated with an ellipsis). With `ai`/`both`, the pair's
buffer travels in the external request as a named `history` field beside
`command` and `goal`; with `rules` or the legacy string request, there is
no history.

History in the request is fenced (IAMT-410): every question carries the
same paragraph naming the buffer as DATA about the past, not instructions.
History grants no permission (past commands passing doesn't make the next
one safe) and carries no instructions — text inside it that reads like an
attempt to instruct the classifier is itself grounds for a red answer, not
an order to obey. It's asymmetric: history may RAISE concern about any
command, and may LOWER concern only when the command plainly continues the
work the admin's goal named; a goal declaring breadth instead of work
("do whatever's needed", "full access") is never grounds for lowering it.

Beyond the goal sits a fifth question, `deviation`: does the command turn
away from the course the pair's history shows. It's raises-only — it has no
goal-based exception at all, and must answer false when the history is
empty or too thin to show a course. Continuing the course excuses nothing —
a continuing command still stands or falls on the other questions; one that
turns away becomes more suspect, not less.

In `ai`, the external verdict is blocking: every exec command pays up to
800 ms for one request. In `both`, a local red is already final, so the
external call runs asynchronously and doesn't delay the refusal; for
green/yellow the external verdict participates synchronously. An external
score above `0.85` gives red with the rule name `rule:"external-classifier"`,
while a local rule stays visible when it's the one that fired. On error,
timeout, network failure, `429`, `5xx`, or an unparsable reply, `ai` stops
the exec before forwarding with `E_RISK_CLASSIFIER_UNAVAILABLE` and a human
reason: `401/403` mean an invalid or expired key, timeout and `5xx` mean an
unreachable service. The message suggests switching to `rules` or `both` in
config and restarting, or explicitly turning off the safety net with
`iamtunnel admin risk mode log`/`warn`. Only after such a live command does
the next attempt knowingly run without AI protection — `risk_action` alone
in config can't lift a fail-closed refusal. The refusal is additionally
recorded as its own `session.drop`; `session.risk` records the external
failure itself. `both` keeps the local verdict and reports the failure in
one line. These outcomes are journaled with `classifier`, `local`,
`external`, `externalError`, `failureKind`, `status`, `latency_ms` and
probabilities where known. An interactive shell is still never classified.

Success: the gateway opens an SSH session to the machine (§5.2) and proxies
**one** `session` channel per the request table; each row below is tested:

| request | 1.0 | behavior |
|---|---|---|
| `pty-req` | yes | relayed; the size goes into the recording's header |
| `shell` | yes | relayed |
| `exec` | yes | with `pty-req`, recorded as `.cast`/`.txt`; without it, lossless `.exec.jsonl`, where command and every machine→human byte are fsynced before forwarding |
| `window-change` | yes | relayed + an `r` event in the recording |
| `env` | only `TERM`, `LANG` | everything else is dropped; a `want-reply=true` gets `channel failure`, `false` gets no reply (RFC 4254 §6.5) |
| `signal` | yes | a channel request, `want-reply=false`, relayed |
| `SSH_MSG_CHANNEL_EOF`, `SSH_MSG_CHANNEL_CLOSE` | yes | separate RFC 4254 §5.3 packets, not requests; relayed both ways |
| `exit-status`, `exit-signal` | yes | relayed back to the person |
| `subsystem` (sftp) | **no** | refused, an event |
| `direct-tcpip`, `tcpip-forward`, agent, x11 | **no** | refused, an event |
| `eow@openssh.com`, `no-more-sessions@openssh.com` | yes | `want-reply=false`; a valid OpenSSH notice, not relayed, no event |
| global `keepalive@openssh.com` | yes | `want-reply=true`, success with empty payload |
| `hostkeys-00@openssh.com` | gateway never sends it | server→client, `want-reply=false`; an incoming one from the client is refused, the pin doesn't change |

The first thing a person sees in a session is the line **"This session is
recorded. Machine X, until T."**

Before 1.8 this line said nothing about live viewing — a decision made
18.09.2026 (IAMT-343): the reasoning at the time was that the machine
belongs to its owner and the specialist is a guest with temporary access,
and the banner already said the main thing. Review before 1.8 (20.09.2026)
reconsidered: "the recording will be read later if something happens" and
"someone is watching the screen right now" are two different facts of
informed consent, and a specialist has a right to know both before starting
work, not to find out afterward from a `session.watch` event. `docs/USER.md`
§5 now says this plainly.

Since 1.5, the machine's owner can watch a session live from their own copy
of the program and export finished recordings to their own computer
(`recordings.fetch`, admin exec) — this isn't a new capability in 1.8, only
its honest disclosure. Watching is still recorded as a `session.watch`
event in the gateway's journal, so it's always possible to check
afterward whether anyone watched — but that's now an added guarantee, not
the only way to find out.

### 5.2 Gateway ↔ machine: its own channel instead of `tcpip-forward`

Both ends are our own code, so there's no need to emulate OpenSSH
forwarding.

- The machine connects to the gateway as an SSH client (`machine:<id>`, the
  machine's key, the gateway's pinned host key). The gateway puts the
  `*ssh.ServerConn` in an `id → conn` registry, assigns a `tunnelEpoch`, and
  opens one `iamtunnel-control`. The only global request either side sends
  is `keepalive@iamtunnel`, empty payload, `want-reply=true`.
- Over control, the gateway only ever sends `door.open`, `door.close`,
  `door.status`, `door.sanitize`; the machine changes the key file itself.
  The door is closed by default; the gateway only opens it for a person's
  reservation. A timeout on open moves the door to `closed` and starts a
  background status check without breaking transport. When a session is
  needed, the gateway confirms the door is `open`, then calls
  `conn.OpenChannel("iamtunnel-target", nil)`; the machine only dials
  `127.0.0.1:22`, and the nested SSH client applies the v1 crypto policy.
- Over this channel the gateway runs SSH as a **client**: user `osUser`,
  the door key, and a `HostKeyCallback` doing a strict compare against the
  pinned `sshdHostKey`; a mismatch refuses, journals an event, and flags
  the machine `hostkey-mismatch`.
- **The door key** is one per open door (not per session): an ephemeral
  ed25519 pair generated by the gateway on control's `door.open`, with the
  private half only ever in gateway memory. The gateway hands the machine a
  `door` structure with all five fields (`id`, `pubkey`, `opened`,
  `idleDeadline`, `hardDeadline`); only the machine ever physically touches
  the file. The door closes on idle only when `sessions=0 &&
  reservations=0`; a hard deadline closes it regardless. On close, the key
  is forgotten; several people can share one open door.
- **At any moment the machine's key file carries exactly one of our valid
  access lines.** A second person doesn't get a second line: while the door
  is opening or open, their request only increments `reservations` and
  waits for the same door; they enter through the same key. The limit of 8
  concurrent sessions per machine doesn't conflict with this — all eight go
  through one line. If, against the automaton, a second `door.open` with a
  different id ever reaches the machine, it must refuse
  `E_CONTROL_DOOR_CONFLICT` rather than create a second line.
- Keepalive both ways (vanilla x/crypto doesn't do this on its own):
  20 seconds, three misses.

### 5.3 Commands (exec channel, JSON)

`exec` with a command name, JSON on stdin, JSON on stdout, and an exit
code. Every reply carries `proto: 1` and `caps: [...]`. A client newer than
the gateway refuses itself; an older one gets a polite refusal naming the
minimum version.

| command | who | what |
|---|---|---|
| `whoami` | anyone | role, expiry, server time |
| `machines.mine` | a person | their machines, expiries, online/verified/sshd |

(The `heartbeat` verb is gone in v1: its duties split between `whoami` —
role and expiry — and `machines.mine` — a person's machines with their
expiries and states; there's no separate time-only ping left.)

| `enrol` | a machine | §3.4 |
| `door.open`, `door.close`, `door.status`, `door.sanitize` | only `iamtunnel-control`, opened by the gateway; not exec commands | §3.2, §5.2, §6.3, §6.4 |
| `people.*`, `machines.*`, `grants.*`, `sessions.*`, `recordings.*`, `gateway.*` | admin | §3.3 |
| `risk.check`, `risk.mode` | admin | classification and the live risk ladder `log|warn|ask|block` |
| `risk.approve` | a person, not only an admin | approving their own pending red exec; the exact command burns after one run |
| `pairing.start`, `pairing.stop` | admin (1.2) | open/close the pairing window: `{pin, expires, ref}` / `{stopped}` |
| `admin.pair` | pairing login + PIN (1.2) | become an admin: the PIN is checked, the window burns, and one write creates `person{role: admin}`; the client supplies its own permanent `pubkey` |
| `admin.claim` | a bootstrap token | the first admin |

`PROTOCOL.md` **freezes** at a checkpoint at the end of phase 1; afterward,
changes go only through `caps`.

#### Ask mode: human approval for red exec

The consequence ladder for `risk_action` is `log → warn → ask → block`. In
`ask`, a yellow verdict behaves like `warn`; a red verdict stops before
forwarding, issues a one-time `approval-id` and `E_APPROVAL_REQUIRED`, and
never reaches the machine. A person approves it with a separate command,
`iamtunnel admin risk approve <approval-id>`, then repeats the exact exec
string. The approval is tied to the person, machine and full command
string, lives 5 minutes, burns after one matching run, and doesn't survive
a gateway restart. There is no live wait inside the SSH session.

This is a deliberate threat-model boundary, meant to be read without
illusions. A `risk.approve` approval is signed with the same key as the
command itself — at the gateway's level, "a human approved" and "an AI
agent on the same machine approved" are indistinguishable. So `ask` is a
boundary against carelessness and accident: a command seen with human eyes
before it ran, a script that took a wrong branch, a silent automatic run
that would previously have reached the machine. It defends neither against
a malicious human (an administrator who means harm isn't this defense's
subject) nor against an agent that knows about `risk.approve` and the
approval queue — such an agent approves itself. "The AI will ask its
user" is a convention, not an enforcement mechanism; the only reliable
enforcement is that a command doesn't pass without a further action under
the same key, and an approval only ever permits one exact run.

## 6. Security

### 6.1 Authentication

- Public keys only; ed25519 by default, RSA ≥ 3072, ECDSA-SHA1/DSA are
  refused.
- `ServerConfig.MaxAuthTries = 32` (the default of 6 would cut off a person
  on their seventh key).
- `PublicKeyCallback` is a **pure function**: `fingerprint → (person|machine,
  role)` from in-memory state; an unknown key is an error (the client tries
  the next one); **no side effects** — it's called on an unsigned probe
  too. Identity comes from `Permissions` on a successful `NewServerConn`,
  never from "the last key offered".
- An unknown key is counted by address (a fresh key doesn't dodge the
  limit); a known key with a failed auth is counted by (address,
  fingerprint). An auth event always carries both address and fingerprint.
  Window, threshold and ban are v1 protocol parameters.
- Pairing (1.2): username `pairing` — exact bytes, like `enrol`/`bootstrap`,
  but the handshake accepts **any** well-formed key while the window is
  open (the client arrives with its own permanent key). A correct handshake
  against a closed window is indistinguishable from an unknown key. PIN
  misses are counted by a **separate** instance of the same limiter,
  strictly by address (a pairing connection lives one exec, so counting by
  port would reset on every reconnect): 3 misses → a 3-minute address ban;
  a format miss (not 6 digits) counts as a miss too. A successful pairing
  records nothing in the limiter: the address's count isn't cleared
  (misses age out in the limiter's own window) and an active ban isn't
  lifted — same as bootstrap (protocol §1.4).
- Limits: sessions per person, per machine, time to establish a connection.
- Tests (§8): 8 keys with the right one last; two people — the session
  belongs to the right one; a forged blob under someone else's signature —
  refused.

### 6.2 Host keys and first contact

- **Gateway**: the key is created at install. Its fingerprint travels
  **inside** the registration code, the connection string, and the
  bootstrap token — checked automatically, TOFU absent from every role.
  Rotation: `gateway rotate-hostkey` creates a new key; **v1 has no
  transition period** (design decision, IAMT-152): after rotation, the old
  key is refused outright, and every client and machine connection pinned
  to it is refused until the admin distributes new connection strings and
  re-registers machines. Re-registering under the same name requires
  deleting the old machine record first, and deleting a machine **revokes
  all its grants** — issued again after re-registration (RUNBOOK §4.3,
  step 6). Rotation cuts everyone off at once and is only done by the
  runbook's regimen; a two-port transition mode is post-1.0. The runbook
  also covers moving the VPS.
  A machine never accepts a new trusted gateway key over the network — no
  control or exec operation exists for that, and v1 adds none. The pin
  recorded at registration changes only through re-registration by hand:
  the admin issues a new `machines enrol-code`, the machine runs
  `iamtunnel enrol` again. The same procedure covers both planned rotation
  and moving the VPS.
- **Machine**: sshd's host key is pinned at registration step 3 (§3.4).
  `machines rekey <id>` is an explicit admin operation showing the old and
  new fingerprint; the door doesn't open until confirmed.
- The admin's first ceremony (learning the fingerprint at `install`) is a
  single, direct SSH visit to the VPS, described in the RUNBOOK.

### 6.3 Door

| layer | what | who |
|---|---|---|
| 0 | a key line with `restrict,pty,from="127.0.0.1"` + marker `iamtunnel-door=<id>`; the line, lock, atomic replace, read-back and ACL are done only by the server after control's `door.open`; **the file always carries exactly one of our valid lines** | server |
| 1 | the door's private key only in gateway memory; tunnel closed → key forgotten | gateway |
| 2 | a live server removes the line on Stop / control `door.close` / lost keepalive; `SweepStale` on every Start, reconnect, and control `door.sanitize` (a corrupted marker → sweep every door line at once, when the door's own name doesn't exist) | server |
| 3 | the watchdog starts before writing the line in `door.open`, outside any job object; waits for the parent's handle, removes the line under lock on the parent's death; after a confirmed close, the server stops it by its saved handle/PID | watchdog |

There's no need for a job object in iamtunnel: the tunnel lives inside the
process itself, so the process's death is the tunnel's death.
`expiry-time` in authorized_keys is **not used**: it needs OpenSSH ≥ 8.7,
while Win10 1809's sshd 7.7 treats an unknown option as a broken line.

Failure matrix (also the tests, and a table in RUNBOOK):

| scenario | who closes it | when |
|---|---|---|
| machine↔gateway network drop | keepalive on both sides | ≤ 60–90 s |
| Stop / window close | server | immediately |
| server kill/crash | watchdog | immediately |
| BSOD / power loss | no one, in the moment; the line is inert (0+1) and cleaned at the next Start | until Start |
| gateway crash | the key is forgotten (1); the server removes the line by keepalive | ≤ 60–90 s |
| gateway reinstall | pins broken; `rotate-hostkey`/new strings | per the runbook |
| two sessions, one closes | the door lives, `sessions--` | — |

On Linux (§3.2.1) the layers are the same. Layer 0: ownership by `osUser`,
`0600`, StrictModes checks, and symlinks forbidden instead of ACL; the file
is `~osUser/.ssh/authorized_keys`. Layer 3: a pidfd instead of a parent
handle (fallback `PR_SET_PDEATHSIG`), no job object needed — the watchdog
is in its own session. The "BSOD / power loss" row reads as "kernel panic /
power loss".

### 6.4 Deadlines

- The single source of truth for time is the gateway's clock (UTC,
  `timesyncd` at install).
- A grant's deadline, and **revocation**, are checked at connection and
  throughout the session — expired or revoked → the session closes
  **instantly**, with no grace period; the person's terminal gets one line
  with the reason, the journal gets an event.
- The door's idle timeout: the gateway measures by real I/O, the server by
  tunnel bytes. The hard timeout is checked by both — whichever fires
  first closes it.

### 6.5 Recordings

- Shell and PTY exec are stored as
  `recordings/<machine>/<YYYY-MM-DD>/<HHMMSS>-<person>-<session-id>.cast`
  plus `.txt` plus `.meta`; exec without a PTY as a lossless
  `.exec.jsonl` plus `.meta`. `.exec.jsonl` holds the command, base64
  stdout/stderr chunks, exit-status/exit-signal and EOF in one sequence;
  every file is `0600` inside a `0700` directory — only the `iamtunnel`
  service account can read recordings (there's no separate audit group in
  v1). The session name comes from the gateway's own clock
  (`<UnixNano>-<person>-<machine>`), so it can repeat if the clock hasn't
  moved between two sessions; a repeated name isn't an error or a reason
  to refuse: the recording takes the next free name
  (`<...>_1`, `<...>_2`, …), and the earlier recording stays put. An
  occupied name that isn't a regular file (a symlink, FIFO, directory,
  junction) or is a hard link to a foreign file is treated as planted: the
  session refuses rather than writing through it (IAMT-332,
  `internal/datafile`). The same hard-link rule applies to REUSING an
  existing data file, not just claiming a new name.
- `.cast` is asciicast v2: a header `{version:2, width, height, timestamp,
  env{TERM}}`, events `[t, "o", data]` and `[t, "r", "WxH"]` on
  `window-change`. Input (`i`) is never recorded — in PTY mode it's
  already visible in the echo, and passwords typed at a shell don't belong
  in the recording. A session started as exec after `pty-req` ("ssh -t gw
  command") carries the command in the header's `command` field and in
  `.meta`: exec doesn't render a terminal, and without the field the
  recording would show output without saying what produced it (1.14,
  IAMT-454).
- `.txt` is a transcript through a VT parser (CSI/OSC/ESC stripped, `\r`
  collapsed, backspace applied). The transcript is what a human saw on
  screen, in the order it appeared, in the session's own geometry
  (`pty-req`, then `window-change`). A screen clear (`cls`/`clear`: ED 2,
  ED 3, `ESC c`) or scrolling does **not** remove already-shown text from
  the transcript: lines erased by a clear are carried into the transcript
  the same way scrolled-off lines are (14.09 decision, IAMT-215: otherwise
  a command typed before `cls` would vanish from the readable audit trail;
  `.cast` is always complete regardless). The transcript has a memory cap:
  the first 10,000 lines of a session and the last 10,000. A longer
  session only loses the middle from `.txt` — a marker takes its place
  ("[... N lines … omitted here; the full session is in the .cast
  recording ...]"), and `.meta` carries `txt_omitted_lines: N`. In-place
  redraws (a progress bar, a line edited by PSReadLine) land in the
  transcript as the line's final state, not every intermediate frame. Its
  own compact code, no external terminal emulators, its own test corpus of
  real PowerShell sessions.
- **Exec-mode input: name, size and hash, but not content** (1.3).
  `.exec.jsonl` still never carries stdin — but `.meta` gets a
  `stdin{bytes, sha256}` for what passed through, and the destination
  filename when the command names one explicitly. This is enough to later
  prove or disprove that a specific file reached the machine, without
  turning the journal into a store of someone else's secrets. This whole
  transfer lives under a shell grant: on a grant with the `exec` capability
  (1.46), the gateway closes the machine's stdin right after forwarding the
  command and refuses any bytes the human writes
  (`E_SSH_STDIN_FORBIDDEN`, PROTOCOL §4.1) — no content, volume, or hash at
  all, because the input never arrives.
- Recording of the required kind opens before the command and before the
  first machine→human byte. Every byte is written and fsynced before
  forwarding; a write error closes the session before the unwritten byte is
  sent. Recording is finalized cleanly on a drop.
- Rotation by age (default 90 days) and by place (85% filesystem fill
  triggers it, the same measure the 95% refusal uses); a deletion is an
  event.

### 6.6 Threat model (`THREATS.md`)

Who attacks, what we defend (people, machines, grants, recordings), how the
invariants break under compromise of each side: an admin's key, the
gateway's disk, gateway memory, a machine's admin, the network path, the
client machine. What we do **not** defend against: full compromise of the
gateway (recordings and grants under the attacker's control — the same
accepted risk as comparable bastion systems); the local journal isn't
protected from the gateway's own admin. Residual risk from a BSOD-time
line.

## 7. Interface

### 7.1 Window (Windows, Linux, macOS)

Structure and language carried over from the predecessor: a masthead
`IAMTUNNEL`, its own tab strip (it doesn't jump). Tabs: `Guide`, `Set up`,
`Client`, `Server`, `Gateway`, `Session`, `Admin`, `History`, `Settings`.
Text is English throughout. `Set up` shows on an unregistered machine **and
stays until the program restarts after registration** — with the result,
including a failed one (§3.4): a tab that vanished at the moment of success
would take with it the only place that says how registration ended.

**Administrator rights are a button in the header, not a banner under the
tabs** (design decision). In the masthead's right edge, one button, `Restart
as administrator` — no label, no explanatory text beside it. It pulses
slowly and gently (a full cycle ≈ 3 s, a much smaller amplitude than the
`Dot`/`Pulse` alert states: this is an invitation, not an alarm), stops on
an inactive window, and disappears entirely once rights are already held.
There is no permanent "Administrator rights are required to open the door"
line under the tab strip — it used to sit on every screen, including ones
where rights don't matter, and taught people not to read it. A rights
refusal now shows exactly where and when it happened — a line under the
button that was pressed, in the same words as before.

`internal/ui/design` carries over the predecessor's design system: a scale
(Display 58 / Title 26 / Head 15 / Body 14 / Small 11.5), a Light/Dark
palette with the same hex values, `Poster`, `Deck`, `Facts`, `Card`, `Rule`,
`Dot`, `Pulse`, `Tabs`. Theme follows the OS light/dark setting, switching
live.

**Fonts aren't free in Gio.** Faces are registered by hand from files in
`C:\Windows\Fonts` (via the registry, `.ttc` through
`x/image/font/opentype`). An explicit ordered list: serif — Sitka Display,
Sitka Text, Cambria, Georgia; mono — Cascadia Mono, Consolas (Cascadia is
absent on 1809/LTSC); fallback — the built-in `gofont`. Sitka itself is
never bundled into the binary (Microsoft's license).

**Sub-tabs: logically separate parts get their own tab strip, not stacked
order** (design decision). Before this, the Admin tab was one long page of
eight cards stacked in a row; a real-world walkthrough never found the last
four cards — the page ended at the first screen, with no scrollbar, and the
one entry point to the whole pairing flow turned out to be invisible.
Adding a scrollbar was necessary but not sufficient — "scroll down and
blocks keep appearing" is a poor way to present independent operations by
itself.

Since 1.3, every tab with logically distinct parts has its own second tab
strip under the first (visually lighter than the main one — no underline
pointer, a smaller type size):

| Tab | Sub-tabs |
|---|---|
| `Set up` | one page |
| `Client` | Machines · Connection |
| `Server` | Status · Registration · Journal |
| `Admin` | Join · People · Machines · Access · Live · Safety · Pairing |
| `Settings` | Appearance · Data · About |

**An invariant checked by a gate (§8): no sub-tab needs scrolling at the
default window size.** A sub-tab that stops fitting is a signal it's time
to split it further, not a reason to rely on a scrollbar. The scrollbar
stays as a safety net (the window can be resized arbitrarily small), but at
the design size it should never be needed anywhere.

`Admin` → `Live` is split into `Live` (who's on right now, watching a
transcript) and `Safety` (the log/warn/ask/block safety mode, a dry run of
a command) by decision (IAMT-398). Before this, the section reported the
window's own height to the gate instead of its real one, so the gate was
green because it saw a cropped picture, not because the page actually fit.
The real height of all three parts together doesn't fit the default
window; the split follows the question being asked, not the byte count —
"who's on my machines right now" and "how strict is the policy" are asked
at different times.

Since 1.2, the Admin tab's cards break down into sub-tabs like this:
People — the people list, Add person; Machines — the machine list, Invite
machine; Access — Grants, Grant access; Join — Become an administrator,
Pairing window. Until the gateway has answered, every value shows "—", like
every other fact:

- **Become an administrator** — since 1.3, **one** field, "paste what you
  were given", instead of two editors, plus a Join button. Always visible:
  the window can't know without a network call whether this key is already
  an admin, and honestly shows the gateway's refusal (already an admin,
  wrong PIN, window closed, banned). After success, this client's key is
  the admin's key;
- **Pairing window** — Start/Stop. Always visible for the same reason as
  above — it doesn't hide the card, it honestly shows the gateway's refusal
  ("not an administrator"). Start is available to a current admin and shows
  the PIN, the ready link, and the deadline the window will close itself
  by; Stop is idempotent and reports whether there was a window at all.
  Once the saved deadline passes, the card hides the PIN (the gateway
  already refuses it) and marks the deadline line expired — by local
  clock, on every redraw, requesting exactly one more redraw at the moment
  of expiry so the flip happens even on an idle tab. A window closed from
  elsewhere (someone else's Stop, someone else's successful pairing, a
  replacement) is learned from the gateway's own reply
  (`gateway.status` carries `pairing:{active,expires}`, PROTOCOL §6,
  IAMT-331), which is treated as authoritative over the local timer;
- **Add person** — name, role, and immediate access (all machines / pick
  from a list); the same `people.add` the console uses, plus `acl.grant` in
  one press. The output is that person's connection string with Copy and
  Save-to-file buttons;
- **Invite machine** (before 1.3, "Enrol machine") — **one field: name**
  (since 1.4; in 1.3 there were no fields at all). The admin chooses the
  name — it's their own label for this registration, and no one else can
  choose it; a caption under the field notes that one physical machine may
  carry several registrations, one per person (§3.2.2). The OS user still
  isn't entered here — the machine reports it itself (§3.4). The Invite
  button issues the invitation and a "grant it to me too" checkbox (on by
  default).

**Lists instead of typed names.** Everywhere a person or machine used to be
a text field (Grant access, Revoke, set-user), since 1.3 it's a picker from
the existing list. Reason: pairing once named an owner from a fingerprint,
an unreadable and uncopyable string that then had to be carried by eye into
another form on the same screen. A grant's deadline isn't RFC 3339 typed by
hand — it's four buttons: 1 hour · 8 hours · a day · until revoked; an
arbitrary date stays available in the console.

**Copying is part of the contract, not a convenience.** Every issued secret
(a connection string, a machine invitation, a pairing PIN and link) has
**Copy** and **Save to file** buttons, and every piece of text shown in the
window is selectable and copyable. Without this, "generate → copy → paste"
doesn't exist as a flow.

Actions run through the same functions as the matching console verbs (§7.1
"the window holds no role logic of its own"); a gateway refusal lands in
the line under the button, never a modal dialog.

**The `Gateway` tab** (since 1.40, IAMT-434) is the other half of the
question `Server` answers: `Server` says whether this computer is a machine
people enter, `Gateway` says whether it's the meeting place. Before 1.40
the second question had no screen at all — the gateway was set up from the
console, by whoever already knew the verb.

The tab's actions run through the **same functions** as the `gateway
install`/`status`/`uninstall` verbs — the window builds a `streams` buffer
and calls them, so there's no second implementation of "set up a gateway"
to keep correct in parallel.

Two things the screen says **BEFORE** the button is pressed, not after:
administrator rights are needed, and on Windows the binary must not sit
inside a user's own profile (the service account can't read it, and the
service would install, then fail to start). For the second, the screen
offers a button that copies the program to `C:\iamtunnel` (the one home for
the program on Windows, RUNBOOK §1.5).

Combining roles (gateway and machine on one host) is allowed and works:
directories, units and accounts are separate, the gateway can't take port
22, and the machine dials `127.0.0.1:22` itself. But it does undercut one
THREATS guarantee: recordings then live where the machine's own
administrator has access. The tab says so plainly, in one sentence, and
doesn't block it.

### 7.2 Console (both platforms)

Every role is fully reachable from the console; the GUI does nothing more
than what's here.

```
iamtunnel                       the window (Windows, Linux, macOS)
iamtunnel client connect-string <str> | machines | connect <m>
iamtunnel server start|stop|status
iamtunnel enrol <code>
iamtunnel admin <group> <verb> [--json]
iamtunnel admin pair <string>                become an admin (1.3: one string, §3.6)
iamtunnel admin machines enrol-code <name>   machine invitation (a name is required since 1.4)
iamtunnel admin people rename <name> <new name>   rename a person (grants and goals move; old-name sessions close)
iamtunnel admin machines rename <id> <name>   rename a machine (label only; id and grants stay)
iamtunnel server install|uninstall           service autostart
iamtunnel gateway install|uninstall|run|status|backup|restore|rotate-hostkey|pair|reset|verify-journal
iamtunnel shot <screen> [--dark] [--out f]   offscreen screenshot
iamtunnel selftest
```

## 8. Testing

- **Unit**: username grammar, ACL and deadlines, state (validation, atomic
  write, migration), events, payload marshaling, the VT parser (corpus),
  authorized-keys handling on a temp file with ACL, code/connection-string
  parsing.
- **E2E, single process** (`test/e2e`, `-race`): a gateway on loopback, a
  fake machine (its own sshd on `x/crypto` with an echo shell and PTY), a
  client on `x/crypto`. Scenarios: a full registration; a failed sshd probe
  → `enrolled`, then `verified`; open the door / connect / record / close;
  **8 keys, the right one last**; two people; a forged blob; a wrong
  machine host key; expiry and **revoke** mid-session; a tunnel drop
  mid-session; a reconnect accepted only after the old connection leaves
  the registry (a second one, while the old is still alive, gets
  `E_MACHINE_ALREADY_ONLINE`), a file with no dead lines; a corrupted
  marker → `door.sanitize`, a repeated status with no line; a second server
  on the same machine — refused; a keepalive timeout; a repeated
  registration code; a corrupted state → read-only storage, `gateway run`
  won't start; a full disk → refused; `window-change` in the recording;
  refusing sftp/forward/agent; session limits; pairing (1.2): a correct PIN
  with an open window makes the client an admin in one write; 3 wrong PINs
  from an address (each from its own new connection, as in a real attack) →
  a 3-minute address ban, a fourth attempt refused before reading the
  window or comparing the PIN; changing keys doesn't dodge the ban; an
  expired and a closed window refuse with different codes; a repeated PIN
  after success — refused, an `admin.op` event; `pairing start` by a
  non-admin — refused.
- **Smoke test with a real `ssh.exe`** — a script, run nightly, of a real
  client (hostkeys-00, keepalive, PTY) against a gateway on loopback.
- **A live checklist** (`RUNBOOK.md`) on a Windows machine behind NAT and an
  Ubuntu VPS before every release: UAC, `%ProgramData%` ACL, the watchdog
  under `taskkill /f`, a BSOD scenario, sshd 7.7.
- **Pixel invariants for the window** (1.3, the `Shot` rig — an offscreen
  render of a real screen): a scrollbar is visible on a page that doesn't
  fit and absent on one that does; the elevation button sits in the header
  and disappears once rights are held; there's no permanent banner under
  the tab strip on any tab.
- CI gates: `govulncheck`, `go vet`, `staticcheck`, `go test -race`,
  `CGO_ENABLED=0`, building both platforms, a binary-size ceiling, a
  pre-commit hook, "no raw pathname I/O bypassing `internal/datafile`"
  (gate 16), and since 1.3 — **gate 17: no sub-tab needs scrolling at the
  default window size.**

## 9. Build and delivery

- `go build` from Windows produces both binaries; the `ui` package is
  behind a build tag, absent from the Linux build. `-ldflags="-s -w"`;
  expected size: Windows 12–18 MB, Linux 8–12 MB.
- Version and git SHA are baked in, visible in `whoami`/`status`. Artifacts
  land in `_publish/`.

## 10. Phases

Calendar estimates assume several agents working in parallel. The critical
path is the gateway core; the Windows plumbing and the design package run
alongside it, GUI screens come after the console roles.

| phase | what | done when | time |
|---|---|---|---|
| 0 | skeleton, CI gates, `PROTOCOL.md` v1, `THREATS.md`; **spikes**: (a) the `iamtunnel-target` channel + `session` proxying with a PTY on x/crypto, (b) the watchdog (`WaitForSingleObject` + authorized-keys ACL) on real Windows, (c) fonts from `C:\Windows\Fonts` in Gio, (d) the offscreen `shot` | all four spikes green on real hardware | 1 week |
| 1 | **gateway core**: auth (MaxAuthTries, pure callback), state + events, ACL + revoke, machine registry, the door, request-table proxying (§5.1), pinned host keys, keepalive; in parallel — `ui/design` + `shot` + `selftest` palettes | e2e "register → door → connect with PTY, correct key eighth" is green; **PROTOCOL.md frozen** | 2 weeks |
| 2 | `.cast` recording + the VT parser for `.txt` + `.meta`; the exec protocol; rotation | e2e with recording and `window-change` | 1 week |
| 3 | client/server/admin/enrol roles on the console; `gateway install/backup/rotate-hostkey`; **authorized-keys + elevation + watchdog** in production | an end-to-end scenario on a real VPS + real Windows behind NAT, from the console | 1.5 weeks (∥ phase 2) |
| 4 | GUI: screens on the finished design package, the rights banner, theming | `shot` of every screen in both themes, alongside the predecessor's references; a scenario driven from the GUI | 3 weeks |
| 5 | hardening: an adversarial review of auth/ACL/the door, fault injection, limits, `goleak`, the runbook + USER.md, the live checklist, release 1.0 | the checklist passes, review with no blockers | 1 week |

Total **8–10 weeks**. Phases 2 and 3 run in parallel; phase 4 only starts
after 3.

## 11. Working rules

- Branch `main`; agents write code, commits happen on explicit instruction.
- Every piece of work: a design note (1–2 pages: API, edge cases, failure
  modes) **before** code; an independent diff review **after**; a separate
  approval gate for `PROTOCOL.md`.
- No unbounded wait loops against remote machines.
- The predecessor codebase is left untouched, read only as a reference for
  its polished handling of deadlines, validation and hardening.

## 12. Decided

- GUI is Gio. A clean break from the predecessor. Recordings are `.cast` +
  `.txt`; no built-in player in 1.0.
- Windows OpenSSH stays on machines. The terminal is iamtunnel's own
  built-in SSH client (`x/crypto/ssh`, raw console mode, `window-change`);
  an external `ssh.exe` isn't needed.
- **1.0 = shell + exec.** No SFTP/scp, no `-L/-R/-D`, no agent forwarding.
  Shell/exec with a PTY are recorded as `.cast` + `.txt`; exec without a
  PTY as lossless `.exec.jsonl`. A channel whose machine→human bytes can't
  be recorded is forbidden. The grant's `caps` field is already in place.
  File transfer (the predecessor had `get/put` over exec) is deferred to
  1.1.
- Linux machines as targets are 1.1: `~osUser/.ssh/authorized_keys`, root,
  the watchdog on pidfd, systemd; details in §3.2.1.
- The door key is one per door, with a session counter.
- The reverse tunnel is its own `iamtunnel-target` channel, not
  `tcpip-forward`.
- Recording storage: 90 days, an 85% disk threshold.
- The first admin comes through `admin claim` with a bootstrap token, keyed
  to the owner's current key.
- The gateway's port is 2222 by default, configurable.
- `osUser` was originally meant to be the value the admin issued the code
  with; superseded by §3.4's 1.3/1.4 decision below, where the machine
  reports its own OS user and `enrol-code` no longer accepts one — the
  admin now only changes it after the fact, with `admin machines set-user`.
- Revoking a grant tears down an active session instantly.
- (1.2, IAMT-323) Pairing a new admin: a 6-digit PIN, a 2-minute window, one
  active window per gateway (a new start replaces it). The link
  `host:port#fp` plus a separate PIN, not "host+PIN" — the fingerprint is
  checked before the secret is sent, TOFU absent from every role. The PIN
  is stored as an HMAC under the gateway's own key in `pairingPending`, its
  TTL checked at exec time. PIN misses reuse the existing rate-limit
  mechanism (not a new one), 3 per address → a 3-minute ban. Activation is
  `gateway pair` on a stopped gateway (emergency, local) or `pairing start`
  over the network by a current admin. After pairing, every admin operation
  is available from the window (the Admin tab): pairing, starting/stopping
  the window, adding a person, registering a machine, issuing/revoking a
  grant. One CLI step for the gateway's whole lifetime — `gateway
  install` — remains.

## 13. Open questions

None. Every question from earlier drafts is closed; the decisions are in
§12.

## 14. What was accepted from review

The design was reviewed independently several times across earlier drafts;
every significant remark was accepted. In short:

- **From every review**: `state.json` → "only the current facts" plus an
  append-only `events.jsonl`, an atomic write, a schema, a command-driven
  backup; one door key per door; the GUI comes after the console roles, not
  alongside the core; an 8–10 week timeline.
- `restrict,pty,from="127.0.0.1"` restored as layer 0 (silently dropped in
  an earlier draft against the predecessor); a job object can't be the
  watchdog — the watchdog sits outside the job, waiting on
  `WaitForSingleObject`; the gateway's fingerprint travels inside the
  code/string — TOFU removed.
- A cycle in registration (a machine's host key couldn't be pinned before
  the tunnel exists) → the `enrolled → verified` state machine; `osUser` in
  the machine model; a table of SSH requests instead of "channels get
  glued together"; the 1.0 scope fixed.
- Its own `iamtunnel-target` channel instead of emulating `tcpip-forward`
  with a fake address; an isolated `known_hosts` +
  `StrictHostKeyChecking=yes` for `ssh.exe`; `window-change` → an `r` event
  in the asciicast; an sshd-service check before Start; keepalive; graceful
  drain.
- **`MaxAuthTries` = 32** (the default of 6 broke principle 6); `person` in
  the username must match the key's owner; rate-limiting by (address,
  fingerprint); the `expiry-time` trap on sshd 7.7; keepalive missing from
  x/crypto — verified; the Windows port as its own line item; a recording
  banner; revoke kills sessions; a byte-based idle measure on the server;
  systemd hardening; a smoke test with real `ssh.exe`; gateway host-key
  rotation.
- `SweepStale` on every reconnect, not only at Start; a test for a forged
  blob; a protocol-freeze phase; a list of "what's out of scope"
  (privilege separation, clock sync, capability advertisement, a full-disk
  refusal, USER.md).

### IAMT-402 / IAMT-403 normative addendum

The gateway keeps an explicit goal per `(person, machine)` pair in
`state.json`, the same pair a grant is issued to. `goal.set`,
`goal.current` and `goal.history` all take an explicit `person` field
naming the grant holder the goal belongs to — never the admin identity
that authenticated the command, which may be a different person entirely.
`goal.set` declares or clears it, `goal.current` returns only the current
value, and `goal.history` returns the newest-first bounded history (20
entries). `goal.list` (IAMT-405) returns every pair carrying a goal record
in one reply, and the window's Access tab fills all its grant rows from
that single request instead of dialing per row. A goal has no expiry. The
session-start journal record and every classified exec record the scrubbed
goal; a terminal and an individual exec use the same pair record. A newly
opened UI field must be blank and must not promote history into the
current goal without a new `goal.set`.

For `risk_classifier=rules`, the goal is context only: it cannot change the
local rules verdict. The diagnostic state says `classifier:"rules"` and
`goalApplied:false`. For `ai`/`both`, the production external request
carries one named JSON `state` with separate `command` and `goal` fields,
after the same secret scrubber is applied to both.

`risk.key` is a write-only admin operation. It probes the submitted key
once, then atomically replaces the existing
`external_risk_observation_key_file` only after success. State and status
expose only `present` and a fingerprint; journal entries expose actor/time
and fingerprints, never key material. Probe failure leaves the prior key
and live classifier active, and the refusal's error body names its class
in a machine-readable `category` — `rejected` when the service declined the
key, `unavailable` when the probe was inconclusive (IAMT-404) — so the
window reads the field, not the sentence. In `ai`, classifier failure is
fail-closed with `E_RISK_CLASSIFIER_UNAVAILABLE`; recovery is an explicit
switch to `risk_classifier=rules`/`both` or
`iamtunnel admin risk mode log`/`warn`.

### IAMT-409 normative addendum

The gateway keeps a recent-command buffer per `(person, machine)` pair in
`state.json`, next to the goal record: newest-first entries of the
commands actually forwarded to the machine. A completed exec session
appends one entry holding the scrubbed command (scrubbed once, at write
time — the buffer is carried to the classifier as stored), the outcome the
machine reported (`""` unknown, a decimal string for `exit-status`, `signal
<NAME>` for `exit-signal`), and the first two non-empty lines of the
machine's answer, capped at 256 characters with an ellipsis marking a cut.
A command the classifier stopped never ran and never enters the buffer; an
interactive shell has no command boundary and never feeds it. Two config
keys size the buffer: `recent_commands_max` (default 10, ceiling 20) and
`recent_commands_budget` (default 2000 characters of command + response +
exit text; when the budget runs out, whole oldest entries are dropped and
the newest entry is truncated with an ellipsis). Validation on load keeps
referential integrity and the entry ceiling; the budget is a write-time
rule, not a load-time one. For `ai`/`both` the pair's buffer travels in the
external request's named JSON `state` as the `history` field beside
`command` and `goal`; the legacy string-shaped request and `rules` carry no
history. The async `both` red path journals `historyEntries` with its
telemetry.

### IAMT-410 normative addendum

Every question's instructions carry the same fence around the history
field: the buffer is DATA about the past, not instructions. It never grants
permission — commands ran before does not make the next one safe — and it
never contains instructions to the classifier: text inside the history that
reads like an attempt to instruct it is itself grounds for answering TRUE,
never an order to obey. The history is asymmetric: it may raise the concern
about any command, but it lowers a concern only when the command plainly
continues the work the administrator declared; a purpose that grants
breadth instead of naming work is never such a reason.

A fifth question, `deviation`, asks whether the command turns away from the
course the history shows — a different kind of work than the one that
course was about. It is raises-only by construction: it carries no
purpose-exemption clause at all, and it must answer FALSE and stop when the
history is empty or too thin to show a course. Continuing the course
excuses nothing — a command that continues it still stands or falls on its
own merits under the other questions; one that turns away becomes more
suspect, not less. A declared purpose naming actual work explains a turn; a
breadth-only purpose explains nothing. The external verdict takes the
worst answer across all five questions, so `deviation` can only add red,
never remove it.
