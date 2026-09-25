# iamtunnel: administrator and on-call runbook

## Command risk: what the owner sees

`iamtunnel admin gateway status` shows the mode (`log`, `warn`, `ask` or
`block`), the classifier source (`rules`, `ai` or `both`), and the yellow,
red and blocked commands over the last 24 hours; the latest red command is
shown with its person, machine and rule. `iamtunnel admin sessions history`
shows the same events alongside session start/end, including the selected
source, level and reason. Yellow is not an alarm, it's a "this changed
state" label — `Restart-Service`, `taskkill`, `git reset --hard` and
`reg add HKLM` are usually repair steps. Red means data destruction or loss
of access.

The mode is set while the gateway runs: `log` only records, `warn` records
and warns, `ask` stops red until a separate human approval, `block` stops
red exec commands outright. The source is `risk_classifier`: `rules`
(default) uses only local rules, `ai` takes the external classifier's
synchronous decision, `both` takes the stricter verdict. For `ai` and
`both`, the command is sent to the external classifier only after
scrubbing; the wait is capped at 800 ms. On failure, `both` keeps the local
rules and shows one warning line, while `ai` stops the exec before the
machine with `E_RISK_CLASSIFIER_UNAVAILABLE`. The human sees the reason
(invalid/expired key for `401/403`, or unreachable service for
timeout/`5xx`) and is offered a switch to `rules` or `both` in config (with a
restart) or `iamtunnel admin risk mode log`/`warn`. A red local verdict in
`both` blocks immediately; the external call finishes asynchronously.
Interactive shells are never classified. To check a command ahead of time,
run `iamtunnel admin risk check "<command>"` — it's sent to the gateway and
classified by the same rules a real session would face; green exits 0,
yellow and red exit non-zero. Don't turn the check off over yellow entries —
match them against the work and the journal first.

This document is for the system administrator and the on-call engineer
running the iamtunnel gateway. It has no architecture discussion — only
exact, step-by-step instructions, command sequences and incident procedures.

Every command below is checked against the parser's own code
(`cmd/iamtunnel/*.go`).

---

## 1. Setting up a gateway from scratch

This is written for a clean Ubuntu Linux 22.04 or 24.04 LTS server (x86_64 or
aarch64). iamtunnel builds as a static binary with no external dependencies
(`CGO_ENABLED=0`).

### 1.1. Firewall

Open **only** iamtunnel's own port and the port for administering the Linux
host itself.

**Open:**
1. iamtunnel's SSH bastion port (default `2222/tcp`):
   ```bash
   sudo ufw allow 2222/tcp comment "iamtunnel gateway port"
   ```
2. The host's own system SSH port (e.g. `22/tcp`), restricted to the
   administrator's IP:
   ```bash
   sudo ufw allow proto tcp from 203.0.113.50 to any port 22 comment "VPS admin SSH"
   ```
3. Enable the firewall:
   ```bash
   sudo ufw enable
   sudo ufw status verbose
   ```

**Never open:**
- Port `22/tcp` for the iamtunnel service — the gateway runs unprivileged, on
  a port ≥ 1024.
- Any other inbound port ($\le 1023$ or arbitrary).
- Any forwarding or proxy port: v1 forbids direct port forwarding
  (`direct-tcpip`, `tcpip-forward`), agent forwarding and SFTP subsystems.
  Every machine and client connection goes through the single `2222/tcp`
  port.

---

### 1.2. Where the binary comes from, and where it goes

**The gateway runs the HEADLESS build** (`-tags nogui`, since 1.44,
IAMT-439). The gateway never opens a window, but until 23.09.2026 it carried
the window's code anyway: on Linux the window talks to X11/Wayland through
cgo, and the linker records `libEGL.so.1`, `libwayland-{egl,client,cursor}`,
`libxkbcommon-x11`, `libX11-xcb`, `libXcursor`, `libXfixes` as required —
**the dynamic linker demands them before `main` even runs**. A clean Ubuntu
Server 24.04 doesn't have them, and the very first command on a fresh gateway
— `iamtunnel version` — dies with exit code 127 and not one word from the
program.

The headless build has no cgo at all, so it **builds anywhere**, including
Windows, and needs no graphics libraries on the gateway host:

```powershell
# on any machine, from the repository root
.\build.ps1 -Version 1.44        # produces _publish/iamtunnel-headless
```
```bash
# the same by hand
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -tags nogui \
    -ldflags "-s -w -X main.version=1.44 -X main.gitSHA=$(git rev-parse HEAD)" \
    -o iamtunnel-headless ./cmd/iamtunnel
```

`iamtunnel version` names the build on its third line:

```text
iamtunnel 1.44 (git f36aaf6c856f)
platform linux/amd64 go1.27.1
build headless (no window compiled in)
```

If the gateway host somehow has the full (windowed) build, check
`ldd $(which iamtunnel) | grep 'not found'` before `gateway install` and
install what's missing: `sudo apt-get install -y --no-install-recommends
libegl1 libwayland-egl1 libwayland-client0 libwayland-cursor0
libxkbcommon-x11-0 libx11-xcb1 libxcursor1 libxfixes3`. These libraries never
actually run in the gateway process — the path to them only exists through
opening a window — but without them the process won't even start.

**The full Linux binary (with the window) cannot be built on Windows.** The
Linux window talks to X11/Wayland through cgo, and the whole product is one
binary, so the gateway drags the window's code along even though it never
opens it. `GOOS=linux go build ./cmd/iamtunnel` from another platform fails
on `gioui.org/internal/vk` — this is by design: gates 1 and 2 build
everything under Linux except `cmd/iamtunnel` and `internal/ui` for the same
reason, and the full tree is only built on a Linux host
(`scripts/gates.sh`).

So a FULL build needs a Linux host with the same Go version and the desktop
dev packages (`libx11-dev libxkbcommon-dev libgl1-mesa-dev libwayland-dev
libxcursor-dev`):

```bash
# on a Linux host, from the repository root
SHA=$(git rev-parse HEAD)
CGO_ENABLED=1 go build -ldflags "-s -w -X main.version=1.5 -X main.gitSHA=$SHA" \
    -o iamtunnel ./cmd/iamtunnel
sha256sum iamtunnel
```

`-X main.version` and `-X main.gitSHA` aren't decoration. Without them,
`iamtunnel version` prints `dev (git none)`, and afterward neither logs nor
eyes can say which commit is running on a live gateway.

Deploy with the old binary kept alongside, so rollback is one command:

```bash
sha256sum iamtunnel                       # on the build host
scp iamtunnel <gateway>:/tmp/iamtunnel-new
ssh <gateway>
sha256sum /tmp/iamtunnel-new              # same checksum
sudo cp /usr/local/bin/iamtunnel /usr/local/bin/iamtunnel.bak-<old-version>
sudo install -m 0755 /tmp/iamtunnel-new /usr/local/bin/iamtunnel
sudo systemctl restart iamtunnel-gateway
```

Confirm the new one is running:
```bash
systemctl is-active iamtunnel-gateway
iamtunnel version
```
*Expected output:*
```text
iamtunnel 1.5 (git ae86a7e68560755c2b29e460906c58473d907c59)
platform linux/amd64 go1.27.0
```
If the second word is `dev` with `git none`, the build skipped
`-ldflags` — it works, but it's anonymous; rebuild it.

---

### 1.3. First-time gateway setup (`gateway install`)

Run initial setup (`--public-host` is required, IAMT-202):
```bash
sudo iamtunnel gateway install --public-host gw.example.com
```
*(For a non-default port, add `--port`, e.g. `sudo iamtunnel gateway install
--public-host gw.example.com --port 2222`.)*

`--public-host` is the DNS name or IP address clients and machines actually
dial (the same address that's in `gw.example.com`'s A record and in every
connection string / enrol code you hand out). It's checked against SPEC
§3.1's host grammar — e.g. `gw.example.com`, `203.0.113.10` or `[2001:db8::1]`.
Without the flag, install refuses before doing anything (exit 2): otherwise
the bootstrap link and every later connection string would carry the
`<this-host>` placeholder and be useless. The same value can be set with
`public_host` in the config file (`iamtunnel help config`); the flag wins
over the file.

**What the command does (idempotent):**
1. Creates the base directory `/var/lib/iamtunnel` (mode `0700`) and
   generates the permanent host private key `/var/lib/iamtunnel/hostkey`
   (mode `0600`).
2. Writes `bootstrapPending` to `state.json` and a one-time `bootstrap-token`
   (valid 24 hours) — enough for `iamtunnel admin claim` to work against this
   very install (IAMT-131).
3. Runs the systemd half (IAMT-177): checks for and, if missing, creates the
   system user `iamtunnel` (no shell, home `/var/lib/iamtunnel`), then
   **hands ownership of the data directory to the service user** —
   recursively, including `recordings/` if it exists (IAMT-199: without
   this, a unit running as `User=iamtunnel` loops failing to open
   `state.lock` with "permission denied"). Then writes the unit
   `/etc/systemd/system/iamtunnel-gateway.service` (contents below), then
   `systemctl daemon-reload`, `enable`, `start`. A failure at any step is
   named and exits install with code 3 — fix that step by hand from the
   list below and retry. The unit's `ExecStart` carries the same
   `--public-host <host>` given to install, so `gateway run`, started by
   systemd, hands out that same address in connection strings/enrol codes.
   After `start`, install re-checks `systemctl is-active
   iamtunnel-gateway.service` (up to five tries with a pause): "start"
   succeeds the moment the process forked — before it has had a chance to
   die on its first fatal error. If the daemon never confirms `active`,
   install also exits with code 3, pointing at `systemctl status`/
   `journalctl -u iamtunnel-gateway` instead of reporting success over a dead
   process (IAMT-308/310 — the same defect turned up in the macOS/Windows
   install halves too).
4. Prints the first admin's bootstrap link (below) — with the real public
   host instead of `<this-host>`.

On Windows and macOS, install runs steps 1–2 and 4, and its own service half
(an SCM service or a LaunchDaemon — §1.5 and §1.6) instead of systemd. On any
other OS, install runs only steps 1–2 and 4 and exits with code 3: the
service half exists for Linux, Windows and macOS (run install on the
gateway's own host machine).

**Reissuing the bootstrap token** (24 hours passed and the first admin never
claimed; a repeated install without the flag never touches `state.json`):
```bash
sudo systemctl stop iamtunnel-gateway
sudo iamtunnel gateway install --public-host gw.example.com --rebootstrap
```
`--public-host` is required here too — without it, install (and
`--rebootstrap` as its branch) refuses before anything happens (exit 2, see
§1.3 above). The command issues a fresh token and a fresh 24-hour window,
writes an `admin.op` event (`result:"rebootstrap"`) to `events.jsonl`, and
refuses if an admin already exists (bootstrap is for the FIRST admin only,
SPEC §3.3) or if the gateway is running. Running under `sudo` still leaves
data-directory files owned by the service user `iamtunnel`: before replacing
any file (`state.json`, the bootstrap token), the gateway takes over the
replaced file's ownership (IAMT-332); `sudo -u iamtunnel ...` also works, as
in §5.11.

---

### 1.4. Registering the first administrator (bootstrap claim)

From the administrator's own workstation (with an ed25519 SSH key already
generated), claim admin rights:
```powershell
iamtunnel admin claim 203.0.113.10:2222#43_char_fingerprint:token --key "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... admin@example.com"
```
*(If the key is in a file: `--key "$(Get-Content ~/.ssh/id_ed25519.pub)"` in
PowerShell, or `--key "$(cat ~/.ssh/id_ed25519.pub)"` in bash.)*

**The same thing without a terminal (since 1.3).** Paste the
`iamtunnel-claim://…` string install printed into the single field of the
**Become an administrator** card: Admin tab → **Join** sub-tab. The field
takes the whole string, shows a preview — the action, the gateway's address
and its fingerprint in words — and only the button acts (SPEC §3.6, §7.1).
The client's own key is used automatically; there's no `--key` to pass here.
**Check the fingerprint in the preview against what `gateway status` prints
on the gateway itself** — this is the one moment a human verifies which
gateway they're trusting.

If the string is lost and 24 hours haven't passed, don't reissue the token:
`iamtunnel gateway status` on the gateway reprints it as-is (§1.3).
`--rebootstrap` is only for a token that's actually expired or spent.

Successful execution registers the first user with the `admin` role. The
token burns in the same atomic transaction; reuse is impossible.

---

### 1.4.1. Granting admin rights after setup (the pairing window)

Bootstrap Claim (§1.4) grants rights exactly once per gateway lifetime. Every
later admin is added through the **pairing window**: a current admin opens a
short-lived PIN on the gateway, the new admin pastes one string on their own
machine, and becomes a permanent admin. No terminal is needed for the new
admin: both steps are Admin-tab buttons in the GUI, under the **Join**
sub-tab ("Pairing window" for the current admin, "Become an administrator"
for the new one).

**Step 1 — open the window (current admin).** From a machine that already
has admin rights:
```powershell
iamtunnel admin pairing start
```
The gateway prints a PIN (6 decimal digits, leading zeros allowed — it's a
code, not a number), a reference `host:port#fingerprint`, and a deadline: the
window lives **2 minutes**, then closes itself. Since 1.3 it also prints the
**whole ready-made string** — the one the new admin pastes into one field
(SPEC §3.6); the link and PIN also print separately, for anyone who still
wants to send them apart. A repeated `pairing start` replaces the open
window with a new PIN — the old one stops working the moment it's replaced.
`iamtunnel admin pairing stop` closes it early; the command is idempotent —
if there was no window, it just answers `stopped:false`.

**Step 2 — become admin (new admin).** Since 1.3 the link and PIN travel as
**one string**, pasted into **one field** (SPEC §3.6):

- **in the GUI** — Admin tab → **Join** sub-tab → **Become an administrator**
  card: one "paste what you were given" field and a Join button. The field
  accepts not just the bare `iamtunnel-pair://…` string, but the whole
  copied command `iamtunnel admin pair <ref> <pin>`, a "link space PIN" pair,
  and stray whitespace. Pasting does nothing by itself — a **preview**
  appears underneath: what will happen, the gateway's address and
  fingerprint in words — only the button acts. Read the preview; it's the
  one place a human verifies the gateway's fingerprint, because TOFU is
  absent from every role (SPEC §6.2);
- **from the console** — the same one string:
  ```powershell
  iamtunnel admin pair "iamtunnel-pair://gw.example.com:2222#43_char_fingerprint:012345"
  ```

The key created is the machine's own client key (like an ordinary client),
so after success pairing never needs repeating: the Join card and every
admin command/form on this machine work from then on. A repeated
`admin pair` after success gets "pairing window is not open" — the window
burned in the same write that created the person.

**The new admin's name.** Since 1.3 the client supplies it, rather than the
gateway deriving it from the key's fingerprint: the window asks for a name
in one field, prefilled with the system username. An empty or taken name is
replaced with `admin`, or `admin2`, `admin3`, and so on by the first free
number. A bad name isn't final —
`iamtunnel admin people rename <name> <new-name>` (grants and goals move
with the new name in one write, old-name sessions close; journal lines under
the old name are not rewritten) and
`iamtunnel admin machines rename <id> <name>` (label only: `id`, grants and
journal stay put).

**Window rules** (PROTOCOL §3.4): a wrong or non-six-digit PIN counts as one
pairing-limiter miss; **3** misses from one address in 5 minutes locks
pairing from that address for **3 minutes** (`E_PAIRING_LOCKED`). Address is
the client's IP **without port**: reconnecting with a new source port
doesn't reset the count — every attempt needs a new connection, but they all
share one count. Refusals for "no window" and "window expired" aren't
counted as attempts — a PIN with nothing to check is not evaluated. A closed
window is indistinguishable from a gateway with no pairing at all.

**Passing the secret: the "reference and PIN over different channels" rule
is gone (design decision, 2026-09-17).** Before 1.3 this section required
splitting the link and the PIN across separate channels — a rule that
assumed an attacker reading one channel and not the other. Real-world use
showed the second channel never materializes: the link and the PIN went
through the same message, one screenshot. The rule protected nothing and
doubled the actions on every pairing — so it was removed, not weakened.

What works instead, and isn't just declared:

- **2 minutes** of pairing-PIN lifetime, by the gateway's clock;
- **15 minutes** of machine-invitation lifetime instead of the old 24 hours
  (§1.7) — that was this scheme's real weakness: a secret sitting in
  correspondence for a day;
- **one-time use**: the secret burns in the same atomic `state.json` write
  as its result;
- **three** wrong PINs from one address — an address ban for 3 minutes
  (`E_PAIRING_LOCKED`, rules above);
- a **mandatory preview** before acting: the action, the gateway's address
  and its fingerprint in words — a human sees the fingerprint before
  trusting the gateway;
- everything that just joined is flagged "new" in every list and can be
  removed with one button.

**Accepted residual risk, stated plainly:** anyone who reads the clipboard or
the transfer channel during the two-minute window can become a gateway
administrator. This is the price of one field instead of two, and the owner
accepted it on 2026-09-17 with eyes open. Splitting the link and PIN
manually is still possible — the gateway still prints them so they can be
separated — but the interface no longer forces it.

The PIN is never written to the event journal — `admin.op` records only the
window's deadline and the name of the person created.

*If no admin is left at all (keys lost, someone left without handing over
rights) — see §5.11: local recovery via `iamtunnel gateway pair` on a
stopped gateway. For the FIRST admin, §5.11 was never needed at all: since
1.3, `gateway install` prints the §3.6 string, and `gateway status` reprints
it while it's still good (§1.4).*

---

### 1.5. Setting up on Windows

This is written for Windows Server 2019+ or Windows 10/11 x64. The binary is
the same static build (`CGO_ENABLED=0`); the gateway service lives in the
SCM, no separate systemd needed.

**Placing the binary.** From an administrator console: create a directory,
lock it down to administrators, and only then put the program in it:
```powershell
New-Item -ItemType Directory -Force "C:\iamtunnel" | Out-Null
icacls "C:\iamtunnel" /setowner "*S-1-5-32-544" /T /C /Q
icacls "C:\iamtunnel" /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" /Q
Get-ChildItem "C:\iamtunnel" -Force | ForEach-Object { icacls $_.FullName /reset /T /C /Q }
Copy-Item .\iamtunnel.exe "C:\iamtunnel\iamtunnel.exe"
& "C:\iamtunnel\iamtunnel.exe" version
icacls "C:\iamtunnel"; icacls "C:\iamtunnel\iamtunnel.exe"
```
**Why `icacls` is required (IAMT-445).** The system drive's root grants
every logged-in user the right to create folders in it, and `Modify` on
everything inside them (`NT AUTHORITY\Authenticated Users:(OI)(CI)(IO)(M)`
in a stock `icacls C:\`). A folder created there by an ordinary
`Copy-Item`/`New-Item` inherits that right — and the program launches from
it with administrator rights: the "Restart as administrator" button, the
autostart task (`server install`, running with the highest rights on every
logon), and the gateway service. Whoever can change a file in such a folder
runs administrator code. Order matters: lock down the folder first, then
copy the program in — the copy inherits the already-locked permissions;
the `/reset` line moves files left over from a previous install onto them.
Expected `icacls` output: the folder has exactly
`NT AUTHORITY\SYSTEM:(OI)(CI)(F)`, `BUILTIN\Administrators:(OI)(CI)(F)`,
`BUILTIN\Users:(OI)(CI)(RX)` (plus `NT SERVICE\iamtunnel-gateway:(OI)(CI)(RX)`
after `gateway install`), with no `Authenticated Users` and no inherited
`(I)`; the file carries the same entries with `(I)`. If anything besides
`iamtunnel.exe` is in the folder from before, work out who put it there
while the folder was still open. Install also checks the folder's owner
(IAMT-333, for both the data directory and the binary's folder): a folder
owned by anyone other than `Administrators`, `SYSTEM`, `TrustedInstaller`,
or the account running install (or the service account) is not locked down
— install refuses with code 4 and names the owner, since an owner can always
rewrite permissions back. The folder created by the steps above is owned by
`Administrators`; a refusal means a different account created it — the fix
is the same as install's own step 3: `takeown /f <folder> /r /a`, or create
it fresh.

The Gateway tab's "Move it there for me" button does the same thing on its
own: it requires administrator rights, makes `Administrators` the owner, and
locks down permissions before copying. `server install` locks down
`C:\iamtunnel` the same way, and from any other folder where someone besides
administrators could change the file, it **does not** register the autostart
task (exit code 2, with an explanation). "Restart as administrator" refuses
to relaunch a program that another account could change.

One folder for every Windows machine in this project: `C:\iamtunnel`.
Install's own requirement is only "not inside `C:\Users`" — it hardens ACLs
on whatever folder it finds the binary in.

**Initial setup (`gateway install`).** Run from an **elevated** console
(without elevation, install refuses with code 4 and a "Run as
administrator" hint — the service half writes to `%ProgramData%` and the SCM
database; this applies to `gateway uninstall` too):
```powershell
iamtunnel gateway install --public-host gw.example.com
```
*(A non-default port — same as §1.3: `--port`. The `--public-host`
requirement and its grammar check are the same.)*

**What the command does (idempotent):**
1. Creates the data directory `%ProgramData%\iamtunnel\gateway` (with its
   ACL set right away — step 3), generates the host key `hostkey` and a
   one-time `bootstrap-token` (24 hours) — only after steps 2 and 3
   (R2-CX F-05); the bootstrap link prints with the same `--public-host`
   (IAMT-202, IAMT-200).
2. **Preflight ACL audit (IAMT-315).** Before creating the host key, token,
   or printing the bootstrap link, install reads the current security
   descriptor of the data directory (if one exists from a previous install)
   and of the folder holding the binary. If either carries an **explicit
   (non-inherited) ACCESS_DENIED ACE** for some other principal, install
   refuses (code 4), naming the object and each such ACE (SID or friendly
   name plus a readable access mask) — this is the case where a machine
   administrator placed an explicit DENY that must not be silently erased.
   Inherited DENY entries are ignored, since they came from the parent, not
   a decision about this object. A failure to read the security descriptor
   also refuses — a closed failure, not silent "nothing was there".
3. **Hardens the data directory's and binary folder's ACLs.** Data
   directory: `SYSTEM`/`Administrators` full access, the service account
   full access, nothing else (IAMT-257), owner `Administrators` (R2-CX
   F-07: the owner can always rewrite permissions, and the data directory
   used to stay with whoever created it — `--data-dir` on a path another
   account could create, or even the default path, since `%ProgramData%`
   lets any logged-in user create folders in it). A folder or file inside
   it whose owner isn't `Administrators`, `SYSTEM`, `TrustedInstaller`, the
   service account, or the one running install is not locked down —
   install refuses with code 4 and names the owner: recreate it from an
   administrator console, or reclaim it (`takeown /f <folder> /r /a`) and
   retry. Binary's folder: `SYSTEM`/`Administrators` full access,
   `BUILTIN\Users` and the service account read-and-execute only, owner
   `Administrators` (IAMT-445; IAMT-312: placing it in
   `C:\Program Files\iamtunnel` alone wasn't enough — the virtual service
   account isn't in `BUILTIN\Users` and would get `Access is denied` on
   every start without an explicit ACE). The binary's folder and the binary
   itself are checked and locked through the same handle they were opened
   with, never following a reparse point (IAMT-333): permissions used to be
   set by name (`SetNamedSecurityInfo`), and writing by name follows a
   link — a junction on the path used to redirect the whole lockdown,
   ownership included, to whatever the link named. A binary path that is
   itself a link (junction, symlink, mounted folder) is refused with code
   4 and the real path, same as the data directory; a binary folder owned
   by no one install can vouch for is refused the same way. Hardening the
   data directory also walks existing files and subfolders and sets them
   the same trustee triple; each object is checked and locked through the
   same handle it was opened with (R2-CX F-12), rather than trusting a
   listing's type and then acting by name (a window in which the name
   could become a link to something else). Links and multiply-linked files
   inside the data directory are left alone and only listed. A data
   directory that is itself a link, or reached through one, is refused
   with code 4 and the real path — pass that real path to `--data-dir`
   instead. The data directory stays open until install finishes, and
   nothing above it can be renamed or replaced meanwhile. The folders
   above the data directory are checked first (if any of them, up to the
   volume root, can be renamed, deleted, reconfigured or emptied by anyone
   but `SYSTEM`, `Administrators` and `TrustedInstaller` — an owner always
   counts, since they can grant themselves anything — install refuses with
   code 4 and names them): such a person could swap the locked-down folder
   for their own. The default path passes: `%ProgramData%` and the volume
   root don't grant ordinary accounts that right, and
   `%ProgramData%\iamtunnel` is created by install itself, from an
   administrator console. **This step runs before the first secret
   (R2-CX F-05):** a fresh data directory gets its DACL at creation, and an
   existing one is hardened before install writes the host key, token and
   `state.json` and prints the bootstrap link.
4. **The SCM half (IAMT-258 / IAMT-312).** Creates the `iamtunnel-gateway`
   service under the **virtual account `NT SERVICE\iamtunnel-gateway`** (not
   LocalSystem — it has its own SID, and the ACL is hardened to it), with
   **delayed autostart** and restart on failure (three tries, 10 seconds
   apart), then starts it and confirms the SCM actually reports
   `SERVICE_RUNNING` (not just that it accepted the start command) — if not,
   install exits with code 3, pointing at `services.msc`/Event Viewer (the
   same defect as §1.3/§1.6). The service command line always carries the
   same quoted `gateway run --data-dir … --port … --public-host …`
   (`syscall.EscapeArg`) on creation and on update. A repeated install
   updates the service in place (a new `--public-host` takes effect) and
   never touches `state.json`/`hostkey`/`bootstrap-token`. A repeated install
   of an already-running service updates it in place and does NOT try to
   restart it (Windows would return `ERROR_SERVICE_ALREADY_RUNNING`); if the
   update needs a restart, do it by hand
   (`Restart-Service iamtunnel-gateway`).

**Opening the port.** Install never touches the firewall — it prints the
command to open it yourself (Windows Defender Firewall, an inbound TCP
rule):
```powershell
New-NetFirewallRule -DisplayName "iamtunnel gateway" -Direction Inbound -Protocol TCP -LocalPort 2222 -Action Allow
```

**Checking the service:**
```powershell
sc.exe query iamtunnel-gateway     # state: RUNNING
Get-Service iamtunnel-gateway      # Status: Running
iamtunnel gateway status           # "running" — from holding state.lock
```
Gateway events are written to `events.jsonl` in the data directory (the same
file that goes into a backup, §3.1); liveness is determined by the
`state.lock` lock, not by polling the SCM.

**Re-bootstrapping** (the token burned, the first admin never claimed): stop
the service and repeat install with the flag — a fresh token and a fresh
24-hour window, refused if an admin already exists (SPEC §3.3):
```powershell
Stop-Service iamtunnel-gateway
iamtunnel gateway install --public-host gw.example.com --rebootstrap
Start-Service iamtunnel-gateway
```

**Conflicting ACL with a foreign ACCESS_DENIED (IAMT-315).** If between runs
someone (the machine's administrator, a provisioning script, group policy)
placed an explicit DENY on `%ProgramData%\iamtunnel\gateway` or one of its
files, install refuses with code 4 and prints the object's name and every
ACE found (SID or friendly name plus a readable access mask). Two fixes:

* **Remove the ACE by hand** — object properties → Security → Advanced →
  remove the deny entry for the principal in question (e.g.
  `BUILTIN\Guests`), then repeat `gateway install` with no flags.
* **Deliberately overwrite** — the `--replace-acl` flag tells install:
  "print the ACEs you're about to remove, then set a protected DACL over
  them." Use this too if the folder's access was experimented with before
  and you want the canonical three-trustee shape back:
```powershell
iamtunnel gateway install --public-host gw.example.com --replace-acl
```

**Uninstall.** From an administrator console:
```powershell
iamtunnel gateway uninstall
```
Stops and removes the `iamtunnel-gateway` service. The data directory (host
key, `state.json`, `events.jsonl`) is **not touched** — a later
`gateway install` revives the same gateway identity. If there's no service,
the command succeeds with "nothing to do" (idempotent).

---

### 1.6. Setting up on macOS

This is written for macOS 13+ (Apple Silicon or Intel). Same static binary
(`CGO_ENABLED=0`); the gateway service lives in launchd as a LaunchDaemon.

**Placing the binary:**
```bash
sudo install -m 0755 iamtunnel /usr/local/bin/iamtunnel
iamtunnel version
```

**Initial setup (`gateway install`).** Run as **root** (`sudo`):
```bash
sudo iamtunnel gateway install --public-host gw.example.com
```

**What the command does (idempotent):**
1. Creates the data directory `/Library/Application Support/iamtunnel/gateway`
   (mode `0700`), the host key `hostkey` (`0600`) and a one-time
   `bootstrap-token` (24 hours); the config file, if needed, is
   `/Library/Application Support/iamtunnel/gateway.json`.
2. Creates the service user `_iamtunnel` via `dscl` (IAMT-259): hidden, a
   free system UID below 500, shell `/usr/bin/false`, home `/var/empty`. If
   the user already exists, it's reused.
3. Hands ownership of the data directory and the log directory
   `/Library/Logs/iamtunnel` to `_iamtunnel` — the daemon runs as that user,
   not root.
4. Writes the LaunchDaemon
   `/Library/LaunchDaemons/com.iamtunnel.gateway.plist` (owner `root:wheel`,
   mode `0644`): `RunAtLoad`, `KeepAlive`, `UserName _iamtunnel`,
   `ProgramArguments` with the same `gateway run --data-dir … --port …
   --public-host …`, output to `/Library/Logs/iamtunnel/gateway.log`. A
   repeated install rewrites the plist and restarts the daemon
   (`launchctl bootout` → `bootstrap`) so a new `--public-host`/`--port`
   takes effect immediately; `state.json`/`hostkey`/`bootstrap-token` are
   left alone.
5. Starts the daemon: `launchctl bootstrap system
   /Library/LaunchDaemons/com.iamtunnel.gateway.plist` — then checks (up to
   five tries) `launchctl print system/com.iamtunnel.gateway` that the job
   is really `running`, not merely accepted. If it never confirms running,
   install exits with code 3, pointing at `launchctl print` and
   `/Library/Logs/iamtunnel/gateway.log` (IAMT-308).

**Opening the port.** Install never touches the firewall — it prints the
Application Firewall command; `pf` is left alone:
```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add "/usr/local/bin/iamtunnel" --unblockapp "/usr/local/bin/iamtunnel"
```

**Checking the service:**
```bash
sudo launchctl print system/com.iamtunnel.gateway   # state = running
iamtunnel gateway status                            # "running" — from state.lock
tail -50 /Library/Logs/iamtunnel/gateway.log        # the daemon's output
```

**Re-bootstrapping** (token burned): unload the daemon and repeat install
with the flag; install bootstraps it again at the end:
```bash
sudo launchctl bootout system/com.iamtunnel.gateway
sudo iamtunnel gateway install --public-host gw.example.com --rebootstrap
```

**Uninstall.** As root:
```bash
sudo iamtunnel gateway uninstall
```
Stops and unloads the daemon, removes the plist from
`/Library/LaunchDaemons`. The `_iamtunnel` user and data directory are
**not removed** — a later `gateway install` reuses them, reviving the same
gateway identity. If the plist isn't installed, the command succeeds with
"nothing to do" (idempotent).

---

### 1.7. Setting up a machine on Linux (`enrol` + `server install`)

This is about the **machine** people are let onto (the Server role, SPEC
§3.2.1), not about the gateway. Same static binary (`CGO_ENABLED=0`);
autostart is systemd, unit `iamtunnel-machine.service` (IAMT-249).

**1. Prerequisites.** Check these before setup, or the server refuses to
start (checked before dialing the gateway — "the door doesn't open" — SPEC
§3.2.1):

```bash
ss -lntp | grep '127.0.0.1:22'                      # sshd listens on 127.0.0.1:22
id <osUser>                                         # the OS account exists locally
systemctl list-units --type=service,socket 'ssh*'    # sshd is up as a service or a socket
```

`osUser` is the account the person will use to log in — not root, no
`DOMAIN\` prefix. **Since 1.3, no one on the gateway side names it: the
machine reports its own facts — hostname and OS account — itself, in the
registration request** (SPEC §3.4, step 2). The gateway admin can't know
them and doesn't need to. Right root privileges are needed for every command
in this role: `enrol`, `server start|stop|status|install|uninstall` (SPEC
§3.2.1). Without them the command refuses with `sudo iamtunnel server start`
and does nothing.

**2. Placing the binary:**
```bash
sudo install -m 0755 iamtunnel /usr/local/bin/iamtunnel
iamtunnel version
```

**3. Registering the machine (`enrol`).** The invitation comes from the
gateway admin: since 1.4 it's issued with **one argument, the name** they
choose, `iamtunnel admin machines enrol-code <name>` (in the GUI: the single
field of the **Invite** card, Machines sub-tab of the Admin tab). The name is
their own choice — the label they'll see in the machine list and grant
access against. They still don't enter an OS user — the machine reports it
itself (SPEC §3.4, §7.1). **The invitation lives 15 minutes** (was 24 hours)
and is one-time, so ask for it when you're standing at the machine ready to
paste the string, not an hour ahead:
```bash
sudo iamtunnel enrol 'iamtunnel-enrol://gw.example.com:2222#<gateway key fingerprint>:<secret>'
```
The machine checks the gateway key's fingerprint from the code (a mismatch:
stop, the code isn't spent), generates its own key, sends `enrol` **with its
own OS account** (the name comes from the invitation), raises the tunnel and
runs the OS-user probe. Since 1.4, the machine's own data directory, when run
by a person, is personal — `$XDG_DATA_HOME/iamtunnel/server` (default
`~/.local/share/iamtunnel/server`); the machine-wide
`/var/lib/iamtunnel-machine` (`0700`, owner root; `machine.key` `0600`) is
reserved for the system service `server install` sets up under `sudo`.
Register the machine **using the same command and the same directory** the
server will later run in: `sudo iamtunnel enrol --data-dir
/var/lib/iamtunnel-machine …` if a service will follow.

**4. Autostart (`server install`) is the finish line, not an option.** *The
GUI has no button for this yet* — SPEC §3.4 assigned `Install as a service
and start` in 1.3, and it isn't built; after registration the window offers
only START on the Server tab, i.e. a process that dies at reboot. Set
autostart from the console: `server install` does `enable --now` — installs
and starts the service in one step. Don't skip it — without it, "the machine
is connected" stops being true after the very first reboot. As root:
```bash
sudo iamtunnel server install
```
*(The data directory can be overridden: `sudo iamtunnel server install
--data-dir /srv/iamtunnel-machine` — the same value lands in the unit's
`ExecStart`.)*

**5. Checking:**
```bash
systemctl status iamtunnel-machine          # active (running)
systemctl is-enabled iamtunnel-machine      # enabled
sudo iamtunnel server status                # "the server is running (pid N)"
journalctl -u iamtunnel-machine -n 50       # what the server itself prints
sudo tail -n 20 /var/lib/iamtunnel-machine/events.jsonl   # the machine's own local journal
```

**6. Stop and start.** `server stop` and `server status` work **the same
way** whether the server was started by systemd or by hand from the
console: both talk to the live process through `control.json` in the data
directory and never poll systemd (IAMT-249).

```bash
sudo iamtunnel server stop            # ordinary stop: the door line comes off, the tunnel closes
sudo systemctl stop iamtunnel-machine # the same, via SIGTERM from systemd
sudo systemctl start iamtunnel-machine
sudo iamtunnel server start           # manual console start — still supported
```

**7. Updating the binary.** Replace the file and restart the service; a
repeated `install` is only needed if the binary path or `--data-dir`
changed:
```bash
sudo install -m 0755 iamtunnel.new /usr/local/bin/iamtunnel
sudo systemctl restart iamtunnel-machine
```

**8. Uninstall.** As root:
```bash
sudo iamtunnel server uninstall
```
Stops and removes the unit. The machine's data directory (`machine.key`,
registration, local journal) is **not touched** — a later `install`/
`server start` revives the same machine. If there's no unit, the command
succeeds with "nothing to do" (idempotent).

**Machine on macOS.** Everything the same, but the service half is a
LaunchDaemon `/Library/LaunchDaemons/com.iamtunnel.machine.plist` (label
`com.iamtunnel.machine`, run as root, output to
`/Library/Logs/iamtunnel/machine.log`), managed by `launchctl`, not
`systemctl`: `sudo launchctl print system/com.iamtunnel.machine`,
`sudo launchctl kickstart -k system/com.iamtunnel.machine` (restart),
`sudo launchctl bootout system/com.iamtunnel.machine` (stop). macOS has two
permissions a human must enable: "Remote Login" (System Settings → General
→ Sharing → Remote Login) — without it the preflight check refuses — and
"Full Disk Access", only if the door file sits inside a protected folder
(Desktop, Documents, Downloads, iCloud Drive). `enrol` and `server start`
print this hint themselves; step-by-step instructions for the machine's
owner are in USER.md's macOS section.

---

### 1.8. Setting up a machine on Windows (`enrol` + `server install`), since 1.4

This is about the **machine** people are let onto, under Windows. One
difference from Linux shapes everything else: **registration on Windows is
personal**. One physical machine carries one registration per person who
works on it, and each has their own name, directory, door line, and journal
trail (SPEC §3.2.2). This is exactly the case where two or three people RDP
into a shared server under their own domain accounts.

**1. Put `iamtunnel.exe` in `C:\iamtunnel`, locked down to
administrators** — the same commands as §1.5 ("Placing the binary"). The
autostart task will remember this exact path, so moving the file after
setup breaks autostart (fixed by a repeated `server install`). The task
launches the program with the highest rights on every logon, with no
prompt, so `server install` only registers it for a file no one but an
administrator can change (IAMT-445): from the desktop, "Downloads",
`C:\Tools`, or any folder that inherited the drive root's permissions, it
refuses with code 2 and names who could change the file. In `C:\iamtunnel`
it locks the folder down itself. Every folder up to the volume root is also
checked (R1-CX F-18): a folder another account could rename or empty could
be moved aside along with the locked-down folder, replaced with the
attacker's own.

**2. Make sure the OpenSSH Server service is running**
(`Get-Service sshd`) — without it, the door can't open, and `server start`
refuses before anything else.

**3. Each person registers themselves, under their own account.** The
gateway admin issues an invitation with a name:
`iamtunnel admin machines enrol-code office-pc`. Names must differ between
people on the same machine — the gateway checks and refuses on collision.
Then, from a console started **"as administrator"**, but under YOUR OWN
account (not `runas` as someone else — registration is tied to the
`DOMAIN\user` the command actually runs as, and the gateway verifies it
with a real login):

```powershell
iamtunnel enrol "iamtunnel-enrol://gw.example.com:2222#<fingerprint>:<secret>"
```

The data directory here is personal: `%LOCALAPPDATA%\iamtunnel\server`. A
colleague on the same machine has their own, in their own profile.

**4. Autostart (`server install`) is the finish line, and the order is
strict.** `enrol` first, then `install`: the personal task is named after
your registration and tied to your account — neither exists before
registration, and the command will say so plainly. From the same
administrator console:

```powershell
iamtunnel server install
```

What it does:

1. Registers the scheduled task `\iamtunnel\<registration name>` — trigger
   "on `DOMAIN\user` logon", principal the same `DOMAIN\user`,
   `InteractiveToken` + `HighestAvailable` (no password is stored anywhere —
   the task takes the session's own token).
2. Starts it right away — not waiting for the next logon. This is the
   Windows analogue of `enable --now`.
3. Prints which registration's task was set up and against which directory.

Every Task Scheduler default that would have been a defect is overridden: no
execution time limit (the default `P3D` would kill a healthy server on the
third day), no stopping on battery (otherwise the server dies when a laptop
is unplugged), no stop on idle, and it's allowed to run in an RDP session.

**5. Checking.**

```powershell
schtasks /Query /TN "\iamtunnel\office-pc" /V /FO LIST    # task state
iamtunnel server status                                    # what the server itself says
Get-Content "$env:LOCALAPPDATA\iamtunnel\server\events.jsonl" -Tail 20
```

The GUI's **Set up** tab shows the registration as a pair — `office-pc
(EXAMPLE\dana)`. If two people have windows open on the machine, each sees
their own.

**6. Removal.** `iamtunnel server uninstall` removes the task, but **does
not kill a running server** — Task Scheduler has no graceful stop, and a
killed server would leave the door line hanging. Stop the server
separately — `iamtunnel server stop`, which removes its own line on the way
out. Neither command touches the data directory.

**Registration anchor (R4, THREATS §3.16).** `enrol` writes a second copy of
the registration's routing facts (address, port, fingerprint, machine id) to
`%ProgramData%\iamtunnel\anchors\<your-SID>\enrolment.anchor.json` — a place
an unprivileged process under your own account can't create or rename into.
An elevated `server start` checks the profile record against the anchor on
every run and refuses if they've diverged: swapping the personal directory
stops being a way to steer an elevated process at someone else's gateway. A
machine registered before the anchor existed gets one the first time
`iamtunnel server install` runs from an elevated console — the one moment
the current profile record is trusted (the operator is present and
elevated; the command says so in its output). Until the anchor exists, an
elevated `server start` refuses, naming both paths: `server install` once
more (if it's the same machine), or `enrol` again (if the registration
moved on purpose).

**Upgrading from an older version.** There is no migration. The old
registration lived in `%ProgramData%\iamtunnel`; 1.4 works in
`%LOCALAPPDATA%\iamtunnel\server` and never looks at the old directory —
`server install` on an upgraded machine will say "not registered", and it's
true: repeat steps 3 and 4. No command deletes the old directory; remove it
by hand once the new registration is confirmed working.

**What Windows doesn't have and won't.** A machine service for the Server
role. A service has no person: it would run under one account against one
directory — no one's registration — and every journal line would be signed
by the service, not by whoever actually worked. The gateway *is* installed
as a Windows service (§1.5) — it's impersonal by design, and that's a
different thing.

**No isolation between registrations, and none is promised.** Windows
administrators aren't isolated from each other by the OS's own design:
anyone can read and rewrite anyone else's files, including the shared
`%ProgramData%\ssh\administrators_authorized_keys`. What 1.4 gives is
attribution: it's visible whose registration did what.

---

## 2. Checking that everything is alive

One single command gives a quick health read.

### 2.1. Local check on the gateway host
```bash
sudo iamtunnel gateway status
```

### 2.2. Remote check from an admin machine
```powershell
iamtunnel admin gateway status
```
*(For automated parsing, add `--json`: `iamtunnel admin gateway status --json`.)*

---

### 2.3. What each output line means

The local and remote commands print different fields; only the ones they
actually print are listed here.

**Local `iamtunnel gateway status` (on the gateway host):**

| Output line | Example value | Meaning |
|---|---|---|
| `running (data dir …)` / `not running (data dir …)` | `running` | Liveness comes from holding `state.lock`, which only a running gateway holds. |
| `host key fingerprint: …` | `SHA256:hQ7...` | The gateway host key's SHA-256 fingerprint. **Must match** the one in every connection string and enrol code issued. |
| `people=N machines=N grants=N` | `people=3 machines=2 grants=5` | Record counts in `state.json`: people, machines, grants. |

The binary's own version is printed by a separate command, `iamtunnel version`.

**Remote `iamtunnel admin gateway status`:**

| Field (in `--json`) | Line | Meaning |
|---|---|---|
| `online` | `online=true` | The gateway answered its own status exec channel. |
| `fingerprints` | — (JSON only) | The gateway's host-key fingerprint; `iamtunnel admin gateway fingerprint` prints the same value. **Must match** what's in issued connection strings. |
| `machinesOnline` | `machines-online=12` | Machines (Windows/Linux/macOS servers) the gateway currently holds an active outbound tunnel with, past the initial `door.status` check. |
| `machinesVerified` | `machines-verified=14` | Total registered and verified machines in `state.json` (including ones currently off or offline). |
| `sessions` | `sessions=2` | Users connected right now through a terminal to a remote machine. |
| `serverTime` | `server-time=2026-09-13T12:00:00Z` | The gateway's clock (the single source of truth for deadlines, SPEC §6.4). |
| `risk.classifier` | `classifier=both` | The risk source: local rules (`rules`), the external classifier (`ai`), or the stricter of both (`both`). |
| `pairing` | `pairing: a window is OPEN, closes itself 2026-09-24T12:02:00Z` / `pairing: no window is open` | Whether a pairing window is open right now and when it closes itself. The PIN is never shown here — it only ever appears in the `pairing.start` reply. The line can be absent: a gateway older than IAMT-331 says nothing about it, and that silence isn't "no window". |

### 2.3.1. Live command-risk switching

The risk mode can be read and changed on a running gateway — no restart
needed:

```powershell
iamtunnel admin risk mode
iamtunnel admin risk mode block
iamtunnel admin gateway status
```

`log` only journals yellow and red verdicts, `warn` adds a warning, `ask`
warns yellow but requires human approval before red, `block` warns yellow
and refuses a classified red `exec` with exit status 126. Interactive shells
are never classified, so `block` never tears down a running shell session or
blocks its keystrokes. The switch applies to the next classification;
current sessions aren't killed.

Roll back with the same command, no restart:

```powershell
iamtunnel admin risk mode warn
```

After a write, the gateway shows `source=live` in the `risk mode` reply and
in `gateway status`. The value is saved in the data directory and survives a
restart.

### 2.3.2. Risk classifier source

Set `risk_classifier: "rules"`, `"ai"` or `"both"` in the gateway's config.
The default is `rules`. `ai` and `both` need an external classifier key in
the existing `external_risk_observation_key_file` field; the name is kept
for compatibility, but now it drives an active decision, not just
observation.

In `ai`, each `exec` waits up to 800 ms for an external answer and takes its
verdict; in `both`, local and external scores are compared, and a red local
verdict is accepted right away with no network wait. On an external service
error, `both` falls back to the local score and shows one warning line,
while `ai` stops the exec before it reaches the machine with
`E_RISK_CLASSIFIER_UNAVAILABLE`; the failure is journaled in `session.risk`,
and the operational refusal separately in `session.drop`. The message
distinguishes an invalid/expired key (`401/403`) from an unreachable service
(timeout/`5xx`) and suggests either `rules`/`both` in config or
`iamtunnel admin risk mode log` / `iamtunnel admin risk mode warn`. Only the
scrubbed command ever goes to the external service, never interactive shell
input.

---

Under `ask`, a red exec never reaches the machine. Its warning carries a
machine-readable `approval-id=apr-...`; approve with
`iamtunnel admin risk approve <approval-id>`, then repeat the exact command
string. Approval is signed with the same key as the command itself — the
on-call engineer should know: the gateway's journal cannot tell a human who
pressed approve from an AI agent on the same machine. So `ask` is a safety
net against carelessness and accidental runs (a command seen before it ran,
a script that took the wrong branch), not against an agent that knows about
`risk.approve` — such an agent approves itself. If a procedure requires
human oversight, that oversight is a human OUTSIDE the machine reading the
warning, or `block` mode. An approval is tied to the person, machine and
full command string, lives 5 minutes, and burns after one run. Look for
separate `risk.approval` entries in the journal with results `pending`,
`approved`, `consumed`, `expired` or `denied`.

### 2.4. OS-level checks
If the gateway process isn't answering, check the system service and port:
```bash
sudo systemctl status iamtunnel-gateway
sudo ss -tulpn | grep 2222
```

---

## 3. Backup and restore

Copying `/var/lib/iamtunnel` with plain `cp` or `rsync` on a running gateway
is **forbidden**: `state.json` and `events.jsonl` are being written
concurrently, so nothing guarantees a consistent copy (risking a corrupted
JSON file).

A backup is the gateway's own atomic operation, packing `state.json` and
`events.jsonl` into one tar.gz archive; the pair is read as one — on a live
gateway (`iamtunnel admin gateway backup`) under the same lock that
access-changing commands hold from a `state.json` write to the matching
journal line, and the local command re-reads and retries if the files
changed while it was reading, refusing rather than returning a pair from two
different moments on a continuously writing gateway (F-22, review round 1).

---

### 3.1. Making a backup

**Locally on the gateway:**
```bash
sudo iamtunnel gateway backup --out /var/backups/iamtunnel/backup-$(date +%Y%m%d_%H%M%S).tar.gz
```

**Remotely through the admin console:**
```powershell
iamtunnel admin gateway backup
```
*(The remote command creates a snapshot in the gateway's own local storage
and returns the archive's id, size and SHA-256.)*

**Suggested frequency:**
- `state.json` and `events.jsonl`: hourly via cron/systemd timer, 30-day
  retention.
- The `recordings/` directory: a separate incremental process daily (e.g.
  `rsync -a --ignore-existing /var/lib/iamtunnel/recordings/
  backup-server:/storage/iamtunnel-recordings/`).

---

### 3.2. Verifying a backup (a mandatory test)

> **Rule:** a backup never restored is not a backup. Verify weekly on a
> scratch directory, without stopping the live service.

**Test-restore steps:**

1. Create a verification archive:
   ```bash
   sudo iamtunnel gateway backup --out /tmp/verify-backup.tar.gz
   ```
2. Check the gzip and tar integrity:
   ```bash
   tar -ztvf /tmp/verify-backup.tar.gz
   ```
   *The listing must show exactly two files: `state.json` and `events.jsonl`.*
3. Create a scratch directory:
   ```bash
   mkdir -p /tmp/iamtunnel-restore-check
   ```
4. Restore into it, skipping the confirmation prompt:
   ```bash
   iamtunnel gateway restore /tmp/verify-backup.tar.gz --data-dir /tmp/iamtunnel-restore-check --yes
   ```
5. Confirm the unpacked state is valid and readable:
   ```bash
   iamtunnel gateway status --data-dir /tmp/iamtunnel-restore-check
   ```
   *This should return status cleanly, with no schema parse error.*
6. Remove the scratch directory:
   ```bash
   rm -rf /tmp/iamtunnel-restore-check /tmp/verify-backup.tar.gz
   ```

---

### 3.3. `state.json` corrupted: the gateway won't start, restore fixes it

**Symptom.** `gateway run` (and the `iamtunnel-gateway` service) refuses to
start at all — a deliberate decision (IAMT-179): a half-working service with
amnesia is more dangerous than a stopped one. The service journal and console
show, verbatim:

```text
gateway run: corrupt state file "/var/lib/iamtunnel/state.json": <reason>; content snippet: "<first 80 bytes>" (opened in read-only mode, run 'gateway restore <backup>' to recover)
```

The gateway has no "run read-only" mode.

**Restoring from backup** (e.g. after a disk failure corrupted `state.json`):

1. Make sure the service is stopped (it likely already failed to start):
   ```bash
   sudo systemctl stop iamtunnel-gateway
   ```
   This isn't optional: restore takes the same `state.lock` as `gateway run`
   and refuses on a running gateway ("a gateway is running in … and holds
   the state lock"). Restoring under a live gateway would be pointless: it
   holds the journal descriptor and would overwrite `state.json` from memory
   on its next save, silently undoing the restore.
2. Restore from a verified archive:
   ```bash
   sudo iamtunnel gateway restore /var/backups/iamtunnel/backup-20260912_120000.tar.gz --yes
   ```
3. Read what the command printed after the first line. It names two things,
   both needed if you restored the wrong archive:
   - `state.json.pre-restore-<moment>` — the state file as it was before
     restoring (created only if one was there). To undo, copy it back over
     `state.json` with the service stopped.
   - `events-<moment>.jsonl` — the journal as it was before restoring. **The
     journal is not rolled back:** `events.jsonl` is append-only, and
     restore doesn't replace it with the archive's copy — it sets the
     current one aside under a name history already reads (`ReadHistory`
     reads both archived `events-<stamp>.jsonl` files and the current one).
     So the History tab and journal export still show every event,
     including ones written after the backup; the new `events.jsonl` starts
     with a `log.rotate` line naming the archive. The archive's own journal
     is put in place **only** if the journal directory was empty (a clean
     disk) — otherwise events would appear twice in history.
   - If the archive is unrelated, corrupted, or its `state.json` fails
     schema validation, restore refuses **before** any replacement: nothing
     on disk changes, and the console shows the reason. The archive entry's
     type is checked too — only a regular file (`tar.TypeReg`) named
     `state.json` is accepted; a symlink or a directory by that name is
     refused.
4. Check the restored files' permissions (should be owned by
   `iamtunnel:iamtunnel`, mode 0600). Restore itself preserves ownership —
   before replacing any file the gateway takes over the replaced file's
   owner, and set-aside copies get the directory's owner (IAMT-332), so the
   step below is only a check (or needed on older versions without that
   transfer):
   ```bash
   sudo chown -R iamtunnel:iamtunnel /var/lib/iamtunnel
   sudo chmod 0600 /var/lib/iamtunnel/state.json /var/lib/iamtunnel/events.jsonl
   ```
5. Start the service:
   ```bash
   sudo systemctl start iamtunnel-gateway
   ```
6. Check status:
   ```bash
   sudo iamtunnel gateway status
   ```

Without a backup, `state.json` has to be repaired by hand from the corrupted
file (schema-1 JSON); the service simply won't run with a broken file.

---

## 4. Host key rotation

### 4.1. Why and when
- **Why:** planned key rotation (e.g. yearly), migrating the VPS to new
  hardware, or a suspected compromise of the private key
  `/var/lib/iamtunnel/hostkey`.
- **When:** strictly inside a planned maintenance window, with admins and
  users notified beforehand.

---

### 4.2. What connected users will feel

- **Active terminal sessions:** keep working without interruption until the
  person finishes normally or the grant expires.
- **People trying to connect:** an attempt with the old connection string is
  **instantly blocked** by the iamtunnel client with the diagnostic:
  ```text
  the gateway host-key fingerprint changed: expected <expected>, got <got> — obtain a new connection string from the administrator
  ```
  The client refuses to connect, protecting the person from a spoofed
  server (there is no TOFU in the protocol; the gateway key is hard-pinned).
- **Machines:** in v1, the gateway's fingerprint is pinned on the machine at
  registration. After rotating the key, machines get a fingerprint mismatch
  on their next tunnel reconnect and cannot come back online until
  re-registered.

---

### 4.3. Step-by-step rotation

> **⚠️ There is no transition period in v1 (design decision, 13.09,
> IAMT-152).** From the moment the gateway restarts with a new key, **every**
> client and **every** machine pinned to the old one is refused. A remote
> admin rotating via `iamtunnel admin` also loses access until they get the
> new string. Plan rotation as a maintenance window: prepare to distribute
> new connection strings and re-register every machine ahead of time
> (`admin machines remove` + `admin machines enrol-code <name>` +
> `iamtunnel enrol` on the machine + reissuing grants — step 6 below).
> **Issue invitations as you walk the fleet, not all at once ahead of
> time:** since 1.3 an invitation lives 15 minutes, and a batch issued at
> the start would expire before you reach the last machine. If key
> compromise is suspected, that's exactly the intended behavior — the old
> key stops working immediately.

1. Rotate the host key:
   - **Locally on the gateway:**
     ```bash
     sudo iamtunnel gateway rotate-hostkey --yes
     ```
   - **Or remotely through the admin console:**
     ```powershell
     iamtunnel admin gateway rotate-hostkey --yes
     ```
   The gateway generates a new ed25519 private key and saves it to disk (the
   old key is kept as `hostkey.old`). The moment of rotation is recorded as
   a `hostkey.rotate` event:
   ```bash
   sudo grep -F '"type":"hostkey.rotate"' /var/lib/iamtunnel/events.jsonl
   ```
2. Restart the gateway service to apply the new key:
   ```bash
   sudo systemctl restart iamtunnel-gateway
   ```
3. Get the new fingerprint:
   ```bash
   iamtunnel gateway status
   ```
4. Get your own admin access back. Your own connection string is also
   pinned to the old key, so you assemble the first one yourself — on the
   gateway, from step 3's fingerprint. The fingerprint in the string has
   **no** `SHA256:` prefix (43 base64 characters; the parser rejects a
   prefixed string):
   ```powershell
   iamtunnel client connect-string "iamtunnel://gw.example.com:2222/<your-name>#<43-char fingerprint>" --replace
   ```
5. Generate new connection strings for everyone else:
   ```powershell
   iamtunnel admin people connection-string <person>
   ```
   Send it to them. They update their client with `--replace`:
   ```powershell
   iamtunnel client connect-string "iamtunnel://gw.example.com:2222/<person>#<43-char fingerprint>" --replace
   ```
6. Re-register every machine. The gateway's fingerprint is pinned at
   registration, and there's no automatic re-pin. Re-registering under the
   **same name** isn't possible while the old machine record exists, and
   removing it **revokes all its grants** (and ends its sessions) — so
   record the grants first and reissue them after. For each machine, as you
   walk the fleet (an invitation lives **15 minutes**):
   1. Record its grants — who, until when, which capability:
      ```powershell
      iamtunnel admin grants list
      ```
   2. Remove the old record:
      ```powershell
      iamtunnel admin machines remove <id> --yes
      ```
   3. Issue an invitation for the same name (a name is required since 1.4):
      ```powershell
      iamtunnel admin machines enrol-code <name>
      ```
   4. On the machine, with administrator rights, register with step 3's
      string (again, no `SHA256:` prefix on the fingerprint):
      ```powershell
      iamtunnel enrol "iamtunnel-enrol://gw.example.com:2222#<43-char fingerprint>:<secret>"
      ```
   5. Reissue the grants from step 1, each with its own deadline and
      capability:
      ```powershell
      iamtunnel admin grants grant <person> <machine-name> <until-ISO8601|""> --cap exec
      ```
   In the journal this shows as `grant.revoke … machine-removed` on removal
   and new `grants.grant` entries on issue — that's expected.

---

## 5. Incident handling

**This document's event dictionary** is the machine-checked block below;
gate 13 (`scripts/check_runbookevents.go`, IAMT-120) checks it against the
code. Names in `written` are ones the code writes; names in
`notWrittenThisBuild` exist in the dictionary but aren't written in this
build, each caveated in the prose as "not written in this build" — this list
is empty as of IAMT-119, and gate 13 won't let a name the code writes slip
back into it silently. One word can be both a control-channel operation
name and an event name: `door.sanitize` is both (since commit 5c6d0dc,
IAMT-103), which is why it's in the block. `door.status` is only an
operation — there's no event by that name, and it's not in the block.
`session.watch` — a machine's owner started watching a session in progress
(IAMT-343); the gateway writes it, once per session, not per poll — search by
the machine's name in `actor` and the session id in `object`. `recording.export`
— a window event, not the gateway's: a person exported a session's text to
files (IAMT-342); look for it in whichever role's journal the window was
running as, with the export folder path in `details` and who exported it in
`actor`.

```iamtunnel-runbook-events-v1
{"written":["admin.op","auth.failure","door.close","door.open","door.sanitize","grant.revoke","hostkey.mismatch","hostkey.rotate","log.rotate","machine.connected","machine.disconnected","machine.rejected","recording.export","risk.approval","session.drop","session.risk","session.start","session.stop","session.watch"],"notWrittenThisBuild":[]}
```

---

### 5.1. Incident 1: a person cannot log in to a machine

**User-visible symptoms:**
- A window error: *"Access to this machine is currently unavailable"*.
- Or *"gateway … refused the connection: ssh: handshake failed: ssh: unable
  to authenticate…"* — authentication failed (including a triggered
  brute-force defense; the reason text isn't sent to the client, see step 1).
- Or: *"the gateway host-key fingerprint changed: expected <expected>, got
  <got> — obtain a new connection string from the administrator"*.

**On-call diagnostic path:**

1. **Check auth events in the gateway journal.** The only failed-auth event
   type is `auth.failure`; there's no separate "unknown key" or "wrong key"
   event, and a single failed attempt isn't journaled at all — an entry
   appears only when the brute-force defense triggers. The case lives in
   `result`, so search by that field's value, not by event type:
   ```bash
   sudo grep '"type":"auth.failure"' /var/lib/iamtunnel/events.jsonl
   ```
   - `result` like `rate limited until 2026-09-13T12:34:56Z` — the
     brute-force defense triggered: more than 10 failed attempts in 5
     minutes (by address+key pair, or by address). Ready search:
     ```bash
     sudo grep '"type":"auth.failure"' /var/lib/iamtunnel/events.jsonl | grep -F '"result":"rate limited until'
     ```
     `address` and `fingerprint` are filled in — the key whose attempts
     triggered the limit; the pair (address, key) or the whole address is
     banned for 15 minutes.
     *Action:* wait out the ban, or use `fingerprint` to find whose key is
     being brute-forced.
   - No `auth.failure` records at all does **not** mean no attempts
     happened. A refusal with an unregistered key or a wrong name in
     `<person>:<machine>` is only journaled when the limiter triggers (see
     above). Check the registered keys and the client-side login; add the
     right public key if needed:
     ```powershell
     iamtunnel admin people keys add <name> "ssh-ed25519 AAAA..."
     ```

2. **Check the grant exists and hasn't expired:**
   ```powershell
   iamtunnel admin grants list
   ```
   - No grant: create one:
     ```powershell
     iamtunnel admin grants grant <person> <machine> 2026-09-12T20:00:00Z
     ```
     A grant without `--cap` gets `exec` — the only kind of access the
     gateway can fully check before it reaches the machine. `--cap shell`
     grants an interactive terminal, which no safety mode can touch — the
     CLI confirms such a grant with a separate warning.
   - `until` is in the past: create a fresh grant.

3. **Check the target machine's status:**
   ```powershell
   iamtunnel admin machines list
   ```
   The output has `id`, `name`, `state`, `online`, `osUser`, `doorState`,
   `doorOpen`, `reservations`.
   - `online: false` → the machine is offline (see Incident 5.2).
   - `state: enrolled` instead of `verified` → the machine's initial
     account check never finished:
     ```powershell
     iamtunnel admin machines verify <machine-id>
     ```

---

### 5.2. Incident 2: a machine won't come online

**Symptoms:** `iamtunnel admin machines list` shows `online: false` for the
target machine.

**Diagnostic path:**

1. **Check the gateway journal for the machine's connection attempts:**
   ```bash
   sudo grep -E '"type":"(machine\.|enrol\.)' /var/lib/iamtunnel/events.jsonl | tail -n 100
   ```
   - No events at all: the machine's network traffic isn't reaching the
     gateway.
   - `machine.connected` appears, but the machine never becomes
     `online: true`, and there's no `machine.disconnected`: the tunnel came
     up, but the initial `door.status` check got no reply in 5 seconds. The
     journal has no separate event for this timeout (the gateway silently
     retries) — the reliable sign is "connected but not online".
   - `machine.connected` followed by `machine.disconnected` with
     `control-read-error` or `keepalive-timeout`: the control channel or
     transport died after connecting.
   - The machine's local sshd key changed — a sign of machine substitution,
     journaled plainly since IAMT-119:
     ```bash
     sudo grep -F '"type":"hostkey.mismatch"' /var/lib/iamtunnel/events.jsonl
     ```
     Look nearby for people's login refusals for this machine:
     `session.drop` with `result: "machine is not verified"`:
     ```bash
     sudo grep -F '"result":"machine is not verified"' /var/lib/iamtunnel/events.jsonl
     ```

2. **Check the OpenSSH service on the machine itself (local login):**
   ```powershell
   Get-Service sshd
   ```
   If stopped:
   ```powershell
   Start-Service sshd
   ```
   Confirm sshd listens on `127.0.0.1:22`:
   ```powershell
   Test-NetConnection -ComputerName 127.0.0.1 -Port 22
   ```

3. **Check network reachability from the machine to the gateway:**
   ```powershell
   Test-NetConnection -ComputerName 203.0.113.10 -Port 2222
   ```
   *If `TcpTestSucceeded: False`, outbound traffic is blocked by a
   corporate firewall or router.*

4. **Check the iamtunnel process on the machine:**
   ```powershell
   Get-Process iamtunnel
   iamtunnel.exe server status
   ```
   If the process crashed, restart the server role:
   ```powershell
   iamtunnel.exe server stop
   iamtunnel.exe server start
   ```

---

### 5.3. Incident 3: access was revoked but the session is still alive

**Symptoms:** the admin revoked a grant, but a suspicious session still
shows as active, or the person is still sending commands.

**Diagnostic path:**

1. **Check active sessions on the gateway:**
   ```powershell
   iamtunnel admin sessions active
   ```
   Shows session IDs (e.g. `session:1`).

2. **Force-kill the session:**
   ```powershell
   iamtunnel admin sessions kill <session-id> --yes
   ```
   *(Immediately tears down the SSH proxy channel on the gateway side.)*

3. **Confirm the grant is revoked:**
   ```powershell
   iamtunnel admin grants revoke <person> <machine> --yes
   ```

4. **Confirm the door is physically closed on the Windows machine:**
   ```powershell
   Get-Content C:\ProgramData\ssh\administrators_authorized_keys
   ```
   *`server start` writes the door line to
   `%ProgramData%\ssh\administrators_authorized_keys` — the file Windows
   OpenSSH reads for administrators (IAMT-156). If the server runs with
   `--key-file <path>` (a changed `AuthorizedKeysFile` in sshd_config's
   `Match Group administrators` block), check that path instead — it's
   visible in the process command line:
   `Get-CimInstance Win32_Process -Filter "Name='iamtunnel.exe'" |
   Select-Object ProcessId,CommandLine`.*
   If a line with `restrict,pty,from="127.0.0.1"` and an `iamtunnel-door=`
   marker is still there, the server failed to run the close for some
   reason:
   - The temporary key in the line is inert (the private half is already
     gone from gateway memory), but the line should still be removed.
   - Run on the machine:
     ```powershell
     iamtunnel.exe server stop
     iamtunnel.exe server start
     ```
     `start` runs `SweepStale`, removing every stale iamtunnel line.

---

### 5.4. Incident 4: session recordings stopped appearing

**Symptoms:** sessions run, but `.cast`/`.txt` or `.exec.jsonl` files don't
show up under `/var/lib/iamtunnel/recordings/` or in
`iamtunnel admin recordings list`.

**Diagnostic path:**

1. **Check free space on the gateway disk:**
   ```bash
   df -h /var/lib/iamtunnel
   ```
   *If a recording can't be created (including a real out-of-space
   condition, ENOSPC), the gateway refuses the session immediately and
   journals a `session.drop` whose `result` starts with `recording:`. Ready
   search:*
   ```bash
   sudo grep '"type":"session.drop"' /var/lib/iamtunnel/events.jsonl | grep -F '"result":"recording:'
   ```

2. **Check permissions on the recordings directory:**
   ```bash
   ls -ld /var/lib/iamtunnel/recordings
   ```
   Should be owned by `iamtunnel:iamtunnel`, mode `0700` or `0750`. If not:
   ```bash
   sudo chown -R iamtunnel:iamtunnel /var/lib/iamtunnel/recordings
   sudo chmod 0700 /var/lib/iamtunnel/recordings
   ```

3. **Check the session type in the events:**
   ```bash
   sudo tail -n 50 /var/lib/iamtunnel/events.jsonl | grep "session\."
   ```
   - Shell and PTY exec are saved as three files sharing a base name:
     `<base>.cast`, `<base>.txt`, `<base>.meta`; exec without a PTY is
     `<base>.exec.jsonl` plus `.meta`.
   - Recordings interrupted by a gateway crash get `exit_reason` `gateway
     restart` and no `ended` field.
   - Confirm you're checking the right sub-directories:
     `/var/lib/iamtunnel/recordings/<machine>/<YYYY-MM-DD>/`.

---

### 5.5. Incident 5: running out of disk space

**Symptoms:** the `/var/lib/iamtunnel` partition is filling up (watch `df`;
this build's status output doesn't show fill percentage — see §2.3).
`recordings_disk_stop_percent` triggers rotation of old recordings; it does
not refuse new sessions. A separate `recordingRefusePercent` refuses new
recordings; when a recording can't be created (including ENOSPC), sessions
refuse with `session.drop`, `result` starting with `recording:` (see §5.4).

**Diagnostic path and actions:**

1. **Find the largest recording directories:**
   ```bash
   du -h --max-depth=2 /var/lib/iamtunnel/recordings | sort -hr | head -n 20
   ```
2. **Check the event journal's size:**
   ```bash
   ls -lh /var/lib/iamtunnel/events.jsonl
   ```
   If it's grown to several gigabytes, stop the gateway service first
   (`sudo systemctl stop iamtunnel-gateway`) — a running process holds the
   file open and keeps writing to the renamed file after `mv`, leaving the
   new `events.jsonl` empty. Then:
   ```bash
   sudo mv /var/lib/iamtunnel/events.jsonl /var/lib/iamtunnel/events-$(date +%Y%m%d).jsonl
   sudo touch /var/lib/iamtunnel/events.jsonl
   sudo chown iamtunnel:iamtunnel /var/lib/iamtunnel/events.jsonl
   sudo chmod 0600 /var/lib/iamtunnel/events.jsonl
   sudo systemctl start iamtunnel-gateway
   ```
   The archive name `events-<stamp>.jsonl` matters — history only
   recognizes archives with that shape.

   > **Automatic archive retention (since R4 F-11, 24.09.2026).** The
   > manual procedure above is no longer routine maintenance: on its
   > one-second tick, the gateway deletes rotation archives older than
   > `30 days` (`JournalArchiveRetentionDays`) and keeps no more than `20`
   > (`JournalArchiveMaxCount`), newest surviving. Each deletion is an
   > `admin.op` event with `result: journal.archive.prune`. Pruning only
   > touches rotation archives; tagged restore names
   > (`events-<...>-restore...`) and anything you placed there yourself are
   > left alone. The manual step above still helps when a lot of space is
   > needed at once; tighten retention via `JournalArchiveRetentionDays` /
   > `JournalArchiveMaxCount`.

3. **Archive old recordings to external storage:**
   ```bash
   sudo tar -zcvf /tmp/recordings-archive-$(date +%Y%m).tar.gz /var/lib/iamtunnel/recordings/*-*-*
   # copy the archive to long-term storage
   scp /tmp/recordings-archive-*.tar.gz backup-user@nas.example.com:/storage/archives/
   ```
4. **Delete recordings older than 90 days:**
   ```bash
   sudo find /var/lib/iamtunnel/recordings -type f -mtime +90 -delete
   sudo find /var/lib/iamtunnel/recordings -type d -empty -delete
   ```

---

### 5.6. Incident 6: the door is stuck open on a machine, but there are no sessions

**Symptoms:** all sessions ended, the tunnel is torn down, but the Windows
authorized-keys file still shows an iamtunnel key line
(`%ProgramData%\ssh\administrators_authorized_keys`, or the path from
`--key-file` — see §5.3, step 4).

**Diagnostic path:**

1. **Assess the actual danger (threat-model analysis):**
   - **Layer 0:** the key line carries `from="127.0.0.1"`. It can't be used
     from outside — OpenSSH only accepts this key locally.
   - **Layer 1:** the door key's private half was generated once by the
     gateway and existed only in its memory. It's destroyed the moment the
     session or tunnel ends.
   - **Conclusion:** the stray line on the machine is **completely inert**.
     No one in the world holds the private key for it.

2. **Why the watchdog (layer 3) didn't fire:**
   The door watchdog (`server doorwatch <door-id> <parent-pid> <keyfile>`)
   waits for the parent process's handle via `WaitForSingleObject`. If
   Windows rebooted abruptly (BSOD or power loss), the watchdog simply had
   no chance to run.

3. **How to safely remove the stray line:**
   - **Ordinary way:** restart the `iamtunnel server`:
     ```powershell
     iamtunnel.exe server start
     ```
     `SweepStale` runs at start, clearing every `iamtunnel-door=` line while
     keeping any other administrator keys byte-for-byte.
   - **Manual way (elevated PowerShell):**
     ```powershell
     $path = "C:\ProgramData\ssh\administrators_authorized_keys"
     (Get-Content $path) | Where-Object { $_ -notmatch 'iamtunnel-door=' } | Set-Content $path
     ```
   - Check file permissions (only SYSTEM and Administrators should have
     access):
     ```powershell
     icacls "C:\ProgramData\ssh\administrators_authorized_keys"
     ```

---

### 5.7. Incident 7: `door.close` doesn't get confirmed — the gateway drops the epoch and requires a machine reconnect

**Both ends of a door's life are in the journal.** Opening a door — granting
admin-level entry to a Windows machine — is recorded as `door.open`; closing
it, `door.close`; each carries an outcome (`ok`, `refused`, `timeout`) in
`result`. Get one door's full history:
```bash
sudo grep -E '"type":"door\.(open|close|sanitize)"' /var/lib/iamtunnel/events.jsonl
```
An open with no matching close means the door is still open, or the close
never got confirmed — read on.

**This is normal.** A confirmed refusal of `door.close` (or two `door.close`/
`door.sanitize` timeouts in a row) means the gateway couldn't confirm the
line was removed, and it follows the §5.2 protocol `closing` rule: **close
the transport and wait for a new epoch** — expect the machine to reconnect
and pass the initial `door.status` check again. The gateway won't let anyone
onto this machine until the door line is confirmed removed:
`verdict: new-epoch-required`.

**Symptoms:**
- `iamtunnel admin machines list` shows the machine `online: false` when it
  was `online: true` a minute ago.
- A person trying to log in gets the standard refusal: "Access to this
  machine is currently unavailable".
- `events.jsonl` has a `door.close` event with `result: "failed"` and
  `details.verdict: "new-epoch-required"`:
  ```bash
  sudo tail -n 100 /var/lib/iamtunnel/events.jsonl | grep "door.close"
  ```

**Why this is correct, not broken.** A close refusal is the one case where
the gateway can't trust the state of the machine's key file. The refusal
direction is deliberately safe: better to lock everyone out than to let
someone in with an uncleaned line. The machine isn't gone forever — its
return needs no admin action.

**Diagnostic path:**

1. **Confirm the event is really `new-epoch-required`** (the grep above). If
   so, no further action is needed — it worked as designed.
2. **Wait for the machine to reconnect.** The machine's agent watches its
   tunnel and reconnects on its own. A new epoch always starts with
   `door.status`: if the line really is still there, the gateway closes the
   found `doorId` as a foreign door (`reason: "reconnect"`) or cleans it via
   `door.sanitize` (a corrupted marker), then re-confirms via status — only
   then does the machine become `online: true` again.
3. **If it doesn't reconnect for a long time** — check the machine per
   Incident 5.2 (sshd service, the `iamtunnel` process, gateway
   reachability).
4. **If this keeps happening** — the machine has a stuck door line: run
   `iamtunnel.exe server stop` and `iamtunnel.exe server start` on it
   (start's `SweepStale` removes every `iamtunnel-door=` line), then check
   the machine's local journal for a watchdog stop failure at `door.close`.

**When the gateway trusts the machine as alive again.** Only after the new
tunnelEpoch's initial `door.status` confirms the line is gone — either
directly (`installed:false`) or after a confirmed cleanup (closing a foreign
door, or `door.sanitize`) plus a confirming status. Until then,
`MachineOnline` is false, and ACL admits no one to it.

### 5.8. Incident 8: a machine's administrator failed one login with their own key, and a retry worked

**Symptom.** A Windows-machine administrator's own (non-iamtunnel) key login
is refused once, and the next attempt a second later succeeds. The gateway's
`events.jsonl` shows a `door.open` or `door.close` for this machine in the
same second. The machine's own sshd event log
(`Get-WinEvent -LogName OpenSSH/Operational`) is worth checking alongside
the refusal.

**Cause — a known Windows limitation, not a misconfiguration.** Every door
open/close atomically replaces the key file: a new file is written
alongside and swapped in with one call (IAMT-214: the protected ACL is set
before the swap). While the swap is in progress (microseconds), opening the
file for read without delete permission fails — and OpenSSH reads it exactly
that way. A read caught in this window gets `ERROR_SHARING_VIOLATION`, and
that one login attempt is refused.

**What to do.** Nothing but retry the login: the file is intact after the
swap, the keys are in place. If refusals repeat back-to-back, or without a
matching `door.open`/`door.close`, that's a different incident: check the
file's ACL (§6, item 3b) and the door lines (Incident 5.6).

---

### 5.9. Failure matrix for a Linux machine (SPEC §3.2.1, §6.3)

The failure matrix from THREATS §5 is worked through there for a Windows
machine; here it is for Linux. The mechanisms are the same (§3.2.1: "Every-
thing in §3.2 about Start, keepalive, one tunnel, `door.*`, ceilings and
Stop applies unchanged"), so the timing windows are the same too — only
platform details differ: the door file's path
(`<osUser-home>/.ssh/authorized_keys` instead of
`administrators_authorized_keys`), how the watchdog detects the parent's
death (`pidfd_open`+`poll` instead of a `WaitForSingleObject` handle), and
how processes are group-killed (`kill -9`, `killall`, `systemctl stop`
instead of `taskkill /f`).

| Scenario | Who removes the door line | When it fires | Window (door was OPEN) | Window (door was CLOSED) |
|---|---|---|---|---|
| **1. Network drop machine ↔ gateway** | Keepalive on both sides (`keepalive@iamtunnel`, 20 s × 3 misses): the machine removes its own line on its own keepalive; the gateway erases the closed half of the key from memory, with no `door.close` to send — there's no tunnel | 60–90 s after packets stop | **60–90 s** (the line is inert: the gateway's half of the key is already erased from RAM) | **0 s** |
| **2. Normal Stop** (`server stop` or `systemctl stop iamtunnel-machine`) | The server: removes the line under the file lock (`door.lock`), stops the watchdog, closes the tunnel | Synchronously before exit | **A fraction of a second** | **0 s** |
| **3. Server crash** (`kill -9 <pid>`, panic) | The `server doorwatch` watchdog: waits for the parent's death via `pidfd_open`+`poll`, removes the line under lock and journals it on the parent's death | Right after the parent dies (the whole life of the open door) | **A fraction of a second** | **0 s** |
| **3b. Group kill** (`killall iamtunnel`, `kill -9 -<pgid>`, `systemctl stop`'s timeout → `SIGKILL` to the whole group) | The watchdog goes too: the line is removed by `SweepStale` on the next `server start` (the unit starts the server on its own) | The next start / reconnect | **Until the next start** (the line is inert: the tunnel is dead, the gateway's half of the key is erased) | **0 s** |
| **4. Power loss / kernel panic** | `SweepStale` on the next `server start` — with autostart enabled, this is the first boot after the failure | The next server start | **From the failure to the next boot** (the line is inert) | **0 s** |
| **5. All sessions end (idle)** | The gateway (`door.close` at `sessions == 0 && reservations == 0`) or the server's own `maxDoorIdle` (15 min without tunnel bytes) / `maxDoorHard` (8 h) | Right after the last session ends; independently, by timer | **Up to 15 minutes** (a normal close) | **0 s** |

**What the on-call engineer should do for each scenario.**

- **1 (network drop).** Nothing: the line removes itself on timeout, the
  person's session drops. If the machine doesn't return `online` — this is
  no longer a drop, it's downtime: see Incident 5.2 (sshd, the `server`
  process, gateway reachability).
- **2 (Stop).** A normal close. On the gateway, `/var/lib/iamtunnel/events.jsonl`
  shows only `machine.disconnected` (usually `result:"control-read-error"`):
  the machine removed its own line, and the gateway neither sends nor
  journals `door.close`; on the machine, `Op:"close"` appears in
  `/var/lib/iamtunnel-machine/events.jsonl`. There should be no
  `iamtunnel-door=` line in the file:
  `grep -c iamtunnel-door= ~<osUser>/.ssh/authorized_keys`.
- **3 (`kill -9`).** The one scenario where the watchdog, not the server,
  removes the line. By the §6.3 contract this happens in a fraction of a
  second and is journaled on the machine. If the line remains — the
  watchdog didn't fire: compare the process death time
  (`journalctl -u iamtunnel-machine`) with the machine's journal and file a
  bug with both timestamps.
- **3b (group kill).** The watchdog dies with the server, and the line
  stays until the next start. This is safe: the tunnel is dead, and the
  door key's closed half only ever existed in the gateway's RAM. Speed up
  cleanup with `sudo iamtunnel server start` (runs `SweepStale` before
  connecting) or `sudo systemctl restart iamtunnel-machine`.
- **4 (power loss).** With autostart enabled (§1.7), the server comes up on
  boot and runs `SweepStale` first thing; without it, after a manual
  `server start`.
- **5 (idle).** Nothing to check if there were no sessions — the close is
  normal. If someone reports "my session closed itself", check the
  gateway's `door.close` (`reason` is `idle` or `hard`; if the machine
  closed its own line by `maxDoorIdle`/`maxDoorHard`, the gateway finds out
  on the next login and journals `door.close` with `result:"gone"`) and
  remind them about those ceilings.

**Where to look.** The gateway journal
`/var/lib/iamtunnel/events.jsonl` (`door.open`, `door.close`,
`machine.connected`, `machine.disconnected`, `session.start`,
`session.stop`, `session.drop`, `session.risk`, `door.sanitize`) is the only
audit trail an admin sees; the machine's local journal
`/var/lib/iamtunnel-machine/events.jsonl` (`{"Op":"open"|"close"|"sweep",...}`
records) is the door layer's local trace, including watchdog cleanup. Both
journals are only supplementary to the file's state: **the truth about the
door** is the contents of `<osUser-home>/.ssh/authorized_keys`.

### 5.10. Failure matrix for a Mac machine (SPEC §3.2.1, §6.3, IAMT-263/298/299)

The same six matrix rows carry over to macOS: door mechanics and `door.*`
are identical on Linux and macOS (PROTOCOL §5); only platform pieces
differ — sshd's path (a launchd job `com.openssh.sshd`, not
`/etc/ssh/sshd_config` as the sole source of truth), the door file (still
`<osUser-home>/.ssh/authorized_keys`), how the watchdog detects the parent's
death (`kqueue EVFILT_PROC/NOTE_EXIT` instead of `pidfd`/
`PR_SET_PDEATHSIG`), and the platform install/start operations —
`_iamtunnel` via `dscl`, a LaunchDaemon via `launchctl bootstrap system`,
logs under `/Library/Logs/iamtunnel`.

| Scenario | Who removes the door line | When it fires | Window (door was OPEN) | Window (door was CLOSED) |
|---|---|---|---|---|
| **1. Network drop machine ↔ gateway** | Keepalive on both sides (`keepalive@iamtunnel`, 20 s × 3 misses): the machine removes its own line on its own keepalive; the gateway erases its half of the key from memory, no `door.close` to send — no tunnel | 60–90 s after packets stop | **60–90 s** (inert: the gateway's half is already erased) | **0 s** |
| **2. Normal Stop** (`server stop` or `launchctl bootout system/com.iamtunnel.machine`) | The server: removes the line under lock (`door.lock`), stops the watchdog, closes the tunnel | Synchronously before exit | **A fraction of a second** | **0 s** |
| **3. Server crash** (`kill -9 <pid>`, panic) | The `server doorwatch` watchdog: waits for the parent's death via `kqueue EVFILT_PROC`/`NOTE_EXIT`, removes the line under lock and journals it | Right after the parent dies | **A fraction of a second** | **0 s** |
| **3b. Group kill** (`killall iamtunnel`, `launchctl bootout system/com.iamtunnel.machine` — the launchd job kills its own processes) | The watchdog goes too: the line is removed by `SweepStale` on the next `server start` (the LaunchDaemon starts the server on its own) | The next start / reconnect | **Until the next start** (inert: the tunnel is dead, the gateway's half is erased) | **0 s** |
| **4. Power loss / kernel panic** | `SweepStale` on the next `server start` — with autostart (`RunAtLoad` in the plist) this is the first boot after the failure | The next server start | **From the failure to the next boot** (inert) | **0 s** |
| **5. All sessions end (idle)** | The gateway (`door.close` at `sessions == 0 && reservations == 0`) or the server's own `maxDoorIdle` (15 min without tunnel bytes) / `maxDoorHard` (8 h) | Right after the last session ends; independently by timer | **Up to 15 minutes** (a normal close) | **0 s** |

**What the on-call engineer should do for each scenario.**

- **1 (network drop).** Nothing: it clears on timeout. If the machine
  doesn't return `online` — see Incident 5.2 (Remote Login via
  `com.openssh.sshd`, the `server` process, gateway reachability).
- **2 (Stop).** A normal close. On the gateway,
  `/var/lib/iamtunnel/events.jsonl` shows only `machine.disconnected`
  (usually `result:"control-read-error"`); on the machine, `Op:"close"` in
  `/var/lib/iamtunnel-machine/events.jsonl`. No `iamtunnel-door=` line
  should remain: `grep -c iamtunnel-door= ~<osUser>/.ssh/authorized_keys`.
- **3 (`kill -9`).** The one scenario where the watchdog removes the line.
  Happens in a fraction of a second by contract; if the line remains,
  compare the process death time
  (`log show --predicate 'process == "iamtunnel"' --info --last 1h`) with
  the machine's journal and file a bug with both timestamps.
- **3b (group kill).** Speed up cleanup with `sudo iamtunnel server start`
  (runs `SweepStale`) or `sudo launchctl kickstart -k
  system/com.iamtunnel.machine` (restarts the job).
- **4 (power loss).** With autostart (`RunAtLoad` in the plist, §1.6) the
  LaunchDaemon starts the server on boot and runs `SweepStale` first thing;
  without it, after `launchctl bootstrap system`.
- **5 (idle).** Same as Linux: check `door.close`'s `reason` (`idle` or
  `hard`, or `"gone"` if the machine closed it first).

**Where to look.** The gateway journal
`/var/lib/iamtunnel/events.jsonl` and the machine's local journal
`/var/lib/iamtunnel-machine/events.jsonl`, as on Linux; the daemon logs
`/Library/Logs/iamtunnel/gateway.log` and
`/Library/Logs/iamtunnel/machine.log` — launchd's own output, unaffected by
`kill -9` or a daemon restart — are the last trace when everything else has
failed.

---

### 5.11. Incident 9: every admin key is lost

**Symptom.** No admin command works for anyone — every attempt gets "you are
not an administrator": the one admin left, their key lost, or the machine's
data directory reinstalled. No one can open the pairing window:
`iamtunnel admin pairing start` needs an existing admin, and the **Pairing
window** card (Admin → Join) refuses the same way. Bootstrap Claim (§1.4) is
unavailable — it fires once per gateway lifetime.

**When this is your situation, and when it isn't.** §5.11 is the path for
exactly one problem: **no admin key works at all**. It is not for:

- **a freshly installed gateway whose first admin never claimed yet.**
  That's §1.4, not §5.11: `gateway install` prints a ready paste-in string,
  and `iamtunnel gateway status` reprints it while it's still good (§1.3,
  SPEC §3.3);
- **the bootstrap token expired or spent, with zero admins still.** That's
  `gateway install --rebootstrap` (§1.3): issues a fresh token and a fresh
  24-hour window, refuses if an admin already exists;
- **wiping the gateway entirely** (dropping people, machines and grants,
  starting from a clean `state.json`). That's `gateway reset` — §5.13, not
  §5.11;
- **at least one working admin remains.** New admins are added per §1.4.1
  over the network: `pairing start` → one string → `admin pair`. No need to
  stop a live gateway, and `gateway pair` on a live gateway refuses on the
  held lock anyway (step 1 below).

**What to do — local recovery, `stop → gateway pair → start`** (PROTOCOL
§3.4; a terminal is only needed on the gateway itself, and the new admin
works normally afterward, GUI included):

1. **Stop the gateway service.** Windows:
   `Stop-Service iamtunnel-gateway`; Linux:
   `sudo systemctl stop iamtunnel-gateway`. `gateway pair` uses the same
   exclusive lock on `state.json` as a live gateway and refuses if it's
   held: `gateway pair: another gateway process already holds the state
   lock in <directory> — stop it first; for a live gateway use "iamtunnel
   admin pairing start" instead.` — a designed refusal, not a bug.
2. **On the gateway itself, open the window locally:**
   ```powershell
   iamtunnel gateway pair --public-host gw.example.com
   ```
   *(A non-default port — `--port`, a non-default data directory —
   `--data-dir`; same flags as `gateway install`.)* On Linux, run as the
   service user — `sudo -u iamtunnel iamtunnel gateway pair --public-host
   gw.example.com`. The data directory's files (`state.json`,
   `events.jsonl`, `hostkey`) are owned by that user, and the service reads
   them under its own account; a plain `sudo` (as root) is also safe — the
   gateway takes over ownership of any file it replaces before replacing it
   (IAMT-332). The command prints a PIN, a `host:port#fingerprint`
   reference and — since 1.3 — the whole §3.6 string the new admin pastes
   into one field. Format and rules are the same as
   `admin pairing start` (§1.4.1): 6 digits, 2-minute window, a single
   window replaces any open one.
3. **Start the service again** (`Start-Service iamtunnel-gateway` /
   `sudo systemctl start iamtunnel-gateway`). The open window lives in
   `state.json` (`pairingPending`), so it survives the service restart —
   the PIN stays valid until its own 2-minute deadline by the gateway's
   clock.
4. **On the new admin's machine, paste this one string** — into the
   **Become an administrator** card's field (Admin tab → **Join** sub-tab)
   or the console: `iamtunnel admin pair "<string>"`. In the GUI, a preview
   appears below the field — the action, the gateway's address and
   fingerprint in words; **check the fingerprint against what
   `gateway status` prints on the gateway itself**, and only then press the
   button. The key becomes a permanent admin key; recovery doesn't need
   repeating.
5. **Close the window** if it's still open:
   `iamtunnel admin pairing stop`, now from the network, as the new admin.
   The window also expires on its own after 2 minutes; `stop` is just for
   certainty.

**Secret hygiene.** The requirement to pass the PIN and reference over
separate channels was removed on 2026-09-17 along with the rule itself
(§1.4.1): two channels don't materialize in practice, and the rule cost
extra actions without adding protection. Here, on the recovery path, this is
even more true: the string is printed by the gateway's own console and, more
often than not, isn't "passed" anywhere — it's typed on a nearby machine by
hand. The same protections apply as in §1.4.1: 2-minute window life,
one-time use, an address ban after three misses, a mandatory preview.
**The accepted residual risk is the same:** whoever reads the clipboard or
the transfer channel during these two minutes becomes a gateway
administrator. Practical takeaway for the on-call engineer: don't open the
window until the new admin is ready to paste the string right now, and close
it with step 5 rather than waiting it out. The PIN is never written to
`events.jsonl` or `admin.op`. After recovery, give each admin their own key
through §1.4.1 rather than keeping just one — a single admin is this
incident, paused. Reinstalling the gateway (`gateway install`) is **not**
recovery: it never touches an existing `state.json`, so keys and people
don't come back that way.

### 5.12. Incident 10: the audit journal isn't being written (since 1.14)

**Symptoms.** Any command that changes something answers
`E_AUDIT_UNAVAILABLE`; new sessions get "Access to this machine is currently
unavailable."; enrol and pairing refuse. `admin gateway status` prints
`audit: PROBLEM: the audit journal is NOT being written (since …): <reason>`;
so does `gateway status` on the gateway itself (the `audit:` line), the
Admin and Gateway tabs' posters, and a line in the service journal
(`journalctl -u iamtunnel-gateway`, or the `gateway run` console).

**Why.** The gateway does nothing it can't record in `events.jsonl` (SPEC
§3.5): granting access that never reaches the journal means granting access
no one will ever be able to check later. Read-only commands, including
`gateway.status`, still work. Live sessions aren't torn down; how many
there are shows in the same status line (`sessions=`).

**What to do.**

1. Read the reason in the `audit:` line — usually "no space left on device"
   or a file that's become unwritable (permissions, ownership, a
   read-only remount).
2. Fix the cause: space, per §5.5; permissions, restore `events.jsonl`'s
   ownership to the service user (`sudo chown iamtunnel:
   /var/lib/iamtunnel/events.jsonl`) or its write permission.
3. Nothing needs restarting: the first successful write clears the state,
   and the next command goes through. Any read is enough to trigger a
   write right away (e.g. `iamtunnel admin gateway status` — its own login
   is journaled). The service journal gets a line "the audit journal is
   written again … N entries were lost" — **N entries are gone for good**;
   note that time window in your own records.
4. A command that answered `E_AUDIT_UNAVAILABLE` with "… was carried out,
   but the audit journal could not record it" **already did its job** — it
   can't be undone. Don't blindly repeat it — check the result
   (`admin grants list`, `admin people list`) and, if needed, repeat it
   deliberately once the journal is back, so a record finally exists.

### 5.13. Full gateway reset: `gateway reset`

**When it's needed.** The gateway stops belonging to anyone — decommissioning
a test rig, handing a machine to a new owner, a from-scratch drill. The old
path — five manual steps (stop the service, wipe `state.json`,
`bootstrap-token`, `events.jsonl` and `recordings/`, run `gateway install`) —
is easy to get wrong; `reset` (SPEC §3.5) does it all in one command and
prints a new claim string (§1.4, SPEC §3.6) at the end.

**What it wipes, and what it keeps.** Destroyed: `state.json` (every
person, machine, grant, goal, command history), `bootstrap-token`,
`events.jsonl`, `enrol-hmac.key`, the `recordings/` directory, and the
gateway service (stopped and removed, then reinstalled). **The host key is
kept** — the fingerprint in claim strings and on machines doesn't change;
add `--new-hostkey` to replace it too. The journal is wiped entirely,
rotation archives included — otherwise history and `verify-journal` on the
new gateway would keep reading the previous owner's events. `state.lock` is
untouched. All wiping happens inside the data directory; a link planted
where a file or folder should be is removed as a link, never followed. The
old admin gets "you are not an administrator" after reset — zero people in
the new `state.json` is the cleanliness canary.

**Order is a contract.** Stop the service (the only reversible step, frees
the state lock) → count the losses → confirm → refuse if someone else holds
the state lock → wipe the exactly-named files → a new claim string. The
fresh journal's first line is an `admin.op` with `result:"reset"`: the
reason (`operator ran gateway reset`), counts of lost people/machines/grants,
and `hostkeyReplaced` — the old journal is destroyed by design, and this
entry outlives its own destruction.

**What to do.**

1. On the gateway, run:
   ```powershell
   iamtunnel gateway reset --public-host gw.example.com --yes
   ```
   *(A non-default port — `--port`, a non-default data directory —
   `--data-dir`; changing the host key — `--new-hostkey`. On Linux, as the
   service user, as in §5.11 step 2:
   `sudo -u iamtunnel iamtunnel gateway reset --public-host gw.example.com
   --yes`.)*
2. **Without `--yes` the command wipes nothing**: it prints the counted
   losses (`people=…, machines=…, grants=…`, journal, session recordings)
   and requires `--yes` or a typed "yes"; any other answer is "cancelled",
   and nothing changes.
3. **A gateway running live in a console** (`gateway run`, not the service)
   has no service to stop — the command refuses on the held lock with a
   hint to stop it by hand; the refusal comes **before** any wiping.
4. At the end the command prints a new bootstrap claim string. From here
   it's the same as after a fresh `install` (§1.4): whoever spends the
   string first becomes admin; people and machines are set up again from
   scratch (machines need new invitations —
   `admin machines enrol-code <name>` — the gateway no longer knows their
   old keys).
5. `reset` requires the same rights as `install`, and works on Linux,
   Windows and macOS; on any other host, it refuses before any wiping.

---

## 6. Pre-release checklist

Before shipping a 1.0 release on a production rig (a gateway on an Ubuntu
Linux VPS + a Windows machine behind real NAT, no public IP), run the
following checks by hand (SPEC §8):

| # | What to check | Tester action | Expected result |
|---|---|---|---|
| 1 | **Elevation** | Run `iamtunnel.exe server start` from an ordinary, non-elevated console. | The program exits with code 4 and prints `iamtunnel server start: administrator privileges are required — close this console and run it using "Run as administrator".` It opens no door and starts no UAC prompt before this refusal. |
| 2 | **sshd check** | Stop the OpenSSH service on Windows (`Stop-Service sshd`) and run `iamtunnel.exe server start`. | The program refuses, explaining that sshd isn't listening on `127.0.0.1:22`; the door in the key file is **not** opened. |
| 3 | **Full enrol cycle (1.4: a named invitation)** | On the gateway, run `iamtunnel admin machines enrol-code office-pc` — **the admin chooses the name, still no `--os-user`**; the GUI's Invite card on Admin → Machines offers the same single "name" field. On the machine, under your own account, run `iamtunnel enrol <string>`. | The invitation lives 15 minutes; the gateway's fingerprint is checked automatically; a machine key is created; the tunnel connects; OpenSSH is checked; the machine moves to `state: verified, osUserStatus: verified`. The machine list shows the **invitation's name** and the **OS account the machine reported**. 1.4 control: repeat with the name `lab-pc` under a SECOND account on the same machine — both registrations live side by side and both reach `verified`; issuing an invitation with a name already in use is refused. |
| 3e | **Registration's finish line is autostart, not a running window (1.3 assigned, not built in the GUI)** | After successful registration, run `iamtunnel server install` from the console — there is no `Install as a service and start` button, assigned in 1.3 but not built (SPEC §3.4). Then reboot the machine and don't open the GUI at all. | Autostart is installed and running in one command; after reboot the machine comes back on its own and shows as `online` in `iamtunnel admin machines list`, with no human action. Regression check for 1.2: skip the command, and the machine never reappears after reboot. Separately confirm the GUI button still doesn't exist — otherwise this checklist item is stale. |
| 3f | **Elevation button in the header, not a banner (1.3)** | Launch `iamtunnel.exe` **without** administrator rights and look at the window; then press a button that needs elevation (e.g. START on the Server tab) and cancel UAC. | No permanent "Administrator rights are required to open the door" banner under the tab strip. In the masthead's right side, one unlabeled, slowly pulsing button; the pulse stops on an inactive window. The rights refusal appears as a line **under the button that was pressed**, not in a modal dialog. Once elevated, the masthead button disappears entirely. |
| 3g | **Sub-tabs and no scrolling (1.3, updated in 1.4)** | Open every tab and every sub-tab at the default window size (layout — SPEC §7.1). | Admin has six sub-tabs: People · Machines · Access · New grant · Pairing · Join, and the "Become an administrator" card is one click away on Join, not eight cards down. **No sub-tab needs scrolling** at the default size. |
| 3a | **The key file is the real sshd file** | From an administrator console, run `iamtunnel.exe server start` **without** `--key-file`. A person with a grant runs `iamtunnel client connect win-test`. While the session is open, on the machine: `Select-String -Path "$env:ProgramData\ssh\administrators_authorized_keys" -Pattern 'iamtunnel-door='` and `Test-Path C:\ProgramData\iamtunnel\administrators_authorized_keys`. | Exactly one line `restrict,pty,from="127.0.0.1" ssh-ed25519 … iamtunnel-door=<id> iamtunnel-owner=<registration name>` — the owner marker was added in 1.4 (SPEC §3.2.2); other lines in the file are byte-for-byte unchanged (compare against a copy from before the run: `Get-FileHash`); `Test-Path` returns `False`. 1.4 control: with two registrations running, the file has two lines with different `iamtunnel-owner=` values, and restarting one server doesn't touch the other's line. |
| 3b | **Key file ACL** | While the door is open: `icacls "$env:ProgramData\ssh\administrators_authorized_keys"` and `(Get-Acl "$env:ProgramData\ssh\administrators_authorized_keys").AreAccessRulesProtected`. | `icacls` shows exactly two entries: `NT AUTHORITY\SYSTEM:(F)` and `BUILTIN\Administrators:(F)`, with no inherited `(I)`; `AreAccessRulesProtected` returns `True`. Unchanged after the door closes. |
| 3c | **Admin login through the door** | With a grant: `iamtunnel client connect win-test`, then in the session `whoami` and `whoami /groups | findstr S-1-5-32-544`. Then on the machine: `Get-WinEvent -LogName OpenSSH/Operational -MaxEvents 20 | Where-Object Message -like '*Accepted publickey*'`. | A shell prompt appears; `whoami` matches the machine's OS user; the Administrators group is listed; OpenSSH's log shows `Accepted publickey for <user> from 127.0.0.1`. Control: running with `--key-file C:\Temp\x` under a standard `sshd_config` should **fail** to log in, confirming 3c is checking the real file. |
| 3d | **Machine data directory ACL** | After `iamtunnel enrol <code>` (and again after `iamtunnel server start` on an older-version directory) run: `icacls "$env:LOCALAPPDATA\iamtunnel\server"`, `icacls "$env:LOCALAPPDATA\iamtunnel\server\machine.key"`, `(Get-Acl "$env:LOCALAPPDATA\iamtunnel\server").AreAccessRulesProtected` and the same for `machine.key`, plus `.Owner` on both (the server directory became personal in 1.4 — SPEC §3.2.2). | Both `icacls` outputs show exactly `NT AUTHORITY\SYSTEM:(F)` and `BUILTIN\Administrators:(F)`, with `(OI)(CI)` on the folder and none on `machine.key`, no inherited `(I)` anywhere; both `AreAccessRulesProtected` return `True`. Other files (`machine.id`, `enrolment.json`) carry the same two entries. Both `Owner` values are `BUILTIN\Administrators`. A directory or file whose owner isn't `Administrators`, `SYSTEM`, `TrustedInstaller` or the one running the command is refused with code 4, naming the owner, by both `enrol` and `server start`. A directory that is itself a link (junction, symlink) is refused with code 4 too. |
| 4 | **The 8-key rule** | Load 8 SSH keys into the client (via ssh-agent), with the correct one eighth (`MaxAuthTries=32`). | Login succeeds on the 8th attempt, with no dropped connection. |
| 5 | **Person isolation** | Try to log in as Alice with Bob's key (`iamtunnel client connect win-test`). | Authentication is refused immediately; the client sees an SSH refusal. In `events.jsonl`, look for `"type":"auth.failure"` and a `result` like `auth: username does not match the key owner: key belongs to "bob", username is "alice"` (names vary); the internal code `E_PERSON_KEY_MISMATCH` is never written literally to the journal. |
| 6 | **Session recording** | Enter a session, run commands, resize the terminal window, exit. | `/var/lib/iamtunnel/recordings/...` gets `.cast` (with `r` resize events), `.txt` and `.meta`. The recording banner is the first line printed. |
| 7 | **Instant revoke** | During an active terminal session, run `iamtunnel admin grants revoke <person> <machine> --yes` on the gateway. | The person's terminal session ends immediately with "Session closed: the grant was revoked." |
| 8 | **Watchdog on crash (kill)** | With an open door, find the parent's PID: `Get-CimInstance Win32_Process -Filter "Name='iamtunnel.exe'" | Select-Object ProcessId,ParentProcessId,CommandLine` — the process with `server start` in its command line; the watchdog has `server doorwatch` in its command line and this PID as its `ParentProcessId`. Kill **only the parent**: `taskkill /f /pid <PID>`. **Not** `taskkill /im iamtunnel.exe` — that kills the watchdog too, and the check would fail through no fault of the product. | Within 2 s, `Select-String -Path "$env:ProgramData\ssh\administrators_authorized_keys" -Pattern 'iamtunnel-door='` finds nothing; the `server doorwatch` process has exited; other lines and the file's ACL (3b) are unchanged; the person's session dropped, and a new connection fails until the server restarts. |
| 9 | **Stale door cleanup (BSOD)** | Simulate a power failure (leave an `iamtunnel-door=` line in the file) and run `iamtunnel server start`. | `SweepStale` runs before dialing the gateway: the door line is removed, other keys preserved byte-for-byte. |
| 10 | **One tunnel per REGISTRATION** (not per machine, since 1.4) | Under ONE account, start a second `iamtunnel server start` process. | The second process never reaches the gateway: `iamtunnel server start: a server is already running for this machine (data dir C:\Users\<you>\AppData\Local\iamtunnel\server) — stop it first.`, exit code 2; `iamtunnel server status` shows the first process `running`. If a second connection with the same machine key somehow reaches the gateway (e.g. a copied data directory on another computer), the gateway refuses it: `events.jsonl` shows `"type":"machine.rejected"` with `result:"E_MACHINE_ALREADY_ONLINE"`. A reconnect does NOT evict the first connection: after a network drop, the machine returns only once the gateway removes the old connection itself (up to ~60 s, three missed keepalives), and until then its attempts show as `machine.rejected`. 1.4 control: a SECOND registration's server, run under a different account on the same machine, works fine and doesn't interfere with the first — different machine keys, different directories. |
| 11 | **Recording disk limit** | Fill the gateway's partition to 95% and try to open a session from a client. | The person gets `Access to this machine is currently unavailable.`; entry without recording is refused. In `events.jsonl`, look for `"type":"session.drop"` with `result` starting `recording: disk full beyond refuse threshold`; `E_RECORDING_DISK_FULL` is an internal code and is never written literally. |
| 12 | **Forbidden channels blocked** | Try `sftp`, `scp`, or port forwarding `ssh -L 8080:localhost:80`. | The channel is refused immediately. In `events.jsonl`, look for `"type":"session.drop"` with `result:"E_SSH_SUBSYSTEM_FORBIDDEN"` for SFTP/subsystem, or `result:"E_SSH_FORWARD_FORBIDDEN"` for `direct-tcpip`/`tcpip-forward`. |

## IAMT-402 / IAMT-403 operator procedure

Declare the current goal explicitly for a person and machine:

```text
iamtunnel admin goal set <person> <machine> --goal "<goal>"
iamtunnel admin goal current <person> <machine>
iamtunnel admin goal history <person> <machine>
```

The goal is pair-scoped, survives a gateway restart, and is not
time-limited. Clearing it is an explicit empty `--goal`; a blank field on
opening a UI does not load an old history entry. The gateway applies the
same snapshot to terminal sessions and individual exec sessions. Review
`session.start`/`session.risk` for the scrubbed goal and `goalApplied`;
`rules` always reports that the goal was not applied to the verdict. The
full-table view (`iamtunnel admin goal list`, `goal.list` over the wire,
IAMT-405) prints every pair with its current goal and history count; the
GUI's Access tab fills every grant row from that one request instead of one
per row.

Replace the active classifier key without restarting the gateway:

```text
iamtunnel admin risk key --key "<new-key>"
```

The command performs one probe and prints only a fingerprint. A 401/403
means the key was rejected; timeout/5xx means the service was unavailable;
malformed input is refused before probing. Any failed probe leaves the old
key working. The refusal carries a machine-readable `category` beside the
words — `rejected` or `unavailable` (IAMT-404) — and the GUI's Classifier
sub-tab reads that field, so its "refused" versus "unavailable" verdict
doesn't depend on the sentence's wording. `gateway status` reports only key
presence and fingerprint. To inspect the audit, search the complete
`events.jsonl` for `risk.key.replace`; no raw key should occur.
