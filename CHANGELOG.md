# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.52.3] - 2026-10-19

### Changed
- "Restart as administrator" is a steady orange button; it no longer blinks.

### Fixed
- A window without administrator rights redrew itself at the screen's
  refresh rate for as long as it was open, because of the blinking button:
  10–20 % of a processor on a server without a graphics card, with nothing
  running. The button that tells you a command is held, which still
  breathes, now asks for a new frame ten times a second instead of at once.

### Security
- Built with Go 1.27.2, which fixes nine standard library vulnerabilities
  reported against 1.27.0 (net/http, crypto/tls, net/textproto, os).

## [1.52.2] - 2026-10-16

### Fixed
- An agent whose key the gateway no longer knew (a machine removed on the
  gateway while its agent was still running) retried about every 30 seconds,
  and the gateway blocked the whole address after about ten refusals, which
  also blocked the machine's new registration. A refused key is now retried
  every 30 seconds, growing to 5 minutes, and the agent's log says so.
- A refused setup code is no longer reported as "could not reach the
  gateway": the message names the three causes (a code older than 15
  minutes, a code already used, an address blocked after repeated failed
  sign-ins).
- Settings shows the "registration" row as soon as the window has
  registered the machine, without a restart.
- `admin machines remove` and the runbook say to stop the machine's agent
  first.

## [1.52.1] - 2026-09-29

### Fixed
- A claim line pasted into the Client tab's box stays there when joining
  fails; it leaves the box only on success.
- A re-registration from Settings no longer writes "failed" or "working"
  into the Set up tab's status of an already registered machine.
- The OpenSSH prompt is sized to its content; the rights question says
  "Starting" for a stopped service; the PowerShell used for the install is
  found through the system directory, not an environment variable.
- The Server tab's hint under the sshd row said to start the service by
  hand before pressing Start; it now says Start offers to do it.

### Changed
- USER guide: moving a registered machine, the claim line in the Client
  box, "Join another gateway…", the fingerprint prefix and where the AI key
  goes.

## [1.52.0] - 2026-09-29

### Added
- OpenSSH Server: the window asks Windows about the sshd service itself (no
  administrator rights needed), the Server tab says when it is missing or
  stopped, and START opens a prompt that installs and starts it, then
  starts the agent.
- A second gateway: "Join another gateway…" on the Admin tab keeps the first
  gateway, and the Client tab's box takes claim and pairing lines too.
- A registered machine can move to another gateway: Settings → registration
  → "Move to another gateway…".
- Where the AI key goes: Safety offers "No AI key — set it…", and the
  settings window and the Guide name Admin → Classifier.

### Changed
- A connection string accepts its fingerprint with the "SHA256:" prefix.
- "could not reach the gateway" says what a timeout and a refusal mean
  (security group or private address; nothing listening).

## [1.51.1] - 2026-09-28

### Fixed
- The gateway records a window resize before it answers the request, so
  a resize followed at once by more output or by the end of the session
  is no longer missing from the recording.

## [1.51.0] - 2026-09-28

### Changed
- The window's emergency stop button reads "Stop all access now" (in the
  strip above the tabs) and "STOP all access now" (on the Server tab).
- Messages and the status in the window no longer tell you to close a
  console and use "Run as administrator"; they point to the window's own
  "Restart as administrator" button.

### Fixed
- Without administrator rights, the stop buttons failed with "Access is
  denied". They now offer to restart the program as administrator, like
  Start and Register do since 1.49.
- A second first run on Windows could fail to read the client key the
  first run was still writing; it now waits for the key to be complete.

## [1.50.0] - 2026-09-27

### Added
- File transfer through the gateway: the `sftp` subsystem is now allowed on
  any grant, and modern `scp` runs through it. Every file operation (upload,
  download, delete, rename, mkdir/rmdir, attribute changes, machine-side
  copy) is logged as `session.file` (path, size, SHA-256) and judged against
  the grant's declared goal, the same way a command is; a held operation
  prints an `approval-id`, the same as a held command.
- New PROTOCOL §4.3 documenting the `sftp` subsystem.

### Changed
- Exec stdin is no longer closed: it's forwarded to the machine and fully
  recorded (`stream:"stdin"` in `.exec.jsonl`). A script piped into an
  interpreter (`powershell`, `bash`, `python -`, and the like) is read whole
  and judged together with the command. A script that can't be judged whole
  (over 1 MiB, not finished within 60 s, or not text) is refused under
  `ask`/`block` with the new code `E_STDIN_SCRIPT_UNJUDGED`, with no way to
  approve it; send it as a file instead.
- The AI-agent prompt the Client tab generates now gives plain `scp` lines
  for moving files, instead of a base64-over-stdin workaround.

### Removed
- The error code `E_SSH_STDIN_FORBIDDEN` and the exec-grant stdin
  prohibition it described.

## [1.49.0] - 2026-09-27

### Added
- A "start at sign-in" autostart checkbox on the Server tab, off by default;
  turning it on/off runs the same actions as `server install`/`uninstall`.
- A "Confirm setup" prompt on the Server tab for a registration made by an
  older version of the program, whose enrolment record predates the
  enrolment anchor; one press repairs it.
- A dedicated window that offers to restart the program as administrator
  whenever an action (Start, Register this machine, Confirm setup,
  autostart) needs rights the current process doesn't have.
- "Show all" on any status line too long to fit: opens the full text in its
  own window, readable, selectable and copyable.

### Fixed
- `session.drop` is now journaled before the client receives exit status
  `126`, so the journal always explains a refusal before the client can
  observe it.
- The Windows door-lock wait was extended from roughly 2 seconds to a 10-second
  clock budget, so two writers cycling installs/removals on a slow disk no
  longer starve each other.
- `admin goal list` is now recognized by the command parser; it previously
  appeared in `--help` but was refused as an unknown command.

## [1.48.0] - 2026-09-24

### Initial public release

- One Go binary, four roles: client, server (the Windows/Linux/macOS machine),
  admin, and gateway (the public bastion). `CGO_ENABLED=0` static build for
  every role except the windowed GUI.
- Temporary, time-boxed grants: `person → machine until T`, as a full shell or
  as exec-only (single commands). Revoke, extend and narrow at any time;
  revoking kills live sessions immediately.
- No standing access: the target's door (its `administrators_authorized_keys`
  entry) exists only while a grant is live, opened and closed by the gateway
  over a persistent control channel.
- Every session recorded on the gateway: asciicast (`.cast`) plus a readable
  text transcript (`.txt`) plus metadata for shells and PTY exec; a lossless
  JSON stream (`.exec.jsonl`) for exec without a PTY. Sessions can be watched
  live by the machine's owner. The audit journal is hash-chained
  (`gateway verify-journal`).
- A risk classifier for exec commands: local rules and/or an external AI
  classifier, judged against the grant's declared goal and recent command
  history. `log`/`warn`/`ask`/`block` modes; red commands can require a
  one-time human approval or be refused outright.
- No TOFU anywhere: the gateway's host key is pinned from the connection
  string and enrollment code; machine host keys are pinned during
  registration. One-time codes for machine enrollment; PIN-based pairing for
  additional admins.
- A desktop GUI (Gio, Windows/Linux/macOS) and a full CLI covering every role.
- Cross-platform machine support: Windows (Task Scheduler autostart, per-person
  registration), Linux (systemd), and macOS (launchd).
