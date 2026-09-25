# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
