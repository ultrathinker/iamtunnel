# iamtunnel: protocol version 1

Status: candidate for the phase-1 freeze. The normative words "MUST", "MUST
NOT" and "REJECTS" are binding. Document version: 1.

Before the freeze, the "corrupted door name" patch was applied: a fourth
control-channel operation, `door.sanitize`, branches on which operation
finished in the `closing` cells and distinguishes a corrupted marker in the
`closed` cells. The wire version stays 1: the document is not frozen yet, and
backward compatibility is not promised.

## 1. General rules

| Parameter | v1 value |
|---|---|
| Gateway SSH port, default | 2222 |
| SSH authentication | public key only; ed25519, RSA ≥ 3072 bits; ECDSA-SHA1 and DSA rejected |
| Max key attempts | 32 |
| Time | UTC, RFC 3339 / ISO-8601 with an explicit zone; the gateway is the source of truth |
| JSON string encoding | UTF-8; identifiers are ASCII only |
| Session v1 | exactly one `session` channel; shell and exec, no SFTP/scp, port forwarding or agent forwarding |
| KEX | `mlkem768x25519-sha256`, `curve25519-sha256`, `diffie-hellman-group14-sha256` in that order; the post-quantum hybrid comes first (IAMT-226), a peer without it settles on `curve25519-sha256` |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes256-ctr` in that order |
| MAC for non-AEAD | `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com` |
| Host-key algorithms | `ssh-ed25519`, `rsa-sha2-512`, `rsa-sha2-256`; SHA-1/RSA, DSA and ECDSA-SHA1 are forbidden |

The gateway journals every accepted or refused action in `events.jsonl`,
except a local syntax error for which no SSH connection was yet established.
An event carries UTC time, type, subject (if established), address, the
fingerprint of any key that was presented, machine/session (if any), and a
result code. Secrets, private keys and tokens never appear in events. An
SSH-authentication event MUST carry both `address` and `fingerprint`; a record
missing either is invalid.

### 1.1 Version and capabilities

`proto` is a positive integer protocol version; in v1 it is always `1`.
`caps` is an array of unique ASCII strings in lexicographic order; for the
base version it is `[]`. Both fields are REQUIRED in every successful and
error JSON response, including `whoami`.

Every exec JSON request also carries `proto`. Before the first application
operation the client MUST run `whoami` as a version preflight — the one
request allowed before knowing the gateway's version. There are exactly three
exceptions: a connection with `enrol-login` runs the single permitted `enrol`
immediately, a connection with `bootstrap-login` runs the single permitted
`admin.claim` immediately, and a connection with `pairing-login` (§3.4) runs
the single permitted `admin.pair` immediately; `whoami` is forbidden and not
required on these three. iamtunnel clients run the preflight once per
connection, before the first application command, and on refusal or a
mismatched `proto` they send no further operations (R2-CX F-06 fixed a bug
where CLI/GUI admin commands and `machines.mine` used to go out first,
without `whoami`). The client compares the response's `proto` to its own and
on mismatch stops with `E_PROTO_CLIENT_NEWER` or `E_PROTO_GATEWAY_NEWER`. If
the gateway receives `proto < 1` it returns `E_PROTO_GATEWAY_NEWER` with
`minProto: 1`; `proto > 1` returns `E_PROTO_CLIENT_NEWER`. An unknown
capability in an exec request is refused as `E_CAP_UNSUPPORTED`; the same in
an `iamtunnel-control` message is refused the same way; the absence of a
capability never changes v1's meaning.

Every later version only adds new `caps` values, new exec command names, or
new optional fields gated by a capability. It never changes v1 field parsing,
existing message semantics, or SSH payload order.

### 1.2 Canonical JSON response and exit codes

One `exec` command reads one JSON object from stdin and writes exactly one
UTF-8 JSON object to stdout, terminated with a newline. Banners and
diagnostic lines on stdout are forbidden. Common response fields:

```json
{"proto":1,"caps":[],"ok":true,"result":{}}
```

Error:

```json
{"proto":1,"caps":[],"ok":false,"error":{"code":"E_GRANT_EXPIRED","message":"The grant has expired."},"minProto":1}
```

`minProto` is present only for `E_PROTO_GATEWAY_NEWER`. The error body may
carry `category`, a machine-readable class alongside the prose; the field is
optional and, without it, the gateway speaks only through prose, which the
client MUST read. In v1 only one refusal has a class — `E_RISK_KEY_REJECTED`
(IAMT-404): `rejected` (the service answered and declined the key) and
`unavailable` (the probe got no verdict — timeout, 5xx, unreachable). Either
way the previous key keeps working; field and prose are tested to agree, so a
client that doesn't know the field reads the same truth from the words.
Process exit codes: `0` success; `2` an expected application error; `3` a
JSON parse or required-field error; `4` a version/capability violation; `5`
missing authentication or rights; `70` an internal error without detail. An
SSH refusal before `exec` starts creates no process exit code at all: the
gateway sends the human exactly the error text over the channel, journals the
event, and closes the channel.

### 1.3 Universal types

| Type | Format |
|---|---|
| `name`, `person`, `machine`, `id` | `[a-z0-9][a-z0-9._-]{0,31}`; ASCII, 1–32 bytes |
| `time` | RFC 3339 with an explicit zone, e.g. `2026-09-12T08:30:00Z` |
| `fingerprint` | `SHA256:` + 43 base64 characters without `=`; SHA-256 of the SSH public-key blob; 50 ASCII bytes total |
| `pubkey` | one OpenSSH public-key line; a type allowed by §1; no CR/LF |
| `secret`, `token` | 43 base64url characters without padding, 256 random bits |
| `caps` | array of `[a-z0-9][a-z0-9.-]{0,63}` strings, no duplicates |
| `uuid` | RFC 4122 UUID, lower case |
| `sha256hex` | 64 lowercase hex ASCII characters: SHA-256 of the stated bytes |
| `backup-id` | RFC 4122 UUID; an archive identifier on the gateway, not a path or the archive's contents |
| `osUser` | exactly one of two forms: (a) a Windows principal `DOMAIN\\name` or `MACHINE\\name` — exactly one `\\`, both parts non-empty, UTF-8 without NUL/CR/LF/control bytes; (b) since 1.1, a local POSIX name on Linux/macOS: ASCII matching `^[a-z_][a-z0-9_-]{0,31}$` (no `\\`, spaces, `,`, `=`, or leading `-`). The gateway and admin accept both forms and never guess which platform a value belongs to; a machine refuses at `enrol` and `server start` when the form doesn't match its own OS (Windows only (a), Linux/macOS only (b)). The value is not a `name` and is never normalized |

A missing required field, wrong type, duplicate JSON key, NUL byte or invalid
UTF-8 all give `E_JSON_INVALID` before the command runs. Any field absent
from a given message's shape gives `E_JSON_FIELD_UNKNOWN`: silent-ignore is
not allowed in the frozen v1.

### 1.4 Limits and rate limiting

Before verifying a signature, the gateway classifies the presented public key
against the state snapshot: `unknown-key` (no matching fingerprint) or
`known-key`. Failed `unknown-key` attempts are counted **per one
`remote-address`** — precisely, its `peerHost` — without the port, and for
IPv6 collapsed to its `/64` (§1.5; the same key the pairing limiter uses,
IAMT-446 — an ordinary IPv6 subscriber has 2^64 addresses, so counting by
exact address counts nothing), so generating a fresh key never bypasses the
limit: 10 such attempts are allowed in a 5-minute window, then the address is
banned for 15 minutes with `E_AUTH_RATE_LIMITED`. A failed `known-key`
attempt (bad signature, a username that doesn't match the key's owner, or any
other auth failure) is counted by `(remote-address, fingerprint)` with the
same window, threshold and ban, so one known key's mistake doesn't lock out
everyone else behind the same NAT. Successful authentication never shortens
an active ban. Every classification and every ban creates an event with
required `address` and `fingerprint`.

Numeric v1 limits: 4 active sessions per person, 8 per machine, and 20
seconds to establish an SSH session from the `session` channel-open to a
successful `shell`/`exec`. Exceeding these gives `E_SESSION_LIMIT_PERSON`,
`E_SESSION_LIMIT_MACHINE` or `E_SESSION_SETUP_TIMEOUT`, an event, and closing
the session before it ever reaches the machine. These limits are counted by
the gateway and do not depend on the client's clock. On refusal of an
interactive session these codes are not exec exit codes.

### 1.5 v1 parameters not fixed by SPEC

The following numbers are explicit decisions of this v1 protocol, not
derivations from SPEC: auth window/threshold `5 minutes / 10`, ban `15
minutes`; session limits `4/8`, setup `20 seconds`; enrol-code length `1–512
bytes`; enrol TTL **15 minutes** (since 1.3; was 24h); bootstrap TTL `24
hours`; pairing (§3.4): PIN length `6 decimal digits` (leading zeros allowed),
pairing window `2 minutes`, its own limiter with a `5-minute` window, `3`
wrong PINs from one address (address = the peer's IP without port; for IPv6,
its /64 — a pairing connection lives one exec, so counting by port would
reset on every reconnect, and an ordinary IPv6 subscriber has 2^64 addresses,
so counting by exact address counts nothing), ban `3 minutes`, and `10` wrong
PINs against the window itself — counted across all addresses — after which
the window burns; `recordings.fetch.limit` `1–1,048,576`;
`recordingRefusePercent=95` with an upper bound of `99`; accepting control
`10 seconds`, `door.open` reply `10 seconds`, `door.close`/`door.status`/
`door.sanitize` and relayed SSH requests `5/5/10 seconds`, one retry each for
close and sanitize, control line size `16 KiB`; an unanswered `door.status`
retries after `1 s`, doubling to `30 s`, and after `5` unanswered in a row
with no live sessions the transport is dropped; the human↔gateway liveness
probe `keepalive@openssh.com` every `20 seconds`, `3` misses, detection bound
`60 seconds` plus delivery/teardown, `90 seconds` reaction (these numbers are
deliberately symmetric with §5's mechanism and values); local door ceiling
defaults `idle=15 minutes`, `hard=8 hours`. The enrollment numbers in §7 are
also v1 parameters. Changing any of these requires a new version/capability.

### 1.6 Machine state

`machine.state` has exactly two valid values from SPEC §4.3: `enrolled` and
`verified`. `online` is a boolean and is not part of `state`. `requestedOsUser`
has type `osUser`; `verifiedOsUser` is absent until a successful SSH user-auth
probe, and only it is used for the nested login. `osUserStatus` has values
`pending`, `verified`, `rejected`; `verified` requires `state:"verified"`.
`hostKeyStatus` has values `unverified` (for `enrolled`), `match` (for
`verified`), or `mismatch` (the observed SSH host key differs from the
pinned one); `mismatch` forbids opening the door and forbids a session.
`sshdHostKey` and `observedSSHDHostKey` have type `fingerprint`; the latter
is absent until a mismatch has been observed.

The §7 states `code-parsed`, `gateway-connect`, `machine-key-generated`,
`enrol-sent`, `tunnel-connected` are local Set-up process states only; they
are never serialized into `machine.state`. The string `verified/offline` is
not a `state` value: it is `state:"verified", online:false`.

### 1.7 Event dictionary

`events.jsonl.type` in v1 belongs only to the following closed dictionary
(the machine-checked form below is the single source of truth against the
code):

```iamtunnel-event-types-v1
["admin.op","auth.failure","auth.handshake_failure","auth.success","door.close","door.open","door.sanitize","enrol.failed","enrol.start","enrol.verified","grant.revoke","hostkey.mismatch","hostkey.rotate","log.rotate","machine.connected","machine.disconnected","machine.rejected","recording.export","risk.approval","session.drop","session.risk","session.start","session.stop","session.watch"]
```

An unlisted type is an implementation bug. Every rule below that requires an
event uses the matching type from this list; extending the dictionary
requires a capability.

`session.watch` records that a machine's owner started watching a session in
progress (IAMT-343): `actor` is the machine that asked for the tail, `object`
is the session id, `result` is `ok`, and `details` names the session's owner
(`person`). It is written **once per session**, at the moment watching
begins, not on every poll — a live view is a polling loop, and one event per
poll would bury the journal under one machine's curiosity. The event answers
"did anyone watch", asked afterward, not "how many times did the window
refresh".

`recording.export` records a person exporting a session's text to files on
disk (IAMT-342): `actor` is who exported, `object` is `"<person> -> <machine>"`,
`result` is `ok`, and `details` carries the export folder path (`path`), the
session id (`session`), the transcript byte count (`bytes`) and part count
(`parts`). The window writes this event (through the journal it opens in its
own role), not the gateway — the gateway does not know about the export.

`session.risk` records the selected classifier's verdict for an exec, before
the command is forwarded: `actor` is the person, `object` is the machine,
`result` is `yellow`, `red` or `external-error`; `details` carries
`sessionId`, the scrubbed `command`, the `rule` that fired, a human `reason`,
the `action` taken (`log`, `warn`, `ask` or `block`) and the `classifier`
source (`rules`, `ai` or `both`). `risk_classifier=rules` uses only local
rules, `ai` only the external classifier, `both` takes the worse of the two.
The external classifier is asked FOUR named questions, each answered with a
probability: `destroys` (does the command destroy data), `access` (does it
change who can reach the machine), `unrelated` (does it fall outside the work
the declared goal describes — silent when there is no goal) and `tampering`
(does it weaken the machine's defenses or erase the record of what was done,
including means of recovery). The declared goal enters every question only as
an EXCEPTION, and follows the object the command works on, not the text it
contains; a goal that declares breadth instead of work is not such an
exception. The verdict is red if ANY probability is above the `0.85`
threshold. An external verdict above the threshold gets the stable name
`rule:"external-classifier"`, so the answer plainly shows who saw the risk.
On an external error, fail-closed applies in both `ai` and `both` — the
external classifier is called in both modes, and its silence means nobody
judged the command. The command does not reach the machine and waits for a
human decision: the verdict is replaced with red under the rule
`risk-classifier-unavailable`, the person gets `APPROVAL REQUIRED` and
`E_APPROVAL_REQUIRED`, and `session.drop` is journaled with code
`E_RISK_CLASSIFIER_UNAVAILABLE` and fields `failureKind`/`failureReason`. The
reason is named to the agent verbatim and distinguishes: over budget, an
invalid/expired key (`401/403`), exhausted funds (`402`), an exhausted quota
(`429`), and service unavailability (`5xx`). In `block` mode the gateway
stops the command outright instead of asking (`STOPPED`, `E_COMMAND_BLOCKED`),
and an explicit downgrade via `iamtunnel admin risk mode log`/`warn` remains
an emergency escape hatch. The external call is blocking with an 800 ms
budget, except for an already-decided local red in `both`, whose external
request runs asynchronously and does not delay the refusal. `session.risk`
for an external source may additionally carry `local`, `external`,
`externalCalled`, `externalError`, `failureKind`, `status`, `latency_ms`,
`threshold` and `probabilities`. One `risk_action` forms the ladder
`log → warn → ask → block`: `log` only journals, `warn` warns at both levels
and lets it through, `ask` warns yellow and requires a separate one-time
human approval for red, `block` warns yellow and blocks red. Ask is a
boundary against carelessness and accident, not against someone who knows the
bypass: an approval is signed with the same key as the command, and the
gateway cannot tell a person from an AI agent on the same machine, so an
agent that knows about `risk.approve` approves itself; a malicious human is
likewise not this defense's subject. The reply tells the human first whether
the command ran; on `ask` without approval — `APPROVAL REQUIRED` and
`E_APPROVAL_REQUIRED`; on block — `STOPPED` and `E_COMMAND_BLOCKED`; on a
fail-closed external error — `APPROVAL REQUIRED`/`E_APPROVAL_REQUIRED` (or
`STOPPED`/`E_COMMAND_BLOCKED` under `block`); on warn — a warning before
forwarding. The stable diagnostic suffix `[iamtunnel] risk=<level>
rule=<rule> action=<action>` follows the human-readable explanation; under
`ask` it also carries a machine-readable `approval-id=<id>`, and the source
is added as `classifier=<rules|ai|both>`. Color and CR are used only with a
PTY. The scrubber runs before any external call: passwords, tokens,
`Authorization`, `-u user:pass` and long base64/hex runs are replaced with
`<redacted>`; shell input and the session recording are never sent out.

`risk.approval` records every stage of a one-time ask approval: `actor` is
the person acting, `object` is the machine, `result` is `pending`,
`approved`, `consumed`, `expired` or `denied`; `details` carries the approval
id, the scrubbed command, the red rule/reason, the request time and expiry.
An approval lives in the gateway's memory for 5 minutes, is tied to the exact
person, machine and full exec command line, and burns after one matching run.
A gateway restart discards it. `risk.approve` travels over the existing
command-login SSH channel; no new SSH connection is used to run the command.

`auth.success` is written once per `10 minutes` (`AuthSuccessQuiet`) for the
triple "SSH name, key, host" (host = address without port; for IPv6, the
whole address, not its /64 from §1.4 — /64 is the limiter's key, but for the
journal two hosts on one subnet are two distinct sources): repeated logins by
the same key from the same host in that window produce no further lines,
only a count, and at the end of the period the gateway writes one more
`auth.success` line with `details.repeats` (how many logins went unrecorded),
`details.firstRepeat` and `details.lastRepeat` (RFC 3339 of the first and
last); its `address` is the last one's (since 1.14, IAMT-452). The number of
logins in a period is the lines plus their `repeats`. Failures are folded the
same way (R4 F-11, 24.09.2026): one `auth.failure` line (or
`auth.handshake_failure` for a pre-key handshake failure) per
`(host, cause class)` pair per `AuthSuccessQuiet`, repeats counted, and a
summary line of the same type at the period's end carrying the same
`details.repeats`/`firstRepeat`/`lastRepeat`; its fields are the period's last
attempt (fingerprint, name, address, reason). The cause class is coarse, not
raw text: a reason naming the offered key's fingerprint would turn one bucket
per key into a flood. Slow brute-force whose attempts fall outside the quiet
period still gets a line per attempt — IAMT-118's guarantee stands; the
gateway's port sits on the internet, and a line per TCP connect or per
offered key was a flood path into the journal, whose overflowing tape then
refuses to write for everyone (IAMT-451). The GUI keeps one admin connection
to the gateway and sends every command over it (each its own channel, §1.2),
including reading recordings screen by screen (`recordings.fetch`), rather
than logging in again per poll; after `5 minutes` with no command on the
connection, the window closes it and logs in again on the next command.

`auth.handshake_failure` records a refusal that happened before any key was
presented at all: a connection that dropped after the version exchange, or
that only spoke an authentication method the gateway doesn't know (R1-CX
F-03, 24.09.2026). `auth.failure` cannot carry such an event — its validator
requires a fingerprint, and there is none; discarding the attempt would make
the very first wave of brute force invisible. `actor` and `object` carry the
client's network address, `address` the same, `result` the refusal reason;
the fingerprint is absent by definition, and that absence is the event's own
fact.

The gateway rotates its own journal: when `events.jsonl` reaches `64 MiB`
(`JournalRotateBytes`) it is renamed to an archive `events-<UTC time>.jsonl`
alongside it, and the new file starts with a `log.rotate` line carrying the
archive's path in `details.archive` (since 1.14, IAMT-452; checked on the
gateway's one-second tick). History reads both the current file and the
archives. The gateway prunes its own archives too (R4 F-11, 24.09.2026): on
the same tick, an archive is deleted once its age (from the timestamp in its
name) exceeds `30 days` (`JournalArchiveRetentionDays`), or once there are
more than `20` archives (`JournalArchiveMaxCount`) — the newest survive, so a
storm of rotations doesn't push old history out one archive at a time forever.
Each deletion is an `admin.op` event with `result: journal.archive.prune`,
the archive's path, its timestamp (`archived`) and the reason (`age` or
`count`); a deletion that fails is left to the next tick. Pruning only
touches rotation archives — names carrying the rotation timestamp
(`ArchiveName`); tagged names (`ArchiveNameFor`, restore) and anything a
human placed alongside are not counted as rotation archives and are never
deleted.

#### Required event fields (`events.jsonl`)

Every event record is a JSON object. Event schema validation (`Event.Validate`)
enforces:

| Field | Type | Required | Rules |
|---|---|---|---|
| `time` | RFC 3339 string (`state.ZonedTime`) | Required for **all** events | Never empty or zero (`time.IsZero() == false`). |
| `type` | string (`EventType`) | Required for **all** events | Must be one of the 24 dictionary values above (`IsValidEventType(e.Type) == true`). |
| `address` | string (IP:port or IP) | Required for `auth.success`, `auth.failure` and `auth.handshake_failure` | The client's network address. Present either at top level (`address`) or in `details["address"]`. |
| `fingerprint` | string (SHA-256 fingerprint) | Required for `auth.success` and `auth.failure` | The key's SHA-256 fingerprint. Present either at top level (`fingerprint`) or in `details["fingerprint"]`. Absent for `auth.handshake_failure`: a refusal before any key was presented has no fingerprint, and that absence is the event's own fact. |
| `actor` | string | Optional | The acting subject (a person, a machine name, `gateway`, `admin`). Filled by transition-specific rules. |
| `object` | string | Optional | The acted-upon object (a machine, a target resource, an operation). Filled by transition-specific rules. |
| `result` | string | Optional | The outcome or reason/code (`ok`, `failed`, `timeout`, `reconnect`, `corrupted`, an `E_...` error code). |
| `details` | map[string]any | Optional | Extra structured attributes (e.g. `role`, `errCode`, `tunnelEpoch`). |
| `prev_hash` | string | Required in the gateway journal since 1.14 (IAMT-467) | Chain: `sha256:<64 hex>` — the SHA-256 of the previous journal line, byte for byte as it sits in the file, without the line ending; the new journal's first line carries `genesis`; the first line after a rotation names the archive's last line. The journal writer sets this at write time, not the event's sender. Lines from before 1.14 carry no field: they count as "pre-chain", not "broken", and the first chained line names the last of them. A line missing `prev_hash` after the chain began was written by a non-chaining writer (an old build, or by hand) and is reported as such. Checked by `iamtunnel gateway verify-journal` and the Gateway tab's `journal` line. The chain has no anchor outside the files: a truncated tail or a journal restarted from scratch is invisible to it. |


## 2. Username and identity

### 2.1 ABNF

```abnf
lower = %x61-7A
digit = %x30-39
name-char = lower / digit / "." / "_" / "-"
name = (lower / digit) *31name-char
reserved-name = "machine" / "enrol" / "bootstrap" / "pairing"
person-name = name                 ; semantic constraint: not reserved-name
machine-name = name
human-login = person-name ":" machine-name
command-login = person-name
machine-login = "machine:" machine-name
enrol-login = "enrol"
bootstrap-login = "bootstrap"
pairing-login = "pairing"
```

`human-login` applies only to a person's interactive session. `command-login`
applies to `whoami`, `machines.mine` and admin exec. `machine-login` applies
only to a Server-role connection and requires a registered permanent machine
key. `enrol-login` is exactly the bytes `enrol`, only for machine
registration, and requires an ephemeral ed25519 public key deterministically
derived from the enrol secret (§3.2). `bootstrap-login` is exactly the bytes
`bootstrap`, only for the first-admin claim, and requires an ephemeral
ed25519 public key deterministically derived from the bootstrap token (§3.3).
These two forms permit exactly one named command each and nothing else.
`pairing-login` is exactly the bytes `pairing`, only for pairing a new admin
(§3.4); the byte-exact `pairing` is intercepted at the SSH layer before the
ordinary username parse and key lookup, so the parser never sees it and no
one identifies the client on this login before the PIN (§3.4). The literals
`machine`, `enrol`, `bootstrap` are reserved: any bare reserved literal in a
username, other than the exact `enrol` and `bootstrap`, gives `E_NAME_RESERVED`
at parse time; `people.add` refuses a reserved literal (including `pairing`)
as `E_PERSON_NAME_RESERVED`, and `machines.enrol-code` as `E_JSON_INVALID`.
So parsing is unambiguous. Comparison is byte-exact; Unicode normalization,
trimming, case folding, URL-decoding and look-alike substitution are all
forbidden. After successful SSH authentication, the permanent key's owner
MUST equal the `person` in the username, or `E_PERSON_KEY_MISMATCH`.

The refusal priority for an arbitrary login is fixed and runs **over the raw
bytes, before any UTF-8 decoding**: (1) any ASCII control byte `0x00–0x1F` or
`0x7F` — `E_USERNAME_CONTROL`; (2) any byte ≥ `0x80` — `E_USERNAME_NON_ASCII`;
(3) more than one `:` — `E_USERNAME_COLON`; (4) exactly one `:` with an empty
part, or an empty string — `E_USERNAME_EMPTY_PART`; (5) a part longer than 32
bytes — `E_USERNAME_LENGTH`; (6) a bare reserved literal that is not the
exact `enrol`/`bootstrap`/`pairing` (the last is intercepted into the pairing
role before parsing, §3.4) — `E_NAME_RESERVED`; (7) everything else that
doesn't match one ABNF form — `E_USERNAME_GRAMMAR`. This sequence runs before
key lookup and ACL.

### 2.2 Username parser refusal table

| Input | Decision |
|---|---|
| `anna:win01` | accept as `human-login` |
| `anna` | accept as `command-login` |
| `machine:win01` | accept as `machine-login` |
| `enrol` | accept as `enrol-login` |
| `bootstrap` | accept as `bootstrap-login` |
| `pairing` | accept as `pairing-login` (§3.4): byte-exact match intercepted at the SSH layer before the parser |
| `pairing:win01` | grammatically accepted as `human-login`; a person named `pairing` cannot be created (`E_PERSON_NAME_RESERVED`), so the login is refused by key lookup as unknown |
| `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` | accept as a 32-byte `command-login` |
| `machine` | `E_NAME_RESERVED`: the literal is reserved but is not `machine-login` |
| `enrol:win01` | `E_USERNAME_GRAMMAR`: `enrol-login` allows only the exact bytes `enrol` |
| `bootstrap:win01` | `E_USERNAME_GRAMMAR`: `bootstrap-login` allows only the exact bytes `bootstrap` |
| `anna:win01:extra` | `E_USERNAME_COLON`: more than one `:` |
| `anna:` | `E_USERNAME_EMPTY_PART`: empty part |
| `:win01` | `E_USERNAME_EMPTY_PART`: empty part |
| `` (empty) | `E_USERNAME_EMPTY_PART` |
| `anna::win01` | `E_USERNAME_COLON`: more than one `:` |
| `Anna:win01` | `E_USERNAME_GRAMMAR`: an uppercase ASCII letter is forbidden |
| `anna:win 01` | `E_USERNAME_GRAMMAR`: a space is forbidden |
| `anna:<TAB>win01` | `E_USERNAME_CONTROL`: a control character is forbidden |
| `anna:<LF>win01` | `E_USERNAME_CONTROL`: a control character is forbidden |
| `anna:win<NUL>` | `E_USERNAME_CONTROL`: NUL is forbidden |
| `anna:win<DEL>01` | `E_USERNAME_CONTROL`: byte `0x7F` is forbidden |
| `\u0430\u043d\u043d\u0430:win01` (Cyrillic "anna", written as escapes here) | `E_USERNAME_NON_ASCII`: non-ASCII is forbidden |
| `anna:w\u0456n01` (Cyrillic `\u0456` in place of Latin `i`) | `E_USERNAME_NON_ASCII`: visually ambiguous Unicode is forbidden |
| `anna:win%3A01` | `E_USERNAME_GRAMMAR`: `%` and URL-decoding are forbidden |
| `-anna:win01` | `E_USERNAME_GRAMMAR`: the first character isn't lower/digit |
| `anna:win/01` | `E_USERNAME_GRAMMAR`: `/` is forbidden |
| `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:win01` | `E_USERNAME_LENGTH`: a part longer than 32 bytes |
| `machine:` | `E_USERNAME_EMPTY_PART` |
| `machine:Win01` | `E_USERNAME_GRAMMAR` |
| `machine:win01:more` | `E_USERNAME_COLON` |

`<TAB>`, `<LF>`, `<NUL>` and `<DEL>` in the table are the single bytes
`0x09`, `0x0a`, `0x00`, `0x7f`, not two printable characters with a
backslash. Every row is its own unit test. A username refusal happens before
ACL lookup; the gateway never discloses whether a person or machine exists.

## 3. Strings, codes and tokens

### 3.1 Person's connection string

Canonical form: `iamtunnel://<host>:<port>/<person>#<fp>`.

`host` is an ASCII DNS name or an IPv4 address; IPv6 is written as `[v6]`. It
is non-empty and contains no spaces, control characters, `/`, `#`, `@` or a
userinfo part. `port` is an unsigned decimal 1–65535 without leading zeros or
spaces. `person` is a `person-name` (§2.1). `fp` is a `fingerprint` (§1.3).
The string is ASCII-only, with no query, extra fragment, percent-encoding or
trailing bytes. It has no TTL and no one-time use: it is a distributed
configuration string, valid as long as the matching host key is among the
gateway's valid keys and the person hasn't been removed. On re-import, the
client replaces only the stored host/port/person/fingerprint after an exact
parse; this is idempotent.

The client compares `fp` to the gateway's presented host key in its own
`HostKeyCallback` and refuses a mismatch before the handshake completes; no
external `ssh.exe` runs, and there is no file-based trust mechanism at all.
The isolated `known_hosts` next to client state is kept only as a local
record of a verified key and never participates in the trust decision. Key
mismatch: locally `E_GATEWAY_FINGERPRINT_MISMATCH`, text "the gateway
host-key fingerprint changed: expected <expected>, got <got> — obtain a new
connection string from the administrator"; the network request, keys and
state are unchanged.

### 3.2 Enrollment code

Canonical form: `iamtunnel-enrol://<host>:<port>#<fp>:<secret>`.

`host`, `port`, `fp` follow §3.1; `secret` is 43 base64url characters (§1.3).
The code is ASCII, 1–512 bytes, with no query, no `/` after the authority, no
spaces, control characters or percent-encoding.

Since 1.3 the invitation is **not tied to an OS user**; since 1.4 it carries
exactly one thing — **the name the admin chose**: `machines.enrol-code`
accepts `{"proto":1,"name":"<name>"}` and nothing else
(`DisallowUnknownFields` refuses any other field as `E_JSON_FIELD_UNKNOWN`).
`name` follows the §2.1 name grammar and cannot be a reserved literal
(`E_JSON_INVALID`). A name collision, both with existing machines and with
still-live invitations, is checked **inside the same transaction** that
creates the invitation (`E_JSON_INVALID`): checking before the write would
race another admin issuing the same name in the same second. The gateway
generates `secret`, computes `secretHash = HMAC-SHA-256(enrolHMACKey,
raw-secret)` (exactly 32 bytes) and stores the public half of a temporary
ed25519 key; `enrolHMACKey` is 32 random bytes created at install and kept in
a separate 0600 file; the raw secret is never stored on the gateway. The
machine's temporary private key is derived deterministically as
`ed25519.NewKeyFromSeed(HKDF-SHA-256(raw-secret,
salt="iamtunnel-enrol-key-v1", info="", L=32))`; its public half MUST match
the stored one. The machine connects as username `enrol` with this key, then
calls `enrol` presenting the same secret **together with its current OS
user** in the `osUser` field of the §6 body. Since 1.4, the `machine` field
is optional: the name comes from the invitation, and any value the machine
sends is only checked for agreement with it. `PublicKeyCallback` accepts this
key only in the `enrol` role and only until the code is spent.

The gateway creates a machine record with `ID = name = the invitation's name`
(since 1.4; in 1.3 this was the machine-supplied hostname),
`requestedOsUser = claimed_os_user`, `state: "enrolled"`,
`osUserStatus: "pending"`, and stores the machine's public key. A name
collision with an existing machine (by `ID` or by `name`) is refused as
`E_ENROL_SECRET_INVALID` without spending the code — the re-check at
redemption remains, because a machine with that name could have appeared
between issuing the invitation and redeeming it. **One physical machine can
carry several registrations — one per person** (SPEC §3.2.2): different
names, different machine keys, different records. Neither `requestedOsUser`
nor the machine-reported name is ever used to log in or to admit a person —
these are unverified values the gateway checks with its own SSH public-key
user-auth probe at step 3 of §7, and only on success rewrites
`verifiedOsUser` / `osUserStatus:"verified"`.

The code is valid for **15 minutes** by the gateway's clock (since 1.3; was
24h) and permits exactly one redemption attempt. On successful `enrol`, the
gateway creates the `enrolled` machine and removes the temporary
public key/marks the secret used in one atomic write. A repeat, expiry or
wrong secret gives `E_ENROL_SECRET_USED`, `E_ENROL_SECRET_EXPIRED`,
`E_ENROL_SECRET_INVALID`; process exit 2, an event. A retry after a network
drop is resolved by `machines.list`: a new code is not needed if the machine
is already `enrolled`/`verified` with the same key.

Before sending the secret, the machine checks the gateway's key against `fp`.
On mismatch: `E_GATEWAY_FINGERPRINT_MISMATCH`, the code is NOT spent, and a
`hostkey.mismatch` event is written without the secret.

### 3.3 Bootstrap token

`gateway install` prints `host:port#fp:token`; `admin.claim` accepts this
value in the `bootstrap` field. `host`, `port`, `fp`, `token` follow the
rules of §§3.1 and 1.3. The gateway stores
`HMAC-SHA-256(enrolHMACKey, raw-token)` and the public half of a temporary
ed25519 key derived as `ed25519.NewKeyFromSeed(HKDF-SHA-256(raw-token,
salt="iamtunnel-bootstrap-key-v1", info="", L=32))`. The owner extracts the
token, connects as username `bootstrap` with this temporary key, and sends
`admin.claim` with the same token and the first admin's permanent `pubkey`.
`PublicKeyCallback` accepts the temporary key only in the `bootstrap` role
and only until the token is spent; the unknown permanent `pubkey` is not used
for SSH auth at this step.

The token is valid for 24 hours, single-use, one attempt: any syntactically
correct `admin.claim` with a matching token atomically either appoints the
first admin or burns the token on a malformed request. A repeat gives
`E_BOOTSTRAP_USED`; expiry, `E_BOOTSTRAP_EXPIRED`; a fingerprint mismatch,
`E_GATEWAY_FINGERPRINT_MISMATCH`, before the token is spent. The secret is
never logged or returned.

### 3.4 Pairing PIN

Pairing appoints a second and further admins without a terminal (SPEC 1.2).
The canonical pairing link is `host:port#fp` — the same parts and rules as
§3.1, but without a secret: the PIN, sent separately, is the secret.

The PIN is exactly `6` decimal digits (§1.5), leading zeros allowed — it is a
code, not a number, and `000123` is as likely as `900001`. Uniformity comes
from rejection sampling over `crypto/rand`. The PIN is never journaled:
`pairing.start` writes only the window's deadline to `admin.op`, and
`admin.pair` writes only the name of the person created.

An open window is the `pairingPending` field of the state snapshot:
`{secretHash, expires}`, where `secretHash = HMAC-SHA-256(enrolHMACKey,
raw-pin)` — exactly 32 bytes; the PIN itself is never stored on the gateway.
The window lives `2 minutes` by the gateway's clock; at most one window
exists at a time: `pairing.start` on an open window replaces it in one atomic
write, and the old PIN stops working the moment it is written. Only an admin
can replace or close a window (`pairing.start`/`pairing.stop`, §6); the local
recovery path when every admin key is lost is the `iamtunnel gateway pair`
command on a stopped gateway (the same atomic write, the same format, SPEC
§3.5). Window state — without the PIN — is also visible in `gateway.status`:
`pairing:{active,expires}` (§6, IAMT-331). This is the gateway's own word,
not a local client fact: a window closed from elsewhere — another admin's
`pairing.stop`, someone else's successful `admin.pair`, a replacement — dies
on every other admin's card the moment that response arrives, not on their
own timer; the field is absent from a gateway older than IAMT-331, and that
silence does not mean "no window".

While the window is open, the gateway accepts SSH authentication on username
`pairing` (`pairing-login`, §2.1) with **any** well-formed public key: the
key proves nothing here, its fingerprint is only an identity for the
limiter. A closed or expired window is refused with exactly the same shape
as an unknown key — a probe cannot tell a gateway with a closed window apart
from one that never had pairing at all. Neither refusal counts anything at
the handshake level. An address with an active pairing-limiter ban is
refused before the window is even read.

Beyond pairing-login, exactly one exec is allowed — `admin.pair` (§6) with
body `{proto,pin,pubkey}`; any other command or request gives `E_EXEC_UNKNOWN`.
The PIN is checked under HMAC: a wrong or non-six-digit PIN gives
`E_PAIRING_PIN_INVALID` and one miss in a **separate** pairing limiter (§1.5:
`3` misses from one address in `5 minutes` → a `3-minute` address ban;
changing keys does not help — the count belongs to the address). Here,
address is the peer's IP **without port**: a pairing connection lives
exactly one exec and then closes, so an `ip:port` key would hand an attacker
a fresh counter on every reconnect; the pairing limiter collapses to the bare
IP on both sides of the path — at handshake (`pairingKeyCallback`) and in
exec (`runPairing`). An IPv6 address is collapsed further, to its `/64`: an
ordinary IPv6 connection has 2^64 addresses, so counting by a single address
limits nothing — three attempts, a new address, three more. This is the same
`peerHost` that, since IAMT-446, the main login limiter also uses (§1.4), so
the `/64` applies to both; the limiter's journal line for an IPv6 address
names exactly that `/64`, while ordinary authentication events still carry
the connection's full `ip:port`. The journal itself keeps the full
`ip:port` — for investigations, not for counting.

Misses are counted both by address and against the WINDOW itself: `10` wrong
PINs from all addresses together burn the window
(`PairingWindowMissLimit`), because a per-address limiter is powerless
against someone with many addresses, and a PIN is only 10^6 possibilities
inside a two-minute window. The miss that reaches the limit burns the
window and answers `E_PAIRING_INACTIVE` with a reason ("window closed after
N wrong PINs"), not `E_PAIRING_PIN_INVALID`: the window is gone, and the
client that missed ten times should know it closed it itself. Later
attempts get the plain `E_PAIRING_INACTIVE`. Burning is journaled as an
`admin.op` line with `result = pairing.burn:ok` and the miss count in
`details` — from the outside a burned window is indistinguishable from an
expired one, and the operator who opened it must be able to learn that
someone was guessing. A miss that fails to persist (a `state.json` write
error) answers `E_INTERNAL`: an uncounted miss is an unlocked door. A
successful PIN does not clear the address counter (misses age out in the
limiter's own window) and does not lift an active ban — the same rule as
§1.4's main limiter. Refusals for "no window" (`E_PAIRING_INACTIVE`) and
"window expired" (`E_PAIRING_EXPIRED`) count nothing — a PIN with nothing to
check against is not evaluated. This holds for a PIN of any shape, and for a
window that closed, expired or was replaced already by the time of a quick
check: the address and the window take a miss only when it is charged to the
window that the handshake let this connection through by (R2-CX F-04;
previously a non-six-digit PIN was recorded to the address limiter before it
was known there was no window at all). A banned address gets
`E_PAIRING_LOCKED` before the window is read and before the PIN is compared
— the fourth attempt learns nothing, including whether a window is open.
Accepted narrowing (1.2 amendment, IAMT-330 review): the indistinguishability
of a closed window is a property of the handshake layer; the exact
`E_PAIRING_INACTIVE`/`E_PAIRING_EXPIRED` codes at the exec layer are
available only to a connection the handshake already let through on an open
window, and reveal to it only the moment that window closed — masking them
as `E_PAIRING_PIN_INVALID` was rejected: the exact code is a hint to a
legitimate client who fumbled the PIN, and a banned client never gets it
anyway.

A correct PIN trusts the client in one atomic `Store.Update`: `pubkey` is
validated (form and allowed types, §1.3), its fingerprint must not already
belong to a person — re-pairing an already-registered key gives `E_CONFLICT`
and leaves the window open (the refusal does not spend the PIN); a
`person{role:"admin"}` is created with this key, and the window burns in the
same write. The person's name is derived from the key's fingerprint — same
rules and determinism as bootstrap (§3.3). A repeat `admin.pair` after
success finds no window and gets `E_PAIRING_INACTIVE`. The window grants
nothing by itself: trust lives for exactly one successful exec.

## 4. SSH: person → gateway

After the SSH handshake, the gateway checks the username, the key's owner,
the grant, `until`, `verified` state, online, hostKeyStatus, a live
`iamtunnel-control` of the current epoch, and limits. If the door is closed,
that is not a refusal: under the machine's mutex the gateway creates a
`reservation` and runs the §5.2 path. For a person, any refusal after
successful authentication tied to the grant, expiry, the machine's existence,
its state, online, host key, control, the door, the reservation, session
limits or recording space sends exactly `Access to this machine is currently
unavailable.\r\n`, creates a `session.drop` with the precise internal reason
in `result`, and closes the session. The outward code for this is
`E_SESSION_DENIED`; it does not disclose the machine's existence or state.
The detailed codes of §6.1 are available only to admin exec. Before any byte
from the target machine reaches a successful channel, an ASCII line is sent:
`This session is recorded. Machine X, until T.\r\n`, where `X` is the machine
id, `T` the grant's RFC 3339 UTC deadline, or for an indefinite grant the
ASCII literal `revoked` (reading "until revoked.", IAMT-208). Recording
begins before this line. Exactly one `session.start` event is written per
session (actor = person, object = machine); for exec without `pty-req`, the
command travels in its `details.command`.

### 4.1 Request table and exact payloads

`string` is a uint32 length plus bytes, `uint32` is big-endian, `boolean` is
one byte. For every `channel request` line, the full RFC 4254 §5.4 packet is
`byte SSH_MSG_CHANNEL_REQUEST`, `uint32 recipient-channel`,
`string request-type`, `boolean want-reply`, then the stated payload. A
`global request` (§4) is the same shape: `byte SSH_MSG_GLOBAL_REQUEST`,
`string request-name`, `boolean want-reply`, then payload. Payloads are not
JSON. If `want-reply=true`, the gateway MUST send exactly one
`SSH_MSG_CHANNEL_SUCCESS`/`SSH_MSG_CHANNEL_FAILURE` or
`SSH_MSG_REQUEST_SUCCESS`/`SSH_MSG_REQUEST_FAILURE`; with `false`, a reply is
forbidden.

| Type and name | Payload, in strict order | `want-reply` / v1 behavior |
|---|---|---|
| channel request `pty-req` | `string TERM`, `uint32 cols`, `uint32 rows`, `uint32 width-px`, `uint32 height-px`, `string modes` | `true`; with `caps:["exec"]` refuse with `E_SSH_SHELL_FORBIDDEN` **and close the session immediately** (1.8: the line `[iamtunnel] E_SSH_SHELL_FORBIDDEN: this grant allows individual commands only — an interactive terminal (shell) cannot be opened with it.\r\nRun the command like this: iamtunnel client exec <machine> -- <command>.\r\n` in plain text, suggesting `client exec`, goes to the channel's extended data *before* closing — not silence until `SessionSetupTimeout`); otherwise relay and return the machine's result to the human within 10 s; `cols,rows` go into the recording |
| channel request `shell` | empty | `true`; with `caps:["exec"]`, the same as `pty-req`: `E_SSH_SHELL_FORBIDDEN`, a line in extended data, the session closes immediately; without an accepted `pty-req`, refuse with `E_SSH_SHELL_NO_PTY` the same way (since 1.14, IAMT-464: such a program's stderr would reach neither the human nor the recording); otherwise relay and return the machine's result within 10 s |
| channel request `exec` | `string command` | `true`; classify with the chosen `risk_classifier` before forwarding — **regardless of whether this is the session's first accepted request or exec follows an already-accepted `pty-req`** (1.8: both points apply the same rule): green relays silently; non-green journals `session.risk` and, per `risk_action`, allows/warns/asks for a one-time human approval for red/blocks and returns `exit-status 126` without forwarding. In `ai` and `both` only the scrubbed string leaves for the decision; a local `both` red is already decided and doesn't wait for the second opinion's 800 ms. An AI error explicitly warns the human of degraded protection. With `caps:["exec"]` the gateway closes the machine's stdin right after forwarding exec (`CloseWrite`, 1.46): the grant carries no standard input, and an interpreter started by name without a command meets end-of-input instead of a silent command channel. Bytes the human still writes to stdin never reach the machine: the first one ends the session as `session.drop` with `E_SSH_STDIN_FORBIDDEN`, and a line with the code and a `client exec` hint goes to the channel's extended data |
| channel request `window-change` | `uint32 cols`, `uint32 rows`, `uint32 width-px`, `uint32 height-px` | `false` (RFC 4254 §6.7); relay; add a resize to the cast |
| channel request `env` | `string name`, `string value` | client value preserved: relay `TERM`/`LANG` and return the machine's result at `true`; discard other names, return failure at `true`, no reply at `false` |
| channel request `signal` | `string signal-name` | `false` (RFC 4254 §6.9); relay |
| channel request `subsystem` | `string subsystem` | usually `true`; refuse, event, failure at `true`, `E_SSH_SUBSYSTEM_FORBIDDEN` |
| channel request agent `auth-agent-req@openssh.com` | empty | usually `true`; refuse, event, failure at `true`, `E_SSH_AGENT_FORBIDDEN` |
| channel request x11 `x11-req` | `boolean single`, `string protocol`, `string cookie`, `uint32 screen` | usually `true`; refuse, event, failure at `true`, `E_SSH_X11_FORBIDDEN` |
| channel request `eow@openssh.com` | empty | `false`; accepted as a compatible OpenSSH notice, not relayed, no event |
| channel control `SSH_MSG_CHANNEL_EOF` | `uint32 recipient-channel` | not a request, no name or `want-reply`; relayed both ways via `Channel.CloseWrite()` (RFC 4254 §5.3) |
| channel control `SSH_MSG_CHANNEL_CLOSE` | `uint32 recipient-channel` | not a request, no name or `want-reply`; relayed both ways via `Channel.Close()` (RFC 4254 §5.3) |
| channel request `exit-status` | `uint32 status` | machine → human only; `false` (RFC 4254 §6.10); relayed |
| channel request `exit-signal` | `string signal`, `boolean core-dumped`, `string error-message`, `string language-tag` | machine → human only; `false` (RFC 4254 §6.10); relayed |
| channel-open `direct-tcpip` | `string dest-host`, `uint32 dest-port`, `string origin-host`, `uint32 origin-port` | not a request; refuse the channel-open, event, `E_SSH_FORWARD_FORBIDDEN` |
| global request `tcpip-forward` | `string bind-address`, `uint32 bind-port` | client value preserved; refuse, event; request failure at `true`, `E_SSH_FORWARD_FORBIDDEN` |
| global request `keepalive@openssh.com` | empty | `true`; request success with empty payload, not relayed |
| global request `no-more-sessions@openssh.com` | empty | `false`; accepted as an OpenSSH notice, not relayed, no event |

`hostkeys-00@openssh.com` is not an incoming request from person to gateway.
It is an OpenSSH server → client global request with `want-reply=false` and a
payload of `string hostkey` values; v1 gateways never send it. So the gateway
neither replies nor re-pins on it. An incoming one from the client violates
direction: request failure at `want-reply=true`, ignored at `false`. An
unsolicited success is never sent.

The table preserves all 10 normative classes from §5.1; `eof` and `close` are
listed as their real packet types, and OpenSSH compatibility notifications
are added without extending 1.0's capabilities. If the machine's result for
`pty-req`/`shell`/`exec` doesn't arrive in 10 seconds, the gateway returns
`CHANNEL_FAILURE` to the human, closes the target and session as `E_TIMEOUT`,
and creates a `session.drop` (result: "timeout"); a late result is not
relayed. An unknown channel/global request is refused with
`E_SSH_REQUEST_FORBIDDEN`, with a failure only if `want-reply=true`. After
the first accepted `shell` or `exec`, a second starting request is refused as
`E_SSH_SESSION_ALREADY_STARTED` by the same reply rule.

At a clean session end, the final `exit-status` (or `exit-signal`) usually
arrives over the same channel before the `SSH_MSG_CHANNEL_EOF` that ends the
byte copy. Both ends of this relay — the gateway waiting for it from the
machine before closing the person↔gateway channel, and the client waiting for
it from the gateway before closing its own end of that channel — wait no
more than 5 seconds after the data-side EOF that was supposed to be followed
by `exit-status`, then close the channel anyway. If it doesn't arrive in 5
seconds (the peer half-closed and went silent without closing the channel
itself), the channel closes without it: the recipient learns the session
ended, but no exit code is delivered.

### 4.2 Active liveness probes

The gateway sends the human a `keepalive@openssh.com` global request with
empty payload and `want-reply=true` every 20 seconds. Three misses in a row
mean a dead connection: the gateway closes the transport, and teardown
follows the existing §5.2 path (`Bridge.Read` returns an error, the
recording aborts, the session count is decremented, the door moves to
`closing` if no other sessions remain). This ending is journaled as
`session.drop` (not `session.stop`), and `result` names the loss of liveness
probes — otherwise a keepalive-triggered drop is indistinguishable from an
ordinary exit.

The name `keepalive@openssh.com` is the same one §4.1 uses for
client→gateway direction. **Any reply counts as alive** — a request success
or a request failure: a human connects with an external SSH client, and
OpenSSH replies with request failure to a global request it doesn't
recognize (the default handler in `golang.org/x/crypto/ssh` does the same);
the reply itself proves the transport and client are alive. A miss is only a
transport error or no reply within the interval. Our own clients
(`iamtunnel client`, admin) still answer with request success. This is a
14.09 decision (IAMT-220): the earlier rule ("failure = miss") used to drop a
live, silent human on OpenSSH after roughly 40–60 seconds, confirmed on a
real session through the gateway. The rule for the machine (§5) is
unchanged: only our own agent answers `keepalive@iamtunnel`, and a failure
there is a protocol violation.

Detection is bounded at 60 seconds plus delivery/teardown; the normative
reaction bound is 90 seconds. These numbers are deliberately symmetric with
§5 — one detection class, one doctrine.

The probe starts right after a successful handshake and is cancelled on any
exit path: an ordinary end via the bridge, an early ACL/door/host-key
refusal, and gateway shutdown. Probes are not sent once a session has
already ended another way, and they do not extend the door's idle close:
transport closed by the human follows the ordinary path, and the probe stops
right away.

## 5. Gateway ↔ machine

A machine connects as `machine:<id>` with its registered key and the
gateway's pinned host key. The gateway keeps one current `*ssh.ServerConn`
per id and one monotonic `tunnelEpoch` per accepted connection. While the
current epoch is registered (transport/control still alive), any second
authenticated connection with the same id is refused with
`E_MACHINE_ALREADY_ONLINE`; it does not close the current transport, its
sessions, or the door. A reconnect is a new authenticated connection,
accepted only after the transport/control is actually lost and the old epoch
removed from the registry; it gets the next epoch and is journaled as
`machine.connected` with result `reconnected`. No client claim, flag or
setting can turn a live second instance into a reconnect. A control response
from another epoch is invalid.

The gateway opens exactly two valid channel types to the machine, both with
a zero-length initial payload: the long-lived `iamtunnel-control` and the
short-lived `iamtunnel-target`. The machine accepts only these names; any
other channel-open, a non-empty initial payload, or an attempt by the machine
to open a channel gets channel failure. `iamtunnel-target` connects only to
`127.0.0.1:22` and transparently splices bytes/half-close. Over it the
gateway runs an SSH client handshake as `verifiedOsUser`, with the door key
and a `HostKeyCallback` that byte-compares the host-key blob to the pinned
`sshdHostKey`; the nested handshake's client configuration MUST apply the
same ordered KEX/cipher/MAC/host-key algorithm sets from §1, not library
defaults.

Keepalive in BOTH directions is called `keepalive@iamtunnel`: a global
request with empty payload and `want-reply=true`; the receiver answers with
request success and empty payload. The initiator sends it every 20 seconds;
three consecutive error/failure/missing replies mean a dead connection. The
gateway then closes the transport, and the server detects the loss and
removes its own line; the gateway's local state changes strictly per §5.2.
Detection is bounded at 60 seconds plus delivery/teardown, normative reaction
bound 90 seconds. Any other global request from the machine gets request
failure.

A mismatched target sshd key gives `E_MACHINE_HOSTKEY_MISMATCH`: opening a
session is forbidden, `hostkey.mismatch` is recorded, `machine.state` stays
`verified`, `hostKeyStatus` becomes `mismatch`, and `observedSSHDHostKey`
keeps the observed fingerprint until `machines.rekey`.

### 5.1 The `iamtunnel-control` channel

Right after registering a new `tunnelEpoch`, the gateway opens one
`iamtunnel-control` and waits up to 10 seconds for it to be accepted. The
machine accepts at most one active control channel per tunnel; a second is
refused with channel failure `E_CONTROL_CHANNEL_DUPLICATE`, without closing
the first. On a duplicate or a closed control channel, the gateway treats the
epoch as unusable, closes the transport, and waits for an ordinary reconnect.
`online:true` is allowed only after a successful control-channel open, an
initial `door.status`, and — if that found a line — its confirmed cleanup
per §5.2.

One control channel lives for the whole tunnelEpoch; messages inside it are
one UTF-8 JSON object each, LF-terminated, with no banner and no stdout/exit
code. Every object carries `proto`, `caps`, a `uuid`-typed `id` and `op`;
`id` is allocated once and unique **across the whole tunnelEpoch**, including
after success, failure, timeout or cancellation. The gateway keeps the set of
completed and retired `id`s until the epoch ends. A success has the shape
`{"proto":1,"caps":[],"id":"<uuid>","ok":true,"result":{...}}`, an error the
common §1.2 shape with the same `proto`, `caps`, `id`, `ok:false`,
`error.code`, `error.message`. An unknown field gives
`E_JSON_FIELD_UNKNOWN`; a wrong type, a duplicate JSON key, a repeated id, or
an object with no LF gives `E_CONTROL_PROTOCOL`; an unknown capability gives
`E_CAP_UNSUPPORTED`. One line is capped at 16 KiB.

| `op` gateway → machine | Request | Success | Refusal / required machine action |
|---|---|---|---|
| `door.open` | `{id,op:"door.open",door:{id,pubkey,opened,idleDeadline,hardDeadline}}` | `{doorId,installed:true,publicKeyFingerprint}` | Check the UUID; `pubkey` must have exactly the form `ssh-ed25519 SP <base64-blob>` with no options or comment; `opened < idleDeadline < hardDeadline`; the differences `idleDeadline-opened` and `hardDeadline-opened` don't exceed the local ceilings. Start the watchdog before writing; then, under lock, atomically replace the file with the added line `restrict,pty,from="127.0.0.1" ssh-ed25519 <KEY> iamtunnel-door=<door-id>`, read back and set ACL. Another installed door → `E_CONTROL_DOOR_CONFLICT`. |
| `door.close` | `{id,op:"door.close",doorId,reason}`; `reason` is only `idle`, `hard`, `stop`, `tunnel-lost`, `reconnect`, `late-reply`; `stop` — the gateway closes the door by its own decision, not a timer: the admin changed the machine's OS user (`machines.set-user`; since 1.14, IAMT-469 — previously the gateway sent `os-user-changed`, which isn't in the dictionary, and the machine refused, breaking transport by the §5.2 `closing` rule); `tunnel-lost` carries no request: the machine removes a lost tunnel's line itself | `{doorId,removed:true}` | Remove only the line with the exact marker for this `doorId`; a missing line still gives `{removed:true}`; a marker/key mismatch gives `E_CONTROL_DOOR_MISMATCH`. After confirmed removal, stop the watchdog by its saved handle/PID; image-name wildcard stopping is forbidden. A watchdog-stop failure (the process already exited, or the API refused) does not undo the result: the line is already removed and the door is closed; the failure is logged locally on the machine, and the operation still returns `{doorId,removed:true}`. |
| `door.status` | `{id,op:"door.status"}` | `{installed,doorId?,publicKeyFingerprint?}` | Return only the installed iamtunnel line's marker/id and fingerprint; never the file's contents or other keys. |
| `door.sanitize` | `{id,op:"door.sanitize",reason}`; `reason` is only `corrupted` | `{sanitized:true}` | Under the file lock, run `SweepStale`: remove every line with the `iamtunnel-door=` marker prefix (including corrupted or invalid-UUID ones), keeping all other lines byte-for-byte in order, read back and set ACL. No lines found still gives `{sanitized:true}`. The gateway only sends `door.sanitize` from state `closed` (it holds neither a key nor its own door there): the operation doesn't distinguish a live line from a dead one, and its safety rests on this restriction. |

`<KEY>` is exactly the base64 part of the verified `ssh-ed25519` key, with no
type, comment or options. "Atomically replace the file" means: only the line
with the exact iamtunnel marker is added/removed, while every other existing
line in `administrators_authorized_keys` is preserved byte-for-byte and in
order; the file may never be written from a single door line alone.
`SweepStale` means: under the same file lock, remove **all** lines with the
`iamtunnel-door=` marker prefix and keep every other line byte-for-byte; the
server runs it before every Start and every reconnect.

The door policy belongs to the machine: `maxDoorIdle` and `maxDoorHard` are
configured locally, defaulting to 15 minutes and 8 hours respectively. The
machine refuses `door.open` with `E_CONTROL_DOOR_LIMIT` if any requested
duration exceeds its own ceiling; it also ends the door by its own monotonic
timer no later than `receipt+maxDoorHard` and at `maxDoorIdle` idle,
independent of the gateway's clock or good faith. The gateway hands over the
RFC 3339 `opened` and deadlines as its own time decision, but this cannot
extend the local ceiling.

The gateway waits 10 seconds for `door.open`, and 5 seconds for
`door.close`, `door.status` and `door.sanitize`. These events change **door
state and reservations per §5.2**, but on their own never change
`machine.state` or `hostKeyStatus`. A repeated `door.open` with the same
`door.id` and same `pubkey` idempotently returns success; the same id with a
different key gives `E_CONTROL_DOOR_MISMATCH`. The machine does not accept
`door.*` messages from a person, admin, or the target channel.

**Only the machine ever touches the key file.** The gateway generates an
ephemeral ed25519 key pair, keeps the private half only in memory, counts
sessions, and sends the machine the `door` structure from the table above —
public half, id and deadlines; the private half stays on the gateway. It
never gets a handle, path, bytes or contents of
`administrators_authorized_keys`, and cannot run any arbitrary command or
file operation over the control channel. The machine MUST refuse
`E_CONTROL_PROTOCOL` for any `op` outside the table's four strings, and for
any attempt to specify a path, command, content or other destination.

**The reverse direction — `sessions.tail`.** The control channel also
carries messages from the machine: it sends a request and gets an answer on
the same channel. The shape is the same as §5.1: an envelope
`{proto,caps,id,op}` with a uuid `id`, unique across the whole tunnelEpoch,
carrying the operation's body inside. This direction has two operations in
v1, and the first exists for the second:

```
{proto,caps,id,op:"sessions.tail",tail:{proto,id,offset,limit}}
```

The nested `tail` is a §6 request shape (`id` is a session identifier, not a
uuid — the envelope's uuid is one level up, a different field; `offset` is a
uint64; `limit` a uint32, 1..1048576). A success is an ordinary §5.1
response, whose `result` is the body of the §6 `sessions.tail` response
(`{id,offset,total,live,data,mode}`); a failure is an ordinary §5.1 error
with `code`/`message`. Sides tell request from reply by the presence of `op`.

```
{proto,caps,id,op:"sessions.mine"}
```

`sessions.mine` carries no body: there's nothing to ask beyond "what
sessions are running on me". A success returns `{sessions:[{id,person,
started}]}`, where `id` is the session identifier later used with
`sessions.tail`. Without this operation, the reverse direction is headless:
the gateway mints the session id, and the machine cannot see it any other
way — the tunnel carries a nested SSH stream the machine doesn't parse. The
list is built by the control channel's identity, not a field in the body,
exactly as access to `sessions.tail` is checked; a machine with no sessions
and a machine that asked about someone else's get the identical empty list,
because these two facts can't be told apart from outside. There is no
`until` in the list: expiry lives in the grant, not the session registry,
and inventing it here would assert something the source of truth never said.

The machine is a courier on this path. It doesn't decide whose session is
visible to whom (that's the gateway, by the control channel's identity, not
a field in the body), caches nothing, and never substitutes its own refusal
for the gateway's: "the gateway refused" and "the machine couldn't ask" are
two different messages, and the second is never presented as the first. The
machine waits 4 seconds for an answer; a later reply is discarded without
tearing down the channel. `limit` on this path is capped from above by the
machine so the base64 response fits the control line with margin for the
envelope: the cap is 3/4 of (16 KiB minus a 1 KiB reserve) = 11520 raw
bytes. A `limit` above the cap is clamped, not refused — otherwise the
answer wouldn't fit the line, and the machine, by its own strict frame,
would tear down the tunnel along with a live session. The gateway holds the
same frame on its side (R2-CX F-01): a `limit` above this cap is clamped the
same way, not read up to 1 MiB as for admin exec (§6); a reply that still
wouldn't fit the line is replaced with a short `E_CONTROL_PROTOCOL` carrying
the same `id` — a refusal to the request, not a channel abort. `caps` in
every reply to the machine is `[]`, never `null`.

**At any moment the machine carries exactly one valid access line of ours.**
A second person doesn't create a second line: while a `Reservation` is in
`opening` or `open`, the gateway's state machine only increments
`reservations` and never sends a second `door.open`. A second person either
waits for that same `door.open`, or enters through the already-open door
with the same key. The §1.5 limit of 8 active sessions per machine doesn't
contradict this: all eight go through one line. If a second `door.open` with
a different id ever does arrive, the machine answers `E_CONTROL_DOOR_CONFLICT`
and never writes a second line.

### 5.2 Door open, sessions, and the full state machine

The `sessions` and `reservations` counters live on the gateway: only it sees
grants, ACL, recording, and actual person→machine sessions. `reservations`
are admitted connections that haven't yet finished the nested SSH handshake.
Observed door state has exactly four values: `closed`, `opening`, `open`,
`closing`. The private key exists only in `opening`, `open`, `closing`, **for
this epoch's own door**; cleaning up a foreign/stale door leaves the private
key absent. Idle-close is allowed only when `sessions=0` and `reservations=0`.

Within one control channel, the machine handles `door.*` strictly in
receipt order and does not start the next handler before answering the
previous one. After a `door.open` timeout, the gateway sets an internal
`reconcilePending` flag: it stays `closed`, accepts new reservations, but
does not send the next `door.open` until a queued `door.status` confirms the
line is gone. A timeout/error on that status only repeats the background
reconciliation with backoff and does **not** close the transport — except
for a machine that stays silent on the control channel entirely: after `5`
unanswered statuses in a row with `sessions=0`, the gateway closes the
transport (`machine.disconnected`, result `control-unresponsive`), and the
machine returns as a new epoch (since 1.14, IAMT-457). The retry delay is
`1 s` after the first unanswered one, doubling each further miss, capped at
`30 s`; any reply, even a refusal, resets the count. Live sessions protect
the machine from being dropped: they run over their own channels, and an
unreconciled door isn't a reason to end them — the retries just continue with
delay up to `30 s`. This is how a late operation and a status are ordered on
the machine, so one slow open cannot knock out the tunnel or active sessions.

The normative table of events is exhaustive: a success reply; a refusal; a
timeout; a control drop; an epoch change/eviction; a reservation arriving; a
reservation cancelled; a late reply for a retired id; an initial or
reconciliation `door.status`. An unlisted state/event pair is an
implementation's `E_CONTROL_PROTOCOL`, and must be added before shipping a
new version.

| Current state | Event / condition | Action and next state |
|---|---|---|
| `closed` | initial `door.status` = `installed:false` | clear `reconcilePending`; `closed`, `online:true`; reservations may be accepted |
| `closed` | initial `door.status` returned a foreign `doorId` | `door.close` (result: "reconnect"); `closed → closing` without the private key, send `door.close(reason:"reconnect")` |
| `closed` | initial or reconciliation `door.status` returned `installed:true` without a valid `doorId` (corrupted marker) | `door.close` (result: "corrupted"); `closed → closing` without the private key, send `door.sanitize(reason:"corrupted")` |
| `closed` | reconciliation status after cleanup/sanitize = `installed:false` | clear `reconcilePending`; stay `closed`; waiting reservations may start an open |
| `closed` | reconciliation status timeout/error | stay `closed`, keep `reconcilePending`, retry the status with backoff (1 s, doubling, up to 30 s); transport and live sessions untouched. Exception — `5` unanswered in a row with `sessions=0`: close the transport (`control-unresponsive`) and wait for a new epoch (since 1.14, IAMT-457) |
| `closed` | reconciliation status again returned `installed:true,doorId` | `door.close` (result: "reconnect"); `closed → closing` without the private key, send close for this id |
| `closed` | a reservation arrives with no `reconcilePending` | increment `reservations`, create the door id/key/deadlines, `door.open`, `closed → opening`, send open |
| `closed` | a reservation arrives during `reconcilePending` | increment `reservations`, leave it waiting on the background status; a new open is forbidden only until its `installed:false` |
| `closed` | a waiting reservation is cancelled | decrement `reservations`; stay `closed`; status/reconciliation continue as needed |
| `closed` | a late successful reply for a retired `door.open` | do not restore the key; `door.close` (result: "late_reply"), `closed → closing` without the private key, close the returned `doorId` |
| `closed` | a late refusal of open, or a late reply for a retired close/status | event only; no change to state or transport |
| `closed` | initial status timeout/error, control drop, or epoch change | `closed`, `online:false`; initial status stops, reservations end; transport closes only on a drop/change, not on an open timeout |
| `opening` | a success matching the current id with `reservations>0` | `opening → open`, `door.open` (result: "ok"); all waiting reservations may open a target |
| `opening` | a success matching the current id with `reservations=0` | `opening → closing`, `door.open` (result: "ok"), immediately send `door.close(reason:"idle")` |
| `opening` | a refusal of the current open | `opening → closed`, invalidate the door id, forget the private key, drop reservations, `door.open` (result: "failed"); do not open the target |
| `opening` | a 10 s open timeout | `opening → closed`, invalidate the door id, forget the private key, drop reservations, `door.open` (result: "timeout"), set `reconcilePending` and queue a status; do not close the transport |
| `opening` | a control drop, or an epoch change/eviction | `opening → closed`, forget the private key, end reservations, `online:false`; transport is closed only by the drop/eviction itself |
| `opening` | a reservation arrives | increment `reservations`; leave it waiting on the **same** pending open |
| `opening` | the last reservation is cancelled before the reply | keep the current open; its success leads to `closing`, its refusal/timeout to `closed`, per the rows above |
| `opening` | a late reply for a retired id | event only; `opening` doesn't change. A retired open colliding with a new open cannot happen, because `reconcilePending` serializes the next open through a status |
| `open` | a reservation arrives | increment `reservations`; use the existing door and open a target for it |
| `open` | a successful nested handshake | the reservation becomes `sessions++`, state stays `open` |
| `open` | a nested-handshake error/timeout, or a cancelled reservation | drop the reservation; if both counters are zero, apply the idle rule below |
| `open` | sshd rejected the door key at the nested handshake | do **not** drop the reservation; send a control `door.status` (since 1.14, IAMT-461): the machine closes the door itself by its own timers and never tells the gateway (§5.1), so an sshd refusal is checked against the machine first. The §7 probe (`sshd-probe`, including `machines.verify`) does the same: an already-self-closed temporary door's key rejection does not declare the OS user rejected — the probe re-enters through a new door (since 1.14, IAMT-461) |
| `open` | a control `door.status` = `installed:true` with the current door's `doorId` | stay `open`; a refusal is sshd's own: drop the reservation per the "nested handshake error" row above, the human gets sshd's refusal |
| `open` | a control `door.status` = `installed:false` | `door.close` (result: "gone"); `open → closed`, forget the private key, don't close the line (there isn't one); with `reservations>0`, immediately a new `door.open` (`closed → opening`), waiting ones — including the failed handshake's — enter through the new door, retrying the handshake once; `sessions` untouched |
| `open` | a control `door.status` returned a foreign `doorId`, or `installed:true` without a valid `doorId` | `open → closed`, forget the private key, then as the matching `closed` rows (close this id, or `door.sanitize`) |
| `open` | a control `door.status` timeout/error | change nothing: the status question ordered nothing; the reservation drops as a nested-handshake error, the human gets sshd's refusal |
| `open` | idle or hard deadline, Stop (the machine's OS user changed, `reason:"stop"`), or `sessions=0 && reservations=0` under idle policy | `open → closing`, forbid new targets, send close with the matching reason |
| `open` | the door's hard deadline by the gateway's clock (`hardDeadline` from its `door.open`) with `reservations=0` | `open → closing`, `door.close(reason:"hard")` (since 1.14, IAMT-461; checked on the same one-second tick as grant expiry). A handshake in progress (`reservations>0`) delays close until its outcome. Live `sessions` are not torn down: the door is an entry, not a session's deadline — that's the grant. Waiting reservations get a new door after the close, per the `closing` row |
| `open` | control drop, or epoch change/eviction | `open → closed`, forget the private key, end sessions and reservations, `online:false`; the server cleans its own line via layers 2/3 |
| `open` | a late reply for a retired id | event only; `open` and the current door don't change |
| `closing` | a successful close of its own door | `closing → closed`, forget the private key, `door.close` (result: "ok"); waiting reservations only start a new open now |
| `closing` | a successful close of a foreign/late door, or a successful sanitize | `closing → closed`, without the private key, `door.close` (result: "ok"), `reconcilePending=true`, queue a control status; its outcomes are the `closed` rows above |
| `closing` | the first close or sanitize timeout | keep the operation's context (for close, the door id), `door.close` (result: "timeout"), retry the same operation once (sanitize — with the same `reason`); state stays `closing` |
| `closing` | a second timeout, a close refusal, a sanitize timeout/refusal, or a marker mismatch | `closing → closed`, forget the private key, end reservations, `door.close` (result: "failed"), close the transport and wait for a new epoch |
| `closing` | control drop, or epoch change/eviction | `closing → closed`, forget the private key, end reservations, `online:false`; transport is already closed by the event itself |
| `closing` | a reservation arrives | increment `reservations`, leave it waiting on the close; a new open is forbidden until `closed` |
| `closing` | a waiting reservation is cancelled | decrement `reservations`; close continues, state stays `closing` |
| `closing` | a late reply for a retired id | event only; `closing` doesn't change |

A reply for a retired id inside a live epoch is neither ignored nor restores
the prior state. A late successful open in `closed` always gets a cleanup
close; after an open timeout its outcome is reconciled by the following
status, FIFO. A late refusal of open, and any retired close/status, don't
change the door. So one slow reply never leaves a pending id, never creates
a competing key, and never leaves the door forever `opening`/`closing`.

A mismatched target sshd host key is **not** an event of this table, and the
door does not close because of it. The §5.2 automaton has no such input at
all (`core.DoorEvent`: `status`, a reservation and its cancellation,
`success`, `failure`, `timeout`, transport loss, a late reply, a nested
handshake failure). The gateway learns of the mismatch inside the nested
handshake and refuses the person per §5.1 (`E_MACHINE_HOSTKEY_MISMATCH`, a
`hostkey.mismatch` event recorded, `machine.state` stays `verified`,
`hostKeyStatus` becomes `mismatch`), without touching the door itself: it is
`hostKeyStatus:"mismatch"` at the access layer (§4, §5.1) — before the
reservation — that removes the right to a session or a new door; an already
open door isn't closed by this refusal and ends on its own `idle`/`hard`
deadlines (rows above) or idle policy, once its `sessions` run out.
`door.close` is not sent for a mismatch, and `open → closing` doesn't happen
for this reason. The §7 probe's temporary door (`sshd-probe`) is its own
entry and its own deadline, unrelated to this table.

Order for a new person's connection: after ACL/limits, the gateway creates a
`reservation` under the machine's mutex. At `open` it uses the existing
door; at `opening` it waits for the current open; at `closing` it waits only
for its specific outcome from the table; at `closed` it starts an open or
waits for reconciliation status. Only after `open` does the gateway open
`iamtunnel-target` and start the nested SSH. A successful handshake turns
the reservation into `sessions++`; an error/timeout drops the reservation. A
person facing any control refusal gets exactly `Access to this machine is
currently unavailable.\r\n`.

### 5.3 Races and control refusal

> **The invariant every race below serves.** At any moment the machine
> carries exactly one valid access line of ours. None of the races listed may
> ever produce two lines — not even for an instant, not even until the next
> cleanup.

1. **Two people while the door is closed.** The first, under the mutex,
   creates one door and one pending open; the second adds a reservation and
   waits for the same result. On success both open a separate
   `iamtunnel-target`; on refusal/timeout the table drops both reservations
   and returns to `closed`.
2. **Idle-close racing a new connection.** The idle worker takes the same
   mutex and closes the door only after checking `sessions=0 &&
   reservations=0`. A reservation created before that check cancels the
   close. If the worker reached `closing` first, a new reservation doesn't
   create a second door and waits for the close's terminal transition.
3. **Machine reconnect.** Losing control/transport first atomically removes
   the old `tunnelEpoch` from the registry, then invalidates its pending and
   retired handling, ends active sessions, forgets the private key, and ends
   reservations; only after the old epoch is removed can a new one with the
   same id be accepted. A second transport arriving before the old epoch is
   removed gets `E_MACHINE_ALREADY_ONLINE` and doesn't change the old
   epoch's state. A new epoch always starts with `door.status`. If it shows
   any marker, the gateway closes the found `doorId` (or calls `door.sanitize`
   for a corrupted marker without a valid id), re-checks the line is gone via
   status, and only then sets `online:true` or a new `door.open`.
4. **A slow reply and a person's cancellation.** These are the `opening` and
   retired-id rows: a reply can't be tied to a new request, and a line
   installed too late still gets an unconditional `door.close`. A success
   with no reservation leads to an immediate close.
5. **A second control-channel attempt.** The machine refuses the second
   channel, keeping the first. The gateway records `machine.rejected` (with
   `E_MACHINE_ALREADY_ONLINE`) or `machine.disconnected`, closes the epoch's
   transport and waits for a reconnect; the automaton moves the door to
   `closed` per the transport-loss row.
6. **Close racing a session's end/start.** `door.close` applies to a specific
   door id and doesn't decrement `sessions`. A session ending during
   `closing` only decrements the counter; a new reservation doesn't reuse the
   old key and doesn't open a new one before the close's terminal
   transition. The `sessions` counter belongs to the machine, not the door:
   a session outlives the door it entered through (a hard deadline, a
   machine-closed door), and its end is counted regardless of door state;
   idle-close only happens from `open`.

The machine starts the watchdog **before** writing the door line in the
`door.open` handler, and outside any job object. After a confirmed
`door.close`, the machine removes the line and stops the watchdog only by
its saved handle/PID; ordinary stopping by image-name is forbidden, so it
can't kill the watchdog. If the watchdog fails to stop, `door.close` does
not fail: the key is already removed from the file, the closed-door
invariant holds; the failure is logged locally on the machine, and the
gateway is still told `{doorId,removed:true}`. On Stop, window close,
keepalive loss, or control/transport loss, the server removes the marker
itself under the file lock. Layer 2 cleans the line while the server is
alive; layer 3 only when its parent dies — they are not the same mechanism.
The control channel does not replace these layers and never gives the
gateway a write into the file.

## 6. Exec commands

General rule: the SSH username matches the role; `stdin` is one JSON
request, `stdout` is §1.2. `proto` is required in every request. If `caps`
is present in a request, it is checked per §1.1. `result` below lists only
the specific fields; the common envelope is not repeated. `until`,
`serverTime`, `opened`, `closed`, `added` have type `time`.

| Command | Role and request | Success `result` |
|---|---|---|
| `whoami` | any; `{proto}` | `{subject,role,serverTime}`; for a person also `{person}` |
| `machines.mine` | person; `{proto}` | `{machines:[{id,name,until,online,state,sshdListening,doorOpen,caps}]}` |

(There is no `heartbeat` verb in v1 anymore: its two duties split between
`whoami` — role and expiry — and `machines.mine` — a person's machines, with
their expiries and states; no separate time ping is left.)

| `enrol` | username `enrol`, temporary key and `secret` §3.2; `{proto,secret,machine,osUser,machineKey}` — since 1.3: `machine` and `osUser` are REQUIRED (the hostname and OS user the machine reports about itself; before 1.3 these were optional and came from the code's binding) | `{machine,state:"enrolled",requestedOsUser:osUser,osUserStatus:"pending",hostKeyStatus:"unverified",serverTime}` — since 1.3: a `machine` collision with an existing machine is refused as `E_ENROL_SECRET_INVALID` without spending the secret |
| `door.open`, `door.close`, `door.status`, `door.sanitize` | not v1 exec commands; refused if called via exec | `E_CONTROL_ONLY`; door operations run only per §5.1, via `iamtunnel-control` |
| `people.add` | admin; `{proto,name,role,keys}` | `{person:{name,role,keys}}` |
| `people.remove` | admin; `{proto,name}` | `{removed:name}` |
| `people.rename` | admin; `{proto,from,to}` | `{from,to,terminatedSessions}`; moves the person's grants and goals to the new name in one write; open sessions under the old name close per `grants.revoke` rules; the key follows the person |
| `people.keys.add` | admin; `{proto,name,pubkey}` | `{person,key:{fingerprint,pubkey,added}}` |
| `people.keys.remove` | admin; `{proto,name,fingerprint}` | `{person,removedFingerprint:fingerprint}` |
| `people.list` | admin; `{proto}` | `{people:[{name,role,keys:[{fingerprint,pubkey,added}]}]}` |
| `people.connection-string` | admin; `{proto,name}` | `{connectionString}` |
| `machines.enrol-code` | admin; `{proto,name}` | `{enrolCode,expires}` — since 1.4: the invitation carries the name the admin chose; not tied to an OS user, 15-minute TTL; an `osUser` field is refused as `E_JSON_FIELD_UNKNOWN` |
| `machines.list` | admin; `{proto}` | `{machines:[{id,name,state,online,sshdListening,requestedOsUser,verifiedOsUser?,osUserStatus,doorOpen,doorState,reservations,tunnelEpoch?,sshdHostKey,hostKeyStatus,observedSSHDHostKey?}],pendingEnrolments:[{name,expires}]}` — since 1.4: `pendingEnrolments` carries `name` (the name the invitation will redeem under) and `expires`; no `osUser` — the invitation isn't tied to one |
| `machines.remove` | admin; `{proto,id}` | `{removed:id}` |
| `machines.rename` | admin; `{proto,id,name}` | `{id,name}`; changes only the machine's label — its `id`, grants and journal keep pointing at the same machine; a label collision with another machine's name or `id` gives `E_CONFLICT` |
| `machines.rekey` | admin; `{proto,id,confirmFingerprint}` | `{id,oldHostKey,newHostKey,state:"verified",hostKeyStatus:"match"}` |
| `machines.set-user` | admin; `{proto,id,osUser}` | `{id,requestedOsUser:osUser,osUserStatus:"pending",state:"enrolled"}` |
| `machines.verify` | admin; `{proto,id}` | `{id,state,requestedOsUser,verifiedOsUser?,osUserStatus,sshdHostKey,hostKeyStatus,observedSSHDHostKey?}` |
| `grants.grant` | admin; `{proto,person,machine,until,caps}` | `{grant:{person,machine,until,caps:["shell"|"exec"]}}` |
| `grants.extend` | admin; `{proto,person,machine,until}` | `{until,was,terminatedSessions}`; changes an existing grant's deadline: extending never touches a live session, shortening acts per `grants.revoke`; `until:""` means indefinite |
| `grants.revoke` | admin; `{proto,person,machine}` | `{revoked:true,terminatedSessions:[uuid]}` |
| `grants.list` | admin; `{proto,person?,machine?}` | `{grants:[{person,machine,until,caps}]}` |
| `risk.check` | admin; `{proto,command}` | `{level:"green"|"yellow"|"red",rule,reason,classifier:"rules"|"ai"|"both",externalError?}` |
| `risk.mode` | admin; `{proto,mode?}` | `{mode:"log"|"warn"|"ask"|"block",source:"config"|"live",changed,previous}`; without `mode`, read-only |
| `risk.source` | admin; `{proto,classifier?}` | `{classifier:"rules"|"ai"|"both",source:"config"|"live",changed,previous}`; without `classifier`, read-only |
| `risk.approve` | person; `{proto,approvalId}` | `{approvalId,approved,changed,expiresAt}`; approves the caller's own pending red permission |
| `sessions.active` | admin; `{proto}` | `{sessions:[{id,person,machine,started,bytesIn,bytesOut}]}` |
| `sessions.history` | admin; `{proto,from?,to?,person?,machine?}` | `{sessions:[{id,person,machine,started,ended,reason}]}` |
| `sessions.kill` | admin; `{proto,id,reason}` | `{id,killed:true}` |
| `recordings.list` | admin; `{proto,machine?,from?,to?}` | `{recordings:[{id,machine,person,sessionId,mode?,started,ended,bytesIn,bytesOut}]}` |
| `recordings.fetch` | admin; `{proto,id,part,offset,limit}` | `{id,part,offset,total,sha256,data}`; one base64 chunk |
| `gateway.status` | admin; `{proto}` | `{version,fingerprints,online,verified,sessions,diskPercent,draining}` — `version`, `diskPercent` (recording filesystem fill percentage; or `diskError` if it can't be read) and `draining` (the gateway is stopping: no new sessions, live sessions warned) since 1.14, IAMT-466; `risk` also carries `{mode,source,classifier:"rules"|"ai"|"both",yellow,red,blocked,latestRed?}`; `audit:{ok,since,error?,lostWrites,readError?}` — whether the audit journal is writable (since 1.14, IAMT-451; absent on an older gateway, and that absence is not "ok"); `pairing:{active,expires?}` — whether a §3.4 pairing window is open and when it self-closes (IAMT-331; absent on an older gateway, and that absence is not "no window"; the PIN never appears here — it goes out exactly once, in the `pairing.start` reply) |
| `gateway.fingerprint` | admin; `{proto}` | `{fingerprints:[fingerprint]}` |
| `gateway.rotate-hostkey` | admin; `{proto}` | `{oldFingerprint,newFingerprint}` |
| `gateway.backup` | admin; `{proto}` | `{backup:{id,created,size,sha256}}` |
| `admin.claim` | username `bootstrap`, temporary key and token §3.3; `{proto,bootstrap,pubkey}` | `{person,role:"admin"}`; `person` = `admin`, or if that name is taken, a name from the key's fingerprint, as in §3.4 |
| `pairing.start` | admin; `{proto}` | `{pin,expires,ref}` — opens the §3.4 pairing window, replacing one already open |
| `pairing.stop` | admin; `{proto}` | `{stopped}` — closes the pairing window; idempotent, `stopped:false` when there was none |
| `admin.pair` | username `pairing` (`pairing-login` §2.1), any well-formed key while the §3.4 window is open; `{proto,pin,pubkey}` | `{person,role:"admin"}` — the only exec allowed in this role, everything else is `E_EXEC_UNKNOWN` |

There is no `heartbeat` line in this table anymore, and that's not a gap: the
verb is retired from v1, and its two duties split between the surviving
verbs — role and expiry are `whoami`'s job, a person's machines with their
states and capabilities are `machines.mine`'s. A separate "server-time ping"
isn't needed after that: server time already comes back in every response of
these commands, and `heartbeat`'s machine list used to be a stripped-down one
anyway (no states or capabilities).

`sshdListening` in the `machines.mine` reply is a verification history at
the moment the tunnel came up (`online` and `state == "verified"` or
`hostKeyStatus == match`, and no `mismatch`), **not** a live sshd port probe
at call time. If sshd dies while the tunnel stays up, the field remains
`true` until the first session attempt, which gets a plain refusal: `Access
to this machine is currently unavailable: the target machine's sshd service
is not responding.` or `... rejected the door key.` Don't treat this field as
a live fact.

`recordings.list` returns two different identifiers, and confusing them is a
mistake. `id` is a hash of the recording's path inside the recordings
directory; only it is accepted by `recordings.fetch`, and it cannot be
derived from anything else. `sessionId` is the identifier the session ran
under and the one `sessions.history` returns; a history row is matched to
its recording by this. `mode` says how to parse the bytes: `"exec"` — one
command, written line by line in `.exec.jsonl`; empty or any other value — a
terminal session in asciicast. A reader MUST ask `mode` BEFORE opening the
bytes: running a line-by-line journal through a terminal emulator produces
plausible garbage, not an error. Older `.meta` files written before this
distinction existed carry no `mode` and are read as asciicast.

`sessions.tail` and `recordings.fetch` answer DIFFERENT questions.
`sessions.tail` follows a RUNNING session and takes its path from the
in-memory registry of live recordings; after `drainGrace` past the session's
end it disappears from there, and the verb honestly answers with emptiness.
`recordings.fetch` reads a finished recording from disk. A client showing
history MUST call the second: by definition, only what's finished belongs in
history. While a recording's `.meta` still says `status:"recording"`,
`recordings.fetch` refuses `E_CONFLICT` regardless of the requested
part — including `meta`, which the recorder rewrites on finalization; live
viewing is `sessions.tail`'s job (R1-CX F-13, 24.09.2026). The `mode` field of
a `sessions.tail` reply names the byte format returned: `"cast"` — asciicast
v2 (shell and exec with `pty-req`), `"exec"` — `.exec.jsonl` (exec without
`pty-req`, §8). The formats are similar enough that the wrong reader doesn't
crash, it silently shows nothing, so a client picks its reader by `mode`
alone; a missing field (a gateway older than 1.14) means `"cast"`. A live
exec session is visible to a watcher the same way a live shell is (since
1.14, IAMT-453).

`risk.mode` is an admin-only switch for the risk ladder, with no gateway
restart. A request with `mode:"log"`, `"warn"`, `"ask"` or `"block"` is
atomically saved to the data directory and applies from the next
classified exec onward; existing sessions are not closed. An empty or
missing `mode` only reads state. `source:"live"` means the switch file was
chosen, `source:"config"` means the settings' `risk_action` applies. An
invalid value is refused and changes nothing. `gateway.status`'s
`risk.source` shows the action-mode source, and `risk.classifier` the
chosen verdict source (`rules`, `ai` or `both`).

`risk.source` is an admin-only switch for WHO judges a command, structured as
a twin of `risk.mode`. A request with `classifier:"rules"`, `"ai"` or
`"both"` is atomically saved to the data directory and applies from the next
classified exec onward; existing sessions are not closed. An empty or
missing `classifier` only reads state. `source:"live"` means the switch file
was chosen, `source:"config"` means the settings' `risk_classifier` applies.
`"ai"` and `"both"` refuse to switch on while the gateway has no classifier
key: without a key, fail-closed would stop every command, and the one who
flipped the switch would lock themselves behind their own approval queue.
`gateway.status` adds `risk.classifierSource` (`config` or `live`) and
`risk.classifierKey` (whether any key is present at all).

`risk_classifier` is set in the gateway's configuration and defaults to
`rules`. `ai` and `both` require an API-key file; the historical name
`external_risk_observation_key_file` is kept for compatibility. The old
`external_risk_observation_enabled:true` without an explicit
`risk_classifier` selects `both`. The external service sees every exec
command under `ai` and `both` (the local red path in `both` sends it
asynchronously), but only after `ScrubCommand`; a password, token,
authorization header or long credential-like literal never leaves.

Under `ask`, a red command is fully stopped before forwarding: the gateway
issues `approval-id=<id>` and `E_APPROVAL_REQUIRED`, and the machine never
receives the exec. A person approves it via `risk.approve`, then repeats
exactly the same command line; the person, machine and exact string are all
checked, the approval lasts 5 minutes and burns after one run. A changed
command, a different person, or a different machine cannot use this
approval. This is a deliberate boundary: `ask` holds back AI/scripted
automation until a human acts, but it is not proof of the human's good
faith. There is no live wait inside the SSH session.

The `machines.mine` reply's `caps` field (1.8) is this person's own
grant capability on this machine — the same array `grants.grant` accepts and
admin exec sees: `["shell"]` or `["exec"]`. Before 1.8, a client had no way
to know in advance that `connect` would refuse on an exec-only grant — only
by hitting the refusal (§4.1, `E_SSH_SHELL_FORBIDDEN`); now it's visible
already in the machine list, before any attempt to enter. The value comes
from the same `acl.Grant` that already supplies `until` — there is no second
source of truth.

`people.add.keys` is a non-empty array of allowed `pubkey` values; `role` is
only `user` or `admin`; `name` cannot be a §2.1 reserved literal, which gives
`E_PERSON_NAME_RESERVED`. Since 1.4, `machines.enrol-code` creates a §3.2
code tied to the NAME the admin chose, and nothing else (`osUser` in the body
is refused). A successful `enrol` creates an `enrolled` machine under that
name in one write and removes the pending code; the machine reports its own
`osUser` (and, optionally, a hostname — only for cross-checking), the gateway
accepts it and checks its shape; a name collision with an existing machine
refuses `E_ENROL_SECRET_INVALID` without spending the code. `machines.set-user`
MUST close an active door, clear `verifiedOsUser`, move `osUserStatus` to
`pending`, and start a re-probe. With `hostKeyStatus:"mismatch"`,
`machines.list` and `machines.verify` show both `sshdHostKey` (the old
pinned key) and `observedSSHDHostKey` (the new, observed one).
`machines.rekey` accepts only `confirmFingerprint`, which MUST exactly equal
`observedSSHDHostKey`; the gateway itself replaces the pinned key with the
observed one and returns old/new fingerprints. The door stays closed until
success. `risk.check` classifies a string with the GATEWAY's chosen source
and executes nothing: the owner is asking not "is this command dangerous in
general" but "what will my gateway do with it" — so the answer comes from
whoever decides the verdict (`rules`, `ai` or `both`), not a copy of rules
baked into a client binary that could drift after an update. When the
external source is unreachable, the reply keeps the chosen fallback and may
carry `externalError`; `classifier` shows the source. An empty command gives
`E_JSON_INVALID`. `grants.grant` v1 accepts exactly one capability:
`caps:["shell"]` or `caps:["exec"]`; any other array gives
`E_CAP_UNSUPPORTED`.

`doorState` is returned to admin only from the §5.2 set, `reservations` is a
non-negative uint32, `tunnelEpoch` a uint64 absent only when offline. For the
compatible boolean `doorOpen`, one mapping holds: `true` if and only if
`doorState:"open"`; `false` for `closed`, `opening`, `closing`. So an admin
can observe every automaton invariant, while a non-admin client gets no
extra internal information.

For `recordings.fetch`: `part` is exactly `cast`, `txt`, `meta` or `exec`
(`exec` is the `.exec.jsonl` file of a no-PTY exec recording, §8; a
terminal recording answers `E_NOT_FOUND` for it); `offset` is a uint64 from
0; `limit` is a uint32, 1–1,048,576 raw bytes. For a growing recording
(`status:"recording"` in `.meta`), the gateway refuses `E_CONFLICT` before
reading any part: a growing file's `total` and `sha256` are facts of
different moments, and a client stepping through by `offset` against a
concurrently appended file would be lied to (R1-CX F-13, 24.09.2026). The
gateway returns at most `limit` bytes in `data` (base64), the raw file's
total size in `total`, the full file's SHA-256 in `sha256`; the client
repeats the request with `offset + decodedLen(data)` until `offset=total`. A
zero-length chunk is allowed only at `offset=total`. This keeps the single
JSON object of §1.2 bounded and never requires loading a whole recording
into memory. Computing `sha256` is done ONCE, not per chunk: for a finished
recording, the recorder computes the hash at finalization and stores it in
`.meta`, and the gateway serves that stored fact; for one without a stored
hash (older than this convention), the gateway computes it on first request
and keeps it in memory for the process's lifetime — but only for a finished
recording: hashing a prefix of a growing one (`status:"recording"`) would lie
about the whole file. The gateway also doesn't walk the tree by `id` on
every chunk — the path is cached and invalidated by recording rotation.
`gateway.backup` creates an archive in the gateway's local storage,
identified by `backup-id`; `gateway.restore` is only a local console command
`iamtunnel gateway restore <backup>`, not a remote exec and not part of this
table.

`grants.extend` changes an already-issued grant's deadline, not a fresh
grant. `until` follows the same format `grants.grant` accepts; `until:""`
makes access indefinite. Extension (a later deadline or indefinite) never
touches open sessions: they live until the new deadline. Shortening acts per
`grants.revoke`: sessions open under this grant close immediately, and their
count is returned as `terminatedSessions`. A non-existent person/machine pair
gives `E_NOT_FOUND`, an expired or unparsable deadline `E_JSON_INVALID`. The
reply's `until` (new deadline) and `was` (previous) follow `grants.list`'s
convention: an empty deadline is omitted. As with any access-changing
command, the state change and its publication to the ACL engine are one
whole.

`people.rename` corrects a person's name without recreating them. Renaming
is one state write: the person, all their grants and all their goals move to
the new name together; keys already belong to the person and follow them.
Everything stored BY the name moves; everything WRITTEN ABOUT the old name
does not — journal lines under the old name aren't rewritten, the journal is
honest about the past. Publication to the ACL engine is the same single
whole as a grant issue: live sessions under the old name close per revoke
rules (their count is `terminatedSessions`), and access continues under the
new name. A taken name gives `E_CONFLICT`, a §2.1 reserved literal
`E_PERSON_NAME_RESERVED`, an unknown name `E_NOT_FOUND`. `machines.rename`
symmetrically changes only a machine's label: the machine keeps its `id`,
and grants, goals and the journal reference it, so the access engine is
untouched; a label collision with another machine's name or `id` gives
`E_CONFLICT`, an invalid or reserved name `E_JSON_INVALID`, an unknown
machine `E_NOT_FOUND`.

`grants.revoke`, `grants.extend` on shortening, expiry, and `sessions.kill`
all close a session immediately, finalize its recording, and create an
event. Idle and hard deadlines belong to the door, not the session: they
close the entrance (§5.2), while whoever already entered stays until their
grant ends (explicitly recorded since 1.14, IAMT-461).

### 6.1 Exec and SSH error codes

The third column is the code of the **exec process only**. `—` means the
error happens before exec (SSH handshake, channel/open, or a local check)
and the protocol creates no process exit code. A person's interactive
session gets the single `E_SESSION_DENIED` for any ACL/machine-state
refusal; the detailed state codes are available only to admin commands.

| Code | Exact text to the human | Process code |
|---|---|---|
| `E_PROTO_CLIENT_NEWER` | The client is newer than the gateway and cannot safely continue. | 4 |
| `E_PROTO_GATEWAY_NEWER` | The client version is too old; protocol {minProto} or newer is required. | 4 |
| `E_CAP_UNSUPPORTED` | The requested capability is not supported by the gateway. | 4 |
| `E_JSON_INVALID` | Invalid JSON request. | 3 |
| `E_JSON_FIELD_UNKNOWN` | The request has an unknown field. | 3 |
| `E_USERNAME_COLON` | Invalid username: extra colon. | — |
| `E_USERNAME_EMPTY_PART` | Invalid username: empty part. | — |
| `E_USERNAME_CONTROL` | Invalid username: control character. | — |
| `E_USERNAME_NON_ASCII` | Invalid username: only ASCII is allowed. | — |
| `E_USERNAME_GRAMMAR` | Invalid username. | — |
| `E_USERNAME_LENGTH` | Invalid username: a part longer than 32 bytes. | — |
| `E_NAME_RESERVED` | This name is reserved by the protocol. | — |
| `E_PERSON_NAME_RESERVED` | This name is reserved by the protocol. | 2 |
| `E_PERSON_KEY_MISMATCH` | The key does not belong to the person named in the username. | — |
| `E_AUTH_KEY_UNKNOWN` | The key is not registered. | — |
| `E_AUTH_RATE_LIMITED` | Too many failed authentication attempts. | — |
| `E_SESSION_DENIED` | Access to this machine is currently unavailable. | — |
| `E_GRANT_MISSING` | No grant for this machine. | 2 |
| `E_GRANT_EXPIRED` | The grant has expired. | 2 |
| `E_MACHINE_NOT_VERIFIED` | The machine is not yet verified. | 2 |
| `E_MACHINE_UNVERIFIED` | The machine's sshd check failed. | 1 |
| `E_MACHINE_REKEY_UNAVAILABLE` | There is nothing to confirm: no sshd key mismatch was observed. | 1 |
| `E_MACHINE_REKEY_CONFIRMATION` | `confirmFingerprint` doesn't match the observed sshd key. | 1 |
| `E_MACHINE_OFFLINE` | The machine is offline. | 2 |
| `E_MACHINE_ALREADY_ONLINE` | This machine is already connected. | — |
| `E_MACHINE_HOSTKEY_MISMATCH` | The machine's SSH key doesn't match the pinned one. | 2 |
| `E_SESSION_LIMIT_PERSON` | The person's session limit is reached. | — |
| `E_SESSION_LIMIT_MACHINE` | The machine's session limit is reached. | — |
| `E_SESSION_SETUP_TIMEOUT` | SSH session setup timed out. | — |
| `E_GATEWAY_FINGERPRINT_MISMATCH` | the gateway host-key fingerprint changed: expected <expected>, got <got> — obtain a new connection string from the administrator | — |
| `E_ENROL_SECRET_INVALID` | The enrollment code is invalid. | 2 |
| `E_ENROL_SECRET_USED` | The enrollment code has already been used. | 2 |
| `E_ENROL_SECRET_EXPIRED` | The enrollment code has expired. | 2 |
| `E_BOOTSTRAP_USED` | The bootstrap token has already been used. | 2 |
| `E_BOOTSTRAP_EXPIRED` | The bootstrap token has expired. | 2 |
| `E_PAIRING_PIN_INVALID` | Wrong PIN — check the code from the pairing window. | 2 |
| `E_PAIRING_EXPIRED` | The pairing window has expired — request a new PIN. | 2 |
| `E_PAIRING_INACTIVE` | The pairing window is not open. | 2 |
| `E_PAIRING_LOCKED` | Too many wrong PINs — pairing from this address is locked. | 2 |
| `E_TARGET_CHANNEL_INVALID` | Invalid machine channel. | — |
| `E_CONTROL_ONLY` | This door operation is only available on the machine's control channel. | 2 |
| `E_CONTROL_CHANNEL_DUPLICATE` | A second control channel for this tunnel is forbidden. | — |
| `E_CONTROL_PROTOCOL` | Invalid control-channel message. | — |
| `E_CONTROL_TIMEOUT` | The machine did not answer the control operation in time. | — |
| `E_CONTROL_EPOCH_STALE` | The reply belongs to a closed machine connection. | — |
| `E_CONTROL_DOOR_CONFLICT` | Another door is already installed on the machine. | — |
| `E_CONTROL_DOOR_MISMATCH` | The door id or key doesn't match. | — |
| `E_CONTROL_DOOR_LIMIT` | The request exceeds the machine's local door ceilings. | — |
| `E_COMMAND_BLOCKED` | The exec command was stopped by the gateway's risk policy. | — |
| `E_RISK_CLASSIFIER_UNAVAILABLE` | In `ai`/`both`, the external classifier is unreachable; exec is stopped before reaching the machine and awaits human approval. Journaled in `session.drop` to distinguish "the AI often objects" from "the AI was down". Ways out: approve in the window, switch to `rules` with `iamtunnel admin risk source rules`, or explicitly turn off the safety net with `iamtunnel admin risk mode log` / `iamtunnel admin risk mode warn`. | — |
| `E_APPROVAL_REQUIRED` | A red exec is stopped under `ask` and awaits a one-time human approval; the command never reached the machine. | — |
| `E_RISK_KEY_REJECTED` | The submitted external-classifier key failed the probe request; the previous key kept working. The reason distinguishes the service declining the key from the service being unreachable. | 1 |
| `E_APPROVAL_FORBIDDEN` | This person cannot approve someone else's ask permission. | 2 |
| `E_APPROVAL_NOT_FOUND` | The ask permission is unknown or already expired. | 2 |
| `E_SSH_SUBSYSTEM_FORBIDDEN` | SSH subsystems are forbidden in version 1.0. | — |
| `E_SSH_FORWARD_FORBIDDEN` | Port forwarding is forbidden in version 1.0. | — |
| `E_SSH_AGENT_FORBIDDEN` | Agent forwarding is forbidden in version 1.0. | — |
| `E_SSH_X11_FORBIDDEN` | X11 forwarding is forbidden in version 1.0. | — |
| `E_SSH_REQUEST_FORBIDDEN` | This SSH request is forbidden in version 1.0. | — |
| `E_SSH_SESSION_ALREADY_STARTED` | The SSH channel already started. | — |
| `E_SSH_SHELL_FORBIDDEN` | Interactive shell sessions are forbidden by the `exec` capability. | — |
| `E_SSH_SHELL_NO_PTY` | A shell only opens inside a terminal: request one (`ssh -t`), or run one command via exec. | — |
| `E_SSH_STDIN_FORBIDDEN` | On a grant with the `exec` capability, standard input is not carried: the command starts with the machine's stdin already closed, and any byte the human writes is refused by the gateway — the session ends, and a line with the code and a `client exec` hint goes to extended data. | — |
| `E_RECORDING_DISK_FULL` | Not enough space for the required session recording. | — |
| `E_EXEC_UNKNOWN` | Unknown exec command. | 2 |
| `E_NOT_FOUND` | The requested object was not found. | 2 |
| `E_CONFLICT` | The operation conflicts with current state. | 2 |
| `E_TIMEOUT` | The operation timed out. | 2 |
| `E_AUDIT_UNAVAILABLE` | The gateway's audit journal is not being written: everything that should reach it is refused until the next successful write; or the action already happened but was not recorded (the text says which case). | 1 |
| `E_INTERNAL` | Internal gateway error. | 70 |

Machine-checked error dictionary (single source of truth for reconciling
this document with the code; `wire` = the code MUST occur as a literal in
product code, `internal` = an internal classification: a literal in product
code is allowed only with an explicit `// errdict:internal` comment on the
same line, and only for a code in the internal list; an unmarked internal
literal is a gate failure; every internal code the code never produces is
listed in the checker as reserved with a reason):

```iamtunnel-error-codes-v1
{"wire":["E_AUDIT_UNAVAILABLE","E_BOOTSTRAP_EXPIRED","E_BOOTSTRAP_USED","E_CAP_UNSUPPORTED","E_CONFLICT","E_CONTROL_CHANNEL_DUPLICATE","E_CONTROL_DOOR_CONFLICT","E_CONTROL_DOOR_LIMIT","E_CONTROL_DOOR_MISMATCH","E_CONTROL_PROTOCOL","E_ENROL_SECRET_EXPIRED","E_ENROL_SECRET_INVALID","E_ENROL_SECRET_USED","E_EXEC_UNKNOWN","E_INTERNAL","E_JSON_FIELD_UNKNOWN","E_JSON_INVALID","E_MACHINE_ALREADY_ONLINE","E_MACHINE_OFFLINE","E_MACHINE_REKEY_CONFIRMATION","E_MACHINE_REKEY_UNAVAILABLE","E_MACHINE_UNVERIFIED","E_NOT_FOUND","E_PAIRING_EXPIRED","E_PAIRING_INACTIVE","E_PAIRING_LOCKED","E_PAIRING_PIN_INVALID","E_PERSON_NAME_RESERVED","E_PROTO_CLIENT_NEWER","E_PROTO_GATEWAY_NEWER","E_TARGET_CHANNEL_INVALID"],
"internal":["E_APPROVAL_FORBIDDEN","E_APPROVAL_NOT_FOUND","E_AUTH_KEY_UNKNOWN","E_AUTH_RATE_LIMITED","E_COMMAND_BLOCKED","E_CONTROL_EPOCH_STALE","E_CONTROL_TIMEOUT","E_CONTROL_ONLY","E_GATEWAY_FINGERPRINT_MISMATCH","E_GRANT_EXPIRED","E_GRANT_MISSING","E_MACHINE_HOSTKEY_MISMATCH","E_MACHINE_NOT_VERIFIED","E_NAME_RESERVED","E_PERSON_KEY_MISMATCH","E_RECORDING_DISK_FULL","E_RISK_CLASSIFIER_UNAVAILABLE","E_RISK_KEY_REJECTED","E_SESSION_DENIED","E_SESSION_LIMIT_MACHINE","E_SESSION_LIMIT_PERSON","E_SESSION_SETUP_TIMEOUT","E_SSH_AGENT_FORBIDDEN","E_SSH_FORWARD_FORBIDDEN","E_SSH_REQUEST_FORBIDDEN","E_SSH_SESSION_ALREADY_STARTED","E_SSH_SHELL_FORBIDDEN","E_SSH_SHELL_NO_PTY","E_SSH_STDIN_FORBIDDEN","E_SSH_SUBSYSTEM_FORBIDDEN","E_SSH_X11_FORBIDDEN","E_TIMEOUT","E_USERNAME_COLON","E_USERNAME_CONTROL","E_USERNAME_EMPTY_PART","E_USERNAME_GRAMMAR","E_USERNAME_LENGTH","E_USERNAME_NON_ASCII","E_APPROVAL_REQUIRED"],"absent":["E_DOOR_CLOSED"]}
```

`E_AUTH_KEY_UNKNOWN` only occurs in `PublicKeyCallback` when a fingerprint is
absent from the state snapshot; `E_GRANT_MISSING`/`E_GRANT_EXPIRED`,
`E_MACHINE_NOT_VERIFIED`, `E_MACHINE_OFFLINE` and
`E_MACHINE_HOSTKEY_MISMATCH` are returned only by admin exec asking about or
changing an explicitly named object. An interactive person gets
`E_SESSION_DENIED` instead. `E_MACHINE_NOT_VERIFIED` and
`E_MACHINE_UNVERIFIED` are DIFFERENT refusals worth keeping straight, since
the names differ by one prefix. The first is an internal classification: the
machine isn't verified, so access isn't granted (an ACL refusal reason). The
second goes out on the wire from `machines.verify` and means the verification
attempt itself just failed — the sshd probe didn't pass. `machines.rekey`
adds two more wire codes: `E_MACHINE_REKEY_UNAVAILABLE`, when there's nothing
to confirm (no sshd key mismatch was observed), and
`E_MACHINE_REKEY_CONFIRMATION`, when the submitted `confirmFingerprint`
doesn't equal the observed key. `E_TARGET_CHANNEL_INVALID` means a wrong
name, initial payload, or direction for the machine's channel-open.
`E_NOT_FOUND` means an explicitly named id/name is missing in an admin
command; `E_CONFLICT` an attempt to create a duplicate or change an object in
an incompatible state; `E_TIMEOUT` an explicit timeout on a synchronous admin
operation; `E_INTERNAL` an unforeseen error after a safe shutdown of the
operation. An exec command name outside the §6 table gives `E_EXEC_UNKNOWN`.
Pairing (§3.4) adds four codes in the same exit-2 group:
`E_PAIRING_PIN_INVALID` — a wrong or non-six-digit PIN while a window is
open, the only one of the four the pairing limiter counts as a miss;
`E_PAIRING_EXPIRED` — a window that was open but expired;
`E_PAIRING_INACTIVE` — no window at all, including right after a successful
`admin.pair` that burned it in the same write; these two count nothing,
because there's nothing to check the PIN against. `E_PAIRING_LOCKED` is
given to an address with an active pairing-limiter ban first of all — before
the window is read and before the PIN is compared, at both layers: a fourth
attempt learns nothing, including window state. The exact
`E_PAIRING_INACTIVE`/`E_PAIRING_EXPIRED` remain the property of a connection
the handshake already let through on an open window (§3.4) — a banned
address never gets them. So `E_DOOR_CLOSED` doesn't exist in v1: the door is
opened by the §5.2 automaton, not by an exec command.

## 7. Registration state machine

| State | Input / check | Transition and event | Timeout / drop |
|---|---|---|---|
| `code-parsed` | parse §3.2 | `gateway-connect` (local Set-up step) | wrong format: `E_ENROL_SECRET_INVALID`, no network |
| `gateway-connect` | no TLS; SSH host key equals `fp` | `machine-key-generated`, `enrol.start` on the gateway | 20 s for TCP+SSH; drop/timeout: `connect-failed`, the code isn't spent |
| `machine-key-generated` | ed25519 generated, key protected | `enrol-sent` (local Set-up step) | 20 s for generation/local save; failure: `local-failed`, the code isn't spent |
| `enrol-sent` | send `enrol` with secret, machineKey, osUser | `enrolled`, `enrol.verified` (result: "enrolled"); the secret burns in the same state write | 20 s waiting for a reply; drop: `enrol-unknown`; the operator checks `machines.list`, a repeated `enrol` with the same code does not run automatically |
| `enrolled` | machine's key registered | `tunnel-connected`, `machine.connected` | 60 s for the first tunnel; a drop stays `enrolled`, reconnecting is allowed |
| `tunnel-connected` | open `iamtunnel-control`, run an initial `door.status`; clean up any found line per §5.2 | `sshd-probe`, `machine.connected`; only now `online:true` | 10 s for control, 5 s for status/cleanup; failure: `enrolled`, `machine.disconnected` (control/status failed), transport closed |
| `sshd-probe` | open `iamtunnel-target` and SSH-handshake to localhost:22 with no user-auth, pin the host key; then temporarily open the door and run SSH public-key user-auth as `requestedOsUser` with no shell/exec | success: record `verifiedOsUser=requestedOsUser`, `osUserStatus:"verified"`, `verified`, `enrol.verified`; close the temporary door | 20 s for target+handshake and user-auth; failure: `enrolled`, `osUserStatus:"rejected"`, `enrol.failed`; retry is `machines.verify` or the next tunnel |
| `verified` | pinned sshd host key and osUser confirmed | terminal | tunnel drop: `state:"verified", online:false`, `machine.disconnected`; registration is not cancelled |

The overall bound for one interactive enrollment attempt is 6 minutes. The
20/60-second numbers and the overall bound are v1 parameters chosen for an
unambiguous implementation; they don't change the enrol TTL (15 minutes since
1.3). The Set-up UI keeps the last explicit state until restart. If the
process dies at any point after `enrolled`, the gateway keeps only this fact;
a partially created local key does not mean a new code was spent.

## 8. Recording, deadlines and reserved capabilities

Recording starts before the first byte. Shell and exec with `pty-req` carry
`.cast`, `.txt`, `.meta`; if `.txt` dropped the middle of a long session out
(SPEC §6.5: the first and last 10,000 lines), `.meta` carries
`txt_omitted_lines` — how many lines exist only in `.cast`; exec without
`pty-req` carries the lossless `.exec.jsonl`, `.meta`: first the command,
then base64 stdout/stderr chunks, exit-status/exit-signal and EOF in one
sequence. Before reaching the human, every byte from the machine is written
and fsynced; a failure to create, write or fsync closes the session before
passing on the unwritten byte and creates a `session.drop` with the write
failure's result. `.cast` is asciicast v2: `{version:2,width,height,
timestamp,env:{TERM},command?}`, output `[t,"o",data]`, resize
`[t,"r","WxH"]`; input is not recorded. `command` (and the same field in
`.meta`) appears for a session started as exec after `pty-req` ("ssh -t gw
command"): exec draws no terminal, and without the field the recording would
show output without saying what produced it (since 1.14, IAMT-454). Such an
exec is also a session-start request: setup (§1.4) lasts until shell or
exec, and `pty-req` doesn't end it; the command also lands in the
`session.start` event's `details.command`. A grant is checked at entry and
continuously; expiry/revoke immediately ends the SSH session with "Session
closed: the grant expired." or "Session closed: the grant was revoked.";
`sessions.kill` uses "Session closed: an administrator ended this session.
Your access is unchanged." (since 1.14, IAMT-440: the grant itself is
untouched here, and the old text about revocation was a lie); narrowing a
grant to exec (`grants.set-caps`) and pulling its deadline closer
(`grants.extend`) use "Session closed: an administrator changed your access
to this machine. Log in again to continue on the new terms.", renaming a
person (`people.rename`) uses "Session closed: an administrator renamed you
on this gateway. Your access moved to the new name; log in again with it.",
changing the machine's OS user (`machines.set-user`) uses "Session closed: an
administrator changed the account the gateway uses on this machine. It is
being checked now; your access is unchanged.", and the matching `session.drop`
carries `access changed by administrator`, `person renamed by administrator`
and `machine is not verified` respectively (since 1.14, IAMT-440: access
survives all three, where the human and the journal used to be told about
revocation).

The 85% threshold means **85% of the filesystem holding the recordings
directory** (used/total, as `df` reports), and it triggers rotation by
place: delete recordings older than 90 days, then the oldest recordings
until fill drops below 85%; each deletion is an event. Refusing new sessions
uses a separate `recordingRefusePercent=95`% of the same measurement — both
checks measure the same thing, or a disk filled by someone else's data would
trip the refusal before rotation had a chance to free space (13.09 decision,
IAMT-171). The parameter must be greater than 85 and no more than 99; at 95%
the gateway returns `E_RECORDING_DISK_FULL` before opening a recording. So
rotation gets an 85–95% window to free space, distinct from the access
refusal.

The door's idle deadline is measured by the gateway from real I/O, by the
server from tunnel bytes; the hard deadline is checked by both, whichever
fires first closes it. `door.open` carries required RFC 3339 `opened`,
`idleDeadline`, `hardDeadline` with `opened < idleDeadline < hardDeadline`;
the machine accepts them only within its own `maxDoorIdle`/`maxDoorHard`
(§5.1). v1 has no separate command or control operation to change or read
door policy.

Reserved exclusively via `caps`: `file-transfer-exec` (1.1, exec file-transfer
commands, not SFTP), `linux-target` (1.1, the alternate authorized_keys
path) and `grant-caps` (grant values other than `shell`). None of these
permit sftp, `-L/-R/-D` or agent forwarding without a further, newer spec.

## 9. Reconciliation with SPEC

| SPEC | Protocol section |
|---|---|
| §3.1, pinned gateway key and connection string | §§3.1, 4 |
| §3.2, one tunnel, door, keepalive | §5 |
| §3.3, admin operations | §6 |
| §3.4, enrol and states | §§3.2, 7 |
| §4.3, name model, grants and time | §§1.3, 2, 6 |
| §5.1, SSH request table | §4.1 |
| §5.2, `iamtunnel-target` | §5 |
| §5.3, JSON exec and version | §§1.1–1.2, 6 |
| §6.1, keys and identity | §§1, 2, 4 |
| §3.3, §3.5 and §6.1 (1.2 amendment, IAMT-323), pairing | §§2, 3.4, 6 |
| §6.2, host keys | §§3, 5 |
| §6.3, door and refusal | §5 |
| §6.4, deadlines and revoke | §§7–8 |
| §6.5, recording | §§4, 8 |
| §12, 1.0/1.1 boundaries | §8 |

No contradictions with SPEC were found in the normative rules. SPEC's
underspecified numeric parameters and formats, needed for a byte-exact,
testable implementation, are fixed by the implementation and its tests.

### IAMT-402 / IAMT-403 command and event contract

The admin command table additionally contains:

| command | request | result |
|---|---|---|
| `goal.set` | admin; `{proto,person,machine,goal}`; `person` names the grant holder, not the caller; an empty goal explicitly clears the current one | `{person,machine,goal,history}` |
| `goal.current` | admin; `{proto,person,machine}` | `{person,machine,goal}`; no history is returned |
| `goal.history` | admin; `{proto,person,machine}` | `{person,machine,goal,history}`; newest first, maximum 20 |
| `goal.list` | admin; `{proto}` | `{goals}`: every pair carrying a goal record, each row shaped as `goal.history` returns it (IAMT-405) |
| `risk.key` | admin; `{proto,key}` | `{replaced,present,fingerprint}`; the key is never returned |

Goal is durable per person/machine pair and has no expiry. `session.start`
and `session.risk` carry the scrubbed goal beside the session/command, with
`goalApplied` showing whether the selected external client accepted the
richer command-plus-goal request. In `rules`, `goalApplied:false` is
explicit and the goal doesn't affect the verdict. The external `state` is
named JSON (`command` and `goal`), not an ambiguous concatenated string.
`goal.list` (IAMT-405) returns the whole table in one reply — every pair
carrying a goal record, history included — so a page of many grant rows is
filled by one request, not one per row; pairs without a goal record are
absent, which reads as the empty goal the row already shows.

`risk.key` probes exactly once before an atomic `datafile` replacement with
mode 0600 and service ownership. A rejected probe preserves the previous
file and classifier. Failure diagnostics distinguish 401/403 key rejection,
timeout/5xx service unavailability, and invalid key form. A failed probe
answers `E_RISK_KEY_REJECTED` whose error body names the class in `category`
(IAMT-404): `rejected` for a 401/403 key refusal, `unavailable` for a
timeout/5xx/no-answer probe — the field and the prose reason agree, so a
client reading either reaches the same outcome. The operation journals
actor, time, result, and fingerprints only. The existing `sudo install`
key-file path remains supported.
