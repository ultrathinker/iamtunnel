package main

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/ultrathinker/iamtunnel/internal/config"
)

// usageText is the top-level help; every role has its own section via
// helpTopic. Help goes to stdout and exits 0 — without arguments and on
// request alike.
const usageText = `iamtunnel — temporary, recorded SSH access to Windows machines behind NAT.

One binary, four roles (SPEC §3): client (the person), server (the
machine), admin, gateway (the VPS bastion).

Usage:
  iamtunnel [--tab guide|setup|client|server|gateway|session|admin|history|settings]
                                               GUI window (Windows, Linux, macOS);
                                               --tab opens a specific screen (check aid)
  iamtunnel version                           print version, git sha, platform
  iamtunnel client connect-string <str>       remember a gateway (first run, and each new one)
  iamtunnel client key                        my public key, for the administrator who adds me
  iamtunnel client gateways                   the gateways I have saved, current one marked
  iamtunnel client use <name>                 switch to another saved gateway
  iamtunnel client forget <name>              drop one saved gateway
  iamtunnel client machines                   machines allowed to me, with expiries
  iamtunnel client connect <machine>          open a terminal to a machine
  iamtunnel client exec <machine> -- <cmd>    run one command (exec-only grants)
  iamtunnel server start [--idle-minutes N] [--max-hours N]
  iamtunnel server stop|status                the door and the tunnel
  iamtunnel server install|uninstall          automatic start (systemd, launchd, Windows logon task)
  iamtunnel enrol <code>                      register this machine
  iamtunnel admin <group> <verb> [args] [--json]
  iamtunnel gateway install|uninstall|run|status|backup|restore|rotate-hostkey|pair|reset
  iamtunnel gateway verify-journal            check the journal's hash chain
  iamtunnel shot <screen> [--subtab n] [--dark] [--out f]
                                              offscreen GUI screenshot
  iamtunnel desktop install|uninstall       Linux .desktop + icons (user-only)
  iamtunnel selftest                          built-in self check
  iamtunnel help <topic>                      topics: client server admin gateway
                                              enrol shot desktop selftest config

Destructive commands (removing access, killing sessions, rotating keys,
restoring state) ask for confirmation; pass --yes to skip the question.

Exit codes:
  0  success (also version and --help)
  1  internal error
  2  user error: unknown command, bad argument or value, unconfirmed or
     cancelled destructive command
  3  environment error: unparsable config file, missing restore source
  4  access denied: a configured path cannot be read with current rights

Configuration — one precedence rule everywhere, strongest wins:
flags, then environment variables, then the config file, then built-in
defaults. Details: "iamtunnel help config".
`

// helpTopic routes "iamtunnel help <topic>" and the per-command
// --help. Role topics end with the path block resolved for this machine.
func helpTopic(s *streams, topic string) int {
	if txt, ok := topicText[topic]; ok {
		fmt.Fprint(s.out, txt)
		if roleDirs[topic] || topic == "config" {
			fmt.Fprintln(s.out, "\nPaths resolved on this machine ("+runtime.GOOS+"):")
			fmt.Fprint(s.out, config.FormatConfigHelp(runtime.GOOS, s.env))
		}
		return exitOK
	}
	if txt, ok := leafText[topic]; ok {
		fmt.Fprint(s.out, txt)
		return exitOK
	}
	if txt, ok := adminLeafHelp(topic); ok {
		fmt.Fprint(s.out, txt)
		return exitOK
	}
	fmt.Fprintf(s.out, "iamtunnel %s: no separate help topic — showing the top-level usage.\n\n", topic)
	fmt.Fprint(s.out, usageText)
	return exitOK
}

// adminLeafHelp builds the short help of "admin <group> <verb> --help"
// from the verb table: the usage line and, for destructive verbs, the
// consequence sentence and the --yes hint.
func adminLeafHelp(topic string) (string, bool) {
	parts := strings.SplitN(strings.TrimPrefix(topic, "admin "), " ", 2)
	if len(parts) != 2 || !strings.HasPrefix(topic, "admin ") {
		return "", false
	}
	v, ok := adminVerbs[parts[0]][parts[1]]
	if !ok {
		return "", false
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Usage: iamtunnel %s%s\n", topic, joinArgs(v.args))
	if v.destructive {
		fmt.Fprintf(&b, "\nDestructive: this command %s\nPass --yes to skip the confirmation question.\n", v.consequence)
	}
	return b.String(), true
}

func joinArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return " " + strings.Join(args, " ")
}

// roleDirs marks topics whose help ends with the resolved path block.
var roleDirs = map[string]bool{"client": true, "server": true, "gateway": true, "enrol": true}

// helpTopicNames lists what "iamtunnel help <topic>" understands.
var helpTopicNames = []string{"client", "server", "admin", "gateway", "enrol", "shot", "desktop", "selftest", "config"}

func cmdHelpTopic(s *streams, args []string) int {
	if len(args) == 0 {
		fmt.Fprint(s.out, usageText)
		return exitOK
	}
	if len(args) > 1 {
		return fail(s, userErrf("iamtunnel help: want exactly one topic — %s.", strings.Join(helpTopicNames, ", ")))
	}
	if _, ok := topicText[args[0]]; !ok {
		if _, ok := leafText[args[0]]; !ok {
			return fail(s, userErrf("iamtunnel help: unknown topic %q — want: %s.", args[0], strings.Join(helpTopicNames, ", ")))
		}
	}
	return helpTopic(s, args[0])
}

const clientHelp = `iamtunnel client — the person's role (SPEC §3.1): a directory of the
machines you are allowed on and the commands to connect or run a
single command on them. It tunnels and forwards nothing.

Usage:
  iamtunnel client connect-string <str> [--name NAME] [--replace]
      Remember the connection string the admin gave you, and switch to
      it:
        iamtunnel://<host>:<port>/<person>#<sha256 of the gateway host key>
      The gateway key is pinned from the string itself — nothing to
      verify on screen.
      More than one gateway can be remembered: a personal one and a
      work one live side by side, and --name labels them. What still
      needs --replace is the same gateway presenting a DIFFERENT host
      key — the same address with a new lock, which is either a rebuilt
      gateway or somebody standing between you and it.
  iamtunnel client key
      Print this machine's public key, creating it on first use. Give it
      to the administrator who adds you; they answer with your
      connection string. Works before any connection string is saved.
  iamtunnel client gateways
      The gateways this machine remembers. The marked one is what every
      other command acts on.
  iamtunnel client use <name>
      Switch to another saved gateway. Nothing is asked and nothing is
      dialled: there are no logins in this product, only your key, and
      every gateway that knows you already holds its public half.
  iamtunnel client forget <name>
      Drop one saved gateway. Your key stays — it is this machine's
      identity, not that gateway's opinion of it — and so does the
      person record there: a client can always forget, only an
      administrator can revoke.
  iamtunnel client machines
      Machines allowed to you, with expiry times and online state.
  iamtunnel client connect <machine>
      Open a terminal to <machine> through the gateway, using the
      pinned host key and an isolated known_hosts. Refused on an
      exec-only grant — see "client exec" below.
  iamtunnel client exec <machine> -- <command>
      Run exactly one command on <machine> through the gateway and
      exit with the command's own exit code (126 if the gateway's risk
      policy stopped it before it reached the machine). The "--" is
      required; everything after it is the command verbatim, its own
      flags included — this program parses none of them. stdout and
      stderr are kept separate: the command's own stderr and the
      gateway's own words (the recording notice, a risk warning, a
      block) both land on this program's stderr, never mixed into the
      command's stdout. Works on both an exec-only and a shell grant;
      "client connect" only works on a shell grant.

Flags: --config <file>, --data-dir <dir> (client data directory,
holding key, known_hosts, machines.mine). An elevated command refuses to
write into a data directory owned by another account (IAMT-333): the
refusal names the owner and --accept-foreign-data-dir — pass it only for
a directory you have verified yourself. On Linux and macOS, a command run
under sudo against the invoking account's OWN directory does not refuse:
it gives up root for good and runs as that account (IAMT-504).
`

const serverHelp = `iamtunnel server — the machine-side role (SPEC §3.2): holds the
outbound tunnel to the gateway and opens/closes the door (the
gateway's key in administrators_authorized_keys). Needs administrator
rights; the Start check refuses to open the door without sshd.

Usage:
  iamtunnel server start [--idle-minutes N] [--max-hours N] [--key-file <path>]
      Check sshd, sweep stale door lines, connect to the gateway, open
      the door, start the watchdog.
      --idle-minutes N   close the door after N minutes with no tunnel
                         traffic (1..10080)
      --max-hours N      close the door after N hours regardless (1..720)
      --key-file <path>  the authorized_keys file sshd reads administrators'
                         keys from; default on Windows
                         %ProgramData%\ssh\administrators_authorized_keys
  iamtunnel server stop      remove the door key, close the tunnel
  iamtunnel server status    tunnel state, door id, timers
  iamtunnel server install   automatic start, so the machine comes back on
      its own (SPEC §3.2.1); "server start" keeps working by hand.
      Linux: the systemd unit iamtunnel-machine.service, run as root.
      macOS: the LaunchDaemon com.iamtunnel.machine.plist (launchd), run
      as root. Both need a root console: sudo iamtunnel server install.
      Windows: the logon task \iamtunnel\<registration> in Task Scheduler,
      run as the Windows account the machine's registration is bound to,
      with that account's highest privileges, every time it signs in. It
      needs the machine enrolled first ("iamtunnel enrol") and a console
      opened with "Run as administrator"; other accounts' registrations
      on this computer are not touched.
  iamtunnel server uninstall remove what install added: the systemd unit,
      the LaunchDaemon or the Windows logon task (a server running right
      now keeps running there - "server stop" ends it). The machine key,
      the enrolment record and the local journal are not touched.
  iamtunnel server doorwatch <door-id> <parent-pid> <keyfile>   (internal)
      The watchdog child process of SPEC §6.3; started by the server
      itself, not by hand.

Flags: --config <file>, --data-dir <dir> (server data directory,
holding machine.key and machine.id).
`

const adminHelp = `iamtunnel admin — the administrator role (SPEC §3.3). Every operation
is a command to the gateway over SSH; output is a table, or JSON with
--json. Destructive verbs ask for confirmation; pass --yes or answer
"yes" at the prompt.

Usage: iamtunnel admin <group> <verb> [args] [--json]

  people add <name> --key <pubkey> [--role user|admin]
  people rename <name> <new-name>                           (--yes)
      grants and goals move to <new-name> in one write; sessions opened
      under the old name are closed right now; the key follows the person
  people remove <name>                                      (--yes)
  people list
  people keys add <name> <pubkey>
  people keys remove <name> <fingerprint>                   (--yes)
  people connection-string <name>     print the §3.1 string for <name>
  machines enrol-code <name>                  invite one registration
      <name> is yours to choose: it is what you grant access against and
      revoke by. One physical machine may hold several — one per person
      who works on it.
      --os-user is no longer accepted: the machine reports the account
      it runs as when it registers, and the gateway verifies it by
      logging in as that account. It is still recognised, and refused
      with that sentence, so an old script is told why rather than
      "unknown flag".
  machines list
  machines rename <id> <new-name>
      changes the display label only; the id, grants and journal keep
      pointing at the same machine
  machines remove <id>                                      (--yes)
  machines rekey <id> --confirm-fingerprint <fp>            (--yes)
  machines verify <id>                retry the sshd probe
  machines set-user <id> <os-user>                          (--yes)
      <os-user> is DOMAIN\name or MACHINE\name on Windows and a local
      POSIX name (lowercase, like alice) on Linux and macOS
  grants grant <person> <machine> <until-ISO8601|""> [--cap shell|exec]
                                                   "" issues an indefinite grant (§4.3);
                                                   without --cap the grant is exec — the one
                                                   kind of access any safety mode can judge;
                                                   --cap exec permits one command, not a shell
  grants extend <person> <machine> <until-ISO8601|"">       (--yes)
      moves the deadline of an existing grant: "" makes it indefinite and
      a later date touches no live session; a shorter date closes the
      sessions opened on the grant right now
  grants set-caps <person> <machine> <shell|exec>           (--yes)
  grants revoke <person> <machine>                          (--yes)
  grants list
  sessions active | history
  sessions kill <session-id>                                (--yes)
  sessions tail <session-id> [--offset N] [--limit N]  follows a session that is still running
  recordings list [--from RFC3339] [--to RFC3339]
  recordings fetch <id> [--out DIR]   downloads .cast+.txt (or .exec.jsonl for exec) plus .meta
  gateway status | fingerprint | backup
  gateway rotate-hostkey                                    (--yes)
  goal set <person> <machine> [--goal GOAL]  declare or explicitly clear the grant holder's current goal
  goal current <person> <machine>            show only the current goal
  goal history <person> <machine>            show the last 20 explicit goal declarations
  goal list                                  show every declared goal pair, current and history counts
  risk check <command>             classify one command against the gateway's selected classifier
      [--goal GOAL]                provide an explicit goal for this diagnostic request
  risk mode [log|warn|ask|block]   read or change the live safety mode
      log journals; warn runs with a warning; ask requires one human approval for red;
      block refuses red exec commands. Yellow is a warning under ask and block.
  risk source [rules|ai|both]      read or change which checkers judge a command
      rules is the gateway's own patterns and sends nothing outside; ai is the external
      classifier alone; both is the strictest — a command passes only when both allow it.
      ai and both need a classifier key, and are refused without one. Survives a restart,
      and overrides risk_classifier in the gateway settings file.
  risk pending                     list the red commands held for you
  risk approve <approval-id>       approve your own pending red command once
  risk deny <approval-id>          settle one held command with a refusal
  risk key --key <new-key>         replace the external classifier's API key
      --key - reads the key from standard input instead, which is the form to
      prefer: a key passed as an argument is visible in the shell history and
      in the process list of every other user on this machine.
      The gateway probes the new key with one real request BEFORE storing it:
      a key it refuses leaves the working one untouched. The key is never
      printed, returned or journalled; "gateway status" shows only whether a
      key is present and its fingerprint.
      Interactive shell sessions have no command classification, so block does not stop keystrokes.
  pairing start                       open a 2-minute PIN pairing window;
                                      prints the one "iamtunnel-pair://"
                                      string of SPEC §3.6, and the ref and
                                      PIN separately under it
  pairing stop                        close the pairing window
  pair <pasted-string>                become a permanent admin: paste the
                                      whole line the pairing window printed
                                      (SPEC §3.6). The older two-argument
                                      form <ref> <pin> still works.
  claim <host:port#fingerprint:token> --key <pubkey>   one-time bootstrap

Names are [a-z0-9][a-z0-9._-]{0,31}; times are ISO-8601 with a zone;
RSA keys below 3072 bits and dsa/ecdsa-sha1 keys are rejected (§6.1).
Flags: --config <file>, --json. An elevated command refuses to write into
a client data directory owned by another account (IAMT-333); the refusal
names the owner and --accept-foreign-data-dir.
`

const gatewayHelp = `iamtunnel gateway — the gateway bastion host (SPEC §3.5, §3.5.1).
These are local lifecycle commands run on the gateway host itself; the
remote admin variants live under "iamtunnel admin gateway". The service
half of install/uninstall is per-OS: a systemd unit on Linux, the
"iamtunnel-gateway" SCM service on Windows, a LaunchDaemon on macOS.

Usage:
  iamtunnel gateway install [--port P] [--public-host HOST] [--rebootstrap]
      Idempotent setup: directories, host key, the OS service (systemd
      unit on Linux — created under its own user; SCM service on
      Windows — under NT SERVICE\iamtunnel-gateway with the data
      directory's ACL hardened; LaunchDaemon on macOS), enable and
      start, then print the one-time bootstrap token twice: as the
      bare reference "iamtunnel admin claim" takes, and as the one
      pasteable "iamtunnel-claim://..." string of SPEC §3.6 that
      goes straight into the Admin tab's single field.
      --public-host <host> is REQUIRED: the DNS name or IP address
      that clients and machines use to dial the gateway (SPEC §3.1
      host grammar). It is written into the service command line so
      "gateway run" started by the service inherits the same value,
      and replaces the bootstrap link's <this-host> placeholder with
      the real address. A repeated install never touches state.json or
      the host key; the service IS updated in place when --public-host
      changes. On Windows install needs an elevated console; on macOS
      it must run as root (sudo) — the service user _iamtunnel is
      created through dscl and the LaunchDaemon lands in
      /Library/LaunchDaemons. The firewall is never touched — install
      prints the command to open the port (netsh on Windows, the
      Application Firewall tool on macOS; pf is never configured).
      --rebootstrap re-issues the one-time bootstrap reference (fresh
      token, fresh 24h window) when the first admin was never claimed
      in time; refused while the gateway is running or when an admin
      already exists (SPEC §3.3).
  iamtunnel gateway uninstall
      Stop and remove the OS service install created (systemd unit /
      SCM service / LaunchDaemon, SPEC §3.5.1). Needs elevation on
      Windows; on macOS it must run as root (sudo). The data directory
      — host key, state, event log — is
      left untouched, so a repeated "gateway install" revives the same
      gateway identity. Idempotent: when the service is not installed,
      reports "nothing to do" and succeeds.
  iamtunnel gateway reset --public-host HOST [--port P] [--new-hostkey] [--yes]
      The one command of what used to be five manual steps (IAMT-388):
      stop the service, wipe the data (state.json, bootstrap-token,
      events.jsonl, enrol-hmac.key, recordings/), put a fresh empty
      gateway back and print its new bootstrap claim. The host key is
      KEPT — already handed-out connection strings keep checking
      against the same fingerprint; pass --new-hostkey to replace it
      too. Without --yes the command names what will be lost — the
      people, machines and grants it counted, the journal, the
      recordings — and requires --yes or a typed "yes". The reset and
      its counts land as the first line of the fresh journal
      (admin.op result:"reset"). Needs elevation on Windows; on macOS
      as root (sudo). A gateway running in a console (not as the
      service) is refused by its state lock — stop it by hand first;
      if the fresh install then fails, repeat "gateway install" to
      finish the setup.
  iamtunnel gateway run [--port P] [--public-host HOST]    serve; SIGTERM drains gracefully
      "gateway run" requires public host from --public-host or the
      public_host key in the config file (flag beats file). Under the
      Windows SCM service the Stop control drains the same way.
  iamtunnel gateway status [--port P] [--public-host HOST]
      alive, version, fingerprint, load.
      Also reprints the bootstrap string of SPEC §3.6 for as long as
      it can still be used. Once it has been spent or its 24 hours
      have run out, status says so in words instead of printing a
      string that would only fail: the token expiring unseen is what
      forced the emergency path of RUNBOOK §5.11 on 17.09.
      The string carries the address clients dial, and install put
      that address in the service command line, not in a file: pass
      --public-host (and --port, if it is not 2222) or set them in
      the config file, or status says the string cannot be rendered
      instead of rendering the wrong one.
  iamtunnel gateway backup [--out F]  atomic tarball of state and events
  iamtunnel gateway restore <F> [--yes]
      Overwrite state.json from a backup tarball.
  iamtunnel gateway rotate-hostkey [--yes]
  iamtunnel gateway verify-journal
      Check the journal's hash chain (IAMT-467): exit 0 intact, 3 not;
      see "iamtunnel gateway verify-journal --help".
  iamtunnel gateway pair [--public-host HOST]
      Open a 2-minute PIN pairing window locally (IAMT-323, PROTOCOL
      §3.4). Prints, in this order: the one "iamtunnel-pair://" string
      of SPEC §3.6, the ready "iamtunnel admin pair <string>" line, and
      — for whoever still wants to hand the two halves over through two
      channels — the reference and the PIN on lines of their own. The
      whole block can be pasted into "admin pair" or into the Admin
      tab's field as it stands. The recovery path for when every admin
      key is lost — no network admin is needed, only this one local
      command on the gateway host. Refused while the gateway service is
      running (its state file is locked): use "iamtunnel admin pairing
      start" from any admin machine instead.

Flags: --port (1024..65535, default 2222 — SPEC §3.5 runs without
extra capabilities), --public-host (DNS name or IP — required by
install and reset, optional for run via config file), --rebootstrap
(install only), --new-hostkey and --yes (reset only), --config <file>,
--data-dir <dir>.
`

const enrolHelp = `iamtunnel enrol — register this machine (SPEC §3.4).

Usage:
  iamtunnel enrol <code>
      <code> is the line "iamtunnel admin machines enrol-code" printed:
        iamtunnel-enrol://<host>:<port>#<sha256>:<secret>
      The gateway host key is verified automatically against the
      fingerprint inside the code. The code is single-use and lives
      15 minutes; a failed probe keeps the machine "enrolled".

Flags: --config <file>, --data-dir <dir> (server data directory).
`

const shotHelp = `iamtunnel shot — offscreen screenshot of a GUI screen (SPEC §7.2).

Usage:
  iamtunnel shot <screen> [--subtab NAME] [--dark] [--out FILE]

  <screen> is one of: guide, setup, client, server, gateway, session,
  admin, history, settings
  (case-insensitive; the tabs of SPEC §7.1).
  --subtab NAME    open this sub-tab inside the screen before drawing
                   (case-insensitive; a name the screen does not offer
                   draws its first sub-tab). Without it the picture
                   shows the screen as it opens.
  --dark           draw the dark palette instead of the light one
  --out FILE       write the PNG here; default: <screen>.png in the
                   current directory (<screen>-dark.png with --dark)

  The picture is rendered offscreen — no window opens, at 1024x700.
  Drawing is Windows-only (SPEC §9); other platforms refuse with the
  environment exit code.
`

const selftestHelp = `iamtunnel selftest — the built-in self check (SPEC §7.2).

Usage:
  iamtunnel selftest
`

const desktopHelp = `iamtunnel desktop — install/uninstall a Linux .desktop shortcut
(IAMT-255). Writes the .desktop entry + 48 and 256-pixel PNG icons
under $XDG_DATA_HOME (falling back to ~/.local/share) so the live
GUI window is reachable from the application launcher / dock / file
manager the way every other GUI app is. Linux / freedesktop only —
Windows and macOS refuse honestly.

Usage:
  iamtunnel desktop install       write ~/.local/share/applications/iamtunnel.desktop
                                   and ~/.local/share/icons/hicolor/{48,256}/apps/iamtunnel.png
  iamtunnel desktop uninstall     remove the same paths

System locations (/usr/share/applications, /usr/share/icons) are NEVER
touched: install MUST NOT elevate, and uninstall MUST NOT elevate.
Run it as the user whose launcher you want the icon to appear in.
`

const configHelp = `Configuration (all roles read the same schema; only relevant keys
apply to a given role).

Precedence — one rule for every key, the strongest source wins:
  1. command-line flags    (--port, --public-host, --data-dir, --config)
  2. environment variables (IAMTUNNEL_PORT, IAMTUNNEL_DATA_DIR, IAMTUNNEL_CONFIG)
  3. the config file
  4. built-in defaults
A value overridden by a stronger source is never used, so it cannot
break the run; every surviving value is validated before execution.

The config file is JSON and read strictly — an unknown key is an error,
not silence:
  {
    "port": 2222,                       gateway SSH port, 1024..65535
    "public_host": "gw.example.com",    gateway's public DNS name or IP
                                        (SPEC §3.1 host grammar); IAMT-202
    "client_dir":  "…",                  overrides the client data dir
    "server_dir":  "…",                  overrides the machine data dir
    "gateway_dir": "…",                  overrides the gateway data dir
    "recordings_retention_days": 90,    SPEC §12: 90
    "recordings_disk_stop_percent": 85  SPEC §12: 85
  }

Environment variables:
  IAMTUNNEL_PORT       gateway port
  IAMTUNNEL_DATA_DIR   data directory of the role being run
  IAMTUNNEL_CONFIG     path of the config file itself
`

// topicText holds the per-topic help printed by --help and "help".
var topicText = map[string]string{
	"client":   clientHelp,
	"server":   serverHelp,
	"admin":    adminHelp,
	"gateway":  gatewayHelp,
	"enrol":    enrolHelp,
	"shot":     shotHelp,
	"desktop":  desktopHelp,
	"selftest": selftestHelp,
	"config":   configHelp,
}

// leafText holds the short usage lines printed by the deeper
// "--help" of an individual command.
var leafText = map[string]string{
	"gateway verify-journal": `Usage: iamtunnel gateway verify-journal [--data-dir DIR] [--config F]

Check the hash chain of the gateway's journal (IAMT-467): every line of
events.jsonl and of its archives carries prev_hash, the SHA-256 of the
line before it, so a line changed, removed or inserted breaks the link
of the line after it. Lines written before 1.14 carry no chain; they are
counted, not checked, and the first chained line names the last of them.
The chain has no anchor outside the files: lines cut off the end, or a
journal replaced by a new one from its first line, leave nothing to
disagree with. Reads only, so it runs beside a live gateway.
Exit 0 when intact, 3 when a link is broken, a line was written without
the chain after it began, or a line cannot be read at all (an event is
missing from the journal either way).
`,
	"client connect-string": `Usage: iamtunnel client connect-string <str> [--name NAME] [--replace]

Remember a gateway and switch to it (SPEC §3.1):
  iamtunnel://<host>:<port>/<person>#<sha256 of the gateway host key>
Several gateways can be remembered at once; --name labels this one,
and without it the host does. A changed host key on a gateway already
saved is refused, never silently re-pinned: pass --replace once you
know whether it was rebuilt or impersonated.
`,
	"client gateways": `Usage: iamtunnel client gateways

The gateways this machine remembers, the current one marked with *.
That one is what every other client and admin command acts on.
`,
	"client use": `Usage: iamtunnel client use <name>

Switch to another saved gateway. Nothing is asked and nothing is
dialled: authentication in this product is the key in this directory,
and each gateway's administrator already holds its public half.
`,
	"client key": `Usage: iamtunnel client key [--accept-foreign-data-dir]

Print this machine's public key (one OpenSSH line), creating the key on
first use. Hand it to the administrator who adds you: "admin people add"
needs it, and they answer with your connection string. The window shows
the same line on Client → Key.
`,
	"client forget": `Usage: iamtunnel client forget <name>

Drop one saved gateway. The key stays, and so does the person record
on the gateway — a client can always forget, only an administrator
can revoke.
`,
	"client machines": `Usage: iamtunnel client machines

Machines allowed to you, with expiry times and online state (SPEC §3.1).
`,
	"client connect": `Usage: iamtunnel client connect <machine>

Open a terminal to <machine> through the gateway with the pinned host
key and an isolated known_hosts (SPEC §3.1). Refused on an exec-only
grant — see "iamtunnel client exec --help".
`,
	"client exec": `Usage: iamtunnel client exec <machine> -- <command>

Run exactly one command on <machine> through the gateway (SPEC §6.5,
PROTOCOL §4.1) and exit with the command's own exit code — 126 if the
gateway's risk policy stopped it before it reached the machine.
"--" is required; everything after it is the command verbatim, with
its own flags — this program does not parse them. stdout and stderr
stay separate: the command's own stderr and the gateway's own words
(the recording notice, a risk warning, a block) both go to this
program's stderr, never mixed into the command's stdout. Works on
both an exec-only and a shell grant.
`,
	"server start": `Usage: iamtunnel server start [--idle-minutes N] [--max-hours N] [--key-file <path>]

Check sshd, sweep stale door lines, connect, open the door, start the
watchdog (SPEC §3.2). Ranges: idle-minutes 1..10080, max-hours 1..720.
The door's key file defaults to %ProgramData%\ssh\administrators_authorized_keys
on Windows; --key-file names another absolute path (required elsewhere).
`,
	"server stop": `Usage: iamtunnel server stop

Remove the door key and close the tunnel (SPEC §3.2).
`,
	"server status": `Usage: iamtunnel server status

Show tunnel state, door id and timers (SPEC §3.2).
`,
	"server install": `Usage: iamtunnel server install

Automatic machine start (SPEC §3.2.1), so the machine comes back on its
own; manual "server start" continues to work. Repeating the command
overwrites the same autostart.

Linux: install the systemd unit /etc/systemd/system/iamtunnel-machine.service
(User=root, Restart=on-failure, KillMode=mixed), then run daemon-reload and
enable --now.
macOS: install the LaunchDaemon /Library/LaunchDaemons/com.iamtunnel.machine.plist
(launchd; root, KeepAlive only after an unsuccessful exit), then run
launchctl bootstrap system.
On both, root (sudo) rights are required.

Windows: register the logon task \iamtunnel\<registration> in Task Scheduler
and start it. It runs "server start --data-dir <dir>" as the Windows account
the machine's registration is bound to, with the highest privileges that
account has, every time that account signs in (Remote Desktop included),
with no time limit and no stop on battery. The machine must be enrolled
first ("iamtunnel enrol <code>"): the task is named after the registration.
Run it from a console opened with "Run as administrator". Other accounts'
registrations on this computer are not touched.
`,
	"server uninstall": `Usage: iamtunnel server uninstall

The reverse of "server install".
Linux: run systemctl disable --now on the systemd unit, remove the unit
file, then run daemon-reload. macOS: run launchctl bootout on the
LaunchDaemon (launchd) and remove the plist. Root (sudo) rights are
required.
Windows: remove the logon task \iamtunnel\<registration>; the name is read
from this machine's enrolment record. A server running right now keeps
running - Task Scheduler would kill it instead of letting it close its
door - so end it with "iamtunnel server stop". Run it from a console
opened with "Run as administrator".
The machine data directory (machine.key, enrolment record and local
journal) is not touched. If nothing is installed, there is nothing to do;
exit 0.
`,
	"server doorwatch": `Usage: iamtunnel server doorwatch <door-id> <parent-pid> <keyfile>   (internal)

Watchdog child process of SPEC §6.3 (layer 3): watches the parent
process and removes the door line if the parent dies. Linux and macOS
take three more arguments after the journal path — <lock-path>
<owner-uid> <owner-gid> (the unix DoorOptions of SPEC §3.2.1); Windows
takes the five shown. Started by the server itself, never by hand.
`,
	"enrol": `Usage: iamtunnel enrol <code>

Register this machine with the enrol code of SPEC §3.4:
  iamtunnel-enrol://<host>:<port>#<sha256>:<secret>
`,
	"shot": `Usage: iamtunnel shot <screen> [--subtab NAME] [--dark] [--out FILE]

Offscreen screenshot (no window opens, 1024x700 PNG); screen:
setup | client | server | admin | settings. --subtab opens one sub-tab
inside the screen first. Without --out the file is
<screen>.png in the current directory (<screen>-dark.png with --dark).
Drawing is Windows-only.
`,
	"selftest": `Usage: iamtunnel selftest

Built-in self check (SPEC §7.2).
`,
	"admin pair": `Usage: iamtunnel admin pair <pasted-string>
       iamtunnel admin pair <host:port#fingerprint> <pin>

Become a permanent admin through the PIN pairing window (SPEC §3.5,
§3.6, PROTOCOL §3.4 — IAMT-323).

The argument is one pasted string: the "iamtunnel-pair://" form, or the
whole "iamtunnel admin pair <ref> <pin>" line an open pairing window
printed ("admin pairing start" on an admin machine, or "gateway pair" on
the gateway host itself when no admin key works) — quotes, indentation
and the sentence printed above the line are all stripped for you. The
older two-argument form, the one written down in RUNBOOK §1.4.1, keeps
working unchanged; both go through the same parser, so both accept and
refuse exactly the same things.

This machine's own client key is registered and the connection string
is saved automatically. Three wrong PINs lock pairing for the address
for three minutes; the window itself lives 2 minutes.
`,
}
