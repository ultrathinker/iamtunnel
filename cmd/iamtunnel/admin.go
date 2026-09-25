package main

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/paste"
)

// adminVerbs is the §3.3 command table: one row per verb with its
// positional shape, extra flags, and — for the destructive ones — the
// uniform confirmation sentence. The same table drives parsing, the
// help text and the report's pre-execution checks.
type adminVerb struct {
	args        []string // positional names, in order; nil = arity ruled by check
	flags       []string // extra value flags beyond --config/--json
	destructive bool
	consequence string // shown by the confirmation gate
	// destructiveWhen rules the dual-shape verbs: the gate applies to
	// some shapes only ("keys remove" is destructive, "keys add" is not).
	destructiveWhen func(fs *flagSet) (bool, string)
	check           func(fs *flagSet) error
}

var adminGroups = map[string][]string{
	"people":     {"add", "rename", "remove", "list", "keys", "connection-string"},
	"machines":   {"enrol-code", "list", "rename", "remove", "rekey", "verify", "set-user"},
	"grants":     {"grant", "extend", "set-caps", "revoke", "list"},
	"sessions":   {"active", "history", "kill", "tail"},
	"recordings": {"list", "fetch"},
	"gateway":    {"status", "fingerprint", "backup", "rotate-hostkey"},
	"goal":       {"set", "current", "history", "list"},
	"risk":       {"check", "mode", "source", "pending", "approve", "deny", "key"},
	"pairing":    {"start", "stop"},
}

var adminVerbs = map[string]map[string]adminVerb{
	"people": {
		"add": {args: []string{"<name>"}, flags: []string{"role", "key"},
			check: func(fs *flagSet) error {
				if v := fs.val("role"); v != "" && v != "user" && v != "admin" {
					return userErrf("iamtunnel admin people add: --role %q must be \"user\" or \"admin\" (SPEC §4.3 person.role).", v)
				}
				if err := checkNames(fs, 0); err != nil {
					return err
				}
				if fs.val("key") == "" {
					return userErrf("iamtunnel admin people add: --key <pubkey> is required — the new person needs at least one key to log in with; add more later with \"admin people keys add\".")
				}
				_, err := config.CheckPublicKey(fs.val("key"))
				return err
			}},
		"rename": {args: []string{"<name>", "<new-name>"}, destructive: true,
			consequence: "renames the person: grants and goals move to the new name in one write, and the sessions opened under the old name are closed right now (the key follows the person).",
			check:       func(fs *flagSet) error { return checkNames(fs, 0, 1) }},
		"remove": {args: []string{"<name>"}, destructive: true,
			consequence: "removes the person with all their keys and grants; every current permission ends immediately.",
			check:       func(fs *flagSet) error { return checkNames(fs, 0) }},
		"list": {},
		"keys": {args: nil, // arity is shape-dependent; checkPeopleKeys rules
			destructiveWhen: func(fs *flagSet) (bool, string) {
				if len(fs.pos) > 0 && fs.pos[0] == "remove" {
					return true, "removes the key from the person; new logins with it are refused (running sessions are not)."
				}
				return false, ""
			},
			check: checkPeopleKeys},
		"connection-string": {args: []string{"<name>"},
			check: func(fs *flagSet) error { return checkNames(fs, 0) }},
	},
	"machines": {
		"enrol-code": {args: []string{"<name>"}, flags: []string{"os-user"},
			check: func(fs *flagSet) error {
				if v := fs.val("os-user"); v != "" && !config.ValidOSUser(v) {
					return userErrf("iamtunnel admin machines enrol-code: --os-user %q must be a Windows principal (DOMAIN\\name or MACHINE\\name) or a POSIX local name (^[a-z_][a-z0-9_-]{0,31}$) (IAMT-271, SPEC §4.3).", v)
				}
				return checkNames(fs, 0)
			}},
		"list":   {},
		"rename": {args: []string{"<id>", "<new-name>"}, check: func(fs *flagSet) error { return checkNames(fs, 0, 1) }},
		"remove": {args: []string{"<id>"}, destructive: true, consequence: "removes the machine: its registration key trust and pinned sshd host key are deleted and the door can never reopen for it.", check: func(fs *flagSet) error { return checkNames(fs, 0) }},
		"rekey": {args: []string{"<id>"}, flags: []string{"confirm-fingerprint"}, destructive: true, consequence: "replaces the pinned sshd host key of the machine; until the new key is confirmed the door stays closed (SPEC §6.2).",
			check: func(fs *flagSet) error {
				if err := checkNames(fs, 0); err != nil {
					return err
				}
				if fs.val("confirm-fingerprint") == "" {
					return userErrf("iamtunnel admin machines rekey: --confirm-fingerprint <fp> is required — it must equal the machine's observedSSHDHostKey shown by \"admin machines list\" or \"admin machines verify\" (PROTOCOL §6).")
				}
				_, err := config.NormalizeFingerprint(fs.val("confirm-fingerprint"))
				return err
			}},
		"verify": {args: []string{"<id>"}, check: func(fs *flagSet) error { return checkNames(fs, 0) }},
		"set-user": {args: []string{"<id>", "<os-user>"}, destructive: true, consequence: "changes the OS account the gateway logs into on the machine; a fresh probe runs before the door reopens (SPEC §4.3).",
			check: func(fs *flagSet) error {
				if err := checkNames(fs, 0); err != nil {
					return err
				}
				if !config.ValidOSUser(fs.pos[1]) {
					return userErrf("iamtunnel admin machines set-user: OS user %q must be a Windows principal (DOMAIN\\name or MACHINE\\name) or a POSIX local name (^[a-z_][a-z0-9_-]{0,31}$) (IAMT-271, SPEC §4.3).", fs.pos[1])
				}
				return nil
			}},
	},
	"grants": {
		"grant": {args: []string{"<person>", "<machine>", "<until>"}, flags: []string{"cap"},
			check: func(fs *flagSet) error {
				if err := checkNames(fs, 0, 1); err != nil {
					return err
				}
				// SPEC §4.3 (line 276): the deadline is optional. An
				// empty <until> means "indefinite" — the grant stays in
				// force until the administrator explicitly revokes it.
				// Any non-empty value must be a strict RFC 3339 instant.
				if fs.pos[2] != "" {
					if _, err := config.ParseUntil(fs.pos[2]); err != nil {
						return err
					}
				}
				if cap := fs.val("cap"); cap != "" && cap != "shell" && cap != "exec" {
					return userErrf("iamtunnel admin grants grant: --cap %q must be \"shell\" or \"exec\".", cap)
				}
				return nil
			}},
		"extend": {args: []string{"<person>", "<machine>", "<until>"}, destructive: true,
			consequence: "moves the grant's deadline; a later deadline or an empty <until> (indefinite) touches no live session, but shortening the deadline closes the sessions opened on the grant right now.",
			check: func(fs *flagSet) error {
				if err := checkNames(fs, 0, 1); err != nil {
					return err
				}
				// Same contract as grants grant: empty means indefinite,
				// anything else must be a strict RFC 3339 instant. Whether
				// the value shortens the current deadline only the gateway
				// knows, hence the confirmation above on every shape.
				if fs.pos[2] != "" {
					if _, err := config.ParseUntil(fs.pos[2]); err != nil {
						return err
					}
				}
				return nil
			}},
		"revoke": {args: []string{"<person>", "<machine>"}, destructive: true, consequence: "revokes the permission immediately and kills that person's active sessions on the machine (SPEC §3.3).",
			check: func(fs *flagSet) error { return checkNames(fs, 0, 1) }},
		"set-caps": {args: []string{"<person>", "<machine>", "<shell|exec>"}, destructive: true,
			consequence: "changes what the grant permits; narrowing to exec closes any terminal open on it right now.",
			check: func(fs *flagSet) error {
				if err := checkNames(fs, 0, 1); err != nil {
					return err
				}
				if c := fs.pos[2]; c != "shell" && c != "exec" {
					return userErrf("iamtunnel admin grants set-caps: capability %q must be \"shell\" or \"exec\".", c)
				}
				return nil
			}},
		"list": {},
	},
	"sessions": {
		"active":  {},
		"history": {flags: []string{"person", "machine", "from", "to", "limit", "offset"}},
		"tail": {args: []string{"<session-id>"}, flags: []string{"offset", "limit"},
			check: func(fs *flagSet) error {
				if !config.ValidSessionID(fs.pos[0]) {
					return userErrf("iamtunnel admin sessions tail: session id %q has a wrong shape - want 8..128 characters of [A-Za-z0-9._:-], as printed by \"sessions active\".", fs.pos[0])
				}
				return nil
			}},
		"kill": {args: []string{"<session-id>"}, destructive: true, consequence: "kills the session now; the person is dropped back to their terminal.",
			check: func(fs *flagSet) error {
				if !config.ValidSessionID(fs.pos[0]) {
					return userErrf("iamtunnel admin sessions kill: session id %q has a wrong shape — want 8..128 characters of [A-Za-z0-9._:-], as printed by \"sessions active\".", fs.pos[0])
				}
				return nil
			}},
	},
	"recordings": {
		"list": {flags: []string{"from", "to"},
			check: func(fs *flagSet) error {
				for _, k := range []string{"from", "to"} {
					if v := fs.val(k); v != "" {
						if _, err := config.ParseUntil(v); err != nil {
							return userErrf("iamtunnel admin recordings list: --%s %q is not RFC 3339 with explicit zone (PROTOCOL §6 \"recordings.list\").", k, v)
						}
					}
				}
				return nil
			}},
		"fetch": {args: []string{"<id>"}, flags: []string{"out"},
			check: func(fs *flagSet) error {
				if !config.ValidSessionID(fs.pos[0]) {
					return userErrf("iamtunnel admin recordings fetch: recording id %q has a wrong shape — want 8..128 characters of [A-Za-z0-9._:-], as printed by \"recordings list\".", fs.pos[0])
				}
				return nil
			}},
	},
	"gateway": {
		"status":         {},
		"fingerprint":    {},
		"backup":         {},
		"rotate-hostkey": {destructive: true, consequence: "rotates the gateway host key over SSH; every client pin, enrol code and connection string stops working until the admin hands out new ones (SPEC §6.2)."},
	},
	"goal": {
		"set":     {args: []string{"<person>", "<machine>"}, flags: []string{"goal"}},
		"current": {args: []string{"<person>", "<machine>"}},
		"history": {args: []string{"<person>", "<machine>"}},
		"list":    {},
	},
	"risk": {
		"check":   {args: []string{"<command>"}, flags: []string{"goal"}},
		"mode":    {args: nil, check: checkRiskMode},
		"source":  {args: nil, check: checkRiskSource},
		"pending": {},
		"approve": {args: []string{"<approval-id>"}, check: checkRiskApproval},
		"deny":    {args: []string{"<approval-id>"}, check: checkRiskApproval},
		"key":     {flags: []string{"key"}, check: checkRiskKey},
	},
	"pairing": {
		"start": {},
		"stop":  {},
	},
}

// checkNames validates the given positional indexes as §4.3 names.
func checkNames(fs *flagSet, idx ...int) error {
	for _, i := range idx {
		if !config.ValidName(fs.pos[i]) {
			return config.NameError("name", fs.pos[i])
		}
	}
	return nil
}

func checkPeopleKeys(fs *flagSet) error {
	if len(fs.pos) == 0 || fs.pos[0] != "add" && fs.pos[0] != "remove" {
		return userErrf("iamtunnel admin people keys: want \"add <name> <pubkey>\" or \"remove <name> <fingerprint>\".")
	}
	if len(fs.pos) != 3 {
		return userErrf("iamtunnel admin people keys %s: want exactly two more arguments — \"<name>\" and %s: usage: iamtunnel admin people keys %s <name> <pubkey|fingerprint>.",
			fs.pos[0], map[string]string{"add": "<pubkey>", "remove": "<fingerprint>"}[fs.pos[0]], fs.pos[0])
	}
	if !config.ValidName(fs.pos[1]) {
		return config.NameError("person", fs.pos[1])
	}
	if fs.pos[0] == "add" {
		_, err := config.CheckPublicKey(fs.pos[2])
		return err
	}
	_, err := config.NormalizeFingerprint(fs.pos[2])
	return err
}

func checkRiskMode(fs *flagSet) error {
	if len(fs.pos) > 1 {
		return userErrf("iamtunnel admin risk mode: want no argument to read the current mode, or exactly one of log, warn, ask or block to change it.")
	}
	if len(fs.pos) == 1 && fs.pos[0] != "log" && fs.pos[0] != "warn" && fs.pos[0] != "ask" && fs.pos[0] != "block" {
		return userErrf("iamtunnel admin risk mode: %q must be one of log, warn, ask or block.", fs.pos[0])
	}
	return nil
}

// checkRiskSource guards the choice of WHICH checkers judge a command,
// the twin of checkRiskMode's guard over what happens to a red one.
func checkRiskSource(fs *flagSet) error {
	if len(fs.pos) > 1 {
		return userErrf("iamtunnel admin risk source: want no argument to read the current choice, or exactly one of rules, ai or both to change it.")
	}
	if len(fs.pos) == 1 && fs.pos[0] != "rules" && fs.pos[0] != "ai" && fs.pos[0] != "both" {
		return userErrf("iamtunnel admin risk source: %q must be one of rules, ai or both.", fs.pos[0])
	}
	return nil
}

func checkRiskApproval(fs *flagSet) error {
	if !validRiskApprovalID(fs.pos[0]) {
		return userErrf("iamtunnel admin risk approve: approval id %q has a wrong shape — want apr- followed by 16 lowercase hexadecimal characters, as printed by the red-command warning.", fs.pos[0])
	}
	return nil
}

func checkRiskKey(fs *flagSet) error {
	if fs.val("key") == "" {
		return userErrf("iamtunnel admin risk key: --key <new-key> is required; the key is probed once and is never printed or returned.")
	}
	return nil
}

func validRiskApprovalID(id string) bool {
	if len(id) != len("apr-")+16 || !strings.HasPrefix(id, "apr-") {
		return false
	}
	for _, c := range id[len("apr-"):] {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func cmdAdmin(s *streams, args []string) int {
	if len(args) == 0 {
		return fail(s, userErrf(`iamtunnel admin: want "<group> <verb>" — groups: people, machines, grants, sessions, recordings, gateway, goal, risk, pairing, claim, pair. See "iamtunnel admin --help".`))
	}
	if helpWord(args[0]) {
		return helpTopic(s, "admin")
	}
	group := args[0]
	if group == "claim" {
		return cmdAdminClaim(s, args[1:])
	}
	if group == "pair" {
		return cmdAdminPair(s, args[1:])
	}
	verbs, ok := adminGroups[group]
	if !ok {
		if strings.HasPrefix(group, "-") {
			return fail(s, userErrf("iamtunnel admin: flags come after the verb — usage: iamtunnel admin <group> <verb> [args] [--json]."))
		}
		return fail(s, userErrf("iamtunnel admin: unknown group %q — want people, machines, grants, sessions, recordings, gateway, goal, risk, pairing, claim or pair. See \"iamtunnel admin --help\".", group))
	}
	if len(args) == 1 {
		return fail(s, userErrf("iamtunnel admin: want \"<group> <verb>\" — %s has verbs: %s. See \"iamtunnel admin --help\".", group, strings.Join(verbs, ", ")))
	}
	verb := args[1]
	v, ok := adminVerbs[group][verb]
	if !ok {
		return fail(s, userErrf("iamtunnel admin %s: unknown verb %q — want: %s. See \"iamtunnel admin --help\".", group, verb, strings.Join(verbs, ", ")))
	}
	return runAdminVerb(s, group, verb, v, args[2:])
}

func runAdminVerb(s *streams, group, verb string, v adminVerb, args []string) int {
	path := "admin " + group + " " + verb
	fs := newFlagSet(path, strings.Join(v.args, " "))
	fs.valFlag("config")
	fs.boolFlag("json")
	// IAMT-333 (P1.6): the escape from the foreign-directory refusal
	// below, named in the refusal itself.
	fs.boolFlag("accept-foreign-data-dir")
	if v.destructive || v.destructiveWhen != nil {
		fs.boolFlag("yes")
	}
	for _, f := range v.flags {
		fs.valFlag(f)
	}
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	// A nil args slice means the verb rules its own arity (people keys:
	// add|remove <name> <value>) inside its check.
	if v.args != nil {
		if err := fs.wantN(len(v.args)); err != nil {
			return fail(s, err)
		}
	}
	destructive, consequence := v.destructive, v.consequence
	if v.destructiveWhen != nil {
		destructive, consequence = v.destructiveWhen(fs)
	}
	if v.check != nil {
		if err := v.check(fs); err != nil {
			return fail(s, err)
		}
	}
	// Admin identity is the person's own saved connection string and key
	// (internal/client), not a directory of its own: an admin is the
	// same person who might also run "client connect" — SPEC §3.3's
	// bootstrap makes the first admin's key "the current key of the
	// maintainer", and every subsequent admin is added by "people add" with
	// their own ordinary key. There is nothing "admin"-specific to
	// persist beyond what "client connect-string" already saves.
	clientDir, derr := clientDataDir(s, path, cfgOpts{configPath: fs.val("config")}, fs)
	if derr != nil {
		return fail(s, derr)
	}
	if destructive {
		if err := confirm(s, fs, path, consequence); err != nil {
			return fail(s, err)
		}
	}
	return runAdminExec(s, path, clientDir, group, verb, fs)
}

// cmdAdminClaim is the one-time bootstrap of SPEC §3.3: the reference
// printed by "gateway install" plus the admin's public key.
func cmdAdminClaim(s *streams, args []string) int {
	const path = "admin claim"
	fs := newFlagSet(path, "<host:port#fingerprint:token>")
	fs.valFlag("config")
	fs.valFlag("key")
	fs.boolFlag("json")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(1); err != nil {
		return fail(s, err)
	}
	if fs.val("key") == "" {
		return fail(s, userErrf("iamtunnel %s: --key <pub> is required — it becomes the key of the first admin (SPEC §3.3).", path))
	}
	ref, err := config.ParseClaimRef(fs.pos[0])
	if err != nil {
		return fail(s, err)
	}
	if _, err := config.CheckPublicKey(fs.val("key")); err != nil {
		return fail(s, err)
	}
	// admin claim needs no saved identity of its own — it is the one
	// command that runs before any admin key is known to the gateway at
	// all (SPEC §3.3's bootstrap). loadConfig is still called for its
	// --config plumbing and IAMT-76 guard, but its resolved directory is
	// unused: nothing is read from or written to a role directory here.
	if _, _, lerr := loadConfig(s, "client", cfgOpts{configPath: fs.val("config")}); lerr != nil {
		return fail(s, lerr)
	}

	// The dial and the exec call below are real per PROTOCOL §3.3/§6;
	// against a gateway with no pending claim for this token, the SSH
	// handshake itself is refused (unknown username/key), which
	// adminFail reports honestly rather than a canned message.
	ephemeral, derr := config.DeriveEphemeralSigner(ref.Token, config.BootstrapKeySalt)
	if derr != nil {
		return fail(s, userErrf("iamtunnel %s: could not derive the one-time bootstrap key: %v", path, derr))
	}
	peer := admin.Peer{Addr: fmt.Sprintf("%s:%d", ref.Host, ref.Port), Fingerprint: ref.Fingerprint}
	conn, dialErr := admin.Dial(peer, "bootstrap", ephemeral, 10*time.Second)
	if dialErr != nil {
		return adminFail(s, path, envErrf("could not reach the gateway at %s: %v", peer.Addr, dialErr))
	}
	defer conn.Close()

	res, cerr := conn.AdminClaim(ref.Token, fs.val("key"))
	if cerr != nil {
		return adminFail(s, path, cerr)
	}
	if fs.has("json") {
		return printAdminJSON(s, res)
	}
	fmt.Fprintf(s.out, "iamtunnel %s: %q is now the first admin (role %s).\n", path, res.Person, res.Role)
	return exitOK
}

// cmdAdminPair is the client half of the PIN pairing (SPEC §3.5,
// PROTOCOL §3.4 — IAMT-323): the reference and PIN a pairing window
// printed, plus this machine's own client key. A correct PIN registers
// that key as a permanent admin and saves the connection string, so
// every later "iamtunnel admin ..." (and the GUI Admin tab) works from
// this machine without any further setup — the counterpart of
// "admin claim", but with no token to copy: the PIN is the secret.
//
// Since 1.3 (SPEC §3.6) the command takes ONE pasted string: the
// "iamtunnel-pair://<host>:<port>#<fp>:<pin>" form, or the whole
// "iamtunnel admin pair <ref> <pin>" line the gateway printed, pasted
// as a single argument. The two-argument "<ref> <pin>" form people
// have in their notes and in RUNBOOK §1.4.1 keeps working. Both routes
// meet at once: the positionals are joined back into the one line they
// came from and handed to internal/paste, the single parser of §3.6.
// This command owns no grammar of its own — a second one would be
// exactly the divergence that made the field refuse the gateway's own
// printed line on 17.09.
func cmdAdminPair(s *streams, args []string) int {
	const path = "admin pair"
	fs := newFlagSet(path, "<pasted-string> | <host:port#fingerprint> <pin>")
	fs.valFlag("config")
	fs.boolFlag("json")
	// IAMT-333 (P1.6): the escape from the foreign-directory refusal
	// below, named in the refusal itself.
	fs.boolFlag("accept-foreign-data-dir")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	// wantN cannot express "one or two", and flags.go is shared: the
	// count is checked here, in the one command that accepts both.
	switch len(fs.pos) {
	case 1, 2:
	case 0:
		return fail(s, userErrf("iamtunnel %s: missing the pairing string — paste the whole line the pairing window printed (%q), or pass the reference and the PIN as two arguments: usage: %s.", path, "iamtunnel admin pair <host:port#fingerprint> <pin>", fs.usage))
	default:
		return fail(s, userErrf("iamtunnel %s: unexpected argument %q — this command takes the pasted string, or the reference and the PIN: usage: %s.", path, fs.pos[2], fs.usage))
	}
	// Joining is what makes the two routes one: "<ref> <pin>" is
	// already a line internal/paste reads (SPEC §3.6, "a pair of
	// reference, space, PIN"), and a single pasted argument passes
	// through unchanged.
	parsed, err := paste.Parse(strings.Join(fs.pos, " "))
	if err != nil {
		return fail(s, err)
	}
	if parsed.Kind != paste.Pair {
		return fail(s, userErrf("iamtunnel %s: the string you pasted is a %s, not a pairing reference — %q takes the reference and PIN an open pairing window printed; for a bootstrap string use %q.", path, parsed.Kind, "iamtunnel admin pair", "iamtunnel admin claim"))
	}
	// The pairing reference and the PIN, both already validated by the
	// one parser: internal/paste hands the reference to
	// config.ParsePairingRef and shape-checks the PIN before anything
	// dials, so a fat-fingered entry never burns one of the three
	// attempts per address the pairing limiter allows.
	ref := config.PairingRef{Host: parsed.Host, Port: parsed.Port, Fingerprint: parsed.Fingerprint}
	pin := parsed.Secret
	clientDir, derr := clientDataDir(s, path, cfgOpts{configPath: fs.val("config")}, fs)
	if derr != nil {
		return fail(s, derr)
	}
	// The key that becomes admin is this machine's own client key — the
	// same one "client connect" and every later "admin ..." command
	// authenticate with; nothing admin-specific is kept anywhere else
	// (the same rule runAdminVerb records for the ordinary verbs).
	signer, kerr := client.EnsureKey(clientDir)
	if kerr != nil {
		return fail(s, kerr)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))

	peer := admin.Peer{Addr: fmt.Sprintf("%s:%d", ref.Host, ref.Port), Fingerprint: ref.Fingerprint}
	// Username "pairing", byte-exact: while the window is open the
	// gateway answers this login with any well-formed key — the PIN,
	// not a pre-registered key, is what grades the attempt.
	conn, dialErr := admin.Dial(peer, "pairing", signer, 10*time.Second)
	if dialErr != nil {
		return adminFail(s, path, envErrf("could not reach the gateway at %s: %v", peer.Addr, dialErr))
	}
	defer conn.Close()

	res, cerr := conn.PairClaim(pin, pubLine)
	if cerr != nil {
		return adminFail(s, path, cerr)
	}
	// Persist the admin identity exactly as "client connect-string"
	// would have: after a successful pair this machine is a full admin
	// workstation. SaveConnection refuses to overwrite a different
	// saved connection — that refusal is reported, never bypassed.
	cs := config.ConnString{Host: ref.Host, Port: ref.Port, Person: res.Person, Fingerprint: ref.Fingerprint}
	saveErr := client.SaveConnection(clientDir, cs, false)
	if fs.has("json") {
		return printAdminJSON(s, map[string]any{"person": res.Person, "role": res.Role, "connectionSaved": saveErr == nil})
	}
	fmt.Fprintf(s.out, "iamtunnel %s: %q is now an admin (role %s).\n", path, res.Person, res.Role)
	if saveErr == nil {
		fmt.Fprintf(s.out, "The connection string was saved — \"iamtunnel admin ...\" and the GUI Admin tab now work from this machine.\n")
	} else {
		// The pairing itself succeeded; only the local convenience save
		// failed. Say both halves honestly and give the manual command.
		fmt.Fprintf(s.errs, "iamtunnel %s: pairing succeeded, but the connection string was NOT saved: %v\n", path, saveErr)
		fmt.Fprintf(s.errs, "iamtunnel %s: save it by hand: iamtunnel client connect-string \"iamtunnel://%s:%d/%s#%s\" --replace\n",
			path, ref.Host, ref.Port, res.Person, strings.TrimPrefix(ref.Fingerprint, "SHA256:"))
	}
	return exitOK
}

// validPinShape mirrors internal/gateway's validPin: exactly digits
// decimal digits, leading zeros significant. The CLI checks the shape
// locally so a typo never becomes a counted wrong attempt on the
// gateway; the gateway re-checks anyway and grades a malformed PIN as a
// wrong one (SPEC §6.1) — the local check is courtesy, not security.
func validPinShape(pin string, digits int) bool {
	if len(pin) != digits {
		return false
	}
	for i := 0; i < len(pin); i++ {
		if pin[i] < '0' || pin[i] > '9' {
			return false
		}
	}
	return true
}
