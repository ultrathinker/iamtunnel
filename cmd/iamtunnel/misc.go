package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// gatewayRecordName is the file "enrol" saves inside the server role
// directory: the gateway this machine now dials outbound, the
// machine id the gateway assigned (SPEC §3.2), and the OS user
// the gateway bound this machine to at enrol-code time
// (SPEC §3.2.1 / IAMT-248). It used to be called "gateway.json"
// and so collide on Windows with the default config file path
// (cmd/iamtunnel/misc.go:25 ↔ internal/config/paths.go:75) —
// `server status` and `server start` refused the strict settings parser
// with `unknown field "host"`. The file was renamed to enrolment.json
// (IAMT-206); loadConfig migrates a leftover legacy gateway.json on the
// first run after the upgrade so operators with an already-enrolled
// machine never see that error.
//
// OSUser is the gateway-bound OS-user name: "MACHINE\\name" on
// Windows (where the door is %ProgramData%\\ssh\\administrators_authorized_keys
// regardless of the user), or a bare local name on Linux/Darwin
// (where "server start" needs the user's home directory to
// resolve ~/<osUser>/.ssh/authorized_keys). "enrol" writes
// enrolResult.RequestedOSUser verbatim; "server start" reads
// it back via loadGatewayRecord and surfaces the value to
// the door layer through winkeys.DoorOptions and to the sshd
// pre-flight through sshd -T -C user=<osUser>.
const gatewayRecordName = "enrolment.json"

type gatewayRecord struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Fingerprint string `json:"fingerprint"`
	MachineID   string `json:"machineId"`
	OSUser      string `json:"osUser,omitempty"`
}

func gatewayRecordPath(dir string) string { return filepath.Join(dir, gatewayRecordName) }

// loadGatewayRecord reads back what "enrol" saved. A missing file means
// "never enrolled" and is reported as os.ErrNotExist so callers can
// give the specific "run iamtunnel enrol first" message. The read goes
// through state.ReadDataFile (IAMT-332 round six): enrolment.json is a
// machine data file in the --data-dir, and "server start" — which may
// run privileged — must refuse a symlink or FIFO planted at the name
// instead of reading through it or hanging on it.
func loadGatewayRecord(dir string) (gatewayRecord, error) {
	var rec gatewayRecord
	data, err := state.ReadDataFile(gatewayRecordPath(dir))
	if err != nil {
		return rec, err
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return rec, envErrf("%s: does not parse (%v) — enrol again", gatewayRecordPath(dir), err)
	}
	return rec, nil
}

// legacyGatewayRecordName is the IAMT-206 predecessor of
// gatewayRecordName. Before the rename, "enrol" saved the gateway address
// into <server-dir>/gateway.json, which on Windows is also the default
// settings path (internal/config/paths.go:75) — every "server start" /
// "server status" after a successful enrol tripped the strict settings
// parser on `unknown field "host"`. migrateLegacyGatewayRecord detects
// that legacy file shape on first read and renames it; the new file is
// then read by loadGatewayRecord above.
const legacyGatewayRecordName = "gateway.json"

// legacyGatewayRecordKeys is the closed set of keys a legacy gateway.json
// could carry. Anything outside that set means the file is something else
// (a real config file, a typo, garbage) and must be left for
// config.ParseFile to name in its error.
var legacyGatewayRecordKeys = map[string]bool{
	"host":        true,
	"port":        true,
	"fingerprint": true,
	"machineId":   true,
}

// legacyEnrolmentExtraKeys are the settings keys that have NO overlap
// with the legacy enrolment record shape. A legacy record carries
// host, port, fingerprint, machineId (the four legacy keys), and
// "port" is also a settings key — same name, same meaning (gateway
// listen port), but a legacy record is distinguished by host +
// machineId, which no settings file has. The disqualifier below lists
// only the settings-only keys so the loop rejects "a settings file
// that happens to also have port" without ever rejecting a real
// legacy record.
//
// A future settings key with a brand-new name MUST be appended here so
// it cannot silently make a real settings file look like a legacy
// record. The TestIAMT206_SettingsShapedFileAtConfigPath_NotMigrated
// canary catches a missing entry by failing the
// `{"host":"x","public_host":"gw.example.test"}` fixture as soon as
// public_host is removed from this list.
var legacyEnrolmentExtraKeys = []string{
	"public_host", "client_dir", "server_dir", "gateway_dir",
	"recordings_retention_days", "recordings_disk_stop_percent",
	"max_sessions_per_person", "max_sessions_per_machine",
	"risk_action", "risk_classifier", "external_risk_observation_enabled", "external_risk_observation_key_file",
	"recent_commands_max", "recent_commands_budget",
}

// looksLikeLegacyGatewayRecord decides whether the bytes at configPath
// are a legacy enrolment record (host+port+fingerprint+machineId, and
// NO settings keys). Returns true only when the file is JSON, parses as
// a flat object, has the legacy record keys AND has no settings keys.
//
// This is the canary's "old gateway.json with enrolment-shape fields"
// detector: rewrite any rename of legacyGatewayRecordKeys or removal of
// legacyEnrolmentExtraKeys and the migration test goes red.
func looksLikeLegacyGatewayRecord(data []byte) bool {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	hasHost, hasMachineID := false, false
	for k := range probe {
		if !legacyGatewayRecordKeys[k] {
			return false
		}
		switch k {
		case "host":
			hasHost = true
		case "machineId":
			hasMachineID = true
		}
	}
	for _, k := range legacyEnrolmentExtraKeys {
		if _, ok := probe[k]; ok {
			return false
		}
	}
	return hasHost && hasMachineID
}

// migrateLegacyGatewayRecord inspects the file at legacyPath and, if it
// is a legacy enrolment record (looksLikeLegacyGatewayRecord), moves
// it out of the way so the strict settings parser never sees it.
//
// What "moves it out of the way" means:
//
//   - enrolmentPath does not exist: rename legacyPath -> enrolmentPath.
//     The next read of the enrolment record succeeds; the next read of
//     the settings file at legacyPath returns ErrNotExist, so defaults
//     stand. This is the path a single-machine operator follows after
//     `iamtunnel enrol <code>` already wrote the legacy file.
//
//   - enrolmentPath already exists: do not overwrite it (that would
//     destroy an enrolment record produced by a fresh enrol on a newer
//     binary). Rename the legacy file to legacyPath+".enrolment-migrated"
//     so the operator can compare and delete it by hand. The settings
//     file at legacyPath is also gone after the rename — same default-
//     stand behaviour, but the operator gets to decide which record is
//     the real one.
//
// Any error reading or probing the file is returned only when the file
// truly exists and we cannot decide what to do; a missing legacy file,
// a file that does not parse as JSON, or a file that does parse but is
// not shaped like a legacy record is a NO-OP — config.Load will report
// the real reason for those cases (the user's typo, the strict
// parser's unknown field, etc.). Migration must NEVER touch a file the
// user meant as a settings file: that is the whole point of the
// looksLikeLegacyGatewayRecord shape check.
func migrateLegacyGatewayRecord(legacyPath, enrolmentPath string) error {
	// The probe reads by final pathname, so it goes through
	// state.ReadDataFile like every other data-file read (IAMT-332
	// round six): a non-regular entry at the legacy name is refused
	// promptly, and the refusal lands in the same no-op below —
	// migration never touches a name it cannot read.
	data, err := state.ReadDataFile(legacyPath)
	if err != nil {
		return nil
	}
	if !looksLikeLegacyGatewayRecord(data) {
		return nil
	}
	if _, err := os.Stat(enrolmentPath); err == nil {
		return os.Rename(legacyPath, legacyPath+".enrolment-migrated")
	}
	// The destination directory may not exist yet, and since 1.4 it
	// usually does not: the server directory moved out of %ProgramData%
	// and under the person's own profile, so on the first run after an
	// upgrade the legacy record is in one place and its new home has
	// never been created. Without this the rename fails, the error is
	// swallowed by the caller (deliberately — see main.go), and the
	// legacy file stays where the strict settings parser trips over it
	// with `unknown field "host"` — the exact crash IAMT-206 fixed.
	if err := os.MkdirAll(filepath.Dir(enrolmentPath), 0o700); err != nil {
		return err
	}
	return os.Rename(legacyPath, enrolmentPath)
}

// enrolRequest/enrolResult are the PROTOCOL §6 "enrol" exec shapes.
type enrolRequest struct {
	Proto      int    `json:"proto"`
	Secret     string `json:"secret"`
	Machine    string `json:"machine"`
	OSUser     string `json:"osUser"`
	MachineKey string `json:"machineKey"`
}

type enrolResult struct {
	Machine         string `json:"machine"`
	State           string `json:"state"`
	RequestedOSUser string `json:"requestedOsUser"`
	OSUserStatus    string `json:"osUserStatus"`
	HostKeyStatus   string `json:"hostKeyStatus"`
	ServerTime      string `json:"serverTime"`
}

// cmdEnrol registers this machine from an enrol code (SPEC §3.4,
// PROTOCOL §3.2/§6): derive the one-time ed25519 key the code's secret
// implies, dial the gateway as username "enrol", present the machine's
// own (generated, persistent) key, and save the result — machine id and
// gateway address — to the server role directory so "server start" can
// find them.
//
// The gateway side (auth.RoleEnrol, handleEnrol/runEnrol) is implemented
// in internal/gateway since IAMT-90; the client half here is the other
// end of that wire path.
func cmdEnrol(s *streams, args []string) int {
	const path = "enrol"
	fs := newFlagSet(path, "<code>")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(1); err != nil {
		return fail(s, err)
	}
	code, err := config.ParseEnrolCode(fs.pos[0])
	if err != nil {
		return fail(s, err)
	}
	// IAMT-264: enrol is where the operator first meets this machine's
	// platform requirements, and on macOS the two operator-granted
	// permissions (Remote Login, and Full Disk Access when the key file is
	// in a protected folder) are exactly what the probe in step 3 of SPEC
	// §3.4 and the later door writes need. Same text as `server start`
	// prints — one definition, so the two commands cannot drift.
	//
	// IAMT-297: printed BEFORE the root-gate below, and that order is the
	// point. The hint lists what only the operator can grant; the gate's
	// refusal says "re-run this with rights". Neither implies the other, and
	// on a real Mac (uid 501, ordinary account) the gate used to answer
	// first — the live run showed enrol printing nothing at all, so the
	// person never learned about the two switches. Nothing is weakened by
	// the move: the hint is a constant string, the only thing that crossed
	// the gate is a write to stdout, and every real I/O still happens after
	// it.
	if hint := permissionHint(runtime.GOOS); hint != "" {
		fmt.Fprintln(s.out, hint)
	}
	// Root-gate (IAMT-248 fix1) before any I/O. enrol writes the
	// machine key to disk and (on Linux) prepares to write into
	// the gateway-bound user's home directory; both need the OS
	// to allow the operation. The refusal text names the
	// platform-specific fix the operator should run.
	if err := requireServerElevation(s, path); err != nil {
		return fail(s, err)
	}
	_, dir, lerr := loadConfig(s, "server", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")})
	if lerr != nil {
		return fail(s, lerr)
	}

	res, eerr := enrolMachine(s, dir, code)
	if eerr != nil {
		return fail(s, eerr)
	}

	fmt.Fprintf(s.out, "iamtunnel %s: registered as machine %q (state=%s, os-user=%s status=%s) with gateway %s:%d.\n",
		path, res.Machine, res.State, res.RequestedOSUser, res.OSUserStatus, code.Host, code.Port)
	return exitOK
}

// enrolMachine runs the wire exchange of SPEC §3.4/PROTOCOL §3.2/§6 once:
// derive the one-time ed25519 key the code's secret implies, dial the
// gateway as username "enrol", present this machine's own (generated,
// persistent) key, and save the result — machine id and gateway address —
// to the server role directory so "server start" can find them. Both
// cmdEnrol (the CLI verb) and guiEnrol (the live window's Set up screen,
// cmd/iamtunnel/gui_actions.go) call this — it is the one place the
// exchange happens, so the two paths cannot answer a protocol change
// differently.
//
// Errors are classed exactly as cmdEnrol always returned them
// (userErrf/envErrf) so cmdEnrol's own exit codes and messages are
// unchanged by this extraction; guiEnrol only ever reads err.Error().
func enrolMachine(s *streams, dir string, code config.EnrolCode) (enrolResult, error) {
	var zero enrolResult
	ephemeral, derr := config.DeriveEphemeralSigner(code.Secret, config.EnrolKeySalt)
	if derr != nil {
		return zero, userErrf("iamtunnel enrol: could not derive the one-time registration key: %v", derr)
	}
	// IAMT-213: lock the machine data directory down BEFORE any secret
	// is written into it — the directory and everything already inside
	// get the protected {SYSTEM, Administrators} DACL (no-op on
	// non-Windows). This both creates and heals the directory: a
	// machine enrolled by an older binary carries the inherited
	// Users-read ACL and is fixed here without manual steps. The error
	// arrives already classified: on a healthy machine a refusal here
	// means a non-elevated console, and the message says so (exit code
	// 4, the hint to "Run as administrator").
	if err := hardenServerDir(dir, false); err != nil {
		return zero, fmt.Errorf("iamtunnel enrol: could not lock down the machine data directory: %w", err)
	}
	dirs := config.Dirs{Server: dir}
	// The dial happens after hardenServerDir so the directory is
	// laid down and locked before any network state arrives;
	// however the gateway-bound osUser is only known after the
	// enrol response. Validate the format on the wire side, then
	// validate the local presence before we write machine.key.
	// This is the IAMT-248 fix1 ordering: SPEC §3.2.1 demands
	// "osUser exists locally" as an enrol-time gate, not a
	// server-start gate; a missing user surfaces here, not on
	// the operator's first "server start".
	permanent, kerr := loadOrGenerateMachineSigner(dirs.MachineKey())
	if kerr != nil {
		return zero, kerr
	}

	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(permanent.PublicKey())))

	peer := admin.Peer{Addr: fmt.Sprintf("%s:%d", code.Host, code.Port), Fingerprint: code.Fingerprint}
	conn, dialErr := admin.Dial(peer, "enrol", ephemeral, 10*time.Second)
	if dialErr != nil {
		return zero, envErrf("iamtunnel enrol: could not reach the gateway at %s: %v", peer.Addr, dialErr)
	}
	defer conn.Close()

	// The body reports the OS ACCOUNT this server runs as, and nothing
	// else. The split is 1.4's (SPEC §3.4):
	//
	//   - the NAME is left empty, because the invitation carries it.
	//     The administrator chose it when he minted the code; this
	//     machine has no business guessing, and os.Hostname() would be
	//     a guess — it need not match anything the administrator picked,
	//     and it cannot distinguish two people registering on the SAME
	//     physical box, which is exactly what 1.4 exists to allow.
	//
	//   - the OS ACCOUNT is sent, because it is the one fact in this
	//     exchange that only this machine knows. It is what the gateway
	//     will log in as, and the gateway does not take our word for it:
	//     it becomes requestedOsUser and grants nothing until the
	//     gateway's own SSH login as that account succeeds (SPEC §3.4
	//     step 3).
	//
	// Between IAMT-205 and 1.4 BOTH were left empty, on the reasoning
	// that the gateway's binding was the single source of truth for
	// both. 1.3 then removed the osUser half of that binding without
	// this half following, so the gateway began requiring an account
	// that nothing sent, and `iamtunnel enrol` refused every code with
	// "osUser \"\" is not a valid Windows principal". That is the defect
	// this restores.
	osUser, ouErr := currentOSUser(s.env)
	if ouErr != nil {
		return zero, ouErr
	}
	raw, execErr := conn.Exec("enrol", enrolRequest{
		Proto: 1, Secret: code.Secret, OSUser: osUser, MachineKey: pubLine,
	})
	if execErr != nil {
		return zero, envErrf("iamtunnel enrol: gateway refused registration: %v", execErr)
	}
	var res enrolResult
	if perr := json.Unmarshal(raw, &res); perr != nil {
		return zero, envErrf("iamtunnel enrol: gateway response does not match the expected shape: %v", perr)
	}
	if res.Machine == "" {
		return zero, envErrf("iamtunnel enrol: gateway accepted the registration but did not name a machine id")
	}
	// Format the osUser the gateway bound (IAMT-271) and verify it
	// exists locally before persisting machine.key — the on-disk
	// gate prevents a partial registration that the operator
	// would only see at the next "server start".
	if err := verifyEnrolOSUser(res.RequestedOSUser); err != nil {
		return zero, err
	}
	// IAMT-435: a machine bound to the gateway's own service account is
	// not refused — the binding already happened gateway-side — but the
	// price is named out loud, before machine.key is even written.
	if note := gatewayServiceUserNote(runtime.GOOS, res.RequestedOSUser); note != "" {
		fmt.Fprintln(s.errs, note)
	}

	if err := atomicWriteMachineBytes(dirs.MachineID(), []byte(res.Machine)); err != nil {
		return zero, err
	}
	// Persist the OS-user binding the gateway returned at enrol-time:
	// on Linux/Darwin "server start" reads this to resolve
	// ~/<osUser>/.ssh/authorized_keys (SPEC §3.2.1), and on every
	// platform it threads osUser into the sshd -T -C user=<osUser>
	// pre-flight (also SPEC §3.2.1).
	rec := gatewayRecord{Host: code.Host, Port: code.Port, Fingerprint: code.Fingerprint, MachineID: res.Machine, OSUser: res.RequestedOSUser}
	if err := atomicWriteMachineJSON(gatewayRecordPath(dir), rec); err != nil {
		return zero, err
	}
	// R4 F-04: the anchor the elevated "server start" checks this record
	// against. It is written from rec AS HELD HERE - the values the
	// gateway answered, not anything a re-read of the profile directory
	// could have swapped in since - so an unelevated process racing this
	// enrol cannot make the anchor agree with a planted record. On
	// non-Windows there is nothing to anchor (see machine_anchor.go).
	if err := writeMachineEnrolmentAnchor(s.env, rec); err != nil {
		return zero, fmt.Errorf("iamtunnel enrol: could not write the enrolment anchor: %w", err)
	}
	return res, nil
}

// currentUserFn is the seam currentOSUser reaches for on every platform
// since 1.4 — os/user.Current in production, a fake in tests, so a test
// binary never depends on the account it happens to run under.
//
// Windows joined the other two here when the account stopped being read
// from %USERNAME%/%USERDOMAIN%; see currentOSUser for why. A test that
// used to pin those two variables now pins this.
var currentUserFn = user.Current

// currentOSUser names the OS account this process is running as, in the
// shape SPEC §4.3 prescribes for the local platform. It is the one fact
// the enrol body reports (1.4): the administrator names the
// registration, the machine names the account, the gateway proves the
// account by logging in as it.
//
// Windows: DOMAIN\name from the process TOKEN (os/user, through the
// currentUserFn seam so a test can drive it), and deliberately NOT from
// %USERNAME%/%USERDOMAIN%.
//
// It read the environment until the review of 1.4 pointed out what
// that means: those two variables belong to whoever starts the process.
// `set USERNAME=erik` in a console, then `iamtunnel enrol`, and the
// gateway records the registration as Erik's. The gateway's own proof
// does not catch it either — its probe logs in as the claimed account
// against %ProgramData%\ssh\administrators_authorized_keys, which every
// administrator on the box shares, so the login succeeds and the false
// claim is stamped "verified". The whole point of 1.4 is that a line in
// the journal names WHO, and an attribution one `set` command can
// rewrite is not one.
//
// The token cannot be set that way: it is what Windows authenticated at
// sign-in. os/user reports it already in DOMAIN\name form there.
// %USERDOMAIN% is the machine name on a workgroup box and the domain on
// a joined one — the token carries whichever applies, and which one it
// is is not our business.
//
// This does not make the account unspoofable against a determined local
// administrator: an administrator can start a process as another account
// outright, and nothing here pretends otherwise (SPEC §3.2.2 — no
// isolation, only attribution). It closes the case where the attribution
// is wrong by ACCIDENT, or by one careless environment variable, which
// is the case that would actually happen.
//
// Unix: the login name, with $SUDO_USER winning when it is set. That
// matters because `enrol` is normally run under sudo, so the process
// user is root while the account whose ~/.ssh/authorized_keys the door
// will be written into is the human's. Reporting root would register
// the wrong account and §3.2.1 forbids root anyway; the refusal below
// says so rather than sending a value that cannot work.
func currentOSUser(env map[string]string) (string, error) {
	if runtime.GOOS == "windows" {
		u, err := currentUserFn()
		if err != nil || u == nil {
			return "", envErrf("iamtunnel enrol: cannot tell which Windows account this is running as: %v", err)
		}
		name := strings.TrimSpace(u.Username)
		if name == "" {
			return "", envErrf("iamtunnel enrol: the account this runs as has no name Windows will report.")
		}
		// The token's own form is DOMAIN\name. Anything else means the
		// assumption above has stopped holding, and a principal the
		// gateway cannot resolve is worse than a refusal that says why.
		if strings.Count(name, `\`) != 1 {
			return "", envErrf("iamtunnel enrol: Windows reports this account as %q, which is not the DOMAIN\\name form the gateway needs.", name)
		}
		return name, nil
	}
	if sudo := strings.TrimSpace(env["SUDO_USER"]); sudo != "" {
		return sudo, nil
	}
	u, err := currentUserFn()
	if err != nil || u == nil {
		return "", envErrf("iamtunnel enrol: cannot tell which account this is running as: %v", err)
	}
	name := strings.TrimSpace(u.Username)
	if name == "root" {
		return "", userErrf("iamtunnel enrol: this is running as root, and a machine does not register as root (SPEC §3.2.1) — " +
			"run it as the account that will be entered, or under sudo from that account so $SUDO_USER names it.")
	}
	if name == "" {
		return "", envErrf("iamtunnel enrol: the account this runs as has no name in the user database.")
	}
	return name, nil
}

// verifyEnrolOSUser is the gate between the gateway's enrol
// response and the on-disk write of machine.key. It refuses in
// three layers, each with a text that names the fix:
//   - format: Windows principal form "DOMAIN\name" /
//     "MACHINE\name", OR Linux/macOS POSIX local name
//     ^[a-z_][a-z0-9_-]{0,31}$ (IAMT-271). The local machine's
//     OS picks the form: Windows rejects POSIX names, Linux/
//     Darwin reject Windows principals.
//   - presence: the local user must exist on this machine
//     (via the verifyOSUserFn seam — os/user.Lookup in
//     production, fake in tests). A missing user means the
//     door's first write would fail.
//
// An empty osUser is allowed on Windows: the Windows server role
// has always operated without a per-user OS binding (it writes the
// well-known ProgramData\ssh\administrators_authorized_keys file
// unconditionally, and the Administrators group is the only
// identity that matters). On Linux/Darwin the osUser is mandatory
// because "server start" needs it to resolve <home>/.ssh/authorized_keys.
func verifyEnrolOSUser(name string) error {
	if name == "" {
		if runtime.GOOS == "windows" {
			return nil
		}
		return userErrf("iamtunnel enrol: gateway-bound os user is empty — Linux/macOS require a POSIX local name; pick one with \"iamtunnel admin machines set-user\"")
	}
	if err := config.ValidateOSUser(name); err != nil {
		return userErrf("iamtunnel enrol: gateway-bound os user %q failed format check: %v", name, err)
	}
	if runtime.GOOS == "windows" {
		if strings.Contains(name, `\`) {
			return nil
		}
		return userErrf("iamtunnel enrol: on Windows the gateway-bound os user must be DOMAIN\\name or MACHINE\\name, got %q (POSIX local names are Linux/macOS only)", name)
	}
	if strings.Contains(name, `\`) {
		return userErrf("iamtunnel enrol: on %s the gateway-bound os user must be a POSIX local name (no DOMAIN\\ prefix), got %q", runtime.GOOS, name)
	}
	if err := verifyOSUserFn(name); err != nil {
		return userErrf("iamtunnel enrol: gateway-bound os user %q does not exist on this machine: %v — pick a different user with \"iamtunnel admin machines set-user\" or fix the host's user database", name, err)
	}
	return nil
}

// gatewayServiceUserNote returns the one-line warning for a machine
// bound to the gateway's own service account, "" for any other name and
// platform (IAMT-435). The Linux gateway install creates "iamtunnel"
// with --home-dir inside the gateway data directory and --shell
// /usr/sbin/nologin (gateway.go's useradd line); the macOS LaunchDaemon
// runs as "_iamtunnel", home /var/empty, shell /usr/bin/false
// (gateway_launchd.go, THREATS §3.13.8). A door written for such an
// account lands inside the gateway's state (Linux) or in an account no
// session can ever open through (both), and the person enrolling must
// read that in words, not discover it at the first "server start". A
// warning, not a refusal: the account does exist and the gateway's
// binding stands; the admin moves the machine to a normal account with
// "iamtunnel admin machines set-user". goos is a parameter, not
// runtime.GOOS, so a test binary covers every platform's account.
func gatewayServiceUserNote(goos, name string) string {
	switch {
	case goos == "linux" && name == gatewayServiceUser:
		return fmt.Sprintf("iamtunnel: warning — this machine is bound to %q, the gateway's own Linux service account: its home directory is the gateway state directory and its shell is nologin, so the door would land inside the gateway's data and no session can ever open — move the machine to a normal login account with \"iamtunnel admin machines set-user\"", name)
	case goos == "darwin" && name == darwinServiceUser:
		return fmt.Sprintf("iamtunnel: warning — this machine is bound to %q, the gateway's own macOS LaunchDaemon account (home /var/empty, shell /usr/bin/false): no session can ever open through it — move the machine to a normal login account with \"iamtunnel admin machines set-user\"", name)
	default:
		return ""
	}
}

// cmdShot takes an offscreen screenshot of a GUI screen (SPEC §7.2);
// the screens are the tabs of §7.1. Parsing and validation run the same
// way on every platform; only the drawing behind shotScreen differs —
// Windows renders with the window library, others refuse (SPEC §9).
func cmdShot(s *streams, args []string) int {
	const path = "shot"
	fs := newFlagSet(path, "<screen>")
	fs.boolFlag("dark")
	fs.valFlag("out")
	fs.valFlag("subtab")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(1); err != nil {
		return fail(s, err)
	}
	screen, err := config.ParseScreen(fs.pos[0])
	if err != nil {
		return fail(s, err)
	}
	// shot touches no role data and reads no configuration; only the
	// arguments above apply.
	out := fs.val("out")
	if out == "" {
		out = defaultShotName(screen, fs.has("dark"))
	}
	theme := "light"
	if fs.has("dark") {
		theme = "dark"
	}
	return finishShot(s, screen, fs.val("subtab"), fs.has("dark"), out, theme)
}

// defaultShotName is the file shot writes when --out is not given: the
// canonical screen name in the current directory, suffixed -dark for
// the dark theme. The name is canonicalized here so the written name
// never depends on the caller's spelling.
func defaultShotName(screen string, dark bool) string {
	name := strings.ToLower(screen)
	if dark {
		return name + "-dark.png"
	}
	return name + ".png"
}

// selfCheck is one selftest probe: a name, whether it passed, and a
// one-line detail shown either way — selftest must check something
// real, never just print "OK".
type selfCheck struct {
	name   string
	ok     bool
	detail string
}

// cmdSelftest runs the built-in self check (SPEC §7.2): real loopback
// networking and real filesystem access on each role's own data
// directory — not a printed "OK".
func cmdSelftest(s *streams, args []string) int {
	const path = "selftest"
	fs := newFlagSet(path, "")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	return runSelftest(s)
}

func runSelftest(s *streams) int {
	checks := []selfCheck{checkLoopbackNetworking()}
	dirs, err := config.DirsFor(runtime.GOOS, s.env)
	if err != nil {
		// The environment cannot name an absolute data directory at all
		// (IAMT-76). That is one fact, not three failing directories, and
		// the reason is what the duty engineer needs to read.
		checks = append(checks, selfCheck{"role data directories", false, err.Error()})
	} else {
		if override, oerr := config.EnvOverride(s.env); oerr != nil {
			checks = append(checks, selfCheck{"role data directories", false, oerr.Error()})
		} else if override.DataDir != "" {
			// selftest has no single role, so an explicit role-data override
			// is applied to every probe. This keeps its checks aligned with
			// the paths each role would use when launched with that override.
			dirs.Client, dirs.Server, dirs.Gateway = override.DataDir, override.DataDir, override.DataDir
		}
		for _, rc := range []struct{ role, dir string }{
			{"client", dirs.Client}, {"server", dirs.Server}, {"gateway", dirs.Gateway},
		} {
			// IAMT-310 changed config.Dirs so an unresolved role directory
			// no longer always means DirsFor itself refused (Server/
			// Gateway are fixed absolute paths on Linux/darwin and no
			// longer need $HOME at all) — but a role that DOES still need
			// one (client, when $HOME/$XDG_DATA_HOME is empty) must keep
			// naming the exact danger a bare "could not be resolved"
			// would hide: an empty $HOME would otherwise silently produce
			// a RELATIVE path (IAMT-76). RoleDirE carries that reason;
			// pull it out only when the field actually came back empty.
			var resolveErr error
			if rc.dir == "" {
				_, resolveErr = dirs.RoleDirE(rc.role)
			}
			checks = append(checks, checkRoleDir(rc.role, rc.dir, resolveErr))
		}
		checks = append(checks, checkSavedIdentity("server (enrol)", dirs.Server, dirs.Server != "" && filepath.IsAbs(dirs.Server)))
	}

	allOK := true
	for _, c := range checks {
		status := "OK"
		if !c.ok {
			status, allOK = "FAIL", false
		}
		fmt.Fprintf(s.out, "[%s] %-28s %s\n", status, c.name, c.detail)
	}
	if !allOK {
		fmt.Fprintln(s.errs, "iamtunnel selftest: one or more checks failed — see above.")
		return exitEnv
	}
	return exitOK
}

// checkLoopbackNetworking proves the local TCP stack actually works:
// listen, dial, write one byte, read it back. A host whose loopback
// networking is broken cannot run any role of this program.
func checkLoopbackNetworking() selfCheck {
	const name = "loopback networking"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return selfCheck{name, false, fmt.Sprintf("cannot listen on 127.0.0.1: %v", err)}
	}
	defer ln.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			accepted <- err
			return
		}
		defer conn.Close()
		_, err = conn.Read(make([]byte, 1))
		accepted <- err
	}()
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		return selfCheck{name, false, fmt.Sprintf("cannot dial %s: %v", ln.Addr(), err)}
	}
	_, werr := c.Write([]byte("x"))
	_ = c.Close()
	if werr != nil {
		return selfCheck{name, false, fmt.Sprintf("write failed: %v", werr)}
	}
	select {
	case aerr := <-accepted:
		if aerr != nil {
			return selfCheck{name, false, fmt.Sprintf("accept/read failed: %v", aerr)}
		}
	case <-time.After(2 * time.Second):
		return selfCheck{name, false, "accept timed out"}
	}
	return selfCheck{name, true, "listen + dial + echo on 127.0.0.1 works"}
}

// checkRoleDir proves a role's data directory is usable: absolute
// (IAMT-76), and writable if it already exists. A directory that does
// not exist yet is not a failure — nothing has enrolled/connected/
// installed there yet, which is a normal fresh-machine state.
func checkRoleDir(role, dir string, resolveErr error) selfCheck {
	name := role + " data directory"
	if dir == "" {
		if resolveErr != nil {
			// Carries the real reason (IAMT-310/IAMT-76): e.g. "$HOME is
			// empty ... the path would be relative and unsafe" for the
			// client role — a bare "could not be resolved" would hide
			// exactly the danger this check exists to name.
			return selfCheck{name, false, resolveErr.Error()}
		}
		return selfCheck{name, false, "could not be resolved"}
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return selfCheck{name, true, dir + " (not set up yet)"}
	}
	// The probe name is random (os.CreateTemp), not the fixed
	// ".iamtunnel-selftest-probe" this was (IAMT-332 round 9): a fixed
	// probe name is itself a predictable name a plant can occupy — a
	// symlink there used to aim this truncating write at somebody
	// else's file, and a directory planted at it made selftest report
	// the directory as unwritable. selftest probes each of the client,
	// server and gateway directories, all three overridable to one
	// attacker-chosen path by --data-dir / IAMTUNNEL_DATA_DIR
	// (SPEC §3.1), and the run may be privileged ("sudo iamtunnel
	// selftest" is the natural form on macOS/Linux; on Windows the
	// default dirs need elevation to write).
	probe, err := os.CreateTemp(dir, ".iamtunnel-selftest-probe-*")
	if err != nil {
		return selfCheck{name, false, fmt.Sprintf("%s is not writable: %v", dir, err)}
	}
	probePath := probe.Name()
	_, werr := probe.WriteString("ok")
	cerr := probe.Close()
	_ = os.Remove(probePath)
	if werr != nil {
		return selfCheck{name, false, fmt.Sprintf("%s is not writable: %v", dir, werr)}
	}
	if cerr != nil {
		return selfCheck{name, false, fmt.Sprintf("%s is not writable: %v", dir, cerr)}
	}
	return selfCheck{name, true, dir + " (writable)"}
}

// checkSavedIdentity parses whatever "enrol" may already have saved, so
// a corrupted machine key or gateway record is caught by selftest
// instead of surfacing only the next time "server start" runs.
func checkSavedIdentity(name, serverDir string, dirUsable bool) selfCheck {
	if !dirUsable {
		return selfCheck{name, true, "skipped — server data directory is not usable"}
	}
	dirs := config.Dirs{Server: serverDir}
	if _, err := os.Stat(dirs.MachineKey()); os.IsNotExist(err) {
		return selfCheck{name, true, "not enrolled yet"}
	}
	if _, err := loadOrGenerateSigner(dirs.MachineKey()); err != nil {
		return selfCheck{name, false, fmt.Sprintf("saved machine key is unusable: %v", err)}
	}
	if _, err := loadGatewayRecord(serverDir); err != nil {
		return selfCheck{name, false, fmt.Sprintf("saved gateway record is unusable: %v", err)}
	}
	return selfCheck{name, true, "machine key and gateway record parse"}
}
