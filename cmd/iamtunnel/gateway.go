package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway"
	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// cmdGateway is the gateway role's local lifecycle on the VPS (SPEC
// §3.5). The remote admin variants live under "iamtunnel admin gateway".
func cmdGateway(s *streams, args []string) int {
	if len(args) == 0 {
		return fail(s, userErrf(`iamtunnel gateway: want exactly one of "install", "uninstall", "run", "status", "backup", "restore", "rotate-hostkey", "pair", "reset" or "verify-journal" — see "iamtunnel gateway --help".`))
	}
	if helpWord(args[0]) {
		return helpTopic(s, "gateway")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "install":
		return cmdGatewayInstall(s, rest)
	case "uninstall":
		return cmdGatewayUninstall(s, rest)
	case "run":
		return cmdGatewayRun(s, rest)
	case "status":
		return cmdGatewayStatus(s, rest)
	case "backup":
		return cmdGatewayBackup(s, rest)
	case "restore":
		return cmdGatewayRestore(s, rest)
	case "rotate-hostkey":
		return cmdGatewayRotate(s, rest)
	case "pair":
		return cmdGatewayPair(s, rest)
	case "reset":
		return cmdGatewayReset(s, rest)
	case "verify-journal":
		return cmdGatewayVerifyJournal(s, rest)
	default:
		return fail(s, userErrf("iamtunnel gateway: unknown subcommand %q — want %q, %q, %q, %q, %q, %q, %q, %q, %q or %q. See \"iamtunnel gateway --help\".",
			sub, "install", "uninstall", "run", "status", "backup", "restore", "rotate-hostkey", "pair", "reset", "verify-journal"))
	}
}

// gatewayPortRange is the §3.5 rule: the systemd unit carries no extra
// capabilities, so the listen port must be 1024..65535.
func gatewayPort(s *streams, path, v string) (*int, error) {
	if v == "" {
		return nil, nil
	}
	p, err := config.ParsePort(v, 1024)
	if err != nil {
		return nil, userErrf("iamtunnel %s: --port %q must be a number from 1024 to 65535 (SPEC §3.5 runs the gateway without extra capabilities; the default is 2222).", path, v)
	}
	return &p, nil
}

const hostkeyFileName = "hostkey"

func hostkeyPath(dir string) string { return filepath.Join(dir, hostkeyFileName) }

func fingerprintOfSigner(signer ssh.Signer) string {
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// ---- install / uninstall ---------------------------------------------------
//
// SPEC §3.5 + §3.5.1: "gateway install" is the whole local lifecycle
// setup — data directory, host key, bootstrap token (the local-file
// half, identical on every OS) and then the service half: the systemd
// unit on Linux (IAMT-177), the "iamtunnel-gateway" SCM service on
// Windows (IAMT-258), the LaunchDaemon on macOS (IAMT-259). Each service
// half drives its OS through its own seam, so a test binary never
// touches systemd, the service control manager or launchd.
func cmdGatewayInstall(s *streams, args []string) int {
	return cmdGatewayInstallOrRun(s, "gateway install", args, true)
}

func cmdGatewayRun(s *streams, args []string) int {
	return cmdGatewayInstallOrRun(s, "gateway run", args, false)
}

// cmdGatewayUninstall removes the service half that "gateway install"
// put in place (SPEC §3.5.1): the SCM service on Windows, the systemd
// unit on Linux, the LaunchDaemon on macOS (IAMT-259). The data
// directory — host key, state, event log — is deliberately left alone,
// so a later "gateway install" revives the same gateway identity and
// wiping it stays an explicit operator action. Idempotent: when the
// service half was never installed (or is already gone), uninstall
// reports "nothing to do" and exits OK.
func cmdGatewayUninstall(s *streams, args []string) int {
	const path = "gateway uninstall"
	fs := newFlagSet(path, "")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	// Same administrator gate as install: uninstall stops and deletes
	// the SCM service (no-op off Windows).
	if err := requireServerElevation(s, path); err != nil {
		return fail(s, err)
	}
	// The data directory is only needed to name it in the "left
	// untouched" line of the printout, so a config problem here must not
	// block removing the service: uninstall's own actions are named by
	// constants, and best-effort degrades the message instead.
	//
	// When the operator has EXPLICITLY passed --data-dir, the directory
	// name must appear in the "<dir> was not touched" line even when
	// loadConfig fails (for example, in a Linux container without $HOME
	// or XDG_DATA_HOME): this is an already-chosen path and it must not
	// go through the best-effort config resolution — otherwise IAMT-258
	// TestIAMT258_UninstallCLIReportsIdempotently/installed_reports_
	// removal_and_untouched_data turns red on "the output must name the
	// untouched data directory <dir>: out=\"… the data directory
	// was not touched …\"". Without an explicit flag (or the
	// IAMTUNNEL_DATA_DIR variable) it stays best-effort: loadConfig
	// computes the path itself; if that fails, the impersonal phrase is
	// printed.
	dir := fs.val("data-dir")
	if dir == "" {
		dir = s.env["IAMTUNNEL_DATA_DIR"]
	}
	dirFromEnv := dir != ""
	if _, _, lerr := loadConfig(s, "gateway", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")}); lerr != nil {
		if !dirFromEnv {
			dir = ""
		}
	}
	switch runtime.GOOS {
	case "windows":
		removed, err := teardownGatewayService(windowsService, gatewayServiceName)
		return reportGatewayUninstall(s, path, dir, removed, err)
	case "linux":
		removed, err := uninstallSystemdUnit(linuxSystemd)
		return reportGatewayUninstall(s, path, dir, removed, err)
	case "darwin":
		removed, err := teardownLaunchdDaemon(darwinLaunchd)
		return reportGatewayUninstall(s, path, dir, removed, err)
	default:
		return fail(s, envErrf("iamtunnel %s: the service half of uninstall (systemd unit / SCM service / LaunchDaemon — SPEC §3.5, §3.5.1) supports Linux, Windows and macOS; this build is running on %s and has no service integration for it.", path, runtime.GOOS))
	}
}

// reportGatewayUninstall prints the uninstall outcome. The data-directory
// line makes §3.5.1's promise visible in the operator's terminal: no
// gateway command ever destroys keys, state or event logs.
func reportGatewayUninstall(s *streams, path, dir string, removed bool, err error) int {
	if err != nil {
		return fail(s, err)
	}
	if !removed {
		fmt.Fprintf(s.out, "iamtunnel %s: the gateway service is not installed; nothing to do.\n", path)
		return exitOK
	}
	fmt.Fprintf(s.out, "iamtunnel %s: the gateway service was stopped and removed.\n", path)
	if dir != "" {
		fmt.Fprintf(s.out, "  the data directory %s was not touched (host key, state and event log survive; remove it by hand if you really want a wipe).\n", dir)
	} else {
		fmt.Fprintln(s.out, "  the data directory was not touched (host key, state and event log survive; remove it by hand if you really want a wipe).")
	}
	return exitOK
}

// resetWipe removes what gateway reset destroys, inside an os.Root on dir
// (review finding R4 N-03, N-04): the state, the bootstrap token, the enrol HMAC
// key, the whole event journal with its archives, the recordings tree
// and, with newHostkey, the host key. A name that is already gone is not
// an error. hostkeyPath names the key file by the same rule it is read by.
func resetWipe(dir string, newHostkey bool) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return classifyPathErr(err, dir)
	}
	defer root.Close()
	names := []string{state.StateFileName, bootstrapFileName, state.EnrolHMACKeyFileName}
	if newHostkey {
		names = append(names, filepath.Base(hostkeyPath(dir)))
	}
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return classifyPathErr(err, dir)
	}
	for _, e := range entries {
		if !e.IsDir() && events.IsLogFileName(e.Name()) {
			names = append(names, e.Name())
		}
	}
	for _, name := range names {
		if err := root.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return classifyPathErr(err, filepath.Join(dir, name))
		}
	}
	if err := root.RemoveAll("recordings"); err != nil {
		return classifyPathErr(err, filepath.Join(dir, "recordings"))
	}
	return nil
}

// cmdGatewayReset is the one-command reset of IAMT-388: what used to be
// five manual steps (stop the service, wipe the data, install again,
// hand out a new claim) in the exact order that loses nothing twice.
// Uninstall deliberately never touches the data directory — this command
// is the explicit operator action that does, and it says so out loud
// before it does it.
//
// The order is the contract. The service stop comes first — the one
// reversible step, and the one that frees the state lock for the count.
// The losses are then counted from the OLD state BEFORE the confirmation
// gate names them; the gate stands BEFORE the state-lock probe (a console
// "gateway run" refuses there — the service was this command's to stop, a
// console process is the operator's) and BEFORE the wipe. The journal
// entry lands in the FRESH journal right after the wipe (the old one is
// gone by design — this line is its first), carrying the reason and the
// people/machines/grants counts. Only then does the fresh install run,
// printing the new bootstrap claim.
func cmdGatewayReset(s *streams, args []string) int {
	const path = "gateway reset"
	fs := newFlagSet(path, "--public-host HOST [--port P] [--new-hostkey] [--yes]")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	fs.valFlag("port")
	fs.valFlag("public-host")
	fs.boolFlag("yes")
	fs.boolFlag("new-hostkey")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	// The new claim line needs a host to name (IAMT-202's lesson for
	// install applies verbatim): validate the value first, require it
	// second, both before anything is read or stopped.
	publicHost := fs.val("public-host")
	if publicHost != "" && !config.ValidHost(publicHost) {
		return fail(s, userErrf("iamtunnel %s: --public-host %q is not a valid DNS name or IP address (SPEC §3.1 host grammar) — example: --public-host gw.example.com.", path, publicHost))
	}
	port, perr := gatewayPort(s, path, fs.val("port"))
	if perr != nil {
		return fail(s, perr)
	}
	if publicHost == "" {
		return fail(s, userErrf("iamtunnel %s: --public-host <host> is required — the fresh bootstrap claim names the address clients and machines dial (e.g. --public-host gw.example.com).", path))
	}
	cfg, dir, lerr := loadConfig(s, "gateway", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir"), port: port})
	if lerr != nil {
		return fail(s, lerr)
	}
	return runGatewayReset(s, path, dir, cfg.Port, publicHost, fs.has("new-hostkey"), fs)
}

// runGatewayReset stops, counts, asks, probes, wipes, records and
// reinstalls — in that order. See cmdGatewayReset for why the order is
// the contract.
func runGatewayReset(s *streams, path, dir string, port int, publicHost string, newHostkey bool, fs *flagSet) int {
	// Same administrator gate as install/uninstall: reset stops the
	// service and rewrites the data directory (requireServerElevation is
	// a no-op off Windows).
	if err := requireServerElevation(s, path); err != nil {
		return fail(s, err)
	}

	// Stop and remove the service half first — through the same seams as
	// uninstall — so the wipe cannot race a daemon writing state, journal
	// or recordings behind the command's back, and so the state lock
	// frees up for the loss count below. The stop is the one reversible
	// step, which is why it alone stands before the confirmation; a bare
	// uninstall stops it gate-free. Idempotent: "was never installed" is
	// not an error.
	switch runtime.GOOS {
	case "windows":
		if _, err := teardownGatewayService(windowsService, gatewayServiceName); err != nil {
			return fail(s, err)
		}
	case "linux":
		if _, err := uninstallSystemdUnit(linuxSystemd); err != nil {
			return fail(s, err)
		}
	case "darwin":
		if _, err := teardownLaunchdDaemon(darwinLaunchd); err != nil {
			return fail(s, err)
		}
	default:
		return fail(s, envErrf("iamtunnel %s: the service half of reset (systemd unit / SCM service / LaunchDaemon — SPEC §3.5, §3.5.1) supports Linux, Windows and macOS; this build is running on %s and has no service integration for it. Nothing was wiped.", path, runtime.GOOS))
	}

	// Count what will be lost from the OLD state — now that the service
	// has stopped and released the lock. An unreadable state is itself a
	// loss worth naming, not a reason to stay silent: the file is still
	// destroyed below.
	people, machines, grants := 0, 0, 0
	stateReadable := true
	st, oerr := state.OpenForRead(dir)
	if oerr != nil {
		stateReadable = false
	} else {
		cur := st.Get()
		people, machines, grants = len(cur.People), len(cur.Machines), len(cur.Grants)
		_ = st.Close()
	}

	// The uniform confirmation gate, with every loss named in the
	// consequence sentence the operator answers to.
	hostkeyFate := "is kept (pass --new-hostkey to replace it)"
	if newHostkey {
		hostkeyFate = "is replaced with a fresh one"
	}
	unreadable := ""
	if !stateReadable {
		unreadable = "; the state file could not be read, its contents are destroyed all the same"
	}
	consequence := fmt.Sprintf("stops the gateway service and destroys the state in %s (people=%d, machines=%d, grants=%d%s), the event journal and the session recordings; a fresh empty gateway takes their place and a new bootstrap claim is printed. The host key %s.",
		dir, people, machines, grants, unreadable, hostkeyFate)
	if err := confirm(s, fs, path, consequence); err != nil {
		return fail(s, err)
	}

	// Last gate before the point of no return: a gateway NOT under the
	// service — a console "gateway run" — still holds the state lock. The
	// service was this command's to stop; a console process is the
	// operator's to stop, and the refusal names it. Nothing is wiped yet.
	probe, perr := state.Open(dir)
	if perr != nil {
		if errors.Is(perr, state.ErrLockHeld) {
			return fail(s, userErrf("iamtunnel %s: another gateway process still holds the state lock in %s — stop it first (the service, if one was installed, is already stopped; a \"gateway run\" in a console is not).", path, dir))
		}
		return fail(s, envErrf("iamtunnel %s: open state before the wipe: %v", path, perr))
	}
	_ = probe.Close()

	// The wipe: exact names from the card, nothing else (IAMT-388) - and
	// every one of them inside one os.Root on the data directory (review finding R4
	// N-03): a privileged command deleting by path could be led out of
	// the directory by a link swapped in between the checks above and the
	// delete; a Root cannot leave the directory it was opened on, and it
	// removes a link as a link. The journal goes whole, archives included
	// (N-04): the confirmation promised "the event journal", and archives
	// left behind kept the previous owner's events in the new gateway's
	// history and broke its chain check at the fresh first line.
	if err := resetWipe(dir, newHostkey); err != nil {
		return fail(s, err)
	}

	// The journal entry goes into the FRESH journal: the old one is gone
	// by design, so this line is its first — the reset survives its own
	// destruction. No new event type (the dictionary is closed, gate 12):
	// the same admin.op line the other local lifecycle commands write,
	// with the reason and the loss counts in details.
	log, lerr := events.OpenChainedLog(filepath.Join(dir, "events.jsonl"))
	if lerr != nil {
		return fail(s, envErrf("iamtunnel %s: opening the fresh event log: %v", path, lerr))
	}
	aerr := log.Append(events.Event{
		Time:   state.NewZonedTime(time.Now()),
		Type:   events.EventAdminOp,
		Actor:  "gateway",
		Object: "gateway",
		Result: "reset",
		Details: map[string]interface{}{
			"reason":          "operator ran gateway reset",
			"people":          people,
			"machines":        machines,
			"grants":          grants,
			"stateReadable":   stateReadable,
			"hostkeyReplaced": newHostkey,
		},
	})
	_ = log.Close()
	if aerr != nil {
		return fail(s, envErrf("iamtunnel %s: %v", path, aerr))
	}

	// Put a fresh gateway back: the same half install runs, printing the
	// new bootstrap claim (fresh token — the old one was wiped, fresh 24h
	// window, same host key unless --new-hostkey replaced it).
	return runGatewayInstall(s, path, dir, port, false, publicHost, false)
}

func cmdGatewayInstallOrRun(s *streams, path string, args []string, installOnly bool) int {
	argNames := "[--port P] [--public-host HOST]"
	if installOnly {
		argNames = "[--port P] [--public-host HOST] [--rebootstrap] [--replace-acl]"
	}
	fs := newFlagSet(path, argNames)
	fs.valFlag("data-dir")
	fs.valFlag("config")
	fs.valFlag("port")
	// IAMT-202: required by gateway install (the operator types it once
	// at install time and it lives in the unit's ExecStart forever after),
	// and optional for gateway run (the file may carry it instead).
	fs.valFlag("public-host")
	if installOnly {
		// IAMT-180: install-only flag; "gateway run" rejects it as unknown.
		fs.boolFlag("rebootstrap")
		// IAMT-315: install-only opt-in flag on Windows. On
		// Linux/macOS it is unknown and rejected as such — the
		// foreign-deny check is Windows-only. The flag tells
		// hardenGatewayDirACL to drop explicit ACCESS_DENIED ACEs
		// the operator previously placed on the data directory or
		// its files; without it, the install refuses with a list of
		// the offending ACEs and exit code 4.
		fs.boolFlag("replace-acl")
	}
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	// IAMT-202: validate the flag value up-front so an obviously bad host
	// is rejected before any disk/systemd action runs. The same grammar
	// (config.ValidHost, SPEC §3.1) is reused by connection-string parsing,
	// so the operator gets one set of rules instead of two.
	publicHost := fs.val("public-host")
	if publicHost != "" && !config.ValidHost(publicHost) {
		return fail(s, userErrf("iamtunnel %s: --public-host %q is not a valid DNS name or IP address (SPEC §3.1 host grammar) — example: --public-host gw.example.com.", path, publicHost))
	}
	port, perr := gatewayPort(s, path, fs.val("port"))
	if perr != nil {
		return fail(s, perr)
	}
	if installOnly {
		// IAMT-202: install refuses outright without --public-host. The
		// refusal happens AFTER port validation (so the operator gets
		// the port-range error first on a bad port) and BEFORE any
		// directory creation or state writes — a missing public host is
		// a "would hand out a <this-host> bootstrap link" defect, and
		// the only safe answer is "no, please re-run with --public-host".
		if publicHost == "" {
			return fail(s, userErrf("iamtunnel %s: --public-host <host> is required — pass the DNS name or IP address that clients and machines use to dial the gateway (e.g. --public-host gw.example.com). Without it the bootstrap link and any later connection strings would carry the placeholder \"<this-host>\" and be unparseable.", path))
		}
	}
	cfg, dir, lerr := loadConfig(s, "gateway", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir"), port: port})
	if lerr != nil {
		return fail(s, lerr)
	}
	if installOnly {
		return runGatewayInstall(s, path, dir, cfg.Port, fs.has("rebootstrap"), publicHost, fs.has("replace-acl"))
	}
	// gateway run: flag beats file, and at least one must be set. The
	// text names BOTH sources because the operator may have set either;
	// saying "set --public-host" when the file already has it would be
	// the wrong nudge.
	if publicHost == "" {
		publicHost = cfg.PublicHost
	}
	if publicHost == "" {
		return fail(s, userErrf("iamtunnel gateway run: public host is not set — pass --public-host <host> or set the public_host key in the config file (SPEC §3.1 host grammar)."))
	}
	if !config.ValidHost(publicHost) {
		return fail(s, userErrf("iamtunnel gateway run: public host %q (from the surviving source) is not a valid DNS name or IP address (SPEC §3.1 host grammar).", publicHost))
	}
	cfg.PublicHost = publicHost
	return runGatewayServe(s, path, dir, cfg)
}

func runGatewayInstall(s *streams, path, dir string, port int, rebootstrap bool, publicHost string, replaceACL bool) int {
	// darwinGatewayUID carries the _iamtunnel uid preflightGatewayReachability
	// resolves below to the OS switch further down (IAMT-308 round 8):
	// setupLaunchdDaemon must reuse it rather than resolving the account a
	// second time — see preflightGatewayReachability's own comment for why.
	// Unused on any other host OS.
	var darwinGatewayUID int

	// SPEC §3.5.1: Windows install creates an SCM service and rewrites the
	// data-directory ACL, so it needs the same administrator gate (banner
	// and refusal) as the server commands. requireServerElevation is a
	// no-op off Windows, so the Linux path is unchanged.
	if err := requireServerElevation(s, path); err != nil {
		return fail(s, err)
	}
	// IAMT-308: on macOS the gateway data dir nests under a parent this
	// command itself creates (default /Library/Application
	// Support/iamtunnel, one level above the gateway/ leaf) — MkdirAll
	// below would give that parent the same 0700 as the leaf, and the
	// unprivileged _iamtunnel service account could then not even
	// traverse it. That turned probing the OPTIONAL config file
	// (gateway.json, a sibling of gateway/) into EACCES instead of the
	// ENOENT an absent optional file should give, which the daemon
	// treated as a fatal environment error on every launchd respawn —
	// `gateway install` reported success while the service could never
	// start. The parent carries no secrets of its own (the leaf
	// directory below stays 0700, owned by _iamtunnel), so it is kept
	// traversable — 0755 — instead; the explicit chmod also heals a
	// parent an earlier, broken install already created at 0700. Linux
	// and Windows are unaffected: their default gateway dir sits
	// directly under a parent (/var/lib, %ProgramData%) the OS itself
	// already made traversable, and a custom --data-dir there is the
	// operator's own directory to secure.
	//
	// IAMT-308 round 5 (review finding 2): the unconditional chmod above
	// used to run for ANY dir, including a custom --data-dir the operator
	// passed explicitly — e.g. --data-dir /private/company-secrets/gw
	// would give every other user traverse+listing rights over
	// /private/company-secrets, a directory this command has no business
	// touching. prepareGatewayParentDir now scopes the fix-up to the
	// exact standard macOS gateway path.
	if runtime.GOOS == "darwin" {
		standardDirs, _ := config.DirsFor("darwin", s.env)
		if err := prepareGatewayParentDir(dir, standardDirs.Gateway); err != nil {
			return fail(s, err)
		}
		// IAMT-308 round 10 (review finding F-308-8): round 9's reachability
		// re-check only shrinks the window between checking a custom
		// --data-dir's path and using it again — a successful check and the
		// next path-based syscall are still two different actions, so
		// whoever controls one of its ancestors could still swap a
		// component in between. This removes the threat the window exists
		// for: a custom path's ancestors must all be exclusively
		// root-controlled, or install refuses outright, by name, here.
		// Never applied to the standard path, which this command already
		// owns end to end.
		if dir != standardDirs.Gateway {
			if err := checkCustomDataDirAncestorsAreSafe(darwinLaunchd, dir); err != nil {
				return fail(s, err)
			}
		}
		// IAMT-308 round 7 (review finding F-308-4): a live Mac showed
		// install already creating the host key, the bootstrap token and
		// state.json — and already printing the bootstrap reference —
		// before the (round 6) reachability check ever ran, so a refusal
		// left a working, printable secret behind for an install that had
		// already failed. Checking reachability here, before any of that
		// exists, means a refusal truly leaves nothing behind.
		uid, uerr := preflightGatewayReachability(darwinLaunchd, dir)
		if uerr != nil {
			return fail(s, uerr)
		}
		darwinGatewayUID = uid
		// IAMT-308 round 11 (review finding F-308-9): the ancestor check
		// above never looks at dataDir itself — only its parent and
		// upward — so a symlink (or an ACL grant) planted at the leaf
		// was invisible to it. This checks the leaf too, and creates it
		// now, as root, if it does not exist yet, so nothing else gets a
		// chance to put something else there first. serviceUID is the
		// account just resolved above: a repeat install's own dataDir
		// already belongs to it, not root, from a previous run.
		if dir != standardDirs.Gateway {
			if err := checkCustomDataDirLeafIsSafe(darwinLaunchd, dir, darwinGatewayUID); err != nil {
				return fail(s, err)
			}
		}
	}
	// dirExistedBefore records whether dataDir itself already existed
	// before the MkdirAll just below creates it (IAMT-308 round 9): a
	// repeat install's own pre-existing directory — and everything
	// already inside it — must never be removed by the reachability
	// re-check further down (F-308-6); only a directory THIS call
	// creates fresh is ever cleaned up on that re-check's refusal.
	dirExistedBefore := false
	if _, serr := os.Stat(dir); serr == nil {
		dirExistedBefore = true
	}
	// R1-CX F-21: the systemd unit written at the very end must be able
	// to carry this directory and this binary; a path it cannot is
	// refused here, before the host key, the bootstrap token and the
	// state exist - not after them.
	if runtime.GOOS == "linux" {
		if bin, exeErr := os.Executable(); exeErr == nil {
			if err := refuseSystemdUnitPaths(path, bin, dir); err != nil {
				return fail(s, err)
			}
		}
	}
	// IAMT-315: Windows ACL preflight — sits with IAMT-308's macOS
	// preflight above (and with the lesson of IAMT-308 round 7: a
	// refusal that fires AFTER the host key, the bootstrap token,
	// state.json and the printed bootstrap reference already exist on
	// disk has left a working, printable secret behind for an install
	// that has already failed). Runs BEFORE MkdirAll so a refusal
	// removes nothing: the data dir is read only if it already
	// existed (a repeat install); the binary's dir is always read
	// (os.Executable returned a path, and the binary must be on disk
	// for the install to be running at all). The hardening helpers
	// below re-read both DACLs and refuse-or-overwrite with the same
	// check — this preflight is the early refusal; the hardening is
	// the actual overwrite.
	if runtime.GOOS == "windows" {
		bin, exeErr := os.Executable()
		if exeErr != nil {
			return fail(s, envErrf("iamtunnel %s: locate this binary for the ACL preflight: %v", path, exeErr))
		}
		if err := preflightGatewayACL(dir, filepath.Dir(bin), replaceACL, s.out); err != nil {
			// IAMT-315: route the deliberate refusal through the
			// documented deniedErrf path (exit 4), not the catch-all
			// "internal error" the default fail() would print for an
			// unknown error type. A deliberate, expected refusal must
			// never be reported as an internal error — that is how an
			// operator learns to ignore real internal errors. setupGatewayService
			// below does the same for the hardenExe/harden refusals;
			// this branch keeps the contract consistent.
			var fdr *winkeys.ForeignDenyRefusalError
			if errors.As(err, &fdr) {
				return fail(s, deniedErrf("gateway install: %v — to overwrite these explicit DENY ACEs and proceed, repeat with --replace-acl.", err))
			}
			return fail(s, envErrf("gateway install: read the security descriptor during the ACL preflight: %v", err))
		}
	}
	// R2-CX F-05: on Windows the binary's directory and the data directory
	// get their ACLs BEFORE anything secret is written or printed. The
	// data directory is created with its own DACL (the production seam
	// does it); only its parent comes from MkdirAll, and the MkdirAll just
	// below finds the leaf already there. It used to be the service half's
	// first step, after the host key, the bootstrap token and state.json
	// had been written - readable, under %ProgramData%, to every signed-in
	// user - and after the bootstrap reference had been printed.
	var winSpec gatewayServiceSpec
	if runtime.GOOS == "windows" {
		bin, exeErr := os.Executable()
		if exeErr != nil {
			return fail(s, envErrf("iamtunnel %s: locate this binary for the service command line: %v", path, exeErr))
		}
		if exeUnreachableByServiceAccount(bin, s.env) {
			return fail(s, deniedErrf("iamtunnel %s: %s sits inside a user profile, which the service account %s cannot read by default (RUNBOOK §1.5) — move iamtunnel.exe to %s and run \"%s\" from there.", path, bin, gatewayServiceAccountName, windowsProgramHome(s.env), path))
		}
		if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
			return fail(s, classifyPathErr(err, filepath.Dir(dir)))
		}
		winSpec = gatewayServiceSpecFor(bin, dir, port, publicHost)
		release, err := hardenGatewayDirs(windowsService, winSpec, filepath.Dir(bin), dir, replaceACL, s.out)
		if err != nil {
			return fail(s, err)
		}
		// R2-CX F-12: the data directory stays pinned until install
		// returns - nothing on its path can be renamed away and replaced
		// between the lock and the writes below.
		defer release()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fail(s, classifyPathErr(err, dir))
	}
	// SPEC §3.5.1 / RUNBOOK §1.3: the gateway data dir is 0700 on macOS
	// and Linux. MkdirAll applies the mode only at creation; the chmod
	// also heals a directory a previous run created with looser rights.
	// Windows is excluded: there the §3.5.1 ACL (SYSTEM, Administrators
	// and the service's own account — hardenGatewayDirACL, wired into
	// the service install) replaces the Unix mode bits, and os.Chmod on
	// Windows would only flip the read-only attribute.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fail(s, classifyPathErr(err, dir))
		}
	}
	if runtime.GOOS == "darwin" {
		// IAMT-308 round 9 (review finding F-308-6): preflightGatewayReachability
		// ran above BEFORE dataDir existed at all — the two syscalls just
		// above (MkdirAll, chmod) are a window during which whoever
		// controls a custom --data-dir's ancestor could still swap its
		// mode, ACL, or replace it with a symlink, unnoticed. Re-verifying
		// HERE, immediately before the host key, the bootstrap token or
		// state.json are ever written and before anything is printed,
		// shrinks that window down to those two syscalls instead of
		// leaving it open across the rest of install — this is the review's
		// second suggested fix (re-verify immediately before the first
		// write; the alternative, pinning the whole path through openat
		// file descriptors, is a much larger change for a window this
		// call already keeps to two syscalls). A refusal here removes
		// only the leaf THIS call just created — dirExistedBefore is
		// false — never a repeat install's own pre-existing data, and
		// prints nothing: every stdout write below this point still
		// hasn't run.
		if err := verifyGatewayReachable(darwinLaunchd, dir, darwinGatewayUID); err != nil {
			if !dirExistedBefore {
				_ = os.Remove(dir)
			}
			return fail(s, err)
		}
	}
	signer, err := loadOrGenerateSigner(hostkeyPath(dir))
	if err != nil {
		return fail(s, err)
	}
	fp := fingerprintOfSigner(signer)

	token, terr := ensureBootstrapToken(dir)
	if terr != nil {
		return fail(s, terr)
	}
	// Wire the bootstrap reference into state.json so "iamtunnel admin
	// claim" can actually find it. The bootstrap file on disk is the raw
	// secret the operator types into "admin claim"; state.json carries
	// the HMAC of that secret (under state.EnrolHMACKey), the matching
	// ephemeral ed25519 public key, and the 24h expiry — exactly the
	// three fields bootstrap_role.go (lookup.go:55, bootstrap_role.go:166+)
	// already validate against. Side effect of writing this is that
	// the first "gateway run" finds a fully-formed BootstrapPending
	// rather than an empty state.json.
	//
	// This runs on every platform, before the non-Linux refusal below:
	// the bootstrap-token file and the state.json entry are local
	// artifacts with nothing to do with systemd, and not setting them on
	// Windows would leave "admin claim" perpetually unreachable on a
	// gateway box that was only partially set up.
	//
	// --rebootstrap (IAMT-180) takes the other branch: a FRESH token and
	// a fresh 24h window, overwriting the pending entry even when
	// state.json already exists. Without the flag a repeat install keeps
	// never touching state.json (SPEC §3.5).
	switch {
	case rebootstrap:
		newToken, rerr := rebootstrapPending(dir)
		if rerr != nil {
			return fail(s, rerr)
		}
		token = newToken
	default:
		if err := writeBootstrapPending(dir, token); err != nil {
			return fail(s, err)
		}
	}

	// IAMT-200: the canonical form of a bootstrap reference is the bare
	// 43-character fingerprint without the "SHA256:" prefix (the same
	// form people.connection-string and machines.enrol-code already
	// print — internal/gateway/admin_role.go strips the prefix by
	// hand). The older "SHA256:"-prefixed form is still parsed by
	// ParseClaimRef for backwards compatibility, but install no longer
	// emits it: "fp" here has the prefix stripped for printing, while
	// "fingerprint %s" above keeps the prefix deliberately — that line
	// is not a reference, it is a human-readable marker.
	bareFP := strings.TrimPrefix(fp, "SHA256:")
	// IAMT-202: the <this-host> placeholder in the bootstrap reference
	// is replaced with the real public host the operator passed in
	// --public-host, the same one already written into the unit file's
	// ExecStart.
	//
	// Printed BEFORE the service half of install (systemd/SCM/
	// LaunchDaemon): if the service half fails, the operator already
	// holds the token and the reference, and the local files
	// (state.json, bootstrap-token) are written, so "admin claim" does
	// not depend on the outcome of the service half.
	fmt.Fprintf(s.out, "iamtunnel %s: directory %s and host key ready (fingerprint %s).\n", path, dir, fp)
	fmt.Fprintf(s.out, "bootstrap reference (use once, within 24h, with \"iamtunnel admin claim\"):\n  %s:%d#%s:%s\n", publicHost, port, bareFP, token)
	// IAMT-336 / SPEC §3.3, §3.6: the same secret once more, this time as
	// the ONE string a person pastes into the single field — nothing to
	// assemble by hand. The bare reference above stays because it is what
	// "iamtunnel admin claim" takes as an argument (config.ParseClaimRef
	// refuses a scheme); the line below is what the Admin tab's single
	// field takes (internal/paste). Two renderings of one secret, never
	// two secrets.
	fmt.Fprint(s.out, bootstrapClaimBlock(publicHost, port, bareFP, token))

	// The service half of install is platform-specific (SPEC §3.5 for
	// Linux, §3.5.1 for Windows and macOS); each half drives its OS
	// integration through its own seam so a test binary never touches
	// systemd, the SCM or launchd.
	switch runtime.GOOS {
	case "linux":
		// IAMT-177: the systemd half of SPEC §3.5 — service user, hardened
		// unit, daemon-reload, enable, start — driven through the
		// systemdSetup seam. The product path passes linuxSystemd (real
		// id/useradd/systemctl on the VPS, run as root); tests substitute
		// their own seam so nothing system-level ever runs from a test
		// binary.
		bin, exeErr := os.Executable()
		if exeErr != nil {
			return fail(s, envErrf("iamtunnel %s: locate this binary for the systemd unit: %v", path, exeErr))
		}
		if err := setupSystemd(linuxSystemd, bin, dir, port, publicHost); err != nil {
			return fail(s, err)
		}

		fmt.Fprintf(s.out, "systemd: user %s, unit %s written, daemon reloaded, enabled and started.\n", gatewayServiceUser, systemdUnitDir+"/"+gatewayUnitName)
		return exitOK
	case "windows":
		// SPEC §3.5.1: ACL on the data directory, the iamtunnel-gateway
		// SCM service (delayed autostart, restart-on-failure, virtual
		// service account) and its start — through the windowsService
		// seam (gateway_service.go). The firewall is never touched:
		// install prints the operator's command instead.
		// The ACLs are already in place (R2-CX F-05, above); what is left
		// is the service itself.
		alreadyRunning, serr := startGatewayService(windowsService, winSpec)
		if serr != nil {
			return fail(s, serr)
		}
		if alreadyRunning {
			fmt.Fprintf(s.out, "iamtunnel %s: service %s configuration updated under %s; it was already running and was left running (starting an already-running service is not a failure) — restart it (services.msc or \"Restart-Service %s\") to apply the new configuration to the running process.\n", path, gatewayServiceName, gatewayServiceAccountName, gatewayServiceName)
		} else {
			fmt.Fprintf(s.out, "iamtunnel %s: service %s installed under %s (delayed autostart, restart on failure) and started.\n", path, gatewayServiceName, gatewayServiceAccountName)
		}
		fmt.Fprintf(s.out, "the firewall was not touched — open the port when ready with:\n  %s\n", gatewayFirewallHint(port))
		return exitOK
	case "darwin":
		// SPEC §3.5.1: the service user _iamtunnel (dscl), the
		// LaunchDaemon plist (0644, root:wheel) and launchctl bootstrap —
		// through the darwinLaunchd seam (gateway_launchd.go). Same
		// firewall discipline as Windows: nothing is opened, install
		// prints the Application Firewall command instead; pf is never
		// touched.
		bin, exeErr := os.Executable()
		if exeErr != nil {
			return fail(s, envErrf("iamtunnel %s: locate this binary for the LaunchDaemon plist: %v", path, exeErr))
		}
		if err := setupLaunchdDaemon(darwinLaunchd, bin, gatewayServiceArguments(dir, port, publicHost), dir, darwinGatewayUID); err != nil {
			return fail(s, err)
		}
		fmt.Fprintf(s.out, "iamtunnel %s: LaunchDaemon %s installed (0644, root:wheel; user %s, shell %s) and bootstrapped; logs go to %s.\n", path, darwinPlistPath, darwinServiceUser, darwinServiceShell, darwinLogPath)
		fmt.Fprintf(s.out, "the firewall was not touched — open the port when ready with:\n  %s\n", darwinFirewallHint(bin))
		return exitOK
	default:
		return fail(s, envErrf("iamtunnel %s: the service half of install (systemd unit / SCM service / LaunchDaemon — SPEC §3.5, §3.5.1) supports Linux, Windows and macOS; this build is running on %s and has no service integration for it. Run \"gateway install\" on the gateway host itself.", path, runtime.GOOS))
	}
}

// prepareGatewayParentDir applies IAMT-308's macOS parent-directory
// policy for the gateway data dir, one level above the 0700 leaf
// os.MkdirAll(dir, 0o700) creates next. standardGatewayDir is the
// platform's system-scope default for the gateway role — production
// passes config.DirsFor("darwin", env).Gateway; tests pass a
// t.TempDir()-rooted stand-in, since the real default is a fixed
// absolute path (/Library/Application Support/iamtunnel/gateway) a
// hermetic test must never create or chmod.
//
// dir == standardGatewayDir: the parent is this command's own default
// territory (RUNBOOK §1.3), so it is unconditionally created/healed to
// 0755 — traversable, no secrets of its own (the leaf below stays 0700).
// Any other dir is a custom --data-dir (IAMT-308 round 5 / review finding
// 2): giving its parent's permissions the same unconditional treatment
// would expose the listing of a directory this command does not
// own — e.g. --data-dir /private/company-secrets/iamtunnel-gateway. Its
// parent is left exactly as the operator set it; if it does not exist
// yet it is created at a restrictive 0700 (the operator's own tree, not
// install's to open up).
//
// This function does NOT check whether the parent is traversable by the
// _iamtunnel service account (round 5 tried that here and broke fifteen
// tests: every one of them installs into a --data-dir under
// t.TempDir(), which on a real Mac sits under /var/folders/.../T — a
// per-user tree that is genuinely not world-traversable — and every one
// of them uses a FAKE OS seam, so no real LaunchDaemon was ever going to
// run as _iamtunnel and need that traversal at all). Round 6: that check
// now lives in setupLaunchdDaemon's parentTraversable seam step
// (gateway_launchd.go), which runs only against the real service
// account, right after that account's uid is actually known — production
// checks for real, a test's fake seam answers "yes" unconditionally
// because there is no real account or daemon for it to honestly refuse
// on behalf of.
func prepareGatewayParentDir(dir, standardGatewayDir string) error {
	parent := filepath.Dir(dir)
	if parent == dir || parent == string(filepath.Separator) {
		return nil
	}
	if dir == standardGatewayDir {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return classifyPathErr(err, parent)
		}
		if err := os.Chmod(parent, 0o755); err != nil {
			return classifyPathErr(err, parent)
		}
		return nil
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return classifyPathErr(err, parent)
	}
	return nil
}

// bootstrapFileName holds the one-time admin-claim token SPEC §3.3
// describes. The raw secret lives here for the operator's records; the
// matching BootstrapPending entry in state.json is what the gateway
// actually checks at admin-claim time (internal/gateway/bootstrap_role.go).
const bootstrapFileName = "bootstrap-token"

func ensureBootstrapToken(dir string) (string, error) {
	path := filepath.Join(dir, bootstrapFileName)
	data, err := state.ReadDataFile(path)
	switch {
	case err == nil:
		return string(data), nil
	case errors.Is(err, os.ErrNotExist):
		// First install (or a previous run never got as far as
		// writing the token): mint one below. This is the ONLY
		// branch that regenerates — any other read failure means
		// the name is there and something is wrong with it, and a
		// planted symlink or FIFO must be reported, not papered
		// over with a fresh token renamed over the entry (IAMT-332
		// round five).
	default:
		return "", err
	}
	token, err := newBootstrapToken()
	if err != nil {
		return "", err
	}
	if err := atomicWriteBytes(path, []byte(token)); err != nil {
		return "", err
	}
	return token, nil
}

// newBootstrapToken mints the raw one-time secret of the bootstrap
// reference: 32 random bytes, base64-raw-url. Shared by the first install
// (ensureBootstrapToken) and --rebootstrap (rebootstrapPending) so both
// paths hand out the same shape of secret.
func newBootstrapToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", envErrf("could not generate a bootstrap token: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// writeBootstrapPendingEntry performs the one state transaction both the
// first install and --rebootstrap need: bind the BootstrapPending entry to
// the token (HMAC under the store's enrol key, matching ephemeral ed25519
// public key) with the given deadline. The store must already be open —
// both callers own the lock and the close.
func writeBootstrapPendingEntry(store *state.Store, token string, deadline time.Time) error {
	signer, err := config.DeriveEphemeralSigner(token, config.BootstrapKeySalt)
	if err != nil {
		return envErrf("gateway install: derive the bootstrap ephemeral key: %v", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	return store.Update(func(st *state.State) error {
		st.BootstrapPending = &state.BootstrapPending{
			SecretHash: state.HashEnrolSecret(store.EnrolHMACKey(), []byte(token)),
			PublicKey:  pubLine,
			Expires:    state.NewZonedTime(deadline),
		}
		return nil
	})
}

// writeBootstrapPending records the BootstrapPending state entry that
// makes the bootstrap-token file usable. Idempotent on a repeat install:
// state.json is never touched if it already exists (SPEC §3.5: "a repeat
// install does not touch state.json"). The first-time path opens the store
// — which loads-or-creates enrol-hmac.key, the secret the HMAC needs —
// then runs one Update to install the pending entry.
//
// Failure mode: a state.json left untouched on a repeat install is the
// reason this function must be cheap and unsurprising. Errors are
// surfaced verbatim so the operator can decide whether to "gateway
// restore" first.
func writeBootstrapPending(dir, token string) error {
	statePath := filepath.Join(dir, state.StateFileName)
	if _, err := os.Stat(statePath); err == nil {
		// Repeat install: SPEC §3.5 forbids touching state.json here.
		return nil
	} else if !os.IsNotExist(err) {
		return classifyPathErr(err, statePath)
	}

	store, err := state.Open(dir)
	if err != nil {
		// The same state.lock release as gatewayServeWithSettings: a
		// corrupt state.json comes back with the lock already held by the
		// returned read-only Store — close it before reporting (IAMT-194).
		if store != nil {
			_ = store.Close()
		}
		return envErrf("gateway install: open state.json to register the bootstrap pending entry: %v", err)
	}
	defer func() { _ = store.Close() }()

	return writeBootstrapPendingEntry(store, token, time.Now().UTC().Add(24*time.Hour))
}

// rebootstrapPending re-issues the one-time bootstrap reference (IAMT-180):
// a FRESH token (the bootstrap-token file is overwritten), a fresh 24h
// window, the same three fields bootstrap_role.go validates. It is the one
// sanctioned way to touch state.json after the first install — a repeat
// install without the flag still never does (SPEC §3.5).
//
// Refused when an administrator already exists: the bootstrap reference
// exists to create the FIRST administrator (SPEC §3.3); afterwards adding
// keys is admin work ("iamtunnel admin people keys add"), not install
// work. This is a safety property, not a convenience: a re-issued token on
// an administered gateway would be a second "first admin" path.
//
// The gateway must be stopped: state.Open takes the same exclusive lock
// "gateway run" holds, so a running gateway refuses the re-issue with the
// same operator-facing wording. Every re-issue lands in events.jsonl as an
// admin.op line (no new event type: the dictionary is closed, gate 12).
func rebootstrapPending(dir string) (string, error) {
	store, err := state.Open(dir)
	if err != nil {
		if errors.Is(err, state.ErrLockHeld) {
			return "", userErrf("gateway install --rebootstrap: another gateway process already holds the state lock in %s — stop it first.", dir)
		}
		// The same state.lock release as gatewayServeWithSettings: close
		// the read-only Store state.Open returns together with a
		// *CorruptStateError before reporting the failure (IAMT-194).
		if store != nil {
			_ = store.Close()
		}
		return "", envErrf("gateway install --rebootstrap: open state.json: %v", err)
	}
	defer func() { _ = store.Close() }()

	// cur must be a local (addressable) value: HasAnyAdmin is a pointer
	// method, and store.Get() returns a value.
	cur := store.Get()
	if cur.HasAnyAdmin() {
		return "", userErrf("gateway install --rebootstrap: %s already has an administrator — the bootstrap reference exists only to create the FIRST one (SPEC §3.3). Add further admin keys with \"iamtunnel admin people keys add\".", dir)
	}

	token, terr := newBootstrapToken()
	if terr != nil {
		return "", terr
	}
	if err := atomicWriteBytes(filepath.Join(dir, bootstrapFileName), []byte(token)); err != nil {
		return "", err
	}
	deadline := time.Now().UTC().Add(24 * time.Hour)
	if err := writeBootstrapPendingEntry(store, token, deadline); err != nil {
		return "", err
	}

	log, lerr := events.OpenChainedLog(filepath.Join(dir, "events.jsonl"))
	if lerr != nil {
		return "", envErrf("gateway install --rebootstrap: opening the event log: %v", lerr)
	}
	defer func() { _ = log.Close() }()
	if aerr := log.Append(events.Event{
		Time:   state.NewZonedTime(time.Now()),
		Type:   events.EventAdminOp,
		Actor:  "gateway",
		Object: "bootstrapPending",
		Result: "rebootstrap",
		Details: map[string]interface{}{
			"expires": deadline.UTC().Format(time.RFC3339),
		},
	}); aerr != nil {
		return "", envErrf("gateway install --rebootstrap: %v", aerr)
	}
	return token, nil
}

// ---- pair (IAMT-323) --------------------------------------------------------

// The local pairing window's numbers (SPEC §3.3, §3.5): the same v1
// protocol parameters the gateway applies to a network-opened window
// (internal/gateway/config.go, PairingConfig defaults). The CLI carries
// them as constants the same way install carries the 24h bootstrap
// window — the runtime keeps them configurable for tests, the product
// default lives here.
const (
	pairingPINDigits = 6
	pairingWindowTTL = 2 * time.Minute
)

// cmdGatewayPair opens the pairing window locally on the gateway host —
// the emergency recovery path of SPEC §3.5: every admin key lost, no
// admin left to run "iamtunnel admin pairing start" over the network.
// It prints the pairing reference (host:port#fp) and a fresh PIN and
// exits; the window itself is one atomic write into state.json, so the
// gateway MUST be stopped — state.Open takes the same exclusive lock
// "gateway run" holds, and a live gateway is refused with a hint toward
// the network command. The journal gets one admin.op line from actor
// "gateway" (no new event type: the dictionary is closed, gate 12); the
// PIN goes only to this terminal, never to events.jsonl.
func cmdGatewayPair(s *streams, args []string) int {
	const path = "gateway pair"
	fs := newFlagSet(path, "[--port P] [--public-host HOST]")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	fs.valFlag("port")
	fs.valFlag("public-host")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	// Same flag-first rule as "gateway run": the ref must carry the host
	// clients actually dial, so a missing public host is refused instead
	// of printed as a placeholder.
	publicHost := fs.val("public-host")
	if publicHost != "" && !config.ValidHost(publicHost) {
		return fail(s, userErrf("iamtunnel %s: --public-host %q is not a valid DNS name or IP address (SPEC §3.1 host grammar) — example: --public-host gw.example.com.", path, publicHost))
	}
	port, perr := gatewayPort(s, path, fs.val("port"))
	if perr != nil {
		return fail(s, perr)
	}
	cfg, dir, lerr := loadConfig(s, "gateway", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir"), port: port})
	if lerr != nil {
		return fail(s, lerr)
	}
	if publicHost == "" {
		publicHost = cfg.PublicHost
	}
	if publicHost == "" {
		return fail(s, userErrf("iamtunnel gateway pair: public host is not set — pass --public-host <host> or set the public_host key in the config file (SPEC §3.1 host grammar)."))
	}

	pin, expires, ref, err := openPairingWindow(dir, publicHost, cfg.Port)
	if err != nil {
		return fail(s, err)
	}
	fmt.Fprintf(s.out, "pairing window open until %s\n", expires.Format(time.RFC3339))
	fmt.Fprint(s.out, pairingPrintout(ref, pin))
	return exitOK
}

// pairingPrintout is what a person copies after a pairing window opens,
// and the ONE place that decides its shape: "gateway pair" here and
// "admin pairing start" (admin_exec.go) print the same block, because
// an operator who learnt one of them has learnt both.
//
// The order of the lines is load-bearing, not cosmetic. internal/paste
// takes the FIRST line of a paste that could carry a value, so the one
// string of SPEC §3.6 comes first: paste the whole block, and the
// string is what gets read. Put the labelled "pairing reference:" line
// above it and a whole-block paste is refused for carrying three values
// — which is precisely the refusal that burned the two-minute window on
// 17.09.
//
// The labelled reference and PIN stay, at the bottom: §3.6 keeps the
// separate hand-over possible on purpose (the gateway still prints the
// reference and the PIN in a way that lets them be handed over
// separately), it just no longer forces
// it on anybody.
func pairingPrintout(ref, pin string) string {
	one := pairClaimString(ref, pin)
	var b strings.Builder
	fmt.Fprintf(&b, "paste this one string into the Admin tab's single field (SPEC §3.6):\n  %s\n", one)
	fmt.Fprintf(&b, "On the new admin's machine run:\n  iamtunnel admin pair %s\n", one)
	fmt.Fprintf(&b, "to hand the two halves over separately instead:\n  pairing reference: %s\n  PIN: %s\n", ref, pin)
	return b.String()
}

// pairClaimString renders the one-string pairing form of SPEC §3.6,
// "iamtunnel-pair://<host>:<port>#<fp>:<pin>", from the bare reference
// the pairing window produced. ref is "<host>:<port>#<fingerprint>"
// with the fingerprint already bare (that is what openPairingWindow and
// the gateway's own pairing.start both build), so the PIN is appended
// after the one ':' that separates it from the fingerprint.
func pairClaimString(ref, pin string) string {
	return "iamtunnel-pair://" + ref + ":" + pin
}

// openPairingWindow is cmdGatewayPair's mechanism, factored out of the
// CLI shell the same way rebootstrapPending is: one exclusive state.Open
// (refusing a live gateway by the lock), one Store.Update writing
// state.PairingPending, one admin.op line. It returns the PIN, the
// absolute expiry and the rendered reference; the PIN exists nowhere else
// — not on disk outside the HMAC, not in the journal.
func openPairingWindow(dir, publicHost string, port int) (pin string, expires time.Time, ref string, err error) {
	store, err := state.Open(dir)
	if err != nil {
		if errors.Is(err, state.ErrLockHeld) {
			return "", time.Time{}, "", userErrf("gateway pair: another gateway process already holds the state lock in %s — stop it first; for a live gateway use \"iamtunnel admin pairing start\" instead.", dir)
		}
		// The same state.lock release as gatewayServeWithSettings: close
		// the read-only Store state.Open returns together with a
		// *CorruptStateError before reporting the failure (IAMT-194).
		if store != nil {
			_ = store.Close()
		}
		return "", time.Time{}, "", envErrf("gateway pair: open state.json: %v", err)
	}
	defer func() { _ = store.Close() }()

	signer, err := loadOrGenerateSigner(hostkeyPath(dir))
	if err != nil {
		return "", time.Time{}, "", err
	}
	bareFp := strings.TrimPrefix(fingerprintOfSigner(signer), "SHA256:")
	ref = fmt.Sprintf("%s:%d#%s", publicHost, port, bareFp)

	pin, err = gateway.GeneratePin(pairingPINDigits)
	if err != nil {
		return "", time.Time{}, "", envErrf("gateway pair: %v", err)
	}
	expires = time.Now().UTC().Add(pairingWindowTTL)
	hash := state.HashEnrolSecret(store.EnrolHMACKey(), []byte(pin))
	if uerr := store.Update(func(st *state.State) error {
		// A pending window from an earlier pair is simply replaced: the
		// old PIN stops working the instant the new one lands (one
		// atomic write, PROTOCOL §3.4), the same rule pairing.start uses.
		st.PairingPending = &state.PairingPending{
			SecretHash: hash,
			Expires:    state.NewZonedTime(expires),
		}
		return nil
	}); uerr != nil {
		return "", time.Time{}, "", envErrf("gateway pair: %v", uerr)
	}

	log, lerr := events.OpenChainedLog(filepath.Join(dir, "events.jsonl"))
	if lerr != nil {
		return "", time.Time{}, "", envErrf("gateway pair: opening the event log: %v", lerr)
	}
	defer func() { _ = log.Close() }()
	if aerr := log.Append(events.Event{
		Time:   state.NewZonedTime(time.Now()),
		Type:   events.EventAdminOp,
		Actor:  "gateway",
		Object: "pairingPending",
		Result: "pair",
		Details: map[string]interface{}{
			"expires": expires.UTC().Format(time.RFC3339),
		},
	}); aerr != nil {
		return "", time.Time{}, "", envErrf("gateway pair: %v", aerr)
	}
	return pin, expires, ref, nil
}

// ---- systemd half of install (IAMT-177) -----------------------------------

const (
	// gatewayServiceUser is the unprivileged account SPEC §3.5 runs the
	// gateway under ("runs as the iamtunnel user, not as root").
	gatewayServiceUser = "iamtunnel"
	// gatewayUnitName is the unit name RUNBOOK §1.3 has used since the
	// manual-install days; install writes and enables the same name.
	gatewayUnitName = "iamtunnel-gateway.service"
	systemdUnitDir  = "/etc/systemd/system"
)

// gatewayUnitFile renders the systemd unit (SPEC §3.5). A pure function on
// purpose: the test asserts the hardening directives without running
// anything, and an operator can diff the rendered unit against the example
// in RUNBOOK.md §1.3 — the content below IS that example, parameterised by
// binary path, data dir, port and public host. The hardening block is the
// SPEC's own list — ProtectSystem=strict, ProtectHome=yes, PrivateTmp=yes,
// NoNewPrivileges=yes, ReadWritePaths=<data dir>, AmbientCapabilities=
// (empty: the port is >=1024, no capability needed). time-sync.target is
// ordered before the service because the gateway clock is the single
// source of truth for deadlines (SPEC §6.4).
//
// publicHost is required (IAMT-202): install refuses outright without it
// rather than writing a unit that would hand out connection strings with
// the placeholder <this-host>. ExecStart carries it as --public-host so
// `gateway run` started by systemd inherits the same value the operator
// passed at install time.
func gatewayUnitFile(binPath, dataDir string, port int, publicHost string) string {
	return fmt.Sprintf(`[Unit]
Description=iamtunnel bastion gateway
After=network-online.target time-sync.target
Wants=network-online.target time-sync.target

[Service]
Type=simple
User=%s
Group=%s
ExecStart=%s gateway run --data-dir %s --port %d --public-host %s
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=%s
AmbientCapabilities=
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`, gatewayServiceUser, gatewayServiceUser, systemdExecWord(binPath), systemdExecWord(dataDir), port,
		systemdExecWord(publicHost), systemdPathWord(dataDir))
}

// installLivenessAttempts/-Interval bound how long install waits for a
// freshly started service to prove it is actually running before
// refusing (environment error, exit 3) instead of reporting success over
// one that is already crash-looping — the family IAMT-308 (macOS
// gateway), IAMT-310 (macOS server) and IAMT-312 (Windows gateway) all
// share: the OS call that starts a service (systemctl start, launchctl
// bootstrap, StartService) can return success the instant the process is
// spawned, well before it has had a chance to hit the fatal error that
// kills it. installLivenessSleep is swapped by tests (the same seam-
// variable convention as linuxSystemd/darwinLaunchd/windowsService) so a
// canary never actually waits.
const installLivenessAttempts = 5
const installLivenessInterval = 200 * time.Millisecond

var installLivenessSleep = time.Sleep

// waitForLiveness polls check up to installLivenessAttempts times,
// sleeping installLivenessInterval between attempts, and reports whether
// any attempt said "running". A query that keeps failing counts as dead,
// same as a query that plainly answers "not running" — install has no
// business trusting a state it cannot even read.
func waitForLiveness(check func() (bool, error)) (bool, error) {
	var lastErr error
	for attempt := 0; attempt < installLivenessAttempts; attempt++ {
		ok, err := check()
		if err != nil {
			lastErr = err
		} else if ok {
			return true, nil
		} else {
			lastErr = nil
		}
		if attempt < installLivenessAttempts-1 {
			installLivenessSleep(installLivenessInterval)
		}
	}
	return false, lastErr
}

// waitForGone is waitForLiveness's mirror: it polls check up to
// installLivenessAttempts times, sleeping installLivenessInterval
// between attempts, until check reports "gone" (false) instead of
// "running" (true). Used on macOS (IAMT-308 round 4) to confirm a
// launchd bootout has actually finished tearing a job down before the
// caller bootstraps a new one: launchctl bootout returns as soon as the
// teardown request is accepted, not once launchd's own job table has
// forgotten the label, and an immediate bootstrap in that window
// answers "Bootstrap failed: 5: Input/output error" — confirmed by hand
// against a genuinely still-loaded label.
func waitForGone(check func() (loaded bool, err error)) error {
	var lastErr error
	for attempt := 0; attempt < installLivenessAttempts; attempt++ {
		loaded, err := check()
		if err != nil {
			lastErr = err
		} else if !loaded {
			return nil
		} else {
			lastErr = nil
		}
		if attempt < installLivenessAttempts-1 {
			installLivenessSleep(installLivenessInterval)
		}
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("still loaded")
}

// systemdSetup is the OS-integration seam of install's Linux half. The
// product path passes linuxSystemd (real id/useradd/chown/systemctl,
// executed only on a Linux host); tests pass their own struct so no test
// binary ever creates a user, writes to /etc or talks to systemd.
// Unexported on purpose: it is not a product switch, it is the one place
// install touches the operating system.
type systemdSetup struct {
	// userExists returns nil when the account is already there.
	userExists func(name string) error
	// createUser creates the system account bound to the data dir.
	createUser func(name, home string) error
	// chownDir transfers ownership of path and everything under it
	// (recursively) to user:group. Run AFTER the user is guaranteed to
	// exist (IAMT-199): install created the data directory and every
	// file in it as root, so without this step the unit starts under
	// User=iamtunnel but cannot open state.lock and crashes in a loop.
	chownDir func(path, user, group string) error
	// writeUnit writes the rendered unit to the absolute path.
	writeUnit func(path, content string) error
	// exeWriters names every path through which someone other than root
	// could change the binary a root unit is about to start (IAMT-445b,
	// exe_owner.go); none means only root can.
	exeWriters func(bin string) ([]string, error)
	// systemctl runs one systemctl invocation with the given arguments.
	systemctl func(args ...string) error
	// unitExists reports whether the unit file is on disk. Uninstall only:
	// a missing unit means "nothing to do" (idempotent), not an error.
	unitExists func(path string) (bool, error)
	// removeUnit deletes the unit file. Uninstall only, after
	// "systemctl disable --now" has stopped and unenabled the unit.
	removeUnit func(path string) error
	// isActive reports whether systemd currently considers unitName
	// active (IAMT-308/310 family): "systemctl start" can return success
	// the instant the unit's process forks, before it has had a chance
	// to crash on its first real error, so install confirms with this
	// after start instead of trusting the start call alone. The waiting
	// is the PRODUCT implementation's job (linuxSystemd polls internally
	// with waitForLiveness) — the seam itself is a single call, so a
	// recorder-based test sees exactly one step no matter how many times
	// the real implementation queried systemctl underneath (IAMT-258
	// round 2: a retry loop wrapped around the seam call turned one step
	// into up to five in every test that pins the exact call sequence).
	isActive func(unitName string) (bool, error)
}

// linuxIDPath, linuxUseraddPath, linuxChownPath and linuxSystemctlPath
// are the absolute, documented locations of id(1), useradd(8), chown(1)
// and systemctl(1) on every systemd-based Linux distribution this
// install path targets (IAMT-319: the same PATH-injection class
// IAMT-318 fixed inside the macOS gateway install path — this one runs
// as root from the moment it first calls userExists, well before any
// secret exists, so a bare exec.Command("id", ...) etc. resolved
// through PATH would let anyone who can influence that root process's
// PATH plant their own helper and get arbitrary code execution as
// root). A missing binary at one of these paths fails closed through
// the calling seam's own error handling (a *PathError from exec, since
// each path contains a separator and so is never looked up through PATH
// at all) rather than falling back to anything else.
const (
	linuxIDPath        = "/usr/bin/id"
	linuxUseraddPath   = "/usr/sbin/useradd"
	linuxChownPath     = "/usr/bin/chown"
	linuxSystemctlPath = "/usr/bin/systemctl"
)

// linuxSystemd is the production seam implementation. Every call shells
// out to the real OS tool; errors are the process errors verbatim so the
// caller can name the failing step for the operator.
var linuxSystemd = systemdSetup{
	userExists: func(name string) error {
		return exec.Command(linuxIDPath, "-u", name).Run()
	},
	createUser: func(name, home string) error {
		return exec.Command(linuxUseraddPath, "--system", "--home-dir", home, "--create-home", "--shell", "/usr/sbin/nologin", name).Run()
	},
	chownDir: func(path, user, group string) error {
		// chown -R handles both an existing directory tree and a not-yet-
		// created "recordings" subdirectory: it chowns whatever exists and
		// does not fail on missing entries. -R also follows subdirectories
		// the gateway will create later under the same data dir (IAMT-199).
		return exec.Command(linuxChownPath, "-R", user+":"+group, path).Run()
	},
	writeUnit: func(path, content string) error {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return classifyPathErr(err, path)
		}
		return nil
	},
	exeWriters: serviceExeWriters,
	systemctl: func(args ...string) error {
		return exec.Command(linuxSystemctlPath, args...).Run()
	},
	unitExists: func(path string) (bool, error) {
		_, err := os.Stat(path)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, classifyPathErr(err, path)
	},
	removeUnit: func(path string) error {
		if err := os.Remove(path); err != nil {
			return classifyPathErr(err, path)
		}
		return nil
	},
	// isActive polls "systemctl is-active" itself (waitForLiveness, up to
	// installLivenessAttempts times with installLivenessInterval between
	// them) instead of leaving the retry to the caller: systemdInstallTail
	// calls this seam field exactly once, so the polling stays invisible
	// to anything that counts or orders seam calls (IAMT-258 round 2).
	isActive: func(unitName string) (bool, error) {
		return waitForLiveness(func() (bool, error) {
			err := exec.Command(linuxSystemctlPath, "is-active", "--quiet", unitName).Run()
			if err == nil {
				return true, nil
			}
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				// systemctl is-active exits non-zero (and prints
				// "inactive", "activating", "failed"...) for anything
				// but active — a named process-exit status, not a
				// failure to ask.
				return false, nil
			}
			return false, err
		})
	},
}

// setupSystemd drives the install sequence: ensure the service user (only
// when missing), transfer ownership of the data directory to that user,
// write the unit, then daemon-reload → enable → start, in that order.
// Each failure is reported with the step that failed, so an operator
// reading the error knows exactly what to redo by hand per RUNBOOK.md
// §1.3. The binPath lands in ExecStart verbatim; the caller resolves it
// with os.Executable() so the unit runs the same binary that performed
// the install.
//
// The chown step (IAMT-199) sits between the user and the unit on purpose:
// install created the data directory and every file in it (hostkey,
// bootstrap-token, state.json, state.lock, enrol-hmac.key, plus the new
// bootstrap-token --rebootstrap writes when present) as the root it runs
// under; useradd's --create-home only chowns the directory if it had to
// create it, which is not the case here. Without this step the unit's
// User=iamtunnel directive refuses state.lock at startup and the unit
// crash-loops, which is exactly the defect caught on a live VPS.
//
// publicHost is required (IAMT-202): it lands in ExecStart so `gateway run`
// started by systemd inherits it. A repeat install on the same data dir
// with a different --public-host simply rewrites the unit (state.json and
// the host key are not touched on a repeat install, only the unit file
// changes — that is by design: the unit is the one place the value lives,
// and SPEC §3.5 already says state.json must not be touched on repeat
// install).
func setupSystemd(setup systemdSetup, binPath, dataDir string, port int, publicHost string) error {
	// R1-CX F-21: a path no unit line can carry is refused before the
	// service user, the chown or the unit - runGatewayInstall asks this,
	// and whether the path is absolute, before it creates anything at all.
	if err := refuseSystemdUnitControl("gateway install", binPath, dataDir); err != nil {
		return err
	}
	if uerr := setup.userExists(gatewayServiceUser); uerr != nil {
		if cerr := setup.createUser(gatewayServiceUser, dataDir); cerr != nil {
			return envErrf("gateway install: create the %q service user: %v — run as root on the VPS, or create the user by hand per RUNBOOK.md §1.3 and repeat the install.", gatewayServiceUser, cerr)
		}
	}
	if cerr := setup.chownDir(dataDir, gatewayServiceUser, gatewayServiceUser); cerr != nil {
		return envErrf("gateway install: transfer ownership of %s to %s:%s: %v — fix by hand with \"sudo chown -R %s:%s %s\" per RUNBOOK.md §1.3 and repeat the install.", dataDir, gatewayServiceUser, gatewayServiceUser, cerr, gatewayServiceUser, gatewayServiceUser, dataDir)
	}
	// String concatenation, not filepath.Join: this is a path on the
	// TARGET machine (Linux), so it must be assembled with forward
	// slashes regardless of the OS the test builds/runs on — filepath
	// on Windows would produce "\etc\systemd\...". The path package is
	// not used because this command's own path parameter shadows it.
	unitPath := systemdUnitDir + "/" + gatewayUnitName
	if werr := setup.writeUnit(unitPath, gatewayUnitFile(binPath, dataDir, port, publicHost)); werr != nil {
		return envErrf("gateway install: write the systemd unit %s: %v — write it by hand per RUNBOOK.md §1.3 and run \"systemctl daemon-reload && systemctl enable --now %s\".", unitPath, werr, gatewayUnitName)
	}
	return systemdInstallTail(setup, "gateway", gatewayUnitName)
}

// systemdInstallTail drives the tail every systemd install shares — the
// gateway's (SPEC §3.5) and the machine's (SPEC §3.2.1): daemon-reload, then
// enable, then start, in that order, stopping at the first failure. The order
// is a contract, not a convenience: systemd ignores a unit file it has not
// reloaded, and "enable" before "start" is what makes the unit come back
// after a reboot. role is the command the operator typed ("gateway",
// "server"), so the failure text names the command they must repeat by hand;
// unitName is the unit it failed on.
//
// IAMT-249: extracted from setupSystemd when the machine role grew the same
// three steps — one place for the sequence keeps the two units from drifting,
// and the gateway's own error text and call order stay byte-for-byte what
// iamt177/iamt258 pin.
func systemdInstallTail(setup systemdSetup, role, unitName string) error {
	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", unitName},
		{"start", unitName},
	} {
		if serr := setup.systemctl(args...); serr != nil {
			return envErrf("%s install: systemctl %s: %v — finish by hand with \"systemctl daemon-reload && systemctl enable --now %s\".", role, strings.Join(args, " "), serr, unitName)
		}
	}
	// IAMT-308/310 family: "systemctl start" can report success the
	// instant the unit's process forks, before it has had a chance to
	// hit its own fatal error and crash — confirm systemd itself still
	// calls the unit active before install reports success over it.
	// isActive itself is the one that waits/retries (see linuxSystemd):
	// this is a SINGLE call to the seam, so a recorder-based test sees
	// exactly one step regardless of how many times the real
	// implementation polled systemctl underneath (IAMT-258 round 2 —
	// a generic retry loop calling the seam repeatedly turned one step
	// into up to five in every test that pins the exact sequence).
	active, lerr := setup.isActive(unitName)
	if !active {
		if lerr != nil {
			return envErrf("%s install: %s was started but checking \"systemctl is-active %s\" failed: %v — check \"systemctl status %s\" and \"journalctl -u %s\", fix, and repeat the install (it updates in place and starts again).", role, unitName, unitName, lerr, unitName, unitName)
		}
		return envErrf("%s install: %s was started but systemctl does not report it active — check \"systemctl status %s\" and \"journalctl -u %s\", fix the cause, and repeat the install (it updates in place and starts again).", role, unitName, unitName, unitName)
	}
	return nil
}

// systemdUninstallTail drives the tail every systemd uninstall shares (the
// gateway's §3.5.1 and the machine's §3.2.1): "systemctl disable --now"
// (stop + unenable in one step), remove the unit file, "systemctl
// daemon-reload" so systemd forgets it. Returns false when the unit file is
// not on disk: uninstalling a role whose service was already removed is a
// "nothing to do", not an error. role and unitName name the command and the
// unit in the operator-facing failure text; unitPath is where the file is.
func systemdUninstallTail(setup systemdSetup, role, unitPath, unitName string) (bool, error) {
	exists, err := setup.unitExists(unitPath)
	if err != nil {
		return false, envErrf("%s uninstall: look up the %s unit: %v", role, unitName, err)
	}
	if !exists {
		return false, nil
	}
	if serr := setup.systemctl("disable", "--now", unitName); serr != nil {
		return false, envErrf("%s uninstall: systemctl disable --now %s: %v — run as root, or stop and disable by hand (\"sudo systemctl disable --now %s\") and repeat the uninstall.", role, unitName, serr, unitName)
	}
	if rerr := setup.removeUnit(unitPath); rerr != nil {
		return false, envErrf("%s uninstall: remove the unit file %s: %v — remove it by hand and run \"sudo systemctl daemon-reload\".", role, unitPath, rerr)
	}
	if serr := setup.systemctl("daemon-reload"); serr != nil {
		return false, envErrf("%s uninstall: systemctl daemon-reload: %v — run \"sudo systemctl daemon-reload\" by hand.", role, serr)
	}
	return true, nil
}

// uninstallSystemdUnit drives the Linux uninstall sequence (SPEC §3.5.1):
// "systemctl disable --now" (stop + unenable in one step), remove the
// unit file, "systemctl daemon-reload" so systemd forgets it. The data
// directory is never touched by uninstall — only the service is. Returns
// false when the unit file is not on disk: uninstalling a gateway whose
// service was already removed is a "nothing to do", not an error.
func uninstallSystemdUnit(setup systemdSetup) (bool, error) {
	return systemdUninstallTail(setup, "gateway", systemdUnitDir+"/"+gatewayUnitName, gatewayUnitName)
}

// ---- run --------------------------------------------------------------

// runGatewayServe drives a real gateway.Gateway on a real TCP listener
// until an OS interrupt/terminate signal arrives, then closes it. It is
// split from the CLI wrapper so a test can drive gatewayServe directly
// with its own stop channel instead of fighting OS signals.
func runGatewayServe(s *streams, path, dir string, settings config.Settings) int {
	// SPEC §3.5.1: when this process was started by the Windows service
	// control manager, there are no console signals — svc.Run returns
	// only when the service stops, and Stop arrives through the handler.
	// Console runs (and test binaries) get (false, nil) and continue on
	// the signal path below, unchanged.
	if ran, serr := runGatewayServiceIfSCM(dir, settings); ran || serr != nil {
		if serr != nil {
			return fail(s, serr)
		}
		fmt.Fprintf(s.out, "iamtunnel %s: service stopped.\n", path)
		return exitOK
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	stop := make(chan struct{})
	go func() { <-sigCh; close(stop) }()

	addr, err := gatewayServeWithSettings(dir, settings, func(addr net.Addr) {
		fmt.Fprintf(s.out, "iamtunnel %s: listening on %s (data dir %s).\n", path, addr, dir)
	}, stop)
	if err != nil {
		return fail(s, err)
	}
	fmt.Fprintf(s.out, "iamtunnel %s: stopped (was %s).\n", path, addr)
	return exitOK
}

// gatewayDrainTimeout is how long a stopping gateway waits for its live
// sessions to leave after telling them it is restarting (IAMT-466,
// gateway.Drain), before it cuts what is left. Every service manager this
// program installs under gives a stop only so long: launchd kills after its
// default ExitTimeOut of 20 s, systemd after TimeoutStopSec (90 s by
// default), and Windows at system shutdown after a few seconds whatever the
// service asks for. 15 s is inside all of them, with room for Close.
const gatewayDrainTimeout = 15 * time.Second

// gatewayServe is the whole "gateway run" mechanism factored out of any
// CLI concern (this command's "observable consequence" is proven by
// dialing the address this function reports through ready, not by
// capturing a subprocess). It opens the real
// on-disk state store and event log, listens, serves until stop is
// closed, then drains: Gateway.Close waits for in-flight connections'
// own teardown before returning (internal/gateway/gateway.go).
func gatewayServe(dir string, port int, ready func(net.Addr), stop <-chan struct{}) (net.Addr, error) {
	settings := config.Defaults()
	settings.Port = port
	// IAMT-202: the tests that bring up gatewayServe directly
	// (cmd/iamtunnel/iamt131, iamt180, gateway_status_live,
	// gate2_admin_gateway) do not care about the public host — they
	// dial 127.0.0.1. The default is exactly 127.0.0.1 so those tests
	// do not fail on the new "public host is not set" check. The
	// production path (cmdGatewayRun) always overrides PublicHost
	// before this call, so the default never affects a live run.
	if settings.PublicHost == "" {
		settings.PublicHost = "127.0.0.1"
	}
	return gatewayServeWithSettings(dir, settings, ready, stop)
}

// gatewayServeWithSettings is the production assembly path.  Keeping the
// session caps in Settings makes the policy visible in the same configuration
// layer as the other gateway limits, rather than silently relying on a zero
// value in gateway.Config.
func gatewayServeWithSettings(dir string, settings config.Settings, ready func(net.Addr), stop <-chan struct{}) (net.Addr, error) {
	store, err := state.Open(dir)
	if err != nil {
		if errors.Is(err, state.ErrLockHeld) {
			return nil, userErrf("gateway run: another gateway process already holds the state lock in %s — stop it first.", dir)
		}
		// state.Open's corruption contract hands back a usable read-only
		// Store TOGETHER with the *CorruptStateError — and the state.lock
		// that Store already acquired. Discarding it without Close leaks
		// the lock: every later state.Open in this directory answers
		// "already holds the state lock" for no reason, and on Windows the
		// open handle even blocks deleting the data directory (IAMT-194
		// round two: TempDir cleanup could not unlink state.lock after a
		// refused gateway run). The lock belongs to us — we acquired it
		// — so release it before reporting the failure.
		if store != nil {
			_ = store.Close()
		}
		return nil, envErrf("gateway run: %v", err)
	}
	defer store.Close()

	log, err := events.OpenChainedLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return nil, envErrf("gateway run: opening the event log: %v", err)
	}
	defer log.Close()

	signer, err := loadOrGenerateSigner(hostkeyPath(dir))
	if err != nil {
		return nil, err
	}

	gw, err := gateway.New(gatewayRuntimeConfig(store, log, signer, dir, settings))
	if err != nil {
		return nil, envErrf("gateway run: %v", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", settings.Port))
	if err != nil {
		return nil, envErrf("gateway run: could not listen on port %d: %v", settings.Port, err)
	}
	addr := ln.Addr()
	if ready != nil {
		ready(addr)
	}

	serveErr := make(chan error, 1)
	go func() { serveErr <- gw.Serve(ln) }()

	// IAMT-290: Serve can end by itself before stop fires — an external
	// close of the listener, an immediate Accept failure, or the
	// IAMT-273 already-closed race. The value from serveErr may
	// therefore arrive through either select branch, and it is received
	// EXACTLY ONCE across both of them: the old shape waited for a
	// second value the goroutine never sends after a self-terminated
	// Serve, and the run hung forever holding the state lock. The error
	// is no longer swallowed either: anything that is not the
	// net.ErrClosed-shaped answer a Close produces (Accept's "use of
	// closed network connection") is a real Serve failure and is
	// reported instead of returning success.
	var serveResult error
	select {
	case <-stop:
		// The gentle half first (IAMT-466): nothing new, the live sessions
		// told and given gatewayDrainTimeout to leave; then the cut.
		gw.Drain(gatewayDrainTimeout)
		_ = gw.Close()
		serveResult = <-serveErr
	case serveResult = <-serveErr:
		_ = gw.Close()
	}
	if serveResult != nil && !errors.Is(serveResult, net.ErrClosed) {
		return nil, envErrf("gateway run: %v", serveResult)
	}
	return addr, nil
}

// gatewayRuntimeConfig translates effective application settings into the
// runtime's typed configuration.  It is deliberately a single production
// seam so the configured session limits cannot be omitted at gateway.New.
//
// PublicHost (IAMT-202) and PublicPort are filled from settings: the
// caller (cmdGatewayInstallOrRun) guarantees PublicHost is non-empty
// before runGatewayServe is reached, both for `gateway run` (flag beats
// file, fail-fast at the cmd layer) and for the systemd-managed
// instance (ExecStart carries --public-host from install).
func gatewayRuntimeConfig(store *state.Store, log *events.Log, signer ssh.Signer, dir string, settings config.Settings) gateway.Config {
	return gateway.Config{
		Store:                          store,
		Log:                            log,
		HostKey:                        signer,
		DataDir:                        dir,
		PublicHost:                     settings.PublicHost,
		PublicPort:                     settings.Port,
		ACLLimits:                      acl.Limits{PerPerson: settings.MaxSessionsPerPerson, PerMachine: settings.MaxSessionsPerMachine},
		RecordingBaseDir:               filepath.Join(dir, "recordings"),
		RecordingRetentionDays:         settings.RecordingsRetentionDays,
		RecordingRotatePercent:         settings.RecordingsDiskStopPercent,
		RiskAction:                     gateway.RiskAction(settings.RiskAction),
		RiskClassifier:                 gateway.RiskClassifier(settings.RiskClassifier),
		ExternalRiskObservationEnabled: settings.ExternalRiskObservationEnabled,
		ExternalRiskObservationKeyFile: settings.ExternalRiskObservationKeyFile,
		RecentCommandsMax:              settings.RecentCommandsMax,
		RecentCommandsBudget:           settings.RecentCommandsBudget,
		// The service's own log - the terminal, journald, the launchd log -
		// is where the audit journal's failure is said when the journal
		// itself cannot say it (IAMT-451).
		Diagnostics: os.Stderr,
		// What gateway.status says it is (IAMT-466): the same words as
		// "iamtunnel version".
		Version: fmt.Sprintf("%s (git %s)", version, gitSHA),
	}
}

// ---- status --------------------------------------------------------------

func cmdGatewayStatus(s *streams, args []string) int {
	const path = "gateway status"
	fs := newFlagSet(path, "[--port P] [--public-host HOST]")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	// --port and --public-host are here for one reason (IAMT-336): the
	// bootstrap string status reprints carries the address a client dials.
	// When the gateway is running, --port is read from the installed service
	// declaration unless the operator supplied an explicit override.
	fs.valFlag("port")
	fs.valFlag("public-host")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	publicHost := fs.val("public-host")
	if publicHost != "" && !config.ValidHost(publicHost) {
		return fail(s, userErrf("iamtunnel %s: --public-host %q is not a valid DNS name or IP address (SPEC §3.1 host grammar) — example: --public-host gw.example.com.", path, publicHost))
	}
	port, perr := gatewayPort(s, path, fs.val("port"))
	if perr != nil {
		return fail(s, perr)
	}
	cfg, dir, lerr := loadConfig(s, "gateway", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir"), port: port})
	if lerr != nil {
		return fail(s, lerr)
	}
	if publicHost == "" {
		publicHost = cfg.PublicHost
	}
	return runGatewayStatus(s, path, dir, publicHost, cfg.Port, port != nil)
}

// runGatewayStatus tells "alive" from "not running" the same way a
// second "gateway run" would be refused: internal/gateway/state.OpenForRead
// takes a non-blocking exclusive lock on state.lock (state/
// filelock_windows.go, filelock_posix.go) and returns state.ErrLockHeld
// when another process already holds it. No extra IPC of this
// package's own is needed here, unlike server start/stop/status — the
// lock IS the liveness signal, already provided by internal/gateway/state.
//
// "status" is read-only by contract (IAMT-98): no file is ever
// created by this path. state.OpenForRead distinguishes four states
// on disk:
//
//   - state.json absent, host key absent → "no gateway is installed"
//     (the data dir was never populated by anything);
//   - state.json absent, host key present → "installed but never
//     started" (runGatewayInstall creates the dir and the host key
//     but does not create state.json; before the first `gateway run`,
//     the host key is the only evidence install ran);
//   - state.json present, lock held → "running";
//   - state.json present, lock absent or free → "not running" with
//     the real counts from state.json. A lock file that does not
//     exist cannot be held by anybody (this is the state right after
//     `gateway restore`, which extracts state.json but does not
//     re-create state.lock); a lock file that exists and is not
//     held means the same thing for the running gateway.
func runGatewayStatus(s *streams, path, dir, publicHost string, port int, portExplicit bool) int {
	fp, hasKey := readHostkeyFingerprint(dir)
	store, err := state.OpenForRead(dir)
	if err != nil {
		if errors.Is(err, state.ErrLockHeld) {
			people, machines, grants, _ := peekStateCounts(dir)
			fmt.Fprintf(s.out, "iamtunnel %s: running (data dir %s).\n", path, dir)
			printStatusCounts(s, fp, hasKey, people, machines, grants)
			printAuditHealth(s, dir)
			printBootstrapStatus(s, dir, publicHost, statusPortForRunningService(port, portExplicit), fp, hasKey)
			return exitOK
		}
		if errors.Is(err, os.ErrNotExist) {
			// state.json missing. Distinguish by the host key, which
			// is the marker runGatewayInstall leaves on disk.
			if hasKey {
				fmt.Fprintf(s.out, "iamtunnel %s: installed but never started in %s.\n", path, dir)
				printStatusCounts(s, fp, hasKey, 0, 0, 0)
				printBootstrapStatus(s, dir, publicHost, port, fp, hasKey)
				return exitOK
			}
			fmt.Fprintf(s.out, "iamtunnel %s: no gateway is installed in %s.\n", path, dir)
			printStatusCounts(s, fp, hasKey, 0, 0, 0)
			return exitOK
		}
		return fail(s, envErrf("iamtunnel %s: %v", path, err))
	}
	defer store.Close()
	st := store.Get()
	fmt.Fprintf(s.out, "iamtunnel %s: not running (data dir %s).\n", path, dir)
	printStatusCounts(s, fp, hasKey, len(st.People), len(st.Machines), len(st.Grants))
	printBootstrapStatus(s, dir, publicHost, port, fp, hasKey)
	return exitOK
}

// bootstrapClaimBlock renders the one pasteable string of SPEC §3.6 —
// "iamtunnel-claim://<host>:<port>#<fp>:<token>" — together with the
// sentence that says where it goes. One function, so "gateway install"
// and "gateway status" print the same two lines: the operator who comes
// back to status after the install output has scrolled away finds
// character for character what install showed him.
func bootstrapClaimBlock(publicHost string, port int, bareFP, token string) string {
	return fmt.Sprintf("paste this one string into the Admin tab's single field to become the first admin (SPEC §3.6):\n  iamtunnel-claim://%s:%d#%s:%s\n", publicHost, port, bareFP, token)
}

// bootstrapPendingPeek is the one-time bootstrap entry as it sits in
// state.json. It is read raw (state.ReadDataFile, the same reader
// peekStateCounts uses) rather than through the store, because status
// must answer in every branch — including the one where a live gateway
// holds the state lock and no store can be opened at all.
type bootstrapPendingPeek struct {
	Expires state.ZonedTime `json:"expires"`
}

// peekBootstrapPending reads state.json's bootstrapPending entry.
// present is false when state.json is unreadable or carries no entry.
// Presence alone does not tell "spent" from "never issued"; the caller
// uses the host key (an installed gateway always wrote one) to know
// which of the two it is looking at.
func peekBootstrapPending(dir string) (peek bootstrapPendingPeek, present bool) {
	data, err := state.ReadDataFile(filepath.Join(dir, state.StateFileName))
	if err != nil {
		return bootstrapPendingPeek{}, false
	}
	var raw struct {
		BootstrapPending *bootstrapPendingPeek `json:"bootstrapPending"`
	}
	if json.Unmarshal(data, &raw) != nil || raw.BootstrapPending == nil {
		return bootstrapPendingPeek{}, false
	}
	return *raw.BootstrapPending, true
}

// printBootstrapStatus is the half of "gateway status" that answers a
// question a live run had nowhere to ask (SPEC §3.3): is the
// bootstrap string still usable, and if so, what is it?
//
// The string is printed ONLY while the state entry says the secret is
// still pending and its deadline has not passed. Spent and expired each
// get a sentence of their own: a dead string reprinted as if it still
// worked is what leads down the emergency path of RUNBOOK §5.11, and
// saying nothing at all would risk it again.
// Read-only throughout (IAMT-98): two reads of files install already
// wrote, nothing created.
func printBootstrapStatus(s *streams, dir, publicHost string, port int, fp string, hasKey bool) {
	if !hasKey {
		// Nothing is installed here, so there is no bootstrap string to
		// have an opinion about.
		return
	}
	peek, present := peekBootstrapPending(dir)
	if !present {
		fmt.Fprintf(s.out, "  bootstrap string: already used (or never issued) — the first admin is claimed; %q re-issues it, and only while no admin exists (SPEC §3.3).\n", "iamtunnel gateway install --rebootstrap")
		return
	}
	deadline := peek.Expires.Time
	if deadline.IsZero() || time.Now().After(deadline) {
		fmt.Fprintf(s.out, "  bootstrap string: EXPIRED at %s and can no longer be used — re-issue it with %q (SPEC §3.3).\n", deadline.UTC().Format(time.RFC3339), "iamtunnel gateway install --rebootstrap")
		return
	}
	token, terr := state.ReadDataFile(filepath.Join(dir, bootstrapFileName))
	if terr != nil {
		fmt.Fprintf(s.out, "  bootstrap string: unspent until %s, but %s could not be read (%v), so it cannot be reprinted — re-issue it with %q.\n", deadline.UTC().Format(time.RFC3339), bootstrapFileName, terr, "iamtunnel gateway install --rebootstrap")
		return
	}
	if publicHost == "" {
		fmt.Fprintf(s.out, "  bootstrap string: unspent until %s, but the public host is not set, so the string cannot be rendered — pass --public-host <host> or set public_host in the config file and ask again (SPEC §3.1 host grammar).\n", deadline.UTC().Format(time.RFC3339))
		return
	}
	fmt.Fprintf(s.out, "  bootstrap string: unspent, usable until %s.\n", deadline.UTC().Format(time.RFC3339))
	fmt.Fprint(s.out, bootstrapClaimBlock(publicHost, port, strings.TrimPrefix(fp, "SHA256:"), strings.TrimSpace(string(token))))
}

// printAuditHealth says whether the running gateway's audit journal is
// being written, from the file the gateway keeps in its data directory for
// exactly this (IAMT-451): status cannot ask a gateway whose lock it only
// sees. A gateway from before 1.14 keeps no such file, and then nothing is
// said - which is not the same as "ok".
func printAuditHealth(s *streams, dir string) {
	h, found, err := gateway.ReadAuditHealth(dir)
	switch {
	case err != nil:
		fmt.Fprintf(s.out, "  audit: could not be read: %v\n", err)
	case !found:
	default:
		a := admin.GatewayAuditStatus{OK: h.OK, Since: h.Since, Error: h.Error, LostWrites: h.LostWrites}
		if problem := a.Problem(); problem != "" {
			fmt.Fprintf(s.out, "  audit: PROBLEM: %s (journal entries lost since the gateway started: %d)\n", problem, h.LostWrites)
		} else {
			fmt.Fprintf(s.out, "  audit: ok (journal entries lost since the gateway started: %d)\n", h.LostWrites)
		}
	}
}

func printStatusCounts(s *streams, fp string, hasKey bool, people, machines, grants int) {
	if hasKey {
		fmt.Fprintf(s.out, "  host key fingerprint: %s\n", fp)
	} else {
		fmt.Fprintln(s.out, "  host key: not generated yet")
	}
	fmt.Fprintf(s.out, "  people=%d machines=%d grants=%d\n", people, machines, grants)
}

func readHostkeyFingerprint(dir string) (string, bool) {
	data, err := state.ReadDataFile(hostkeyPath(dir))
	if err != nil {
		return "", false
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return "", false
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return "", false
	}
	return fingerprintOfSigner(signer), true
}

// peekStateCounts reads state.json directly, without the store's lock,
// for use only while another process is known to hold that lock
// (runGatewayStatus's ErrLockHeld branch). state.json is always written
// tmp-then-rename (internal/gateway/state/store.go), so a concurrent raw
// read either sees the previous complete file or the new complete file,
// never a partial one.
func peekStateCounts(dir string) (people, machines, grants int, ok bool) {
	data, err := state.ReadDataFile(filepath.Join(dir, state.StateFileName))
	if err != nil {
		return 0, 0, 0, false
	}
	var peek struct {
		People   []json.RawMessage `json:"people"`
		Machines []json.RawMessage `json:"machines"`
		Grants   []json.RawMessage `json:"grants"`
	}
	if json.Unmarshal(data, &peek) != nil {
		return 0, 0, 0, false
	}
	return len(peek.People), len(peek.Machines), len(peek.Grants), true
}

// ---- backup / restore -------------------------------------------------

// The archive/restore mechanics (member list, tar.gz writer, restore
// extractor) live in internal/gateway/lifecycle.go beside the gateway
// runtime, because the remote admin exec "gateway.backup" (PROTOCOL §6,
// internal/gateway/admin_lifecycle.go) must produce exactly the same
// artifact this CLI verb produces. This file keeps only the CLI front
// end: flags, the --out default, exit-class mapping and the printout.

func cmdGatewayBackup(s *streams, args []string) int {
	const path = "gateway backup"
	fs := newFlagSet(path, "[--out FILE]")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	fs.valFlag("out")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	_, dir, lerr := loadConfig(s, "gateway", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")})
	if lerr != nil {
		return fail(s, lerr)
	}
	out := fs.val("out")
	if out == "" {
		out = fmt.Sprintf("iamtunnel-gateway-backup-%s.tar.gz", time.Now().UTC().Format("20060102-150405"))
	}
	statePath := filepath.Join(dir, state.StateFileName)
	if _, err := os.Stat(statePath); err != nil {
		if os.IsNotExist(err) {
			return fail(s, envErrf("iamtunnel %s: no gateway state found in %s — run \"gateway install\" or \"gateway run\" at least once first.", path, dir))
		}
		return fail(s, classifyPathErr(err, statePath))
	}
	if err := gateway.WriteBackupTarGz(out, dir); err != nil {
		return fail(s, classifySharedErr(err))
	}
	info, serr := os.Stat(out)
	if serr != nil {
		return fail(s, envErrf("iamtunnel %s: wrote %s but cannot stat it: %v", path, out, serr))
	}
	fmt.Fprintf(s.out, "iamtunnel %s: wrote %s (%d bytes).\n", path, out, info.Size())
	return exitOK
}

func cmdGatewayRestore(s *streams, args []string) int {
	const path = "gateway restore"
	fs := newFlagSet(path, "<backup.tar.gz>")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	fs.boolFlag("yes")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantN(1); err != nil {
		return fail(s, err)
	}
	const consequence = "replaces the gateway state.json with the copy in the backup, keeping the file it replaces as state.json.pre-restore-<the moment of the restore>, and rotates the live journal aside as events-<the same moment>.jsonl so the history keeps every event. The gateway must be stopped. Every state change made after that backup is lost."
	if err := confirm(s, fs, path, consequence); err != nil {
		return fail(s, err)
	}
	if _, err := os.Stat(fs.pos[0]); err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fail(s, envErrf("iamtunnel %s: backup file %q does not exist — pass a tarball created by %q.", path, fs.pos[0], "iamtunnel gateway backup"))
		case os.IsPermission(err):
			return fail(s, deniedErrf("iamtunnel %s: backup file %q cannot be accessed: %v — fix the permissions first.", path, fs.pos[0], err))
		default:
			return fail(s, envErrf("iamtunnel %s: backup file %q cannot be accessed: %v.", path, fs.pos[0], err))
		}
	}
	_, dir, lerr := loadConfig(s, "gateway", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")})
	if lerr != nil {
		return fail(s, lerr)
	}
	res, err := gateway.RestoreBackupTarGz(fs.pos[0], dir)
	if err != nil {
		// The state lock is the one failure the operator can fix in a
		// second, and it is the one a restore used to walk straight
		// past: a running gateway holds the journal handle and rewrites
		// state.json from memory, so the restore would have been undone
		// by its next save (M-8, review finding F-11).
		if errors.Is(err, state.ErrLockHeld) {
			return fail(s, userErrf("iamtunnel %s: a gateway is running in %s and holds the state lock — stop it first (\"sudo systemctl stop iamtunnel-gateway\"); restoring under a running gateway would be undone by its next write to state.json.", path, dir))
		}
		return fail(s, classifySharedErr(err))
	}
	fmt.Fprintf(s.out, "iamtunnel %s: restored %s into %s.\n", path, strJoinComma(res.Restored), dir)
	if res.StateKeptAs != "" {
		fmt.Fprintf(s.out, "  the state.json that was there is kept as %s\n", res.StateKeptAs)
	}
	if res.JournalKeptAs != "" {
		fmt.Fprintf(s.out, "  the journal was rotated to %s — the history still reads it, and it holds every event written after the backup; the archive's own copy of the journal was not installed\n", res.JournalKeptAs)
	}
	return exitOK
}

func strJoinComma(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// ---- verify-journal (local, IAMT-467) -------------------------------------

// cmdGatewayVerifyJournal checks the hash chain of the gateway's journal:
// every line of events.jsonl and of its archives names the SHA-256 of the
// line before it (events/chain.go). It only reads, so it runs beside a
// live gateway as well. Exit 0 when the journal is intact as far as the
// chain can tell, exitEnv (3) when a link is broken, a line was written
// without the chain after it began, or a line cannot be read at all
// (F-02, review round 1 24.09.2026: an unreadable line is an event that is
// gone, and this command is the one that answers whether the journal is
// whole).
func cmdGatewayVerifyJournal(s *streams, args []string) int {
	const path = "gateway verify-journal"
	fs := newFlagSet(path, "")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	_, dir, lerr := loadConfig(s, "gateway", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")})
	if lerr != nil {
		return fail(s, lerr)
	}
	rep, err := events.VerifyChain(dir)
	if err != nil {
		return fail(s, envErrf("iamtunnel %s: %v", path, err))
	}
	fmt.Fprintf(s.out, "iamtunnel %s: %s\n", path, rep.Summary())
	fmt.Fprintf(s.out, "  %d file(s), %d line(s): %d chained, %d from before the chain, %d unreadable, %d written without the chain after it began\n",
		rep.Files, rep.Lines, rep.Chained, rep.Legacy, rep.Unreadable, rep.Unvouched)
	if !rep.Intact() {
		return exitEnv
	}
	return exitOK
}

// ---- rotate-hostkey (local) ---------------------------------------------

func cmdGatewayRotate(s *streams, args []string) int {
	const path = "gateway rotate-hostkey"
	fs := newFlagSet(path, "")
	fs.valFlag("data-dir")
	fs.valFlag("config")
	fs.boolFlag("yes")
	if err := fs.parse(args); err != nil {
		return fail(s, err)
	}
	if fs.help {
		return helpTopic(s, path)
	}
	if err := fs.wantNone(); err != nil {
		return fail(s, err)
	}
	const consequence = "rotates the gateway host key; every client pin, enrol code and connection string stops working until the admin hands out new ones (SPEC §6.2)."
	if err := confirm(s, fs, path, consequence); err != nil {
		return fail(s, err)
	}
	_, dir, lerr := loadConfig(s, "gateway", cfgOpts{configPath: fs.val("config"), dataDir: fs.val("data-dir")})
	if lerr != nil {
		return fail(s, lerr)
	}

	hkPath := hostkeyPath(dir)
	evLog, err := events.OpenChainedLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return fail(s, envErrf("gateway rotate-hostkey: %v", err))
	}
	defer evLog.Close()
	// The whole rotation — old key to hostkey.old, fresh key on disk,
	// hostkey.rotate journal event — is internal/gateway/lifecycle.go's
	// RotateHostKey: the remote admin exec gateway.rotate-hostkey runs
	// the exact same function, so the two paths cannot drift apart.
	oldFP, newFP, rerr := gateway.RotateHostKey(dir, evLog, time.Now())
	if rerr != nil {
		return fail(s, classifySharedErr(rerr))
	}

	fmt.Fprintf(s.out, "iamtunnel %s: rotated the gateway host key.\n  old: %s (kept at %s)\n  new: %s\n", path, oldFP, hkPath+".old", newFP)
	return exitOK
}
