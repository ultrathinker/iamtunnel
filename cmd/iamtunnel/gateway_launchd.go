package main

// gateway_launchd.go — the macOS half of the gateway install (SPEC
// §3.5.1): constants, pure assemblies (picking a free system UID,
// parsing dscl answers, rendering the LaunchDaemon plist with XML
// escaping, the Application Firewall hint) and the install/uninstall
// SEQUENCES through the darwinLaunchdSetup seam. The file is
// platform-neutral on purpose — like gateway_service.go for the Windows
// half: the sequences and the output parsing are verified with the
// recording fake on any host OS. The production implementations are in
// gateway_launchd_darwin.go (dscl/launchctl), the stubs in
// gateway_launchd_stub.go.

import (
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// errProbeCouldNotRun marks a parentTraversable failure as "the
// reachability check itself could not run" rather than "the account
// genuinely cannot reach the path" (IAMT-308 round 8) — e.g. the real
// darwin implementation's probe subprocess could not even be started
// (see gateway_launchd_darwin.go's probeAccountCanReach), or looking up
// the account's group memberships failed. Declared here, platform-
// neutral, rather than in the darwin-only implementation file: this
// package's error-handling code (preflightGatewayReachability below)
// must compile and be testable on every host OS, the same reason
// errServiceAlreadyRunning (gateway_service.go) is a platform-neutral
// sentinel instead of living next to golang.org/x/sys/windows.
var errProbeCouldNotRun = errors.New("could not run the reachability probe")

const (
	// darwinServiceUser is the LaunchDaemon's service user (SPEC
	// §3.5.1): hidden, a free UID < 500, shell /usr/bin/false, created
	// through dscl.
	darwinServiceUser = "_iamtunnel"
	// darwinServiceGroup/darwinServiceGID is the service user's primary
	// group: staff (GID 20) exists on every macOS; the daemon does not
	// run in wheel — least privilege.
	darwinServiceGroup = "staff"
	darwinServiceGID   = 20
	darwinServiceShell = "/usr/bin/false"
	darwinServiceGecos = "iamtunnel gateway service"
	// darwinServiceHome is the service user's home: /var/empty, the
	// empty directory macOS keeps precisely for such daemons.
	darwinServiceHome  = "/var/empty"
	darwinSystemUIDMin = 200
	// darwinSystemUIDMax — SPEC §3.5.1: a free UID < 500.
	darwinSystemUIDMax = 499
	darwinPlistLabel   = "com.iamtunnel.gateway"
	darwinPlistPath    = "/Library/LaunchDaemons/com.iamtunnel.gateway.plist"
	darwinLogDir       = "/Library/Logs/iamtunnel"
	darwinLogPath      = darwinLogDir + "/gateway.log"
	darwinFirewallTool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
)

// darwinServiceUserSpec is exactly what dscl creates for the service
// user. The fields repeat SPEC §3.5.1's words: hidden (Hidden), a free
// UID < 500, shell /usr/bin/false.
type darwinServiceUserSpec struct {
	Name   string
	UID    int
	GID    int
	Shell  string
	Gecos  string
	Home   string
	Hidden bool
}

// darwinLaunchdSetup is the seam for every macOS OS action (the
// IAMT-177 requirement: any action on the OS — dscl, launchctl, writes
// under /Library/... — goes through the seam; in a test binary the
// production calls panic, tests plug in the recording fake).
type darwinLaunchdSetup struct {
	// currentUserIsRoot — SPEC §3.5.1: install/uninstall run as root.
	currentUserIsRoot func() (bool, error)
	// makeLogDir creates /Library/Logs/iamtunnel: launchd does not
	// create directories itself, and StandardOutPath/StandardErrorPath
	// point there.
	makeLogDir func(path string) error
	// lookupUser returns the service user's UID if it already exists
	// (a repeat install reuses it rather than breeding a duplicate).
	lookupUser func(name string) (uid int, exists bool, err error)
	// systemUIDsTaken is the set of system users' taken UIDs:
	// pickFreeSystemUID picks a free one out of it.
	systemUIDsTaken func() (map[int]bool, error)
	// createUser runs the whole set of dscl calls that create the user
	// (dsclCreateUserCalls).
	createUser func(spec darwinServiceUserSpec) error
	// chownDir hands a directory to the service user: the daemon reads
	// and writes the data directory and the log directory as _iamtunnel.
	chownDir func(path string, uid, gid int) error
	// writePlist writes the plist with 0644 and owner root:wheel
	// (uid 0, gid 0) — SPEC §3.5.1.
	writePlist func(path string, content []byte, mode os.FileMode, uid, gid int) error
	// plistExists reports whether the LaunchDaemon is installed
	// (uninstall's idempotence).
	plistExists func(path string) (bool, error)
	// removePlist removes the plist file.
	removePlist func(path string) error
	// exeWriters returns who besides root can change the binary the
	// machine's LaunchDaemon will run as root (IAMT-445b,
	// exe_owner.go); empty means root only.
	exeWriters func(bin string) ([]string, error)
	// serviceLoaded reports whether the daemon is loaded into launchd
	// (launchctl print).
	serviceLoaded func(label string) (bool, error)
	// bootout stops and unloads the daemon; a false second result means
	// there was no daemon to begin with (launchctl answered "no such
	// process").
	bootout func(label string) (bool, error)
	// bootstrap starts the daemon from the plist (launchctl bootstrap
	// system).
	bootstrap func(plistPath string) error
	// serviceRunning reports whether the job is running RIGHT NOW — not
	// "loaded" (serviceLoaded) but genuinely "state = running" in the
	// launchctl print output (IAMT-308/310 family): launchctl bootstrap
	// returns success as soon as launchd has queued the job for start,
	// long before the process could fall over on its first fatal
	// error. Waiting is the PRODUCTION implementation's duty
	// (darwinLaunchd polls launchctl itself through waitForLiveness);
	// the seam itself is one call, so a test on the recording fake sees
	// exactly one step, no matter how often launchctl is polled inside
	// (IAMT-258, round 2: a retry loop around the seam call turned one
	// step into several in every test that compares the exact
	// sequence).
	serviceRunning func(label string) (bool, error)
	// parentTraversable reports (as a nil/non-nil error) whether uid:gid
	// (the service account this install just chowned dataDir to) can
	// actually reach dataDir's parent directory (IAMT-308 rounds 6-7): a
	// custom --data-dir's parent is deliberately left untouched by
	// prepareGatewayParentDir (review finding 2, round 5) — a directory
	// this command does not own must not be chmodded on faith — but the
	// LaunchDaemon still needs to reach dataDir to actually start.
	//
	// Round 6 checked only dataDir's immediate parent, by comparing
	// permission bits against uid and a single gid from this (root)
	// process — review finding F-308-3: that misses a non-traversable
	// GRANDparent (or any higher ancestor), it does not know the
	// account's supplementary groups, and it cannot see POSIX ACLs at
	// all. Round 7's real implementation spawns an actual subprocess
	// UNDER the real account's full credential (every group the account
	// actually belongs to, not just gid — round 9 reads that list
	// through os/user rather than shelling out) and has IT stat the
	// parent — the kernel
	// then walks and checks every ancestor component, ACLs and symlinks
	// included, exactly as it will for the real LaunchDaemon; there is
	// no separate model of the filesystem for this check to get wrong.
	//
	// A test's fake OS seam answers nil (traversable) unconditionally by
	// default: there is no real account and no real subprocess for a
	// fake to honestly run, so "assume it would work" is the only
	// meaningful default; a test can set traversableErr/
	// traversableNotTraversable to model the refusal explicitly instead.
	parentTraversable func(dataDir string, uid, gid int) error
	// ancestorsAreSafe reports whether every ancestor of a CUSTOM
	// --data-dir, up to the filesystem root, is exclusively controlled
	// by root — not owned by root, writable by group/other, or itself a
	// symbolic link, means refuse (IAMT-308 round 10, review finding
	// F-308-8): round 9's reachability re-check only shrinks the window
	// between checking a path and using it again; this instead removes
	// the threat the window exists for, since a party who controls no
	// ancestor cannot swap, rename or symlink one out from under install
	// regardless of how long any window is.
	//
	// A test's fake OS seam answers nil (safe) unconditionally by
	// default: there is no real filesystem tree for a fake to honestly
	// inspect, and every existing CLI-level darwin test installs into a
	// --data-dir under t.TempDir(), which a non-root test process can
	// never make root-owned — the exact same "must not fire under a fake
	// seam" lesson round 6 already learned for parentTraversable. A test
	// can model the refusal explicitly instead.
	ancestorsAreSafe func(dataDir string) error
	// leafIsSafe reports whether dataDir ITSELF — not just its ancestors
	// — is safe for a CUSTOM --data-dir to proceed into (IAMT-308 round
	// 11, review finding F-308-9): ancestorsAreSafe's walk starts at
	// dataDir's PARENT and never looks at dataDir itself, so a symlink
	// planted at the leaf before this call was never caught by anything.
	// serviceUID is the account preflightGatewayReachability already
	// resolved: a repeat install's own dataDir was chowned to that
	// account by a PREVIOUS run's setupLaunchdDaemon, so root ownership
	// alone cannot be the accept condition here the way it is for every
	// ancestor above it — accept root OR that one specific account, and
	// nothing else. When dataDir does not exist yet, this creates it
	// itself, as root, right here — closing the gap between this check
	// and the os.MkdirAll that would otherwise run later, still unaware
	// anything had looked at the path in between.
	//
	// A test's fake OS seam answers nil (safe) unconditionally by
	// default, the same "must not fire under a fake seam" reasoning as
	// ancestorsAreSafe and parentTraversable above: every existing
	// CLI-level darwin test installs into a --data-dir under
	// t.TempDir(), owned by whatever unprivileged account runs the test,
	// not root and not any resolved serviceUID. A test can model the
	// refusal explicitly instead.
	leafIsSafe func(dataDir string, serviceUID int) error
}

// pickFreeSystemUID is the pure choice of a free system UID (SPEC
// §3.5.1: "a free UID < 500"): the first unoccupied one in
// [darwinSystemUIDMin, darwinSystemUIDMax]. A false second result
// means no free UIDs are left: there is nobody to create the user as.
func pickFreeSystemUID(taken map[int]bool) (int, bool) {
	for uid := darwinSystemUIDMin; uid <= darwinSystemUIDMax; uid++ {
		if !taken[uid] {
			return uid, true
		}
	}
	return 0, false
}

// dsclUserReadArgs is how the seam asks DirectoryService about an
// already existing user.
func dsclUserReadArgs(name string) []string {
	return []string{".", "-read", "/Users/" + name, "UniqueID"}
}

// dsclListUsersArgs is how the seam gets the list of taken UIDs.
func dsclListUsersArgs() []string {
	return []string{".", "-list", "/Users", "UniqueID"}
}

// dsclCreateUserCalls is the set of dscl calls that create the service
// user: UID, group, shell /usr/bin/false, RealName, home /var/empty and
// IsHidden 1 ("hidden", SPEC §3.5.1).
func dsclCreateUserCalls(spec darwinServiceUserSpec) [][]string {
	base := "/Users/" + spec.Name
	calls := [][]string{
		{".", "-create", base, "UniqueID", strconv.Itoa(spec.UID)},
		{".", "-create", base, "PrimaryGroupID", strconv.Itoa(spec.GID)},
		{".", "-create", base, "UserShell", spec.Shell},
		{".", "-create", base, "RealName", spec.Gecos},
		{".", "-create", base, "NFSHomeDirectory", spec.Home},
	}
	if spec.Hidden {
		calls = append(calls, []string{".", "-create", base, "IsHidden", "1"})
	}
	return calls
}

// parseDSCLUniqueID parses the output of "dscl . -read /Users/x
// UniqueID" (a line of the form "UniqueID: 201"). A false second result
// means the output has no UID (a user without a UniqueID counts as
// absent).
func parseDSCLUniqueID(output string) (int, bool) {
	for _, line := range strings.Split(output, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "UniqueID:")
		if !ok {
			continue
		}
		uid, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil {
			return 0, false
		}
		return uid, true
	}
	return 0, false
}

// parseDSCLUIDList parses the output of "dscl . -list /Users UniqueID"
// (lines of the form "_iamtunnel   201"): the set of taken UIDs. Lines
// without a trailing number are skipped.
func parseDSCLUIDList(output string) map[int]bool {
	taken := map[int]bool{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		uid, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			continue
		}
		taken[uid] = true
	}
	return taken
}

// dsclSaysNoUser distinguishes "no such user" (the normal case for a
// first install) from a genuine dscl error.
func dsclSaysNoUser(output string) bool {
	s := strings.ToLower(output)
	return strings.Contains(s, "edsrecordnotfound") ||
		strings.Contains(s, "edsunknownnodename") ||
		strings.Contains(s, "no such user")
}

// launchctlSaysNotLoaded distinguishes "no daemon" (the normal case)
// from a genuine launchctl error: print/bootout answer "Could not find
// service" or "no such process".
func launchctlSaysNotLoaded(output string) bool {
	s := strings.ToLower(output)
	return strings.Contains(s, "could not find service") ||
		strings.Contains(s, "no such process")
}

func launchctlBootstrapArgs(plistPath string) []string {
	return []string{"bootstrap", "system", plistPath}
}

func launchctlBootoutArgs(label string) []string {
	return []string{"bootout", "system/" + label}
}

func launchctlPrintArgs(label string) []string {
	return []string{"print", "system/" + label}
}

// launchdPlist is the whole content of one LaunchDaemon plist, as data.
// The gateway's plist (SPEC §3.5.1) and the machine's (SPEC §3.2.1,
// IAMT-263) differ in exactly three things — the Label, whether a
// UserName key is present at all, and what KeepAlive means — so the
// document renderer is shared and each role supplies its own values.
type launchdPlist struct {
	// Label is the launchd job's label: it doubles as the launchctl
	// print/bootout argument and the name the operator calls the
	// service by.
	Label string
	// UserName, when not empty, becomes the UserName key: the job runs
	// under that account. Empty — there is no key at all, and launchd
	// runs the job as root: exactly what the machine role needs (SPEC
	// §3.2.1: the door is written into somebody else's home directory,
	// so it cannot be an unprivileged service).
	UserName string
	// KeepAliveOnCleanExit: true renders <KeepAlive><true/> — the job
	// is restarted whatever the exit was (the gateway must stay
	// reachable). false renders
	// <KeepAlive><dict><key>SuccessfulExit</key><false/>…: launchd
	// restarts the job only after an UNSUCCESSFUL exit — the macOS form
	// of systemd's Restart=on-failure, which the machine role needs so
	// that a clean `server stop` is not undone by a restart
	// (SPEC §3.2.1).
	KeepAliveOnCleanExit bool
	// ExePath and Args together become ProgramArguments.
	ExePath string
	Args    []string
	// LogPath is where launchd points StandardOutPath and
	// StandardErrorPath.
	LogPath string
}

// renderLaunchdPlistDoc is the pure LaunchDaemon-plist render: Label,
// RunAtLoad, KeepAlive in the chosen form, an optional UserName,
// ProgramArguments (<ExePath> + Args) and both output paths. EVERY
// string value goes through xml.EscapeText — values in the plist are
// XML-escaped (SPEC §3.5.1), whatever the binary path, data directory
// path or public host is.
func renderLaunchdPlistDoc(p launchdPlist) (string, error) {
	esc := func(s string) (string, error) {
		var b strings.Builder
		if err := xml.EscapeText(&b, []byte(s)); err != nil {
			return "", err
		}
		return b.String(), nil
	}
	label, err := esc(p.Label)
	if err != nil {
		return "", err
	}
	user := ""
	if p.UserName != "" {
		if user, err = esc(p.UserName); err != nil {
			return "", err
		}
	}
	exe, err := esc(p.ExePath)
	if err != nil {
		return "", err
	}
	progArgs := make([]string, 0, len(p.Args)+1)
	progArgs = append(progArgs, exe)
	for _, a := range p.Args {
		e, err := esc(a)
		if err != nil {
			return "", err
		}
		progArgs = append(progArgs, e)
	}
	logPath, err := esc(p.LogPath)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n<dict>\n")
	b.WriteString("  <key>Label</key>\n  <string>" + label + "</string>\n")
	b.WriteString("  <key>RunAtLoad</key>\n  <true/>\n")
	b.WriteString("  <key>KeepAlive</key>\n")
	if p.KeepAliveOnCleanExit {
		b.WriteString("  <true/>\n")
	} else {
		b.WriteString("  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n")
	}
	if user != "" {
		b.WriteString("  <key>UserName</key>\n  <string>" + user + "</string>\n")
	}
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	for _, a := range progArgs {
		b.WriteString("    <string>" + a + "</string>\n")
	}
	b.WriteString("  </array>\n")
	b.WriteString("  <key>StandardOutPath</key>\n  <string>" + logPath + "</string>\n")
	b.WriteString("  <key>StandardErrorPath</key>\n  <string>" + logPath + "</string>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String(), nil
}

// renderLaunchdPlist renders the GATEWAY's plist (SPEC §3.5.1):
// RunAtLoad, KeepAlive (always), UserName _iamtunnel, ProgramArguments
// ("<binary> gateway run --data-dir … --port … --public-host …"),
// output to /Library/Logs/iamtunnel/gateway.log. The signature and the
// output bytes are exactly what they were before IAMT-263: the machine
// role arrived with its own set of values for the shared
// renderLaunchdPlistDoc, not the other way round.
func renderLaunchdPlist(exePath string, args []string) (string, error) {
	return renderLaunchdPlistDoc(launchdPlist{
		Label:                darwinPlistLabel,
		UserName:             darwinServiceUser,
		KeepAliveOnCleanExit: true,
		ExePath:              exePath,
		Args:                 args,
		LogPath:              darwinLogPath,
	})
}

// launchdBootstrapTail is the tail shared by both install halves on
// macOS: ask launchctl whether the job is loaded, unload it if it is (a
// repeat install must pick up the new plist rather than keep running
// the old daemon), and load it again from the plist. role is the
// command the operator typed ("gateway" / "server"): substituting into
// the same formats keeps the gateway half's texts verbatim.
func launchdBootstrapTail(setup darwinLaunchdSetup, role, label, plistPath, logPath string) error {
	loaded, err := setup.serviceLoaded(label)
	if err != nil {
		return envErrf("%s install: ask launchctl whether %s is loaded: %v", role, label, err)
	}
	if loaded {
		if _, err := setup.bootout(label); err != nil {
			return envErrf("%s install: launchctl bootout the previously loaded %s daemon: %v — run \"sudo launchctl bootout system/%s\" by hand and repeat the install.", role, label, err, label)
		}
	}
	// IAMT-308 round 4: bootstrap of a label launchd still considers
	// loaded answers exit status 5, "Bootstrap failed: 5: Input/output
	// error" — confirmed by hand against a genuinely running daemon.
	// That is "already bootstrapped" (the goal state), not a real I/O
	// failure, but distinguishing the two by pattern-matching launchctl's
	// ambiguous error text would be guessing. bootout above already
	// waits for the label to clear (closing the common race), so this
	// error is deliberately NOT returned yet: bootstrapErr is carried
	// through to the running check below, which verifies the ACTUAL
	// state instead of trusting either the error or its absence.
	bootstrapErr := setup.bootstrap(plistPath)
	// IAMT-308/310 family: "launchctl bootstrap" returns success the
	// instant launchd accepts the job, before the daemon has had a
	// chance to hit its own fatal error and crash-loop under KeepAlive —
	// confirm launchctl itself reports the job running before install
	// reports success over it. serviceRunning itself is the one that
	// waits/retries (see darwinLaunchd's production implementation):
	// this is a SINGLE call to the seam, so a recorder-based test sees
	// exactly one step no matter how many times the real implementation
	// polled launchctl underneath (IAMT-258 round 2 — a retry loop
	// wrapped around the seam call turns one step into several in every
	// test that pins the exact call sequence).
	running, lerr := setup.serviceRunning(label)
	if !running {
		// The job never came up: this is a genuine failure, not a stale
		// "already bootstrapped" — surface it and never return early
		// with the machine worse off than it started (IAMT-308's own
		// contract). Name the step that actually failed when there was
		// one: bootstrap itself failing outranks a generic "not
		// reporting running", because it says exactly which OS call to
		// retry by hand.
		if bootstrapErr != nil {
			return envErrf("%s install: launchctl bootstrap system %s: %v — run \"sudo launchctl bootstrap system %s\" by hand to finish.", role, plistPath, bootstrapErr, plistPath)
		}
		if lerr != nil {
			return envErrf("%s install: %s was bootstrapped but checking whether launchd is running it failed: %v — check \"sudo launchctl print system/%s\" and %s, fix, and repeat the install (it updates in place and restarts).", role, label, lerr, label, logPath)
		}
		return envErrf("%s install: %s was bootstrapped but launchctl does not report it running — check \"sudo launchctl print system/%s\" and %s, fix the cause, and repeat the install (it updates in place and restarts).", role, label, label, logPath)
	}
	// running is true here even when bootstrapErr is non-nil: the job is
	// actually up, so a stale "already bootstrapped" error from bootstrap
	// is not a failure to report — the goal state is reached.
	return nil
}

// launchdTeardownTail is the tail shared by both uninstall halves on
// macOS (SPEC §3.5.1 for the gateway, §3.2.1 for the machine): root →
// no plist — "nothing to do" → unload the loaded job → remove the
// plist. Returns false when there is no plist on disk: removing a
// service that is already gone is "do nothing", not an error. specRef
// names the SPEC paragraph the "needs root" refusal refers to: §3.5.1
// for the gateway, §3.2.1 for the machine, and swapping one for the
// other would be a lie in the text the operator reads.
func launchdTeardownTail(setup darwinLaunchdSetup, role, specRef, label, plistPath string) (bool, error) {
	root, err := setup.currentUserIsRoot()
	if err != nil {
		return false, envErrf("%s uninstall: check the effective UID: %v", role, err)
	}
	if !root {
		return false, envErrf("%s uninstall: removing the macOS service half (LaunchDaemon — SPEC %s) needs root — repeat the uninstall with sudo.", role, specRef)
	}
	exists, err := setup.plistExists(plistPath)
	if err != nil {
		return false, envErrf("%s uninstall: look up the %s plist: %v", role, plistPath, err)
	}
	if !exists {
		return false, nil
	}
	loaded, err := setup.serviceLoaded(label)
	if err != nil {
		return false, envErrf("%s uninstall: ask launchctl whether %s is loaded: %v", role, label, err)
	}
	if loaded {
		if _, err := setup.bootout(label); err != nil {
			return false, envErrf("%s uninstall: launchctl bootout system/%s: %v — run \"sudo launchctl bootout system/%s\" by hand and repeat the uninstall.", role, label, err, label)
		}
	}
	if err := setup.removePlist(plistPath); err != nil {
		return false, envErrf("%s uninstall: remove the plist %s: %v — remove it by hand (\"sudo rm %s\") and repeat the uninstall.", role, plistPath, err, plistPath)
	}
	return true, nil
}

// darwinFirewallHint is the ready-made port-opening command through
// Application Firewall that install prints for the operator (SPEC
// §3.5.1: the hint is about Application Firewall; pf is not touched).
// install itself never touches the firewall on any OS.
func darwinFirewallHint(exePath string) string {
	return "sudo " + darwinFirewallTool + ` --add "` + exePath + `" --unblockapp "` + exePath + `"`
}

// resolveGatewayServiceAccount finds the _iamtunnel dscl account,
// creating it (a free system UID < 500, /usr/bin/false, hidden) if it
// does not exist yet. Shared by preflightGatewayReachability (which must
// run before setupLaunchdDaemon, IAMT-308 round 7) and setupLaunchdDaemon
// itself, so both go through the exact same lookupUser →
// systemUIDsTaken → createUser seam calls in the same order; factoring
// this out does not change setupLaunchdDaemon's own sequence contract
// (iamt259_launchd_test.go), only the duplication between the two call
// sites.
func resolveGatewayServiceAccount(setup darwinLaunchdSetup) (uid int, err error) {
	uid, exists, err := setup.lookupUser(darwinServiceUser)
	if err != nil {
		return 0, envErrf("gateway install: look up the %s service user: %v", darwinServiceUser, err)
	}
	if exists {
		return uid, nil
	}
	taken, err := setup.systemUIDsTaken()
	if err != nil {
		return 0, envErrf("gateway install: list system users to pick a free UID: %v", err)
	}
	free, ok := pickFreeSystemUID(taken)
	if !ok {
		return 0, envErrf("gateway install: no free system UID below %d is left for the %s service user — free one by hand and repeat the install.", darwinSystemUIDMax+1, darwinServiceUser)
	}
	if err := setup.createUser(darwinServiceUserSpec{
		Name:   darwinServiceUser,
		UID:    free,
		GID:    darwinServiceGID,
		Shell:  darwinServiceShell,
		Gecos:  darwinServiceGecos,
		Home:   darwinServiceHome,
		Hidden: true,
	}); err != nil {
		return 0, envErrf("gateway install: create the %s service user (dscl): %v — create it by hand (a hidden user with a free UID below %d, shell %s) and repeat the install.", darwinServiceUser, err, darwinSystemUIDMax+1, darwinServiceShell)
	}
	return free, nil
}

// preflightGatewayReachability (IAMT-308 rounds 7-8, review finding
// F-308-4): resolves the real _iamtunnel account — creating it if it
// does not exist yet — and checks whether it can reach dataDir's parent,
// BEFORE runGatewayInstall creates a single secret artifact (host key,
// bootstrap token, state.json) or prints the bootstrap reference. A live
// Mac showed exactly the failure mode this guards against: for an
// unreachable parent, install had already created all of that and
// printed the reference, and only then did the (round 6) traversability
// check refuse — leaving a working, printable secret behind for an
// installation that had already failed.
//
// Round 8: this is now the ONLY place account resolution happens.
// Round 7 had setupLaunchdDaemon resolve (and, when missing, create) the
// account a second time, reasoning that dscl's own idempotency made the
// repeat harmless — but a live Mac's IAMT-177 seam recorder showed
// createUser called twice, which is not harmless: IAMT-177's contract is
// literally "the host touches only its own seam, in this exact shape".
// preflightGatewayReachability now returns the resolved uid, and
// setupLaunchdDaemon takes it as a parameter instead of resolving its
// own — one dscl lookup (and, at most, one create) per install, matching
// what the seam recorder actually sees.
func preflightGatewayReachability(setup darwinLaunchdSetup, dataDir string) (uid int, err error) {
	root, err := setup.currentUserIsRoot()
	if err != nil {
		return 0, envErrf("gateway install: check the effective UID: %v", err)
	}
	if !root {
		return 0, envErrf("gateway install: the macOS service half (LaunchDaemon — SPEC §3.5.1) writes %s and needs root — repeat the install with sudo.", darwinPlistPath)
	}
	uid, err = resolveGatewayServiceAccount(setup)
	if err != nil {
		return 0, err
	}
	if err := verifyGatewayReachable(setup, dataDir, uid); err != nil {
		return 0, err
	}
	return uid, nil
}

// verifyGatewayReachable calls the parentTraversable seam and wraps a
// failure into the operator-facing refusal text, distinguishing
// errProbeCouldNotRun (the check itself did not run — no chmod hint,
// that would mislead) from a genuine denial (the chmod hint). Shared by
// preflightGatewayReachability (the early check, before any secret
// exists) and runGatewayInstall's round-9 re-check immediately before
// the first secret is written (review finding F-308-6) — both name the
// exact same failure the exact same way, with the exact same uid, so a
// test cannot tell which call site produced a given refusal from its
// text alone (nor does it need to: both are the identical claim, checked
// at two different moments).
func verifyGatewayReachable(setup darwinLaunchdSetup, dataDir string, uid int) error {
	if err := setup.parentTraversable(dataDir, uid, darwinServiceGID); err != nil {
		parent := filepath.Dir(dataDir)
		// IAMT-308 round 8: "could not check" and "checked, and it's
		// denied" are different failures and need different words — a
		// chmod hint is useless (and misleading) when the probe itself
		// never ran, and treating "could not check" as a quiet success
		// would reopen exactly the gap the review found (F-308-3).
		if errors.Is(err, errProbeCouldNotRun) {
			return envErrf("gateway install: could not verify whether %s can reach %s: %v — the reachability check itself did not run (this is not a permission verdict); investigate and repeat the install once it can — proceeding without checking is exactly the gap this step exists to close.", darwinServiceUser, dataDir, err)
		}
		return envErrf("gateway install: %s cannot reach %s: %v — prepare the path by hand (every ancestor directory from %s up to the root must let %s traverse it, e.g. \"sudo chmod o+x %s\") and repeat the install.", darwinServiceUser, dataDir, err, parent, darwinServiceUser, parent)
	}
	return nil
}

// checkCustomDataDirAncestorsAreSafe wraps the ancestorsAreSafe seam
// step into the operator-facing refusal text (IAMT-308 round 10, review
// finding F-308-8). Callers must only invoke this for a CUSTOM
// --data-dir, never the standard macOS path, which this command already
// owns end to end (prepareGatewayParentDir, rounds 5-6) — the seam
// implementation itself has no way to tell the two apart, so that
// distinction is the caller's (runGatewayInstall's) job.
func checkCustomDataDirAncestorsAreSafe(setup darwinLaunchdSetup, dataDir string) error {
	if err := setup.ancestorsAreSafe(dataDir); err != nil {
		return envErrf("gateway install: %v", err)
	}
	return nil
}

// checkCustomDataDirLeafIsSafe wraps the leafIsSafe seam step into the
// operator-facing refusal text (IAMT-308 round 11, review finding
// F-308-9). Callers must only invoke this for a CUSTOM --data-dir, after
// preflightGatewayReachability has already resolved serviceUID — the
// same scoping rule as checkCustomDataDirAncestorsAreSafe, for the same
// reason: the standard macOS path is a tree this command already owns
// end to end.
func checkCustomDataDirLeafIsSafe(setup darwinLaunchdSetup, dataDir string, serviceUID int) error {
	if err := setup.leafIsSafe(dataDir, serviceUID); err != nil {
		return envErrf("gateway install: %v", err)
	}
	return nil
}

// setupLaunchdDaemon is the macOS install sequence (SPEC §3.5.1), for
// the part that runs AFTER preflightGatewayReachability has
// already confirmed root, resolved (or created) the _iamtunnel account
// and checked reachability (IAMT-308 round 8 — see that function's own
// comment for why account resolution must not happen twice): log
// directory → hand the data directory and the log directory to their
// owner _iamtunnel → write the plist (0644, root:wheel) → restart the
// already-loaded daemon (a repeat install must pick up the new
// --port/--public-host) → launchctl bootstrap system.
//
// uid is the account preflightGatewayReachability already resolved;
// callers (runGatewayInstall, and every seam-level test below) MUST have
// run that check first — this function trusts uid without re-deriving
// or re-verifying it.
func setupLaunchdDaemon(setup darwinLaunchdSetup, exePath string, args []string, dataDir string, uid int) error {
	if err := setup.makeLogDir(darwinLogDir); err != nil {
		return envErrf("gateway install: create the log directory %s: %v — create it by hand (\"sudo mkdir -p %s\") and repeat the install.", darwinLogDir, err, darwinLogDir)
	}
	if err := setup.chownDir(dataDir, uid, darwinServiceGID); err != nil {
		return envErrf("gateway install: hand the data directory %s to the %s service user: %v — chown it by hand (\"sudo chown -R %s:%s %s\") and repeat the install.", dataDir, darwinServiceUser, err, darwinServiceUser, darwinServiceGroup, dataDir)
	}
	if err := setup.chownDir(darwinLogDir, uid, darwinServiceGID); err != nil {
		return envErrf("gateway install: hand the log directory %s to the %s service user: %v — chown it by hand (\"sudo chown -R %s:%s %s\") and repeat the install.", darwinLogDir, darwinServiceUser, err, darwinServiceUser, darwinServiceGroup, darwinLogDir)
	}
	plist, err := renderLaunchdPlist(exePath, args)
	if err != nil {
		return envErrf("gateway install: render the LaunchDaemon plist: %v", err)
	}
	if err := setup.writePlist(darwinPlistPath, []byte(plist), 0o644, 0, 0); err != nil {
		return envErrf("gateway install: write the LaunchDaemon plist %s (0644, root:wheel): %v — write it by hand and run \"sudo launchctl bootstrap system %s\".", darwinPlistPath, err, darwinPlistPath)
	}
	return launchdBootstrapTail(setup, "gateway", darwinPlistLabel, darwinPlistPath, darwinLogPath)
}

// teardownLaunchdDaemon is the macOS uninstall sequence (SPEC §3.5.1):
// root → if the plist is not installed, "do nothing" → unload the
// loaded daemon (launchctl bootout system/<label>) → remove the plist.
// The service user and the data directory stay: a repeat install
// reuses them, and removing the data is the operator's decision.
func teardownLaunchdDaemon(setup darwinLaunchdSetup) (bool, error) {
	return launchdTeardownTail(setup, "gateway", "§3.5.1", darwinPlistLabel, darwinPlistPath)
}
