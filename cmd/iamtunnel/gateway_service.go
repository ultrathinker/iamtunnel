package main

// gateway_service.go — the Windows half of the gateway install (SPEC
// §3.5.1): the service seam types, the pure assembly of the service
// specification and the install/uninstall SEQUENCES. The file is
// platform-neutral on purpose: the seam fields are ordinary functions
// over strings, so the sequences are verified with a recording fake on
// any host OS (like systemdSetup on the Linux half). The production
// implementations live in gateway_service_windows.go (SCM) and
// gateway_service_other.go (stubs).

import (
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// errServiceAlreadyRunning is the platform-neutral sentinel install's
// sequence recognizes as "the goal state is already reached", not a
// failure (IAMT-312 round 3): a repeat install of an already-installed,
// already-running service called startService, and Windows answered
// ERROR_SERVICE_ALREADY_RUNNING (1056) — starting a service that is
// already running is not an error, it is the outcome install actually
// wants. The production seam (gateway_service_windows.go) translates the
// real windows.ERROR_SERVICE_ALREADY_RUNNING into this sentinel so
// setupGatewayService and its tests never need to import
// golang.org/x/sys/windows — that package does not build outside
// GOOS=windows, and this file (like the rest of the Windows-service seam
// contract) is deliberately platform-neutral.
var errServiceAlreadyRunning = errors.New("service is already running")

const (
	// gatewayServiceName is the SCM service name SPEC §3.5.1 assigns to
	// the Windows gateway.
	gatewayServiceName = "iamtunnel-gateway"
	// gatewayServiceAccountName is the virtual account the SCM derives
	// from the service name under SERVICE_SID_TYPE_UNRESTRICTED. SPEC
	// §3.5.1 requires running the gateway under it, not under
	// LocalSystem.
	gatewayServiceAccountName = `NT SERVICE\` + gatewayServiceName
	// gatewayServiceDisplayName and gatewayServiceDescription are what
	// the operator sees in services.msc; the firewall hint text from
	// SPEC §3.5.1 uses the same "iamtunnel gateway".
	gatewayServiceDisplayName = "iamtunnel gateway"
	gatewayServiceDescription = "iamtunnel bastion gateway (SPEC §3.5.1)"
)

// gatewayServiceSpec is everything install tells the service manager
// about the gateway service (SPEC §3.5.1). A platform-neutral struct on
// purpose: the test pins every value (name, account, delayed
// auto-start, 3×10s recovery) without access to the SCM types, and the
// production implementation translates it into mgr.Config in one piece.
type gatewayServiceSpec struct {
	Name        string   // iamtunnel-gateway
	DisplayName string   // iamtunnel gateway
	Description string   // the text for services.msc
	Account     string   // NT SERVICE\iamtunnel-gateway (not LocalSystem)
	ExePath     string   // the same binary that ran install
	Args        []string // unescaped: escaping is the production implementation's job
	// DelayedAutoStart is the delayed auto-start (§3.5.1): the service
	// starts after the other auto-start entries so it does not slow the
	// machine's boot.
	DelayedAutoStart bool
	// Recovery is what happens on service failure (§3.5.1: "restart
	// after 10s, three times"). Each element is a restart delayed by
	// RestartAfter.
	Recovery []gatewayServiceRecovery
}

// gatewayServiceRecovery is one recovery action. There is a single
// form (a delayed restart) because it is the only one SPEC §3.5.1
// assigns.
type gatewayServiceRecovery struct {
	RestartAfter time.Duration
}

// gatewayServiceArguments is the SERVICE's command-line arguments
// (§3.5.1): "gateway run --data-dir "<dir>" --port <N> --public-host
// <host>". Escaping each argument is the production seam
// implementation's duty (mgr.CreateService escapes by itself;
// changeService assembles the string through
// gatewayServiceBinaryPathName); the test pins both the slice and the
// escaping.
func gatewayServiceArguments(dataDir string, port int, publicHost string) []string {
	return []string{
		"gateway", "run",
		"--data-dir", dataDir,
		"--port", strconv.Itoa(port),
		"--public-host", publicHost,
	}
}

// gatewayServiceSpecFor is the pure assembly of the service
// specification from install's parameters. Everything §3.5.1 assigns to
// the service is visible here at a glance: the name, the virtual
// account, the delayed auto-start, three restarts 10 seconds apart.
func gatewayServiceSpecFor(exePath, dataDir string, port int, publicHost string) gatewayServiceSpec {
	return gatewayServiceSpec{
		Name:             gatewayServiceName,
		DisplayName:      gatewayServiceDisplayName,
		Description:      gatewayServiceDescription,
		Account:          gatewayServiceAccountName,
		ExePath:          exePath,
		Args:             gatewayServiceArguments(dataDir, port, publicHost),
		DelayedAutoStart: true,
		Recovery: []gatewayServiceRecovery{
			{RestartAfter: 10 * time.Second},
			{RestartAfter: 10 * time.Second},
			{RestartAfter: 10 * time.Second},
		},
	}
}

// gatewayFirewallHint is the ready-made port-opening command install
// prints for the operator (SPEC §3.5.1). install itself never touches
// the firewall on any OS — it only prints the command.
func gatewayFirewallHint(port int) string {
	return `New-NetFirewallRule -DisplayName "iamtunnel gateway" -Direction Inbound -Protocol TCP -LocalPort ` +
		strconv.Itoa(port) + " -Action Allow"
}

// windowsPathDir returns the parent of a Windows path as a plain string
// operation — filepath.Dir would split on the HOST OS's separator, which
// makes a Linux/darwin test host answer wrong for a Windows path (the
// same reasoning gatewayUnitFile/machineUnitFile already document for
// Linux paths built on any host).
func windowsPathDir(p string) string {
	p = strings.TrimRight(p, `\`)
	i := strings.LastIndex(p, `\`)
	if i < 0 {
		return ""
	}
	return p[:i]
}

// isAbsWinPath reports whether p is an absolute Windows path (drive
// letter or UNC) — a local copy of internal/config's isAbsWin, which is
// unexported in its own package.
func isAbsWinPath(p string) bool {
	if len(p) >= 3 && p[1] == ':' && p[2] == '\\' {
		c := p[0]
		return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
	}
	return len(p) >= 2 && p[0] == '\\' && p[1] == '\\'
}

// serviceReachableExeDir is where this program lives on Windows.
//
// ONE PLACE, and it is C:\iamtunnel. The maintainer put it plainly on
// 22.09.2026, after this screen had sent them to a third one: the
// agreement is that on Windows the program always lives in a folder on
// the C drive with the exe inside it, so there is no reason to scatter
// it all over the disk.
//
// They are right, and the detour was unnecessary in the first place. The
// only thing the install actually refuses is an executable inside
// C:\Users, which a service account cannot read
// (exeUnreachableByServiceAccount, just above). C:\iamtunnel is not
// inside C:\Users and passes that check untouched; the older refusal
// text suggested Program Files simply because somebody had to name
// somewhere, and this screen turned that suggestion into a button. A
// program with three homes is a program whose version nobody can state,
// which is exactly the confusion that cost an afternoon today.
//
// Empty on the platforms where the question does not arise.
func serviceReachableExeDir(env map[string]string) string {
	if runtime.GOOS != "windows" {
		return ""
	}
	// The system drive, not a hardcoded C: -- a Windows that boots from
	// D: is unusual and not wrong.
	root := env["SystemDrive"]
	if root == "" {
		root = "C:"
	}
	return filepath.Join(root+`\`, "iamtunnel")
}

// exeUnreachableByServiceAccount reports whether exePath sits under the
// user-profiles root — the parent of %USERPROFILE% — IAMT-312, RUNBOOK
// §1.5: a per-profile ACL denies every other account by default,
// including a service's own virtual account, so a service pointed at a
// binary there is created and its start request accepted by the SCM and
// only THEN refuses to run at all ("Access is denied",
// ERROR_ACCESS_DENIED). install refuses up front here instead of
// leaving a service behind that can never start.
//
// A missing or relative %USERPROFILE% answers false rather than
// guessing a default (e.g. C:\Users): a real elevated console always
// has one, so its absence means this check has nothing trustworthy to
// compare against, not that the binary is unreachable.
func exeUnreachableByServiceAccount(exePath string, env map[string]string) bool {
	up := env["USERPROFILE"]
	if !isAbsWinPath(up) {
		return false
	}
	root := windowsPathDir(up)
	if root == "" {
		return false
	}
	root = strings.ToLower(strings.TrimRight(root, `\`))
	p := strings.ToLower(exePath)
	return p == root || strings.HasPrefix(p, root+`\`)
}

// windowsServiceSetup is the Windows half's OS-integration seam for
// install and uninstall (SPEC §3.5.1), built like systemdSetup on the
// Linux half: the production path plugs in the real SCM calls, the
// tests use a recording fake, and no test binary ever touches the
// service database. Deliberately unexported: this is not a production
// switch, it is the single place where gateway install/uninstall
// touches the service manager and the data directory's ACL.
type windowsServiceSetup struct {
	// serviceExists reports whether the service is already installed
	// (uninstall and a repeat install rely on this: a repeat install is
	// an in-place update, not a failure; a missing service at uninstall
	// is "nothing to do", not an error).
	serviceExists func(name string) (bool, error)
	// createService installs a new service from the specification (the
	// auto-start/account/SID-type configuration and the recovery
	// actions live inside the production implementation; the seam
	// receives the whole specification).
	createService func(spec gatewayServiceSpec) error
	// changeService brings an ALREADY-installed service to the same
	// shape createService produces (a repeat install is an idempotent
	// update, SPEC §3.5).
	changeService func(spec gatewayServiceSpec) error
	// startService starts the service by name.
	startService func(name string) error
	// serviceRunning reports whether the service is running RIGHT NOW —
	// one snapshot of the state, no waiting (uninstall: there is
	// nothing to wait for there, the service either already runs or it
	// does not).
	serviceRunning func(name string) (bool, error)
	// waitRunning is the install half of the same question, but with
	// waiting: "start" answers success as soon as the SCM has ACCEPTED
	// the start request, not once the process has settled (IAMT-312).
	// Waiting and re-polling are the PRODUCTION implementation's job
	// (waitForLiveness inside it); the seam itself is one call, so a
	// test on the recording fake sees exactly one step, no matter how
	// often the SCM is polled inside (IAMT-258, round 2: a retry loop
	// around the seam call turned one step into five in every test that
	// compares the exact sequence). A separate field from
	// serviceRunning: uninstall must not be handed a wait it does not
	// need, just because install needed it.
	waitRunning func(name string) (bool, error)
	// stopService stops the running service (uninstall); the stop goes
	// through the same graceful drain as SIGTERM.
	stopService func(name string) error
	// deleteService removes the service's registration from the SCM
	// database (uninstall).
	deleteService func(name string) error
	// hardenDir applies the §3.5.1 ACL to the data directory (IAMT-257:
	// inheritance off, full access for SYSTEM, Administrators and the
	// service account). It sits in the seam so the sequence tests see
	// the call and its position relative to createService, while test
	// runs of install do not lock the test user out of their own
	// t.TempDir().
	// replaceACL is the IAMT-315 opt-in: when true, the hardening wipes
	// the ACCESS_DENIED ACEs it meets (printing the list into report);
	// when false, it refuses. report is the caller-supplied destination
	// for the dropped-ACE printout on the --replace-acl path
	// (runGatewayInstall passes s.out so the report goes to the CLI's
	// captured stdout alongside the rest of the install narrative,
	// NOT to os.Stderr — the no-kill-switch rule forbids an exported
	// mutable writer; threaded explicitly down the chain instead).
	//
	// R2-CX F-12: the directory stays pinned - open, so that nothing on
	// its path can be renamed away and replaced - until the returned
	// release is called; install calls it after its last write.
	hardenDir func(dir string, replaceACL bool, report io.Writer) (release func(), err error)
	// hardenExeDir grants the service account (and BUILTIN\Users, so a
	// non-admin can still launch the same binary as the desktop client)
	// read+execute on the directory holding the binary the service runs
	// AND on the binary itself (IAMT-312): a live install created and
	// started the SCM service successfully and it still refused to run
	// with "Access is denied", because the service's virtual account
	// had no ACE at all on the binary's directory — being under
	// C:\Program Files is not enough by itself.
	//
	// IAMT-312 round 5: the directory ACL alone is not enough either.
	// (OI)(CI) inheritance only reaches objects CREATED after the ACL is
	// set — an exe that already sits there (the ordinary case: the
	// operator already copied it in) keeps whatever ACL it had before,
	// which may deny the service SID outright. A repeated install could
	// then update the service's ImagePath to that unreadable exe,
	// StartService could report ERROR_SERVICE_ALREADY_RUNNING for the
	// still-live OLD process, and waitRunning would certify success over
	// a config that cannot actually start once that old process ever
	// stops. exePath is hardened directly, independent of directory
	// inheritance and independent of whatever the SCM's running process
	// happens to be at the time. replaceACL is the IAMT-315 opt-in for
	// the binary, with exactly the same semantics as for the data dir.
	// report — see hardenDir (same writer, same rationale).
	hardenExeDir func(exeDir, exePath string, replaceACL bool, report io.Writer) error
}

// setupGatewayService is the Windows half's install sequence (SPEC
// §3.5.1): harden the binary's directory and the data directory →
// create or update the service → start it → confirm the SCM really
// reports RUNNING. Every failure stops the sequence and is named, so
// the operator knows what to fix by hand. A repeat install updates the
// existing service in place — that is the idempotence of §3.5, not a
// second instance of the service.
//
// IAMT-312: a startService returning nil was not proof the service was
// alive — "sc start" answers success as soon as the SCM has ACCEPTED
// the start request, not once the process has settled. Without the
// final check, install could report exit 0 for a service that falls
// over at its first touch of the disk (the same defect family as
// IAMT-308 on macOS and IAMT-310 in the server role: bootstrap/start
// succeeded, exit 0, and the daemon is dead).
//
// IAMT-312 round 3: a repeat install of an already-RUNNING service (the
// ordinary update path — replace the binary and repeat install) called
// startService on the live machine and got ERROR_SERVICE_ALREADY_RUNNING
// (1056) — Windows counts that as a failed start request, although the
// goal ("the service runs") is already reached. changeService above had
// already updated the configuration (ImagePath, account, recovery);
// failing install because there is nothing left to restart would break
// the help's promise of "a repeated install... updates in place" and
// the refusal text's own "repeat the install". alreadyRunning tells the
// caller (runGatewayInstall) that no restart happened — the new
// configuration reaches the already-running process only after it is
// restarted, and that is worth saying to the operator plainly rather
// than abandoning the service to "fix it by hand".
//
// replaceACL is the IAMT-315 opt-in: it flows through hardenExeDir and
// hardenDir (both take the one flag). runGatewayInstall's preflight has
// already refused on a foreign DENY ACE on the data dir or the binary
// without creating any secrets; the defence here is a second layer (in
// case the preflight found nothing but the child walk inside hardenDir
// meets a new DENY) and applies under the same contract: a deny error →
// refusedErrf with the --replace-acl hint. report is the caller-supplied
// destination for the
// dropped-ACE printout on the --replace-acl path (runGatewayInstall
// passes s.out; see hardenDir's comment for why this must be
// threaded, not stored in a package-level writer).
func setupGatewayService(setup windowsServiceSetup, spec gatewayServiceSpec, exeDir, dataDir string, replaceACL bool, report io.Writer) (alreadyRunning bool, err error) {
	release, err := hardenGatewayDirs(setup, spec, exeDir, dataDir, replaceACL, report)
	if err != nil {
		return false, err
	}
	defer release()
	return startGatewayService(setup, spec)
}

// hardenGatewayDirs is the first half of setupGatewayService: the
// binary's directory and the data directory get their ACLs. gateway
// install runs it BEFORE it writes the host key, the bootstrap token and
// state.json into the data directory, and before it prints anything
// (R2-CX F-05): the service half used to do it after all of that, so the
// secrets lived under the ACL the parent hands down in between - and
// stayed there when the service half failed.
//
// The data directory comes back pinned (R2-CX F-12): release it after the
// last write into it.
func hardenGatewayDirs(setup windowsServiceSetup, spec gatewayServiceSpec, exeDir, dataDir string, replaceACL bool, report io.Writer) (release func(), err error) {
	if herr := setup.hardenExeDir(exeDir, spec.ExePath, replaceACL, report); herr != nil {
		var fdr *winkeys.ForeignDenyRefusalError
		if errors.As(herr, &fdr) {
			return nil, deniedErrf("gateway install: %v — to overwrite these explicit DENY ACEs and proceed, repeat with --replace-acl.", herr)
		}
		// Finding 19 (IAMT-333): the binary's directory and the binary
		// itself are checked and locked through one handle now, so a
		// linked path (and a foreign owner) reaches this seam too — the
		// same operator decisions the data directory's seam classifies
		// below: denied, not an environment failure.
		var fo *winkeys.ForeignOwnerRefusalError
		var lp *winkeys.LinkedPathRefusalError
		if errors.As(herr, &fo) || errors.As(herr, &lp) {
			return nil, deniedErrf("gateway install: %v — fix the directory or its owner as the refusal says and repeat the install.", herr)
		}
		return nil, envErrf("gateway install: grant %s read+execute on the binary %s: %v — check its security settings by hand (RUNBOOK §1.5) and repeat the install.", spec.Account, spec.ExePath, herr)
	}
	release, herr := setup.hardenDir(dataDir, replaceACL, report)
	if herr != nil {
		// A refusal the seam has already put in words and class - the
		// folders above the data directory (R2 supplementary round) - stays as it is.
		var ce *cliError
		if errors.As(herr, &ce) {
			return nil, ce
		}
		var fdr *winkeys.ForeignDenyRefusalError
		if errors.As(herr, &fdr) {
			return nil, deniedErrf("gateway install: %v — to overwrite these explicit DENY ACEs and proceed, repeat with --replace-acl.", herr)
		}
		var fo *winkeys.ForeignOwnerRefusalError
		var lp *winkeys.LinkedPathRefusalError
		if errors.As(herr, &fo) || errors.As(herr, &lp) {
			return nil, deniedErrf("gateway install: %v.", herr)
		}
		return nil, envErrf("gateway install: apply the data-directory ACL (SPEC §3.5.1: SYSTEM, Administrators and %s, inheritance off) to %s: %v — check the directory's security settings by hand and repeat the install.", spec.Account, dataDir, herr)
	}
	if release == nil {
		release = func() {}
	}
	return release, nil
}

// startGatewayService is the second half of setupGatewayService: the
// service itself - created or brought to the same shape, started, and
// watched until it reports running.
func startGatewayService(setup windowsServiceSetup, spec gatewayServiceSpec) (alreadyRunning bool, err error) {
	exists, eerr := setup.serviceExists(spec.Name)
	if eerr != nil {
		return false, envErrf("gateway install: look up the %s service: %v — is this console elevated (\"Run as administrator\")?", spec.Name, eerr)
	}
	if exists {
		if cerr := setup.changeService(spec); cerr != nil {
			return false, envErrf("gateway install: update the existing %s service: %v — fix it by hand in services.msc and repeat the install (the local files above were already set up).", spec.Name, cerr)
		}
	} else if cerr := setup.createService(spec); cerr != nil {
		return false, envErrf("gateway install: create the %s service (account %s): %v — is this console elevated (\"Run as administrator\")? The service can also be created by hand in services.msc, after which a repeated install updates it in place.", spec.Name, spec.Account, cerr)
	}
	if serr := setup.startService(spec.Name); serr != nil {
		if !errors.Is(serr, errServiceAlreadyRunning) {
			return false, envErrf("gateway install: start the %s service: %v — check services.msc and Event Viewer, fix, and repeat the install (a repeated install updates in place and starts again).", spec.Name, serr)
		}
		alreadyRunning = true
	}
	running, lerr := setup.waitRunning(spec.Name)
	if !running {
		if lerr != nil {
			return false, envErrf("gateway install: the %s service was started but checking its state failed: %v — check services.msc and Event Viewer, fix, and repeat the install (a repeated install updates in place and starts again).", spec.Name, lerr)
		}
		return false, envErrf("gateway install: the %s service was started but is not reporting SERVICE_RUNNING — check services.msc and Event Viewer, fix the cause, and repeat the install (a repeated install updates in place and starts again).", spec.Name)
	}
	return alreadyRunning, nil
}

// teardownGatewayService is the Windows half's uninstall sequence (SPEC
// §3.5.1): stop if running, then delete the service's registration.
// The gateway commands never touch the data directory. Returns false
// when there is no service to begin with — a repeat uninstall is
// "nothing to do", not an error.
func teardownGatewayService(setup windowsServiceSetup, name string) (bool, error) {
	exists, err := setup.serviceExists(name)
	if err != nil {
		return false, envErrf("gateway uninstall: look up the %s service: %v — is this console elevated (\"Run as administrator\")?", name, err)
	}
	if !exists {
		return false, nil
	}
	running, err := setup.serviceRunning(name)
	if err != nil {
		return false, envErrf("gateway uninstall: query the %s service state: %v", name, err)
	}
	if running {
		if serr := setup.stopService(name); serr != nil {
			return false, envErrf("gateway uninstall: stop the %s service: %v — stop it by hand in services.msc and repeat the uninstall.", name, serr)
		}
	}
	if derr := setup.deleteService(name); derr != nil {
		return false, envErrf("gateway uninstall: delete the %s service: %v — remove it by hand in services.msc and repeat the uninstall.", name, derr)
	}
	return true, nil
}

// windowsProgramHome is where this program lives on Windows: one place,
// <system drive>\iamtunnel.
//
// The install's only actual requirement is that the executable is NOT
// inside C:\Users, which a service account cannot read
// (exeUnreachableByServiceAccount). Any directory outside it works, and
// install hardens whichever one it finds (IAMT-312 ACLs the binary's
// own directory). The refusal used to name Program Files because
// somewhere had to be named; naming the project's one convention
// instead means the console, the window and the runbook send a person
// to the same folder.
func windowsProgramHome(env map[string]string) string {
	root := env["SystemDrive"]
	if root == "" {
		root = "C:"
	}
	return root + `\iamtunnel`
}
