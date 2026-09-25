//go:build darwin && !nogui

package main

// runGUI opens the live window (IAMT-157) when iamtunnel is started with
// no arguments on macOS — the same command path as on Windows (IAMT-157)
// and Linux (IAMT-252), now on the third platform (IAMT-262). The wiring
// mirrors gui_linux.go function for function; what differs is exactly what
// differs on the platform:
//
//   - no console to detach and no message box (the same as Linux): a
//     start-up failure is printed to stderr, which is a terminal when the
//     window was started from one and nobody's business when it was not;
//   - the server-start child is spawned with Setsid, as on Linux, so the
//     server outlives the window that started it;
//   - Connect opens a Terminal.app window on "iamtunnel client connect
//     <machine>" instead of refusing as Linux does (IAMT-254) — through
//     internal/macos, which writes a script and hands its path to open(1)
//     rather than interpolating the machine name into AppleScript;
//   - elevation is osascript's "do shell script ... with administrator
//     privileges" (internal/macos.RelaunchAsAdmin), the macOS counterpart
//     of the Windows UAC relaunch and the replacement for the pkexec that
//     macOS does not have.
//
// The actions themselves (enrol, save connection, machines, server
// start/stop, grants) live in gui_actions.go, shared by all three
// windows: none of them touches a platform API, and none of the wire
// protocols is duplicated here.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/elevate"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/macos"
	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// runGUI builds the initial window state from whatever is cheap to read
// at start-up (the saved enrolment, the saved connection, the merged
// settings, one immediate control-status read) and opens the window.
// After that, a background poll keeps the Server half of the snapshot
// current (IAMT-182) while the window's own actions update the rest as
// they complete. The poll sends a ui.LiveUpdate -- the three facts it
// actually dialled for and nothing else -- so there is no second copy of
// the window state here to keep in step. See gui_windows.go, which this
// shares line for line, and internal/ui/live_update.go for what the
// second copy used to cost.
func runGUI(s *streams) int {
	st, serverDir, err := loadConfig(s, "server", cfgOpts{})
	var clientDir string
	if err == nil {
		_, clientDir, err = loadConfig(s, "client", cfgOpts{})
	}
	if err != nil {
		return fail(s, err)
	}

	// So a crash note can be matched to a build (IAMT-367).
	ui.SetCrashVersion(version)
	dirs := config.Dirs{Server: serverDir, Client: clientDir}
	enrolled := false
	machineNameUnknown := false
	if _, statErr := os.Stat(dirs.MachineID()); statErr == nil {
		enrolled = true
	} else if !os.IsNotExist(statErr) {
		// F-GUI-6: a permission-style failure is not the same fact as
		// "not enrolled" — the machine fact must say "unknown", not draw
		// the dash it would otherwise share with a genuinely absent name.
		machineNameUnknown = true
	}
	warnIfSetupTabUnreachable(s, s.env["IAMTUNNEL_GUI_TAB"], enrolled)

	// On macOS "elevated" is euid == 0, the same check as Linux: the
	// notice is a hint about the server actions, never a refusal.
	elevated, _ := elevate.IsElevated()

	snap := ui.Snapshot{
		Settings: ui.SettingsState{
			Version:         version,
			Platform:        runtime.GOOS + "/" + runtime.GOARCH,
			ConfigPath:      resolvedConfigPath(s),
			DataDir:         serverDir,
			Port:            st.Port,
			RetentionDays:   st.RecordingsRetentionDays,
			DiskStopPercent: st.RecordingsDiskStopPercent,
		},
	}
	if enrolled {
		if name, rerr := state.ReadDataFile(dirs.MachineID()); rerr == nil {
			snap.Setup.MachineName = strings.TrimSpace(string(name))
			snap.Setup.Status = "enrolled"
		} else if !os.IsNotExist(rerr) {
			machineNameUnknown = true
		}
	}
	snap.Setup.MachineNameUnknown = machineNameUnknown
	// Which ACCOUNT this registration is bound to. Since 1.4 the
	// registration is the pair (name, account), and on a machine two
	// people share this is the fact that tells each of them the window
	// is driving their own registration and not their colleague's. A
	// record that cannot be read, or one written before 1.4 and so
	// carrying no account, leaves it empty — the screen then draws the
	// name alone, which is what those builds always showed.
	if rec, rerr := loadGatewayRecord(serverDir); rerr == nil {
		snap.Setup.OSUser = strings.TrimSpace(rec.OSUser)
	}
	// What this computer is as a gateway, on the first frame: the tab
	// must not open on "not a gateway" and correct itself a moment
	// later, on the one screen whose whole question is what this
	// computer is (IAMT-434).
	if gw, gerr := guiGatewayStatus(s.env, elevated); gerr == nil {
		snap.Gateway = gw
	}
	// Every gateway this machine remembers, on the very first frame
	// (IAMT-431): the Client tab's first question is which world it is
	// looking at, and a list that arrived one tick later would show the
	// person an empty card on the screen that answers it.
	if list, current, gerr := guiClientGateways(clientDir); gerr == nil {
		snap.Client.Gateways = list
		snap.Client.Current = current
	}
	if cs, cerr := client.LoadConnection(clientDir); cerr == nil {
		snap.Client.Configured = true
		// Who this machine already is, where, under which host key
		// (IAMT-356). Read from the saved record, so the Join card can
		// answer "do I still have to join?" without the network -- which
		// is when the question actually gets asked.
		snap.Admin.ThisMachine = &ui.AdminIdentity{
			Person:  cs.Person,
			Gateway: fmt.Sprintf("%s:%d", cs.Host, cs.Port),
			HostKey: cs.Fingerprint,
		}
	}
	// The key with or without a saved connection (R4 F-14).
	snap.Client.PublicKey = guiClientPublicKey(clientDir)
	// One immediate read, so the very first frame is not artificially
	// "not running" until the poller's first tick — the same cheap
	// control-status dial the poller repeats every interval afterwards.
	snap.Server = pollServerStatus(serverDir)

	updates := make(chan ui.LiveUpdate)
	done := make(chan struct{})
	startServerStatusPoll(serverDir, clientDir, serverStatusPollInterval, updates, done)

	cfg := ui.FrameConfig{
		Enrolled:       enrolled,
		HasAdminRights: elevated,
		Snap:           snap,
		// IAMT-256: --tab (main.go's runGUIWithFlags), for a deterministic,
		// click-free live check. Unset (the ordinary case) leaves
		// NewFrame's own default tab choice untouched.
		InitialTab: s.env["IAMTUNNEL_GUI_TAB"],
		Actions: ui.Actions{
			Enrol: func(code string) (string, string, error) {
				machine, eerr := guiEnrol(s, serverDir, code)
				if eerr != nil {
					return "", "", eerr
				}
				// The account is READ BACK FROM THE RECORD, not taken
				// from what was asked for: enrol has just written it, and
				// the file is the one place that knows which account the
				// gateway actually verified. It travels home in the
				// return value, which is where the result of an action
				// belongs -- it used to be posted into a shadow copy of
				// the window state instead, and the window itself never
				// learned it.
				osUser := ""
				if rec, rerr := loadGatewayRecord(serverDir); rerr == nil {
					osUser = strings.TrimSpace(rec.OSUser)
				}
				return machine, osUser, nil
			},
			SaveConnection: func(str, name string, replace bool) (string, error) {
				return guiSaveConnection(clientDir, str, name, replace)
			},
			ClientGateways: func() ([]ui.GatewayRef, string, error) {
				return guiClientGateways(clientDir)
			},
			ClientUseGateway: func(name string) (string, error) {
				return guiClientUseGateway(clientDir, name)
			},
			ClientForgetGateway: func(name string) (string, error) {
				return guiClientForgetGateway(clientDir, name)
			},
			GatewayStatus: func() (ui.GatewayState, error) {
				return guiGatewayStatus(s.env, elevated)
			},
			GatewayInstall: func(host string, port int) (string, error) {
				return guiGatewayInstall(s.env, host, port)
			},
			GatewayUninstall: func() (string, error) {
				return guiGatewayUninstall(s.env)
			},
			GatewayCopyExe: func() (string, error) {
				return guiGatewayCopyItself(s.env)
			},
			Machines: func(ctx context.Context) ([]ui.MachineAccess, error) {
				return guiMachines(ctx, clientDir)
			},
			SessionsHistory: func(ctx context.Context, person, machine, from, to string, limit, offset int) (ui.HistoryPage, error) {
				// There is no second copy to keep in step any more. This
				// page used to be posted into a shadow snapshot as well,
				// and the day that line was forgotten the tab filled and
				// blanked itself every three seconds -- which is how the
				// owner met it on 21.09.2026.
				return guiSessionsHistory(clientDir, person, machine, from, to, limit, offset)
			},
			ClientRiskPending: func(ctx context.Context) ([]ui.HeldCommand, error) {
				return guiClientRiskPending(clientDir)
			},
			ClientRiskDeny: func(ctx context.Context, approvalID string) error {
				return guiClientRiskDeny(clientDir, approvalID)
			},
			ClientRiskApprove: func(ctx context.Context, approvalID string) error {
				return guiClientRiskApprove(clientDir, approvalID)
			},
			SessionList: func(ctx context.Context) ([]ui.SessionInfo, error) {
				return guiSessionList(ctx, serverDir)
			},
			SessionTail: func(ctx context.Context, req ui.SessionTailReq) (ui.SessionTailResp, error) {
				return guiSessionTail(ctx, serverDir, req)
			},
			SessionExport: func(sessionID string) (string, error) {
				return guiSessionExport(serverDir, sessionID)
			},
			ServerStart: func() (string, error) { return guiServerStart(serverDir, nil) },
			ServerStop:  func() (string, error) { return guiServerStop(serverDir) },
			AdminGrantWithCaps: func(person, machine, until, capability string) (string, error) {
				return guiGrantWithCaps(clientDir, person, machine, until, capability)
			},
			AdminRevoke: func(person, machine string) (string, error) {
				return guiRevoke(clientDir, person, machine)
			},
			AdminSetGrantCaps: func(person, machine, capability string) (string, error) {
				return guiAdminSetGrantCaps(clientDir, person, machine, capability)
			},
			AdminExtend: func(person, machine, until string) (string, error) {
				return guiAdminExtend(clientDir, person, machine, until)
			},
			AdminRenamePerson: func(from, to string) (string, error) {
				return guiAdminRenamePerson(clientDir, from, to)
			},
			AdminRenameMachine: func(id, name string) (string, error) {
				return guiAdminRenameMachine(clientDir, id, name)
			},
			AdminRemovePerson: func(name string) (string, error) {
				return guiAdminRemovePerson(clientDir, name)
			},
			AdminRemoveMachine: func(id string) (string, error) {
				return guiAdminRemoveMachine(clientDir, id)
			},
			AdminGrantGoal: func(person, machine, goal string) (string, error) {
				return guiAdminGrantGoal(clientDir, person, machine, goal)
			},
			AdminPairClaim: func(ref, pin string) (string, *ui.AdminIdentity, error) {
				msg, err := guiAdminPair(clientDir, ref, pin)
				if err != nil {
					return "", nil, err
				}
				// Who this machine now is, read back from the connection
				// this pairing has just written. It travels home in the
				// return value rather than waiting for the next status
				// tick: until the window knows, the card goes on offering
				// a PIN that has already been spent, and a second press
				// can only be refused.
				return msg, adminIdentityOf(clientDir), nil
			},
			AdminClaim: func(ref, token string) (string, *ui.AdminIdentity, error) {
				msg, err := guiAdminClaim(clientDir, ref, token)
				if err != nil {
					return "", nil, err
				}
				// Read back from the file this claim has just written,
				// for the reason spelled out under AdminPairClaim above:
				// a one-time token that still looks unspent is an
				// invitation to spend it twice.
				return msg, adminIdentityOf(clientDir), nil
			},
			AdminList: func(ctx context.Context) (ui.AdminLists, error) {
				return guiAdminLists(ctx, clientDir)
			},
			AdminSessionTail: func(ctx context.Context, id string, offset int64) ([]byte, int64, int64, bool, string, error) {
				return guiAdminSessionTail(ctx, clientDir, id, offset)
			},
			AdminRecordings: func(ctx context.Context, machine, from, to string) ([]ui.RecordingRef, error) {
				return guiAdminRecordings(ctx, clientDir, machine, from, to)
			},
			AdminRecordingFetch: func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error) {
				return guiAdminRecordingFetch(ctx, clientDir, id, part, offset)
			},
			AdminSessionKill: func(id string) (string, error) {
				return guiAdminSessionKill(clientDir, id)
			},
			AdminRiskCheck: func(command string) (string, string, string, error) {
				return guiAdminRiskCheck(clientDir, command)
			},
			AdminRiskMode: func(mode string) (ui.RiskModeResult, error) {
				return guiAdminRiskMode(clientDir, mode)
			},
			AdminRiskSource: func(classifier string) (ui.RiskSourceResult, error) {
				return guiAdminRiskSource(clientDir, classifier)
			},
			AdminSetClassifierKey: func(key string) (ui.AdminSetClassifierKeyResult, error) {
				return guiAdminSetClassifierKey(clientDir, key)
			},
			AdminForget: func() (string, error) {
				return guiAdminForget(clientDir)
			},
			AdminPairingStart: func() (ui.PairingWindow, error) {
				return guiAdminPairingStart(clientDir)
			},
			AdminPairingStop: func() (bool, error) {
				return guiAdminPairingStop(clientDir)
			},
			AdminPeopleAdd: func(name, role, key string) (string, error) {
				return guiAdminPeopleAdd(clientDir, name, role, key)
			},
			AdminMachinesEnrolCode: func(name string) (string, string, error) {
				return guiAdminMachineEnrolCode(clientDir, name)
			},
			AdminMachineVerify: func(id string) (string, error) {
				return guiAdminMachineVerify(clientDir, id)
			},
			AdminMachineSetUser: func(id, osUser string) (string, error) {
				return guiAdminMachineSetUser(clientDir, id, osUser)
			},
			AdminMachineRekey: func(id, confirmFingerprint string) (string, error) {
				return guiAdminMachineRekey(clientDir, id, confirmFingerprint)
			},
			AdminPersonKeyAdd: func(name, pubkey string) (string, error) {
				return guiAdminPersonKeyAdd(clientDir, name, pubkey)
			},
			AdminPersonKeyRemove: func(name, fingerprint string) (string, error) {
				return guiAdminPersonKeyRemove(clientDir, name, fingerprint)
			},
			AdminPersonConnectionString: func(name string) (string, error) {
				return guiAdminPersonConnectionString(clientDir, name)
			},
			AdminGatewayFingerprint: func() ([]string, error) {
				return guiAdminGatewayFingerprint(clientDir)
			},
			AdminGatewayBackup: func() (string, error) {
				return guiAdminGatewayBackup(clientDir)
			},
			AdminGatewayRotateHostkey: func() (string, error) {
				return guiAdminGatewayRotateHostkey(clientDir)
			},
			// Connect opens Terminal.app on a generated script — the macOS
			// shape of the Windows "cmd /c start" terminal (see
			// internal/macos.ConnectTerminal, and its tests, for why the
			// machine name is never spliced into an AppleScript literal).
			ClientConnect: func(machine string) (string, error) {
				if !config.ValidName(machine) {
					return "", config.NameError("machine", machine)
				}
				exe, xerr := os.Executable()
				if xerr != nil {
					return "", fmt.Errorf("could not resolve this program's own executable path: %w", xerr)
				}
				return macos.ConnectTerminal(exe, machine)
			},
			ClientExec: func(ctx context.Context, machine, command string) (string, string, error) {
				return guiClientExec(ctx, clientDir, machine, command)
			},
			RestartAsAdmin: func() error {
				exe, xerr := os.Executable()
				if xerr != nil {
					return xerr
				}
				// R1 supplementary round: a file someone else can change must not be
				// handed to the administrator prompt - they would be
				// answering it for whoever presses the button. The
				// Windows window refuses the same (IAMT-445).
				if terr := refuseElevatingChangeableExe(exe); terr != nil {
					return terr
				}
				if rerr := macos.RelaunchAsAdmin(exe); rerr != nil {
					return rerr
				}
				os.Exit(exitOK)
				return nil
			},
			AgentPrompt: func(machine string) (string, error) {
				return guiAgentPrompt(clientDir, machine)
			},
		},
	}

	// ui.Run returns ONLY when the window could not be built at all; once
	// it is up, Run blocks for the rest of the process's life (app.Main()
	// never returns), so a return is always a failure and there is no
	// success value to branch on.
	runErr := ui.Run(cfg, updates)
	close(done)
	fmt.Fprintf(s.errs, "iamtunnel: could not start the window: %v\n", runErr)
	return exitInternal
}

// defaultSpawnServerStart is guiServerStart's real spawn on macOS: the
// same executable, re-invoked with the same argv a console user would
// type. Never called from a test (see guiServerStart's doc comment in
// gui_actions.go). Setsid: the server outlives the window that started
// it — it must not die with the window's session when the terminal that
// launched iamtunnel goes away.
func defaultSpawnServerStart(exe string) error {
	return runSpawnedServerStart(exe, func(cmd *exec.Cmd) {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	})
}
