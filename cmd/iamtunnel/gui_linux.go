//go:build linux && !nogui

package main

// runGUI opens the live window (IAMT-157) when iamtunnel is started with
// no arguments on Linux — the same command path as on Windows (IAMT-252:
// no new flag, the same seam). The wiring mirrors the Windows runGUI
// function for function; the differences are exactly what differs on the
// platform: no console to detach and no message box (an ordinary terminal
// program prints there), a Setsid spawn instead of CREATE_NO_WINDOW, and
// the two platform actions: Connect opens the session in the first
// terminal emulator it can find, and the elevation relaunch goes through
// pkexec (both IAMT-254; guiClientConnect and elevate.Relaunch are the
// Windows halves of the same seams).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/elevate"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
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
	ensureSoftwareGL(s)

	// On Linux "elevated" is euid == 0 — the banner is a hint about the
	// server actions, never a refusal (same contract as on Windows).
	// linuxIsElevated (not elevate.IsElevated directly) so a test can
	// pretend to be root without actually being one — the same seam
	// announceElevatedSession already reaches for.
	elevated, _ := linuxIsElevated()

	// IAMT-309 round 2: an elevated copy that would render through the
	// forced software rasterizer on a DISPLAY/XAUTHORITY forwarded from
	// someone else's X11 session cannot draw at all — see
	// elevatedForeignDisplayRefusal for the mechanism a live run found.
	// This must run BEFORE any window is opened and before OnWindowReady
	// could ever be wired: a refusal here means the ready line is never
	// even a possibility, not a race against one.
	if elevated && softwareGLActive(s) && linuxGioWillUseX11(s.env) && elevatedDisplayIsForeign(s.env) {
		fmt.Fprintln(s.errs, elevatedForeignDisplayRefusal)
		return exitDenied
	}

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
		// F-GUI-6: a permission-style failure (the server data directory
		// is root-owned 0700) is not the same fact as "not enrolled" —
		// the window cannot tell the two apart from this read alone, so
		// the machine fact must say "unknown", not draw the dash it
		// would otherwise share with a genuinely absent name.
		machineNameUnknown = true
	}
	warnIfSetupTabUnreachable(s, s.env["IAMTUNNEL_GUI_TAB"], enrolled)

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
		// InitialTab: IAMT-256's --tab flag (main.go's runGUIWithFlags)
		// reaches here through IAMTUNNEL_GUI_TAB — a deterministic way to
		// reach a given tab for a live check without a pointer click
		// (IAMT-309 round 2 first asked for this, before the flag existed).
		// Unset leaves NewFrame's own default tab choice untouched, the
		// same field shot_windows.go's offscreen shot takes directly.
		InitialTab: s.env["IAMTUNNEL_GUI_TAB"],
		// The restart handover speaks only when the window is a fact: the
		// window loop calls this once, right after the first frame was
		// SUBMITTED to the window system (e.Frame returned) — a Layout
		// that merely returned is not a window yet.
		OnWindowReady: announceElevatedSession,
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
			ClientConnect: guiClientConnectLinux,
			ClientExec: func(ctx context.Context, machine, command string) (string, string, error) {
				return guiClientExec(ctx, clientDir, machine, command)
			},
			RestartAsAdmin: func() error {
				if rerr := guiRestartAsAdminLinux(); rerr != nil {
					return rerr
				}
				// guiRestartAsAdminLinux returned nil: the elevated copy
				// CONFIRMED it is up — its window's first frame said so on
				// the child's stdout — so this copy ends, per
				// RestartAsAdmin's contract (internal/ui/live.go), the same
				// handover the Windows action performs after
				// elevate.Relaunch succeeds. Its stdout/stderr no longer
				// point here (the elevated copy moved them aside before it
				// spoke), so this exit cannot EPIPE the new window.
				os.Exit(exitOK)
				return nil
			},
			AgentPrompt: func(machine string) (string, error) {
				return guiAgentPrompt(clientDir, machine)
			},
		},
	}

	// The elevated copy's half of the restart handover (IAMT-295): the
	// moment its window's first frame is SUBMITTED to the window system
	// (the strongest "the window is up" signal gio offers — a Layout that
	// returned is only built operations), a root session says so on
	// stdout — the one channel that survives pkexec's exec. The line goes
	// out from the loop's OnWindowReady (above → announceElevatedSession),
	// NOT before: if the window never comes up (no display for root under
	// Wayland/X, a Gio init failure) nothing is announced, and the
	// waiting original then sees pkexec exit without the ready line — it
	// keeps its own window and shows the error, instead of quitting into
	// a screen with no window on it.
	//
	// ui.Run returns ONLY when the window could not be built at all; once
	// it is up, Run blocks for the rest of the process's life (app.Main()
	// never returns), so a return is always a failure and there is no
	// success value to branch on.
	runErr := linuxUIRun(cfg, updates)
	close(done)
	fmt.Fprintf(s.errs, "iamtunnel: could not start the window: %v\n", runErr)
	return exitInternal
}

// linuxSetenv is the one place LIBGL_ALWAYS_SOFTWARE actually reaches
// this process's real environment — a seam so no test that calls
// ensureSoftwareGL ever mutates the test binary's own environment for
// the rest of its run.
var linuxSetenv = os.Setenv

// ensureSoftwareGL forces software OpenGL rendering for this process,
// before any GL context can exist (IAMT-309): a live run found that
// without a working hardware GL driver — a VM with no 3D acceleration, a
// remote desktop, an old GPU — the window opens solid black (or, run as
// root, transparent, with Mesa's own "Failed to attach to x11 shm" going
// straight to the real stderr, never through Gio's event loop) while
// stdout/stderr otherwise stay completely empty and the process reports
// itself ready regardless. The same binary on the same display drew
// every screen correctly once LIBGL_ALWAYS_SOFTWARE=1 was set by hand.
//
// Round 4 (F-GUI-1) tried to decide from evidence instead of forcing
// unconditionally — a working DRM render node (/dev/dri/renderD*) — to
// avoid a performance regression on real hardware. A live run on the
// very VM this item was filed for proved that evidence unreliable: its
// render node exists (VirtualBox publishes one) while its hardware GL is
// not actually usable, so the heuristic left the original black window
// exactly where it started, and — because softwareGLActive mirrored the
// same wrong evidence — also silently defeated the elevated-display
// refusal (round 2/F-GUI-5), which never got to look at Wayland or
// XAUTHORITY at all. Detecting a failed or blank first frame reliably,
// from outside Gio's own event loop, is not something this process can
// do (FrameEvent.Frame carries no render-success signal — IAMT-295's own
// contract — and Mesa's failures go straight to the real stderr, never
// through Go). Absent a reliable positive test, this defaults to
// software rendering unconditionally, the same as round 1: a slow window
// is a nuisance, a black one is the defect this item exists for. Mesa
// reads the variable lazily, at driver load — the first GLX/EGL call
// ui.Run eventually makes — so setting it here, at the very top of
// runGUI and well before any window exists, is enough; no re-exec is
// needed. A person who already set LIBGL_ALWAYS_SOFTWARE (to force it,
// or to "0"/"false" to test hardware GL on purpose) is left alone, both
// ways: this is a default, not an override, and either way the console
// is told which path was taken — never silent.
func ensureSoftwareGL(s *streams) {
	if _, already := s.env["LIBGL_ALWAYS_SOFTWARE"]; already {
		return
	}
	if err := linuxSetenv("LIBGL_ALWAYS_SOFTWARE", "1"); err != nil {
		fmt.Fprintf(s.errs, "iamtunnel: could not force software OpenGL rendering (LIBGL_ALWAYS_SOFTWARE): %v — the window may open black or blank on a display with no working hardware OpenGL\n", err)
		return
	}
	fmt.Fprintln(s.errs, "iamtunnel: forcing software OpenGL rendering (LIBGL_ALWAYS_SOFTWARE=1) — hardware OpenGL cannot be reliably confirmed working from here (a real device file is not proof — a live run found one present on a machine whose hardware GL was not usable); set LIBGL_ALWAYS_SOFTWARE=0 before launching to use hardware OpenGL instead")
}

// softwareGLActive reports whether this process will render through
// Mesa's software rasterizer (llvmpipe) rather than a hardware driver —
// ensureSoftwareGL's own decision, mirrored here rather than re-guessed:
// unset defers to the same unconditional default ensureSoftwareGL itself
// applies (software, absent an explicit override — see its own comment
// for why round 4's render-node evidence was abandoned), and an
// explicit, falsy LIBGL_ALWAYS_SOFTWARE (a person opting out to use
// hardware GL on purpose) always reads as inactive. This is the ONE
// precondition elevatedDisplayIsForeign's refusal is scoped to:
// hardware-accelerated GL presents frames through DRI3/GBM buffer
// sharing, which does not touch the X11 MIT-SHM path at all, so an
// elevated relaunch someone deliberately ran with hardware GL is
// unaffected by IAMT-309 round 2's finding — only the forced (or
// requested) software path is. This must never again silently defeat the
// elevated-display refusal below by guessing "hardware" wrong (the
// F-GUI-1/F-GUI-5 live-run finding, round 5): a false "hardware" reading
// here skipped the refusal's Wayland/XAUTHORITY checks entirely.
func softwareGLActive(s *streams) bool {
	v, set := s.env["LIBGL_ALWAYS_SOFTWARE"]
	if !set {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off", "":
		return false
	default:
		return true
	}
}

// linuxXauthorityOwnerUID resolves the UID that owns the file named by
// the XAUTHORITY entry of env — (0, false) when there is no such
// variable or the file cannot be statted; Gio's own window open fails on
// its own in that case, and this check has nothing useful to add.
var linuxXauthorityOwnerUID = func(env map[string]string) (uid uint32, ok bool) {
	path := env["XAUTHORITY"]
	if path == "" {
		return 0, false
	}
	info, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	st, ok2 := info.Sys().(*syscall.Stat_t)
	if !ok2 {
		return 0, false
	}
	return st.Uid, true
}

// linuxDialUnix is linuxWaylandSocketReachable's one touch of the
// network stack — a seam so a test can fake a reachable or refused
// socket without a real compositor. waylandProbeTimeout bounds it: a
// stream unix socket either refuses or accepts near-instantly, so this
// only guards a genuinely wedged listener, never turning the
// elevated-refusal decision itself into a user-visible pause.
var linuxDialUnix = func(path string) (io.Closer, error) {
	return net.DialTimeout("unix", path, waylandProbeTimeout)
}

var waylandProbeTimeout = 250 * time.Millisecond

// linuxWaylandSocketReachable reports whether THIS process, with these
// privileges, can actually open the Wayland compositor socket — the
// same first step wl_display_connect itself performs, before any
// protocol handshake (F-GUI-5, review round 21): a merely-set
// WAYLAND_DISPLAY is not proof Wayland wins, because gioui.org/app's
// Unix newWindow (os_unix.go) only WINS with Wayland when that connect
// attempt itself succeeds — otherwise it falls back to X11 just the
// same as if the variable were unset. sudo -E/pkexec can leave
// WAYLAND_DISPLAY (and XDG_RUNTIME_DIR, itself just inherited from the
// original user) set in the elevated process's environment while root
// still cannot reach a socket the original user's session scoped to
// itself — DAC permissions, a MAC policy, or anything else that would
// make wl_display_connect itself fail. The previous predicate treated
// the env var alone as proof, so it skipped the MIT-SHM refusal exactly
// where Gio's own fallback to X11 was about to reproduce it: the live
// symptom this whole check exists for. A real connect (not a stat) is
// the honest test — the socket path can exist and still refuse this
// UID. XDG_RUNTIME_DIR unset means there is nowhere to look at all
// (libwayland itself requires it); WAYLAND_DISPLAY unset defaults to
// "wayland-0", the same default wl_display_connect(NULL) uses.
func linuxWaylandSocketReachable(env map[string]string) bool {
	dir := env["XDG_RUNTIME_DIR"]
	if dir == "" {
		return false
	}
	name := env["WAYLAND_DISPLAY"]
	if name == "" {
		name = "wayland-0"
	}
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, name)
	}
	conn, err := linuxDialUnix(path)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// linuxGioWillUseX11 reports whether Gio's own window driver will end up
// on the X11 backend for this process (F-GUI-3, narrowed by F-GUI-5):
// gioui.org/app's Unix newWindow (os_unix.go) tries the Wayland driver
// FIRST and only falls back to X11 when that attempt fails — so the
// decision must rest on whether Wayland would actually have worked
// (linuxWaylandSocketReachable), not merely on whether its environment
// variables are present. The MIT-SHM refusal below describes an
// X11-specific mechanism — the X SECURITY extension's per-client trust —
// that a session where Wayland genuinely wins never goes through at
// all, so it must never fire there; an elevated root process with a
// non-root XAUTHORITY is not proof of an X11 backend by itself (a
// live-run finding: an env-var-only predicate could wrongly refuse a
// working Wayland/XWayland session, or a legitimate root/kiosk desktop
// carrying a stray, unused XAUTHORITY — and, the other way, wrongly
// SKIP the refusal on a stale WAYLAND_DISPLAY it never actually
// verified, letting Gio's own fallback to X11 reproduce the exact
// MIT-SHM symptom this check exists for). No DISPLAY at all means Gio
// has no X11 fallback to reach either way.
func linuxGioWillUseX11(env map[string]string) bool {
	if env["DISPLAY"] == "" {
		return false
	}
	return !linuxWaylandSocketReachable(env)
}

// elevatedDisplayIsForeign reports whether this elevated (root) process
// is about to open a window on an X11 session whose XAUTHORITY belongs
// to a DIFFERENT user (IAMT-309 round 2, narrowed by F-GUI-3 to the X11
// backend alone — see linuxGioWillUseX11): pkexec — and an ordinary
// "sudo -E ... XAUTHORITY=..." root shell alike, the very fallback
// notice_linux.go's banner still names — forwards the invoking user's
// own DISPLAY/XAUTHORITY so the elevated window can share their screen,
// but that user's X server then treats a root client authenticated with
// someone else's cookie as untrusted and denies it MIT-SHM, the shared
// memory Mesa's software rasterizer needs to hand a rendered frame to
// the X server at all. A live run showed the exact signature: stderr
// carried "MESA: error: Failed to attach to x11 shm" and the window
// opened solid black (an ordinary user) or fully transparent (this
// case), never a picture, while the process still announced itself
// ready. A root session with its OWN Xauthority (uid 0 — a genuine root
// desktop login, not a forwarded one) is not this case and is left
// alone; the window then only needs an ordinary root-owned X session
// with a working software (or hardware) GL path, which this check has no
// reason to distrust.
func elevatedDisplayIsForeign(env map[string]string) bool {
	uid, ok := linuxXauthorityOwnerUID(env)
	return ok && uid != 0
}

// elevatedForeignDisplayRefusal is IAMT-309 round 2's honest refusal,
// printed and returned as exitDenied instead of ever building a window:
// an elevated copy that cannot draw must say so and exit non-zero, never
// print elevatedReadyLine over a window nobody can see (IAMT-295's
// contract — the line is a promise the first frame was actually
// SUBMITTED to a window system that could show it, and this case is
// known in advance never to be able to).
const elevatedForeignDisplayRefusal = "iamtunnel: this elevated session cannot draw its window on this display — DISPLAY/XAUTHORITY belong to another user's own X11 session, and that session denies a root client the shared memory (MIT-SHM) the forced software renderer needs to present a frame; no window was opened. Use \"sudo iamtunnel server start\"/\"stop\" from a terminal instead, or run iamtunnel from a genuine root desktop session (its own Xauthority, not one forwarded from another user) for the graphical window."

// linuxUIRun is the window launcher runGUI ends in — a seam so the
// handover's wiring (OnWindowReady) is testable at all: ui.Run opens a
// real OS window, blocks forever, and panics in a test binary on its
// own (see internal/ui/gui.go); streams.openGUI keeps tests from runGUI
// entirely, and this seam is what lets exactly one test back in, aimed
// at a fake.
var linuxUIRun = ui.Run

// defaultSpawnServerStart is guiServerStart's real spawn on Linux: the
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

// -------------------------------------------------------------------------
// IAMT-254: the two platform actions — Connect in a terminal, and the
// pkexec relaunch behind "Restart as administrator".
//
// Everything below runs other programs, so every point where a process
// would actually start is a package-level seam (the shape
// internal/ui's FrameConfig uses for the same reason): tests swap the
// seams for recording fakes and assert on the exact argv. No test ever
// launches a terminal, pkexec or any other program.
// -------------------------------------------------------------------------

// linuxTerminals is the launch order for Connect, widest reach first:
// x-terminal-emulator — the Debian-alternatives umbrella that resolves
// to the distribution's default emulator, whose wrappers translate the
// xterm form into whatever the emulator itself speaks — then the four
// emulators a mainstream desktop actually ships. The second field is
// how the emulator's own option parsing is told where the child command
// begins. Every entry must keep the child command as ARGV ELEMENTS —
// the machine name travels as one argument of exec's argv, never inside
// a string a shell (or an emulator that re-parses one) would read; that
// is the structural half of the injection guard, config.ValidName being
// the other:
//
//   - gnome-terminal: "--". Its old "-e/--command" takes a single
//     STRING the emulator hands to a shell — exactly the round-trip
//     this action must not do.
//   - xterm, konsole: "-e", which consumes ALL remaining argv as the
//     command; no marker needed.
//   - xfce4-terminal: "-x/--execute", its argv-consuming form — its
//     "-e" is a single shell-parsed string, like gnome-terminal's.
//   - x-terminal-emulator: "-e", the xterm form — the alternatives
//     wrappers (xterm's own, Debian's gnome-terminal wrapper,
//     konsole's) all accept it and translate to the emulator's form.
var linuxTerminals = []struct{ name, sep string }{
	{"x-terminal-emulator", "-e"},
	{"gnome-terminal", "--"},
	{"konsole", "-e"},
	{"xfce4-terminal", "-x"},
	{"xterm", "-e"},
}

// guiClientConnectLinux is the Client screen's Connect button on Linux,
// the analog of guiClientConnect on Windows: a terminal window running
// "iamtunnel client connect <machine>" — the session itself is a
// terminal (SPEC §3.1). The first emulator found on PATH wins; none of
// the five is a refusal that names the command that still works.
func guiClientConnectLinux(machine string) (string, error) {
	if !config.ValidName(machine) {
		return "", config.NameError("machine", machine)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not resolve this program's own executable path: %w", err)
	}
	term, sep, err := findTerminal()
	if err != nil {
		return "", err
	}
	args := []string{exe, "client", "connect", machine}
	if sep != "" {
		args = append([]string{sep}, args...)
	}
	cmd := linuxCommand(term, args...)
	// Setsid: the terminal outlives this window's session, exactly like
	// the spawned server above — SIGHUP on the original terminal's
	// close must not take the session down with it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := linuxStartDetached(cmd); err != nil {
		return "", fmt.Errorf("could not open a terminal: %w", err)
	}
	return "Opened a terminal on " + machine + ".", nil
}

// findTerminal returns the first terminal emulator installed (LookPath),
// in linuxTerminals' order, together with its command separator.
func findTerminal() (name, sep string, err error) {
	var tried []string
	for _, t := range linuxTerminals {
		if _, lerr := linuxLookPath(t.name); lerr == nil {
			return t.name, t.sep, nil
		}
		tried = append(tried, t.name)
	}
	return "", "", fmt.Errorf("no terminal emulator found (tried %s) — run \"iamtunnel client connect <machine>\" in a terminal of your choice", strings.Join(tried, ", "))
}

// guiRestartAsAdminLinux is the Server screen's Restart-as-administrator
// action on Linux, the analog of the Windows consent relaunch: pkexec
// runs this same binary with the original arguments, polkit asks for
// the person's consent, and this copy ends only once the elevated one
// has CONFIRMED it is up. Returns only on failure — the words the frame
// shows under the Server Start control, in the same slot the Windows
// UAC refusal lands ("Could not restart as administrator: …").
//
// pkexec (not found → refusal, no dialog) is started detached in its
// own session — the elevated copy must outlive the terminal that
// started this one, the same Setsid discipline as every other child
// this window launches. pkexec BLOCKS while polkit waits for the
// dialog, and its staying alive means nothing: the dialog may sit open
// for minutes and still be cancelled. So the wait is decided by the
// elevated copy itself: its ready line on the child's stdout
// (elevatedReadyLine — the one channel that survives pkexec's exec,
// sent once its window's first frame is submitted) ends the wait with a
// confirmed
// handover, and pkexec exiting first is always an error for the window
// to show, never a success. The wait is still bounded (pkexecConfirmTimeout):
// a pkexec or polkit agent that hangs WITHOUT answering and WITHOUT the
// ready line must not pin the action's restarting flag forever — past
// the bound the attempt is abandoned as an ERROR, its process group is
// killed, and the person can simply try again. The frame runs this
// action off the UI goroutine (frame.go), so even that wait never
// freezes the window, and its restarting flag keeps a second pkexec
// from piling up while this one runs.
func guiRestartAsAdminLinux() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not resolve this program's own executable path: %w", err)
	}
	// R1 supplementary round: a file someone else can change must not be handed to
	// pkexec - they would be answering the password prompt for whoever
	// presses the button. The Windows window refuses the same (IAMT-445).
	if terr := refuseElevatingChangeableExe(exe); terr != nil {
		return terr
	}
	// R1-CX F-25: the invoking user shapes their own PATH, and pkexec is
	// about to carry this binary past root's door — resolving it through
	// that PATH would let anyone who can plant a file decide what
	// actually runs. The lookup is the fixed system paths alone
	// (findPkexec); only Connect's terminal emulators (findTerminal)
	// still go through LookPath, where the worst case is one emulator
	// losing to another.
	pkexec, perr := findPkexec()
	if perr != nil {
		return perr
	}
	cmd := linuxCommand(pkexec, append([]string{exe}, os.Args[1:]...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	ready := newReadyWatcher()
	cmd.Stdout = ready
	var errs bytes.Buffer
	cmd.Stderr = &errs
	if serr := linuxStartChild(cmd); serr != nil {
		return fmt.Errorf("could not start pkexec: %w", serr)
	}
	done := make(chan error, 1)
	go func() { done <- linuxWaitChild(cmd) }()
	timer := time.NewTimer(pkexecConfirmTimeout)
	defer timer.Stop()
	select {
	case <-ready.ready:
		return nil
	case werr := <-done:
		// Photo finish: if the ready line landed in the same instant the
		// child exited, it wins — a confirmed handover is a confirmed
		// handover, even when the elevated copy has already finished.
		select {
		case <-ready.ready:
			return nil
		default:
		}
		output := strings.TrimSpace(ready.buf.String()) + "\n" + strings.TrimSpace(errs.String())
		return pkexecOutcome(werr, output)
	case <-timer.C:
		// A pkexec that never answered and never announced its window is
		// a hung polkit wait, not a decision. Abandon it as an ERROR —
		// never success (frame.go resets restarting on any error, so the
		// person can retry) — and kill the child's whole group (it leads
		// one: Setsid above), so nothing is left holding the dialog.
		linuxKillGroup(cmd)
		go func() { <-done }() // reap the killed child whenever the kill lands
		return fmt.Errorf("pkexec did not answer within %s — the attempt was abandoned and killed; iamtunnel keeps running as it is, try again", pkexecConfirmTimeout)
	}
}

// findPkexec resolves pkexec from the FIXED system paths, never from
// the invoking user's PATH (class R1-CX F-25): the PATH is the caller's
// to shape, and whatever it names would be handed this machine's root
// prompt. A well-formed system keeps polkit's pkexec at /usr/bin/pkexec;
// /bin is its symlink on merged-usr systems, hence the second candidate.
// The refusal wording is the one the old PATH lookup gave.
func findPkexec() (string, error) {
	for _, cand := range []string{"/usr/bin/pkexec", "/bin/pkexec"} {
		if fi, serr := linuxStat(cand); serr == nil && !fi.IsDir() {
			return cand, nil
		}
	}
	return "", errors.New("pkexec is not installed — start iamtunnel from a root shell instead")
}

// pkexecConfirmTimeout bounds the whole wait for the ready line. Five
// minutes: a person may need most of that to notice the polkit dialog,
// type a password, or come back to the desk at all — the same order as
// a screen lock — while anything longer is, in practice, a hung agent
// that will never answer (the dialog does not outlive its own agent).
// A timed-out wait is an ERROR, never success.
var pkexecConfirmTimeout = 5 * time.Minute

// The handover runs over the one channel that survives pkexec:
// standard output. pkexec execs the elevated copy in place of itself
// and, as pkexec(1) documents, clears the environment and keeps only
// file descriptors 0–2 — a private pipe on any other fd is closed
// before the elevated copy could ever speak. Stdout is kept, and this
// action owns it: the child's stdout is a pipe this process reads.

// elevatedReadyLine is the line an elevated copy prints on stdout the
// moment its window's first frame is submitted (announceElevatedSession,
// fired by the window loop's OnWindowReady right after e.Frame returned
// — see runGUI). The waiting original reads it as the confirmed handover
// and ends itself; that is why the elevated copy moves its own
// stdout/stderr aside BEFORE the line goes out (redirectOwnStdio — and
// why a failed redirect sends nothing at all): from that instant the
// original is free to exit, and with it dies the only reader of the pipe
// fd 1 and 2 started on.
const elevatedReadyLine = "iamtunnel: elevated session ready"

// readyWatcher is the pkexec child's Stdout: it forwards every byte
// into a buffer (the diagnostics pkexecOutcome reports) and closes
// ready exactly once, when the elevated copy's ready line arrives.
// Lines are reassembled across writes, so the marker survives being
// split arbitrarily; writes come from os/exec's single copier
// goroutine, so there is no lock.
type readyWatcher struct {
	buf   bytes.Buffer
	ready chan struct{}
	once  sync.Once
	line  []byte
}

func newReadyWatcher() *readyWatcher {
	return &readyWatcher{ready: make(chan struct{})}
}

func (w *readyWatcher) Write(p []byte) (int, error) {
	n := len(p)
	w.buf.Write(p)
	for {
		idx := bytes.IndexByte(p, '\n')
		if idx < 0 {
			w.line = append(w.line, p...)
			break
		}
		w.line = append(w.line, p[:idx]...)
		if strings.TrimSpace(string(w.line)) == elevatedReadyLine {
			w.once.Do(func() { close(w.ready) })
		}
		w.line = w.line[:0]
		p = p[idx+1:]
	}
	return n, nil
}

// The elevated side of the handover; the seams exist for the tests,
// the production bodies are elevate, os and the kernel's dup themselves.
var (
	linuxIsElevated  = elevate.IsElevated
	linuxStdoutIsTTY = func() bool {
		st, err := os.Stdout.Stat()
		return err == nil && st.Mode()&os.ModeCharDevice != 0
	}
	// linuxDup saves the pipe (a private fd of the very same open file),
	// linuxDup2 moves this copy's own fd 1 and 2 to /dev/null (retried
	// through EINTR by dup2UntilDone); a failure of either means NO
	// marker — see announceElevatedSession. The open of /dev/null and the
	// writer over the saved fd complete the plumbing.
	linuxDup         = syscall.Dup
	linuxDup2        = unix.Dup2
	linuxOpenDevNull = func() (*os.File, error) { return os.OpenFile(os.DevNull, os.O_WRONLY, 0) }
	linuxNewFile     = func(fd uintptr, name string) io.Writer { return os.NewFile(fd, name) }
)

// announceElevatedSession is the elevated copy's half of the restart
// handover: a root session whose window's first frame is submitted says
// so on stdout (elevatedReadyLine) — runGUI wires it as the frame's
// OnWindowReady, so the line means a frame the window system was handed,
// and a window that never comes up never announces: the original then
// sees the child exit without the line and keeps showing its own. A
// root session at a terminal says nothing — a person at a root shell
// needs no machine-readable handover, and the line would only be noise.
//
// The order inside is the protocol: save the pipe with a dup, move this
// copy's own stdout and stderr out of it, write the marker on the saved
// fd, give the fd back. The original ends itself the moment it has read
// the marker, taking the pipe's only reader with it — everything this
// process might print LATER must already point elsewhere, or the next
// Gio diagnostic (or a panic report, which Go's runtime writes straight
// to fd 2) dies of EPIPE — on fd 1, SIGPIPE — and takes the very window
// the handover announced down with it.
//
// Hence the one rule the whole function obeys: the marker is written by
// exactly ONE code path, reached only with the pipe saved AND both
// descriptors voided; every other path is SILENT. A dup that could not
// save the pipe, a redirect that did not fully succeed, a marker write
// that failed — all leave the handover unconfirmed: the saved dup is
// closed, no line goes out on any channel (fd 1 and fd 2 may still be
// ends of the pipe whose only reader the original is), and the original
// reads this copy's eventual exit (or its bounded timeout) as the
// never-confirmed restart it is. An unannounced window is strictly
// better than an announced one that can be killed.
func announceElevatedSession() {
	if elevated, err := linuxIsElevated(); err != nil || !elevated {
		return
	}
	if linuxStdoutIsTTY() {
		return
	}
	saved, derr := linuxDup(int(os.Stdout.Fd()))
	if derr != nil {
		// The pipe could not be saved: this copy's fd 1 and fd 2 stay
		// ends of the pipe whose only reader the original closes the
		// instant it reads a marker. A marker here — on the still-piped
		// stdout — would confirm a handover this window's very next
		// write could kill. Silent return: the handover stays
		// unconfirmed, the original keeps its window.
		return
	}
	out := linuxNewFile(uintptr(saved), "elevated-announce")
	// The saved fd lives only for the marker: closed on every path from
	// here on — before the marker because there is nothing to say, after
	// it because this copy will never speak on the pipe again.
	defer func() {
		if c, ok := out.(io.Closer); ok {
			c.Close()
		}
	}()
	if rerr := redirectOwnStdio(); rerr != nil {
		// fd 1 or fd 2 still points at the pipe the original reads, so
		// the marker must NOT go out — the original would end itself on
		// it, and this window's next write (a panic report lands
		// directly on fd 2) could die of EPIPE. Silent return; the
		// deferred close gives the saved fd back.
		return
	}
	// The one and only marker write: both descriptors are voided and the
	// saved fd is valid. A failed write is an unconfirmed handover —
	// readyWatcher confirms only a complete line, so a partial one reads,
	// in the original, as an exit without the ready line — never a
	// success to branch on.
	if _, werr := fmt.Fprintf(out, "%s\n", elevatedReadyLine); werr != nil {
		return
	}
}

// redirectOwnStdio moves this copy's own stdout and stderr to /dev/null
// and succeeds only when BOTH have moved. Runs before the marker (see
// announceElevatedSession): from the marker on, the original may exit at
// any instant, and anything this GUI prints afterwards — diagnostics, a
// panic, a stray fmt — must land in the void, not on a pipe whose reader
// is gone. Each dup2 is retried while the kernel answers EINTR (an
// interrupted dup2 did not happen — a retry, not a failure); any other
// error is returned, never dropped — the caller answers it by not
// confirming the handover at all.
func redirectOwnStdio() error {
	devnull, err := linuxOpenDevNull()
	if err != nil {
		return fmt.Errorf("could not open /dev/null: %w", err)
	}
	defer devnull.Close()
	dn := int(devnull.Fd())
	for _, t := range []struct {
		fd   int
		what string
	}{
		{int(os.Stdout.Fd()), "stdout"},
		{int(os.Stderr.Fd()), "stderr"},
	} {
		if err := dup2UntilDone(dn, t.fd); err != nil {
			return fmt.Errorf("could not move this copy's %s to /dev/null: %w", t.what, err)
		}
	}
	return nil
}

// dup2UntilDone performs one dup2(src, dst), retrying while the kernel
// answers EINTR — the call was interrupted before it happened, which is
// a retry, not a failed redirect.
func dup2UntilDone(src, dst int) error {
	for {
		err := linuxDup2(src, dst)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
}

// pkexecOutcome turns a pkexec exit that beat the ready line into the
// action's error — it is reached only when the elevated copy never
// confirmed the handover, so every path here is a message for the
// window, and the window stays open. pkexec(1) documents 126 for "the
// authorization could not be obtained" (the dialog was dismissed) and
// 127 for "not authorized / authentication failed"; both are the person
// saying no, and the words must say THAT, in the tone of the Windows
// refusal ("likely consent declined") — what happened, no polkit
// internals. Any other non-zero exit is pkexec or the elevated copy
// reporting failure in its own words — captured output first, the raw
// error second, the same discipline runSpawnedServerStart applies to a
// refused server start. A zero exit without the ready line is still a
// restart that was never confirmed (the marker can be lost — a failed
// stdout write in the elevated copy), so it keeps the window too.
func pkexecOutcome(werr error, output string) error {
	if werr == nil {
		return errors.New("the elevated copy exited without confirming the restart — iamtunnel keeps running as it is")
	}
	var ee *exec.ExitError
	if errors.As(werr, &ee) && (ee.ExitCode() == 126 || ee.ExitCode() == 127) {
		return errors.New("administrator permission was not granted — iamtunnel keeps running without it")
	}
	msg := strings.TrimSpace(output)
	if msg == "" {
		msg = werr.Error()
	}
	return errors.New(msg)
}

// The os/exec seams, all in one place: LookPath decides which terminal
// exists, Command builds the child, the two start/wait pairs run it —
// linuxStartDetached for children the window never waits on (the
// terminal), linuxStartChild/linuxWaitChild for pkexec, whose exit
// ahead of the ready line is the answer — and linuxKillGroup is the
// hung-wait escape (SIGKILL to the child's whole group; it leads one,
// Setsid). linuxStat is the existence check behind findPkexec, which
// deliberately does NOT go through LookPath: the caller's PATH is no
// place to resolve a helper that receives root (R1-CX F-25). Production
// bodies are the os/exec, os and syscall calls themselves; tests
// substitute recording fakes.
var (
	linuxLookPath      = exec.LookPath
	linuxStat          = os.Stat
	linuxCommand       = exec.Command
	linuxStartDetached = func(cmd *exec.Cmd) error {
		if err := cmd.Start(); err != nil {
			return err
		}
		_ = cmd.Process.Release()
		return nil
	}
	linuxStartChild = func(cmd *exec.Cmd) error { return cmd.Start() }
	linuxWaitChild  = func(cmd *exec.Cmd) error { return cmd.Wait() }
	linuxKillGroup  = func(cmd *exec.Cmd) error {
		if cmd.Process == nil || cmd.Process.Pid <= 0 {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
)
