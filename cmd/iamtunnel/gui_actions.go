//go:build (windows || linux || darwin) && !nogui

package main

// The window's actions, shared verbatim by the Windows, Linux and macOS
// GUIs (IAMT-252, IAMT-262): nothing here touches a platform API — it is
// the same wiring the "enrol", "client" and "admin" verbs already use,
// reshaped into the function values internal/ui calls. Only the spawn of
// the server-start child (defaultSpawnServerStart, per platform) and the
// launcher itself (runGUI) stay platform files.

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"

	"github.com/ultrathinker/iamtunnel/internal/ui"
)

// serverStatusPollInterval is how often the window re-asks "iamtunnel
// server status" (control.json + the control port) for a session it did
// not start itself (IAMT-182). Seconds, not sub-second: this is a local
// loopback dial, cheap enough to poll often, but the recording strip
// appearing a couple of seconds after a specialist actually connects is
// an acceptable, honestly-disclosed latency — there is no push channel
// from the running server process to this window, only asking again.
const serverStatusPollInterval = 3 * time.Second

// warnIfSetupTabUnreachable is IAMT-256/F-GUI-8's honesty check (review
// round 25, LOW, confirmed): --tab=setup is accepted and
// translated to ui.TabSetUp by main.go's runGUIWithFlags regardless of
// enrolment state — the flag parser is platform-agnostic and has no
// notion of "enrolled" at all, and duplicating that role logic there
// just to validate one flag value would be the wrong layer for it. But
// internal/ui.NewFrame never registers the Set up tab once Enrolled is
// true (SPEC §7.1: the tab does not exist post-enrolment), and
// design.Tabs.Show has no error signal for "this tab does not exist" —
// it silently falls back to the first registered tab (Client). Rather
// than widen the flag's own validation, this says so honestly, once,
// right where "enrolled" is already known — before the Frame is ever
// built — instead of the window quietly opening a different screen
// than the one asked for.
func warnIfSetupTabUnreachable(s *streams, initialTab string, enrolled bool) {
	if enrolled && initialTab == ui.TabSetUp {
		fmt.Fprintln(s.errs, "iamtunnel: --tab=setup was requested, but this machine is already enrolled — the Set up screen no longer exists; opening the default tab instead")
	}
}

// resolvedConfigPath names the config file the way config.Load itself
// picks it (settings.go: flag > IAMTUNNEL_CONFIG > platform default) —
// minus the flag, because the window has no --config of its own. Kept as
// its own function so the Settings screen's "config file" fact is never
// left at config.Dirs{}'s zero value the way a hand-built config.Dirs
// (see dirs above, which exists only for its MachineID()/MachineKey()
// helpers) would leave it.
func resolvedConfigPath(s *streams) string {
	if envOv, err := config.EnvOverride(s.env); err == nil && envOv.ConfigPath != "" {
		return envOv.ConfigPath
	}
	fullDirs, err := config.DirsFor(runtime.GOOS, s.env)
	if err != nil {
		return ""
	}
	return fullDirs.ConfigFile
}

// guiEnrol is the Set up screen's action: parse the code, then run the
// same wire exchange "iamtunnel enrol <code>" runs (enrolMachine, defined
// in misc.go beside cmdEnrol).
func guiEnrol(s *streams, serverDir, codeStr string) (string, error) {
	code, err := config.ParseEnrolCode(codeStr)
	if err != nil {
		return "", err
	}
	res, err := enrolMachine(s, serverDir, code)
	if err != nil {
		return "", guiElevationAdvice(err)
	}
	return res.Machine, nil
}

// guiElevationAdvice retells a console refusal for a window.
//
// Registering a machine writes the machine data directory and locks it
// down to administrators, so without elevation it is refused -- rightly.
// The message it is refused with ends "close this console and run it
// using \"Run as administrator\"", which is exactly right in a terminal
// and nonsense in a window: there is no console to close, and a
// "Restart as administrator" button sits in the top right corner of the
// very window that would be showing this.
//
// The console wording is left alone -- it is correct where it is said.
func guiElevationAdvice(err error) error {
	var ce *cliError
	if !errors.As(err, &ce) || ce.code != exitDenied {
		return err
	}
	const console = `close this console and run it using "Run as administrator".`
	const window = `press "Restart as administrator" in the top right corner of this window, then paste the code again.`
	if !strings.Contains(ce.msg, console) {
		return err
	}
	return &cliError{code: ce.code, msg: strings.ReplaceAll(ce.msg, console, window)}
}

// guiSaveConnection is "iamtunnel client connect-string"'s own work
// (client.go cmdClientConnectString).
func guiSaveConnection(clientDir, str, name string, replace bool) (string, error) {
	cs, err := config.ParseConnString(str)
	if err != nil {
		return "", err
	}
	// The same foreign-directory gate the CLI verb carries (IAMT-333
	// P1.6): no streams and no flag here — a nil streams makes the gate
	// ask the window's own elevation, and the escape stays a CLI flag.
	if err := refuseForeignDataDir(nil, "client connect-string", clientDir, false); err != nil {
		return "", err
	}
	g, err := client.SaveConnectionNamed(clientDir, cs, name, replace)
	if err != nil {
		return "", err
	}
	return "Remembered as “" + g.Name + "” and now in use — " + g.Person + " on " + g.Where() + ".", nil
}

// guiClientGateways is "iamtunnel client gateways"'s own work: what this
// machine remembers, and which one it is looking at (IAMT-431).
//
// No network. The list of gateways is a fact about this machine, and the
// one party with no business knowing it is a gateway -- each must be
// able to believe it is the only one.
func guiClientGateways(clientDir string) ([]ui.GatewayRef, string, error) {
	set, err := client.LoadConnections(clientDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", nil
		}
		return nil, "", err
	}
	out := make([]ui.GatewayRef, 0, len(set.Gateways))
	for _, g := range set.Gateways {
		out = append(out, ui.GatewayRef{
			Name: g.Name, Person: g.Person, Where: g.Where(), Fingerprint: g.Fingerprint,
		})
	}
	current, _ := set.CurrentGateway()
	return out, current.Name, nil
}

// guiClientUseGateway is "iamtunnel client use"'s own work.
func guiClientUseGateway(clientDir, name string) (string, error) {
	if err := refuseForeignDataDir(nil, "client use", clientDir, false); err != nil {
		return "", err
	}
	g, err := client.SelectConnection(clientDir, name)
	if err != nil {
		return "", err
	}
	return "Now on “" + g.Name + "” — " + g.Person + " on " + g.Where() + ".", nil
}

// guiClientForgetGateway is "iamtunnel client forget"'s own work.
func guiClientForgetGateway(clientDir, name string) (string, error) {
	if err := refuseForeignDataDir(nil, "client forget", clientDir, false); err != nil {
		return "", err
	}
	had, err := client.ForgetGateway(clientDir, name)
	if err != nil {
		return "", err
	}
	if !had {
		return "", fmt.Errorf("no saved gateway is called %q any more", name)
	}
	return "Forgot “" + name + "”. Your key is untouched, and so is the person record on that gateway " +
		"— only its administrator can take that away.", nil
}

// guiMachines is "iamtunnel client machines"'s own work (client.go
// cmdClientMachines), reshaped into ui.MachineAccess.
func guiMachines(ctx context.Context, clientDir string) ([]ui.MachineAccess, error) {
	if err := refuseForeignDataDir(nil, "client machines", clientDir, false); err != nil {
		return nil, err
	}
	cs, err := client.LoadConnection(clientDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no connection string saved yet — save one above first")
		}
		return nil, err
	}
	signer, err := client.EnsureKey(clientDir)
	if err != nil {
		return nil, err
	}
	machines, err := client.Machines(ctx, clientDir, cs, signer, 0)
	if err != nil {
		return nil, err
	}
	out := make([]ui.MachineAccess, 0, len(machines))
	for _, m := range machines {
		// A deadline that does not parse is shown as none rather than as
		// raw text — the same choice orDash makes for every other
		// missing fact on these screens.
		until, _ := time.Parse(time.RFC3339, m.Until)
		out = append(out, ui.MachineAccess{
			Name: m.Name, Online: m.Online, SshdListening: m.SSHDListening, Until: until,
			Caps: m.Caps,
		})
	}
	return out, nil
}

// guiClientExec is the Client tab's exec-only row's Run button: the
// same work "iamtunnel client exec <machine> -- <command>" performs
// (cmdClientExec, client.go), reshaped into the plain (stdout, stderr)
// pair ui.Actions.ClientExec's own doc comment asks for — this function
// stays ignorant of window/color concerns, exactly like guiAdminRiskCheck
// does for (level, rule, reason).
//
// Unlike guiClientConnect, this never spawns a console: a one-shot
// command's whole output fits in the window's own CopyableBox, and
// internal/client.Exec already gives separate stdout/stderr writers to
// capture into.
func guiClientExec(ctx context.Context, clientDir, machine, command string) (string, string, error) {
	if !config.ValidName(machine) {
		return "", "", config.NameError("machine", machine)
	}
	if err := refuseForeignDataDir(nil, "client exec", clientDir, false); err != nil {
		return "", "", err
	}
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", "", err
	}
	var stdout, stderr bytes.Buffer
	outcome, err := client.Exec(ctx, client.ExecOptions{
		Conn:           cs,
		Machine:        machine,
		Command:        command,
		Signer:         signer,
		KnownHostsPath: client.KnownHostsPath(clientDir),
		Stdout:         &stdout,
		Stderr:         &stderr,
	})
	if err != nil {
		return "", "", err
	}
	switch {
	case !outcome.Started:
		return stdout.String(), stderr.String(), fmt.Errorf("the gateway did not accept the command — see the output above for the reason")
	case outcome.ExitStatus == nil:
		return stdout.String(), stderr.String(), fmt.Errorf("the connection to the gateway was lost mid-command — no exit status arrived")
	default:
		return stdout.String(), stderr.String(), nil
	}
}

// -------------------------------------------------------------------------
// IAMT-182: the live source of this machine's server state.
// -------------------------------------------------------------------------

// serverStateFromControlReply is IAMT-182's one mapping point: everything
// the live window can honestly say about a session it did not start
// itself comes from here, from one "server status" answer. It is kept
// apart from the polling loop and the network dial on purpose, so it can
// be tested with a hand-built reply — no control.json, no port, no
// window (see gui_windows_test.go).
//
// The machine genuinely cannot name who is on the other end or until
// exactly when they may stay: session and reservation counts live only
// on the gateway (docs/PROTOCOL.md §5.2/§5.4 — "the session and
// reservation counters live on the gateway"). An installed door line IS a fact this
// machine holds on its own authority (server.Machine.DoorOpen), and per
// the same protocol a door stays installed only while at least one
// session or reservation is live — so it is drawn as exactly one Session
// with an unknown Person (the screens already render that as "—",
// orDash) and a zero Until (rendered as "—" too), rather than inventing
// an identity or a deadline this process does not have.
func serverStateFromControlReply(reply controlReplyMsg, contacted bool) ui.ServerState {
	if !contacted {
		return ui.ServerState{}
	}
	st := ui.ServerState{
		Running:     reply.Running,
		Waiting:     reply.Connected,
		SshdRunning: reply.SshdRunning,
	}
	if reply.DoorOpen {
		st.Door = ui.DoorState{State: "open"}
		st.Sessions = []ui.Session{{}}
	}
	return st
}

// pollServerStatus asks "is anyone reaching this machine right now" the
// same way "iamtunnel server status" does — control.json plus the
// control port sendControl already dials — and returns just the Server
// half of the Snapshot.
func pollServerStatus(dir string) ui.ServerState {
	reply, contacted, err := sendControl(dir, "status")
	if err != nil {
		// IAMT-311: sendControl's error used to be discarded here, so a
		// permission-denied read of control.json (the machine data
		// directory is root-owned 0700 — the same read "iamtunnel server
		// status" itself refuses without root) came back indistinguishable
		// from the zero ServerState "no server running at all". An
		// unprivileged window then told its owner sshd was not running and
		// the tunnel was offline while the machine was, in fact, reachable
		// — a false sense of safety, not a cosmetic gap. Any error here
		// means the fact could not be learned, never that it is false.
		return ui.ServerState{Unknown: true, UnknownReason: unreachableStatusText(err)}
	}
	return serverStateFromControlReply(reply, contacted)
}

// unreachableStatusText is pollServerStatus's IAMT-311 wording for a
// "status" attempt that ended in an error instead of an answer. A denied
// read gets requireServerElevation's own sentence for the identical
// missing right on the identical command (server.go), so an owner reads
// the same words whether they asked from a terminal or from this window;
// any other unreachable reason keeps its own words rather than a
// borrowed one that would not describe it.
func unreachableStatusText(err error) string {
	var ce *cliError
	if errors.As(err, &ce) && ce.code == exitDenied {
		if runtime.GOOS == "windows" {
			return "unknown — administrator privileges are required to check: close this console and run \"iamtunnel server status\" using \"Run as administrator\""
		}
		return "unknown — root privileges are required to check: run \"sudo iamtunnel server status\" in a terminal"
	}
	return "unknown — this machine's own status could not be checked: " + err.Error()
}

// startServerStatusPoll asks the three questions a tick can answer and
// sends the answers — and only the answers — on updates every interval,
// until done is closed. It owns its own goroutine and ticker.
//
// It used to send a whole ui.Snapshot, assembled from a shadow copy of
// the window state that cmd/iamtunnel kept beside the window and every
// action had to remember to write into. It no longer keeps or needs one:
// what this function knows is what it dialled for, and ui.LiveUpdate is
// a type that can carry that and nothing else. See internal/ui/
// live_update.go for the two defects the old arrangement produced.
func startServerStatusPoll(dir, clientDir string, interval time.Duration, updates chan<- ui.LiveUpdate, done <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				next := ui.LiveUpdate{Server: pollServerStatus(dir)}
				// WHEN THIS TICK LOOKED, stamped before its first read of
				// the saved connection and not only before the held
				// request (R1-CX F-16): a forget or a switch of gateway
				// landing between the identity read and a later stamp
				// would have passed for older than this tick, and its
				// stale identity would have won. See ui.LiveUpdate.At.
				next.At = time.Now()
				// Who this machine is on its gateway, re-read from the
				// saved connection on every tick (IAMT-389). It used to
				// be read once at startup and then only by the actions
				// that changed it, so a connection restored from outside
				// this window -- the "client connect-string" verb, or a
				// second window -- left the Join card insisting the
				// machine still had to join, and Refresh, which asks the
				// gateway for its lists and nothing else, could not
				// correct it.
				next.Identity, next.IdentityKnown = readAdminIdentity(clientDir)
				// What the gateway is holding for this person
				// (21.09.2026). It rides this tick rather than a timer of
				// its own because it is the same question at the same
				// rhythm -- "what changed out there" -- and a second
				// ticker would mean a second dial-in to the gateway every
				// few seconds for one small answer.
				//
				// HeldKnown carries the difference between "nothing is
				// held" and "could not ask": the gateway being briefly
				// unreachable is not evidence that nothing is held, and
				// blanking the list would retract a question the person
				// may be halfway through reading, with a five-minute
				// clock running on it.
				// The held request talks to the gateway and can take
				// seconds or hang; an action that finishes while it is in
				// flight is newer than everything this tick read, which
				// is what the stamp above says.
				if next.Identity != nil {
					if held, err := guiClientRiskPending(clientDir); err == nil {
						next.Held, next.HeldKnown = held, true
					}
				}
				select {
				case updates <- next:
				case <-done:
					return
				}
			}
		}
	}()
}

// -------------------------------------------------------------------------
// IAMT-181: Server Start/Stop, Admin Grant/Revoke.
// -------------------------------------------------------------------------

// guiServerStart is the Server screen's Start action. The window never
// becomes the server process itself — it re-execs the very same "server
// start" a console user would run standalone, as its own child process,
// exactly as far removed from this window as any other independently
// started copy of iamtunnel. spawn is nil in production (the platform's
// defaultSpawnServerStart runs); tests substitute a fake so no test ever
// starts a real server (a hard requirement here: a real "server start"
// touches the OpenSSH authorized_keys file and the service machinery).
func guiServerStart(serverDir string, spawn func(exe string) error) (string, error) {
	if _, contacted, _ := sendControl(serverDir, "status"); contacted {
		return "", fmt.Errorf("a server is already running for this machine (data dir %s) — stop it first", serverDir)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("could not resolve this program's own executable path: %w", err)
	}
	if spawn == nil {
		spawn = defaultSpawnServerStart
	}
	if err := spawn(exe); err != nil {
		return "", fmt.Errorf("could not start the server process: %w", err)
	}
	return "Starting — the server is coming up in its own process.", nil
}

// runSpawnedServerStart is the shared body of both platforms' default
// spawn: start the child with configure's platform-specific process
// attributes, capture its output, and treat "exited within the first
// seconds" as a refusal whose own words become the error (IAMT-233). A
// child still running after that is up; its later output is not read.
func runSpawnedServerStart(exe string, configure func(*exec.Cmd)) error {
	var out bytes.Buffer
	cmd := exec.Command(exe, "server", "start")
	if configure != nil {
		configure(cmd)
	}
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case werr := <-done:
		msg := strings.TrimSpace(out.String())
		if msg == "" && werr != nil {
			msg = werr.Error()
		}
		if msg == "" {
			msg = "it exited at once without saying why"
		}
		return errors.New(msg)
	case <-time.After(3 * time.Second):
		return nil
	}
}

// guiServerStop is the Server screen's Stop action: exactly
// "iamtunnel server stop"'s own work (server.go cmdServerStopStatus),
// which is only ever a local control-port round trip — no subprocess,
// nothing to spawn.
func guiServerStop(serverDir string) (string, error) {
	reply, contacted, err := sendControl(serverDir, "stop")
	if err != nil {
		return "", err
	}
	if !contacted {
		return "The server is not running.", nil
	}
	return fmt.Sprintf("The server (pid %d) was stopped.", reply.PID), nil
}

// guiGrantWithCaps is the Admin screen's Grant action: the same shape
// checks "admin grants grant" runs (admin.go's check function) before the
// same dialAdmin + GrantsGrant the CLI verb calls (admin_exec.go).
func guiGrantWithCaps(clientDir, person, machine, until, capability string) (string, error) {
	if !config.ValidName(person) {
		return "", config.NameError("person", person)
	}
	if !config.ValidName(machine) {
		return "", config.NameError("machine", machine)
	}
	if until != "" {
		if _, err := config.ParseUntil(until); err != nil {
			return "", err
		}
	}
	if capability != "shell" && capability != "exec" {
		return "", fmt.Errorf("capability %q must be shell or exec", capability)
	}
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	g, err := conn.GrantsGrant(person, machine, until, capability)
	if err != nil {
		return "", err
	}
	if capability == "shell" {
		if g.Until == "" {
			return fmt.Sprintf("Granted %s -> %s until revoked. Interactive shell input is not classified.", g.Person, g.Machine), nil
		}
		return fmt.Sprintf("Granted %s -> %s until %s. Interactive shell input is not classified.", g.Person, g.Machine, g.Until), nil
	}
	status, statusErr := conn.GatewayStatus()
	mode := "could not be read"
	if statusErr == nil {
		mode = status.Risk.Mode
	}
	if g.Until == "" {
		return fmt.Sprintf("Granted %s -> %s until revoked. Exec commands are classified; current risk mode: %s.", g.Person, g.Machine, mode), nil
	}
	return fmt.Sprintf("Granted %s -> %s until %s. Exec commands are classified; current risk mode: %s.", g.Person, g.Machine, g.Until, mode), nil

}

// guiRevoke is the Admin screen's per-grant Revoke action: the same
// dialAdmin + GrantsRevoke the CLI verb "admin grants revoke" calls.
func guiRevoke(clientDir, person, machine string) (string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	killed, err := conn.GrantsRevoke(person, machine)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Revoked %s → %s (%d session(s) killed).", person, machine, killed), nil
}

// guiAdminExtend moves one grant's deadline (M-10) from the Admin
// screen's grant rows: the same dialAdmin + GrantsExtend the CLI verb
// "admin grants extend" calls. The two deadline words follow the CLI's
// own convention — an empty deadline reads "until revoked" — so past
// output and window output read the same way.
func guiAdminExtend(clientDir, person, machine, until string) (string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	newUntil, was, killed, err := conn.GrantsExtend(person, machine, until)
	if err != nil {
		return "", err
	}
	nowWord, wasWord := newUntil, was
	if nowWord == "" {
		nowWord = "until revoked"
	}
	if wasWord == "" {
		wasWord = "until revoked"
	}
	if killed > 0 {
		return fmt.Sprintf("%s → %s now ends %s (was %s); %d session(s) killed.",
			person, machine, nowWord, wasWord, killed), nil
	}
	return fmt.Sprintf("%s → %s now ends %s (was %s); no session touched.",
		person, machine, nowWord, wasWord), nil
}

// guiAdminRenamePerson renames one person from the window's people list
// (D-2a). The gateway moves the person's grants and goals to the new
// name in one write and closes the sessions opened under the old name;
// the message says which it did, so the row's answer is the whole story.
func guiAdminRenamePerson(clientDir, from, to string) (string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	terminated, err := conn.PeopleRename(from, to)
	if err != nil {
		return "", err
	}
	if terminated > 0 {
		return fmt.Sprintf("Renamed %s → %s; %d session(s) opened under the old name killed.", from, to, terminated), nil
	}
	return fmt.Sprintf("Renamed %s → %s; no session touched.", from, to), nil
}

// guiAdminRenameMachine changes one machine's display label from the
// window's machines list (D-2a). It takes the machine's ID -- the thing
// every durable reference carries -- and says back what stayed: the id,
// the grants and the journal keep pointing at the same machine.
func guiAdminRenameMachine(clientDir, id, name string) (string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.MachinesRename(id, name); err != nil {
		return "", err
	}
	return fmt.Sprintf("Renamed machine %s to %s; the id, grants and journal still point at the same machine.", id, name), nil
}

// guiAdminSetGrantCaps changes one grant's mode in place. It is reached
// from the CLIENT tab -- the screen of the person entering -- and it
// travels as an ADMINISTRATOR's request, which is the whole point: the
// window offers it only to a machine that also carries an administrator
// identity, and the gateway grades the request by the key that signed it
// rather than by the screen it came from.
func guiAdminSetGrantCaps(clientDir, person, machine, capability string) (string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	was, killed, err := conn.GrantsSetCaps(person, machine, capability)
	if err != nil {
		return "", err
	}
	if was == capability {
		return fmt.Sprintf("Already %s on %s; nothing changed.", capability, machine), nil
	}
	if killed > 0 {
		return fmt.Sprintf("%s on %s: %s instead of %s. %d live session(s) closed with it.",
			person, machine, capability, was, killed), nil
	}
	return fmt.Sprintf("%s on %s: %s instead of %s.", person, machine, capability, was), nil
}

// guiAdminRemovePerson and guiAdminRemoveMachine are the Remove controls
// of the People and Machines rows. Both verbs existed on the gateway
// and in the CLI from 1.0 and were never drawn in the window, leaving
// no way to delete a person from the GUI at all.
//
// Neither reports more than it knows. The gateway answers a removal with
// the name it removed and nothing else -- it does not count what went
// with it -- so these say what happened and leave the arithmetic to the
// refreshed lists, rather than inventing a session count the way a
// revoke can honestly give one.
func guiAdminRemovePerson(clientDir, name string) (string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	removed, err := conn.PeopleRemove(name)
	if err != nil {
		return "", err
	}
	if !removed {
		// PeopleRemove reports false when the gateway removed a name
		// other than the one asked for, which cannot happen over a sane
		// connection -- but saying "removed" on the strength of an
		// answer that did not confirm it is how a window comes to lie.
		return "", fmt.Errorf("the gateway did not confirm removing %q", name)
	}
	return fmt.Sprintf("Removed %s, with every grant and goal that named them.", name), nil
}

func guiAdminRemoveMachine(clientDir, id string) (string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.MachinesRemove(id); err != nil {
		return "", err
	}
	return fmt.Sprintf("Removed machine %s, with its grants.", id), nil
}

// guiAdminGrantGoal is one grant row's Save goal action (SPEC IAMT-402):
// the same dialAdmin + GoalSet "admin goal set <person> <machine>"
// performs. person and machine are the grant's own pair, not the caller —
// review19 finding 3 is exactly what happens when that distinction is
// lost on the gateway side; here it just has to be threaded through.
func guiAdminGrantGoal(clientDir, person, machine, goal string) (string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	res, err := conn.GoalSet(person, machine, goal)
	if err != nil {
		return "", err
	}
	if res.Goal == "" {
		return fmt.Sprintf("Goal for %s -> %s cleared.", res.Person, res.Machine), nil
	}
	return fmt.Sprintf("Goal for %s -> %s saved.", res.Person, res.Machine), nil
}

// -------------------------------------------------------------------------
// IAMT-327: the Admin tab's pairing and issuing cards.
// -------------------------------------------------------------------------

// guiAdminPair is the "Become an administrator" card's action — the same
// work "iamtunnel admin pair" performs (cmdAdminPair): parse the
// reference, shape-check the PIN so a typo never burns one of the three
// attempts per address, pair THIS machine's own client key (EnsureKey —
// a machine that has never been an admin has no saved connection yet;
// the key the pairing registers is the key every later admin action
// authenticates with), and save the connection on success so the Admin
// tab works from here at once.
func guiAdminPair(clientDir, refStr, pin string) (string, error) {
	ref, err := config.ParsePairingRef(refStr)
	if err != nil {
		return "", err
	}
	if !validPinShape(pin, pairingPINDigits) {
		return "", fmt.Errorf("the PIN must be exactly %d decimal digits (leading zeros count)", pairingPINDigits)
	}
	if err := refuseForeignDataDir(nil, "admin pair", clientDir, false); err != nil {
		return "", err
	}
	signer, kerr := client.EnsureKey(clientDir)
	if kerr != nil {
		return "", kerr
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	peer := admin.Peer{Addr: fmt.Sprintf("%s:%d", ref.Host, ref.Port), Fingerprint: ref.Fingerprint}
	conn, dialErr := admin.Dial(peer, "pairing", signer, 10*time.Second)
	if dialErr != nil {
		return "", pairDialError(peer.Addr, dialErr)
	}
	defer conn.Close()
	res, err := conn.PairClaim(pin, pubLine)
	if err != nil {
		return "", err
	}
	msg := fmt.Sprintf("Welcome — %q is now an administrator on this gateway.", res.Person)
	cs := config.ConnString{Host: ref.Host, Port: ref.Port, Person: res.Person, Fingerprint: ref.Fingerprint}
	if serr := client.SaveConnection(clientDir, cs, false); serr != nil {
		// The pairing itself succeeded; only the local convenience save
		// failed. Say both halves, never swallow one.
		return msg + " The connection string was NOT saved (" + serr.Error() +
			") — run \"iamtunnel client connect-string\" by hand.", nil
	}
	return msg + " The Admin tab and every admin command now work from this machine.", nil
}

// guiAdminClaim is the GUI half of "iamtunnel admin claim" (SPEC 3.3):
// the one-time bootstrap token that makes the FIRST administrator of a
// gateway that has none. The claim string is the only way in at that
// point, because there is nobody yet who could open a pairing window.
//
// It exists because the Admin tab's box accepted the claim string,
// recognised it, said above the button that pressing it would make this
// machine the first administrator - and then handed it to the PAIRING
// action, which measured the bootstrap token against the six-digit PIN
// shape and refused it. The gateway itself prints "paste this one string
// into the Admin tab's single field", so the promise was in the product
// and only the wiring was missing.
func guiAdminClaim(clientDir, refStr, token string) (string, error) {
	// The CLI grammar takes reference and token as one string; the box
	// splits them, so put them back rather than keep a second parser.
	ref, err := config.ParseClaimRef(refStr + ":" + token)
	if err != nil {
		return "", err
	}
	if err := refuseForeignDataDir(nil, "admin claim", clientDir, false); err != nil {
		return "", err
	}
	// This machine's own client key is what becomes the admin key, so it
	// must exist before the gateway is asked to remember it.
	signer, kerr := client.EnsureKey(clientDir)
	if kerr != nil {
		return "", kerr
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	// The bootstrap login is not this key: it is an ephemeral one derived
	// from the token itself, which is what proves the token was held
	// (PROTOCOL 3.3). The client key travels as data, in the request.
	ephemeral, derr := config.DeriveEphemeralSigner(ref.Token, config.BootstrapKeySalt)
	if derr != nil {
		return "", fmt.Errorf("could not derive the one-time bootstrap key: %w", derr)
	}
	peer := admin.Peer{Addr: fmt.Sprintf("%s:%d", ref.Host, ref.Port), Fingerprint: ref.Fingerprint}
	conn, dialErr := admin.Dial(peer, "bootstrap", ephemeral, 10*time.Second)
	if dialErr != nil {
		return "", claimDialError(peer.Addr, dialErr)
	}
	defer conn.Close()
	res, cerr := conn.AdminClaim(ref.Token, pubLine)
	if cerr != nil {
		return "", cerr
	}
	msg := fmt.Sprintf("Welcome - %q is now the first administrator of this gateway (role %s).", res.Person, res.Role)
	cs := config.ConnString{Host: ref.Host, Port: ref.Port, Person: res.Person, Fingerprint: ref.Fingerprint}
	if serr := client.SaveConnection(clientDir, cs, false); serr != nil {
		// The claim itself succeeded and the token is spent; only the
		// local convenience save failed. Say both halves, never swallow
		// one - a person told "failed" here would try the spent token
		// again and get a refusal that explains nothing.
		return msg + " The connection string was NOT saved (" + serr.Error() +
			") - run \"iamtunnel client connect-string\" by hand.", nil
	}
	return msg + " The Admin tab and every admin command now work from this machine.", nil
}

// claimDialError separates "the gateway was not reached" from "the
// gateway was reached, and refused the one-time key" (IAMT-356).
//
// Both said "could not reach the gateway at …" until 19.09.2026, and the
// owner, re-pasting a claim line he had already spent, went looking at
// his network for an hour-old success. A refused key is not an outage,
// and the two want opposite next moves.
func claimDialError(addr string, err error) error {
	if strings.Contains(err.Error(), "unable to authenticate") {
		return fmt.Errorf("the gateway at %s refused this claim line. A claim line is one-time: "+
			"if this machine has already joined, it IS the administrator already and needs nothing "+
			"pasted here (%v)", addr, err)
	}
	return fmt.Errorf("could not reach the gateway at %s: %w", addr, err)
}

// pairDialError is claimDialError's own fix (IAMT-356), repeated for
// pairing (claim strings already separate the two cases — repeat the
// separation): guiAdminPair printed "could not reach the gateway" on a
// refused pairing key even though the gateway answered immediately. A
// closed or expired pairing window refuses the key at the SSH layer
// itself — PROTOCOL §3.4 conditions "pairing-login" accepting any
// correctly-formed key on the window being open; with none open there is
// nothing for that layer to accept against — and that refusal is not an
// outage. The two want opposite next moves: retry the network, or ask an
// administrator to open a fresh window.
func pairDialError(addr string, err error) error {
	if strings.Contains(err.Error(), "unable to authenticate") {
		return fmt.Errorf("the gateway at %s refused this pairing attempt. The pairing window may be closed "+
			"or expired — ask the administrator to open a new one (\"iamtunnel admin pairing start\") and try "+
			"again (%v)", addr, err)
	}
	return fmt.Errorf("could not reach the gateway at %s: %w", addr, err)
}

// guiAdminLists is what the Admin tab shows: people, machines and
// grants, over ONE connection (IAMT-357).
//
// One dial, not three. The tab draws the three lists side by side, and a
// page built from three separate moments can disagree with itself -- a
// grant naming a machine the machine list has not got yet reads as a
// bug in the product rather than as a race in the window.
//
// An empty list is an answer. Only a failure to ASK is an error.
func guiAdminLists(ctx context.Context, clientDir string) (ui.AdminLists, error) {
	var out ui.AdminLists
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return out, err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	if err := ctx.Err(); err != nil {
		return out, err
	}

	people, err := conn.PeopleList()
	if err != nil {
		return out, err
	}
	for _, p := range people {
		keys := make([]ui.PersonKey, 0, len(p.Keys))
		for _, k := range p.Keys {
			keys = append(keys, ui.PersonKey{Fingerprint: k.Fingerprint, Added: k.Added})
		}
		out.People = append(out.People, ui.Person{
			Name:    p.Name,
			Admin:   p.Role == "admin",
			Keys:    len(p.Keys),
			KeyList: keys,
		})
	}

	machines, _, err := conn.MachinesList()
	if err != nil {
		return out, err
	}
	for _, m := range machines {
		name := m.Name
		if name == "" {
			name = m.ID
		}
		osUser := m.VerifiedOSUser
		if osUser == "" {
			osUser = m.OSUser
		}
		// The key "rekey" must be given back, as the fingerprint the
		// machine's owner can read on the machine (IAMT-499). A key the
		// gateway sent but this build cannot fingerprint shows as empty
		// rather than as a guess; the row still says the key changed.
		var observed string
		if m.ObservedSSHDHostKey != "" {
			observed, _ = state.ComputeFingerprint(m.ObservedSSHDHostKey)
		}
		out.Machines = append(out.Machines, ui.AdminMachine{
			ID:                  m.ID,
			Name:                name,
			State:               m.State,
			DoorState:           m.DoorState,
			Online:              m.Online,
			OSUser:              osUser,
			OSUserStatus:        m.OSUserStatus,
			HostKeyStatus:       m.HostKeyStatus,
			ObservedFingerprint: observed,
		})
	}

	grants, err := conn.GrantsList("", "")
	if err != nil {
		return out, err
	}
	// Every pair's goal arrives in ONE request (IAMT-405): goal.list
	// carries the same current goal and bounded history goal.history
	// returns for a single pair, listed for all pairs at once. A grant
	// whose pair has no goal record is simply absent from the list, and
	// the row draws the empty goal it always has.
	goals, err := conn.GoalList()
	if err != nil {
		return out, err
	}
	type goalPair struct{ person, machine string }
	goalByPair := make(map[goalPair]admin.GoalView, len(goals.Goals))
	for _, gv := range goals.Goals {
		goalByPair[goalPair{gv.Person, gv.Machine}] = gv
	}
	for _, g := range grants {
		// An empty "until" is the gateway saying "until revoked". The
		// zero time is how this window already draws that, so an
		// unparseable value must land there too rather than on some
		// year in 1970.
		var until time.Time
		if g.Until != "" {
			if t, perr := time.Parse(time.RFC3339, g.Until); perr == nil {
				until = t
			}
		}
		goal := goalByPair[goalPair{g.Person, g.Machine}]
		recent := make([]string, 0, len(goal.History))
		for _, entry := range goal.History {
			recent = append(recent, entry.Goal)
		}
		out.Grants = append(out.Grants, ui.Grant{
			Person: g.Person, Machine: g.Machine, Until: until,
			Goal: goal.Goal, RecentGoals: recent,
			Caps: g.Caps,
		})
	}

	// Who is inside RIGHT NOW comes with the rest (IAMT-360). It is the
	// one list on this tab that changes without anybody pressing
	// anything, and it rides the same connection for the same reason the
	// other three do: a page assembled from several moments can show a
	// session on a machine its own machine list has not got yet.
	live, err := conn.SessionsActive()
	if err != nil {
		return out, err
	}
	for _, s := range live {
		var started time.Time
		if s.Started != "" {
			if t, perr := time.Parse(time.RFC3339, s.Started); perr == nil {
				started = t
			}
		}
		out.Sessions = append(out.Sessions, ui.Session{
			ID: s.ID, Person: s.Person, Machine: s.Machine, Started: started,
		})
	}
	status, err := conn.GatewayStatus()
	if err != nil {
		return out, err
	}
	out.RiskMode = ui.RiskMode{
		Mode: status.Risk.Mode, Source: status.Risk.Source,
		Classifier:       status.Risk.Classifier,
		ClassifierSource: status.Risk.ClassifierSource,
		// Two sources for one fact, and deliberately so: risk.classifierKey
		// says whether the gateway can be switched to ai/both at all, and
		// externalRiskKey carries the fingerprint an operator compares
		// against the key they issued. Present in either is present.
		ClassifierKey:            status.Risk.ClassifierKey || status.ExternalRiskKey.Present,
		ClassifierKeyFingerprint: status.ExternalRiskKey.Fingerprint,
	}
	// IAMT-451: while the gateway's audit journal is not being written it
	// refuses every change this tab can make, and the tab says so first.
	out.AuditProblem = status.Audit.Problem()
	// The pairing window's state rides along (IAMT-331): the card on the
	// Pairing tab believes this answer over anything it minted itself, so
	// a window ended from the far side dies on screen the moment the
	// refresh lands. nil keeps an older gateway's silence a silence.
	if status.Pairing != nil {
		live := &ui.PairingStatus{Active: status.Pairing.Active}
		if status.Pairing.Expires != "" {
			if t, perr := time.Parse(time.RFC3339, status.Pairing.Expires); perr == nil {
				live.Expires = t
			}
		}
		out.Pairing = live
	}
	return out, nil
}

// guiAdminSessionTail follows one live session (IAMT-360): the same
// "sessions tail" the CLI verb runs, one slice at a time from an offset,
// so a session that has been running for an hour is not re-read from the
// start on every look.
func guiAdminSessionTail(ctx context.Context, clientDir, id string, offset int64) ([]byte, int64, int64, bool, string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return nil, offset, 0, false, "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return nil, offset, 0, false, "", err
	}
	defer conn.Close()
	if err := ctx.Err(); err != nil {
		return nil, offset, 0, false, "", err
	}
	t, err := conn.SessionsTail(id, offset, sessionTailWindowBytes)
	if err != nil {
		return nil, offset, 0, false, "", err
	}
	// base64 undone HERE, once, as the CLI watcher does it. Handing the
	// encoded string on was a defect seen in practice: the window drew
	// the base64 itself.
	raw, derr := base64.StdEncoding.DecodeString(t.Data)
	if derr != nil {
		return nil, offset, 0, false, "", fmt.Errorf("the gateway sent a chunk that is not base64: %w", derr)
	}
	return raw, t.Offset + int64(len(raw)), t.Total, t.Live, t.Mode, nil
}

// sessionTailWindowBytes is how much transcript one look fetches. Big
// enough that a quiet minute arrives whole, small enough that a chatty
// build log does not arrive as one unreadable wall.
const sessionTailWindowBytes = 16 << 10

// guiAdminRecordings lists what the gateway still holds -- the other
// half of the history (IAMT-427).
//
// The journal says a visit happened; this says whether its transcript
// survives, and under which id and in which format it can be read. A
// history row cannot reach its recording without it: the row carries the
// id the SESSION ran under, and recordings.fetch takes a hash of the
// recording's path, which nothing but this list holds beside the other.
func guiAdminRecordings(ctx context.Context, clientDir, machine, from, to string) ([]ui.RecordingRef, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return nil, err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	list, err := conn.RecordingsList(machine, from, to)
	if err != nil {
		return nil, err
	}
	out := make([]ui.RecordingRef, 0, len(list))
	for _, r := range list {
		out = append(out, ui.RecordingRef{
			ID: r.ID, SessionID: r.SessionID, Person: r.Person, Machine: r.Machine,
			Mode: r.Mode, Started: r.Started, Ended: r.Ended,
			BytesIn: r.BytesIn, BytesOut: r.BytesOut,
		})
	}
	return out, nil
}

// recordingFetchWindow is how much of a finished recording one call
// brings back. Larger than the live window: nothing is growing under the
// reader, and a recording somebody sat down to read should arrive in a
// few answers rather than a few hundred.
const recordingFetchWindow = 256 << 10

// guiAdminRecordingFetch reads one slice of a finished recording off the
// gateway's disk (IAMT-427).
//
// Not guiAdminSessionTail: that one resolves an id against the registry
// of recordings currently OPEN, which a finished session has left. It
// answers such a request with an honest emptiness, and an empty window
// is what pressing Transcript on a session that was just closed showed
// in practice.
//
// A transcript is many of these calls, one per window, and every one of
// them dialed the gateway, a whole SSH handshake per slice (M-12). They
// go over the window's one connection now (guiAdminLink), which also
// closes itself once nothing has used it for a while.
func guiAdminRecordingFetch(ctx context.Context, clientDir, id, part string, offset int64) ([]byte, int64, int64, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return nil, offset, 0, err
	}
	var c admin.RecordingChunk
	err = retryOnceUnlessRefused(ctx, func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := guiAdminLink.get(cs, signer)
		if err != nil {
			return err
		}
		defer conn.Close()
		c, err = conn.RecordingsFetch(id, part, offset, recordingFetchWindow)
		return err
	})
	if err != nil {
		return nil, offset, 0, err
	}
	// base64 undone here, once, as the live reader does it: handing the
	// encoded string to the window is how the window came to draw
	// base64 at somebody (IAMT-360).
	raw, derr := base64.StdEncoding.DecodeString(c.Data)
	if derr != nil {
		return nil, offset, 0, fmt.Errorf("the gateway sent a chunk that is not base64: %w", derr)
	}
	return raw, c.Offset + int64(len(raw)), c.Total, nil
}

// retryOnceUnlessRefused runs attempt, and once more when it failed below
// the gateway's own answer (M-12). A refusal the gateway named is an
// answer: asked again, it would only be given again. Anything else - a
// connection that went while the reader sat on a transcript, a gateway
// that stopped answering keepalives - is worth one more try, and the
// window's link has already put a fresh connection under it: a command
// that failed that way marked its connection broken. One more, not more:
// a gateway that fails twice running is down, and the reader is told so.
func retryOnceUnlessRefused(ctx context.Context, attempt func() error) error {
	err := attempt()
	var refused *admin.CommandError
	if err == nil || errors.As(err, &refused) {
		return err
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	return attempt()
}

// guiAdminSessionKill ends one session now (IAMT-360).
func guiAdminSessionKill(clientDir, id string) (string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SessionsKill(id, "cut off from the Admin tab"); err != nil {
		return "", err
	}
	return "Session " + id + " was cut off. Whoever was inside is out now.", nil
}

// guiAdminRiskCheck is the dry run (IAMT-360).
func guiAdminRiskCheck(clientDir, command string) (string, string, string, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", "", "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", "", "", err
	}
	defer conn.Close()
	res, err := conn.RiskCheck(command)
	if err != nil {
		return "", "", "", err
	}
	return res.Level, res.Rule, res.Reason, nil
}

// guiAdminRiskMode is the window half of "admin risk mode". It shares the
// same admin identity and wire client as the CLI and returns only the plain
// result shape internal/ui needs.
// guiAdminRiskSource changes WHICH checkers judge a command, the twin of
// guiAdminRiskMode below.
func guiAdminRiskSource(clientDir, classifier string) (ui.RiskSourceResult, error) {
	var out ui.RiskSourceResult
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return out, err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	res, err := conn.RiskSource(classifier)
	if err != nil {
		return out, err
	}
	return ui.RiskSourceResult{
		Classifier: res.Classifier, Source: res.Source,
		Changed: res.Changed, Previous: res.Previous,
	}, nil
}

func guiAdminRiskMode(clientDir, mode string) (ui.RiskModeResult, error) {
	var out ui.RiskModeResult
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return out, err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	res, err := conn.RiskMode(mode)
	if err != nil {
		return out, err
	}
	return ui.RiskModeResult{
		Mode: res.Mode, Source: res.Source,
		Changed: res.Changed, Previous: res.Previous,
	}, nil
}

// classifierKeyOutcome turns an E_RISK_KEY_REJECTED refusal into the
// window's three-outcome vocabulary's middle names: "refused" when the
// service answered and said no, "unavailable" when the trial was
// inconclusive.
//
// The reply names the class in its category field (IAMT-404), and that
// field is what decides — the sentence is read only when the gateway is
// too old to have sent one. The prose fallback repeats the exact phrase
// the gateway's own reason sentences use (internal/gateway/risk_key.go
// externalRiskKeyReplacementReason); the two agree by test
// (iamt404_risk_key_category_test.go), so an old and a new window
// reading the same refusal reach the same outcome.
func classifierKeyOutcome(ce *admin.CommandError) string {
	switch ce.Category {
	case "rejected":
		return "refused"
	case "unavailable":
		return "unavailable"
	}
	outcome := "unavailable"
	if strings.Contains(ce.Message, "rejected by the classifier service") {
		outcome = "refused"
	}
	return outcome
}

// guiAdminSetClassifierKey is the Classifier sub-tab's Replace key action
// (SPEC IAMT-403): the same dialAdmin + RiskKeyReplace "admin risk key"
// performs, reshaped into the three outcomes ui.AdminSetClassifierKeyResult
// documents.
//
// The wire protocol has one error code for "the trial did not end with a
// working new key" (E_RISK_KEY_REJECTED). Since IAMT-404 its error body
// also names the class in a category field — "rejected" (the service
// answered and said no) or "unavailable" (timeout, 5xx, no response) —
// and classifierKeyOutcome turns that field into the outcome, with the
// prose kept as the fallback for a gateway too old to send it. Any other
// error (malformed key locally, risk_classifier=rules, a dial/transport
// failure) is not part of this three-way trial outcome at all and is
// returned as a plain error, exactly like every other action here.
func guiAdminSetClassifierKey(clientDir, key string) (ui.AdminSetClassifierKeyResult, error) {
	var out ui.AdminSetClassifierKeyResult
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return out, err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return out, err
	}
	defer conn.Close()
	res, err := conn.RiskKeyReplace(key)
	if err == nil {
		return ui.AdminSetClassifierKeyResult{Outcome: "accepted", Fingerprint: res.Fingerprint}, nil
	}
	var ce *admin.CommandError
	if errors.As(err, &ce) && ce.Code == "E_RISK_KEY_REJECTED" { // errdict:internal
		return ui.AdminSetClassifierKeyResult{Outcome: classifierKeyOutcome(ce), Detail: ce.Message}, nil
	}
	return out, err
}

// adminIdentityOf reads back who this machine is on its gateway, or nil
// when no connection is saved. The saved file is the only authority: the
// window asks it rather than remembering, so an identity gained or
// dropped anywhere else still reaches the Join card (IAMT-389).
func adminIdentityOf(clientDir string) *ui.AdminIdentity {
	who, _ := readAdminIdentity(clientDir)
	return who
}

// readAdminIdentity is the same read, with the ANSWER and the QUESTION
// kept apart: who this machine is, and whether that could be established
// at all.
//
// The second return is the whole point (22.09.2026, found in review).
// client.LoadConnection refuses for two unrelated reasons:
// there is no saved connection, or there is one and it could not be
// read -- a directory whose permissions changed under the window, a
// half-written file, a symlink the reader is right to refuse. Folding
// both into a nil pointer made the window announce the first when it had
// only met the second, and invite an administrator to join a gateway he
// had already joined.
//
// It is the same distinction IAMT-311 drew for the server's own facts,
// and the same one HeldKnown draws for the held list: an unreadable
// answer is not a negative answer.
func readAdminIdentity(clientDir string) (*ui.AdminIdentity, bool) {
	cs, err := client.LoadConnection(clientDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Established: there is nothing saved here.
			return nil, true
		}
		return nil, false
	}
	return &ui.AdminIdentity{
		Person:  cs.Person,
		Gateway: fmt.Sprintf("%s:%d", cs.Host, cs.Port),
		HostKey: cs.Fingerprint,
	}, true
}

// guiAdminForget drops the identity this machine carries (IAMT-356).
func guiAdminForget(clientDir string) (string, error) {
	// A write into the client directory: the foreign-directory gate first
	// (IAMT-333; review finding R4 N-01 recheck), like every other window action.
	if err := refuseForeignDataDir(nil, "admin forget", clientDir, false); err != nil {
		return "", err
	}
	had, err := client.ForgetConnection(clientDir)
	if err != nil {
		return "", err
	}
	if !had {
		return "There was nothing to forget - this machine carries no identity.", nil
	}
	return "Forgotten. This machine is nobody on that gateway now; its key is untouched, " +
		"and the person record on the gateway still exists until an administrator removes it.", nil
}

// guiAdminPairingStart is the "Pairing window" card's Start — the same
// wire work "admin pairing start" performs (dialAdmin + PairingStart),
// reshaped into what the card's facts show. An expiry that does not
// parse stays a zero time, which the card draws as "—" rather than a
// made-up moment.
func guiAdminPairingStart(clientDir string) (ui.PairingWindow, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return ui.PairingWindow{}, err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return ui.PairingWindow{}, err
	}
	defer conn.Close()
	res, err := conn.PairingStart()
	if err != nil {
		return ui.PairingWindow{}, err
	}
	expires, _ := time.Parse(time.RFC3339, res.Expires)
	return ui.PairingWindow{Pin: res.Pin, Ref: res.Ref, Expires: expires}, nil
}

// guiAdminPairingStop is the card's Stop — the same dialAdmin +
// PairingStop the CLI verb runs.
func guiAdminPairingStop(clientDir string) (bool, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return false, err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	return conn.PairingStop()
}

// guiAdminPeopleAdd is the "Add person" card — the same shape checks the
// CLI verb's check function makes (role user|admin, a valid name, a
// valid public key) and the same dialAdmin + PeopleAdd it calls.
func guiAdminPeopleAdd(clientDir, name, role, key string) (string, error) {
	if role == "" {
		role = "user"
	}
	if role != "user" && role != "admin" {
		return "", fmt.Errorf("the role must be %q or %q", "user", "admin")
	}
	if !config.ValidName(name) {
		return "", config.NameError("person", name)
	}
	if _, err := config.CheckPublicKey(key); err != nil {
		return "", err
	}
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	res, err := conn.PeopleAdd(name, role, []string{key})
	if err != nil {
		return "", err
	}
	added := fmt.Sprintf("Added person %q (role %s, %d key(s)).", res.Name, res.Role, len(res.Keys))
	// The string the new person saves is the other half of adding them
	// (R4 F-14): without it here the administrator had to leave the
	// window, or build it by hand. The person is added either way; a
	// failure to fetch the string is said, not turned into a failed add.
	cstr, err := conn.PeopleConnectionString(res.Name)
	if err != nil {
		return added + " Their connection string could not be fetched (" + err.Error() + "); \"iamtunnel admin people connection-string " + res.Name + "\" prints it.", nil
	}
	return added + " Send them their connection string: " + cstr, nil
}

// guiAdminMachineEnrolCode is the "Invite machine" card — the same
// dialAdmin + MachinesInvite the CLI verb runs, so the two paths cannot
// mint different invitations.
//
// It takes the NAME the administrator chooses for this registration and
// nothing else (SPEC §3.4, 1.4). It takes no OS user: that was never the
// administrator's fact to supply — requiring a DOMAIN\user before a
// machine could be invited at all was a defect seen in practice — and
// the machine reports its own account when it registers.
// The code and the expiry come back SEPARATELY. They used to be glued
// into one sentence, and that sentence was the only thing the window
// showed: the code could not be copied without the words around it
// (IAMT-355).
func guiAdminMachineEnrolCode(clientDir, name string) (string, string, error) {
	if !config.ValidName(name) {
		return "", "", config.NameError("name", name)
	}
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return "", "", err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	code, expires, err := conn.MachinesInvite(name)
	if err != nil {
		return "", "", err
	}
	return code, expires, nil
}

// guiAgentPrompt is the Client screen's "Copy AI prompt" button (IAMT-223,
// umtunnel's "Copy briefing for an AI"): the text an AI agent needs to run
// commands on one machine with the stock OpenSSH client. The gateway key the
// client pinned is rewritten into an OpenSSH-format known_hosts file next to
// it, so the agent keeps strict host key checking.
func guiAgentPrompt(clientDir, machine string) (string, error) {
	if !config.ValidName(machine) {
		return "", config.NameError("machine", machine)
	}
	// It writes agent_known_hosts into the client directory: the
	// foreign-directory gate first (IAMT-333; review finding R4 N-01 recheck).
	if err := refuseForeignDataDir(nil, "agent prompt", clientDir, false); err != nil {
		return "", err
	}
	cs, err := client.LoadConnection(clientDir)
	if err != nil {
		return "", fmt.Errorf("no connection string saved yet — save one above first")
	}
	// datafile.ReadFile (IAMT-332 round 9): a symlink or FIFO planted at
	// the recorded key's name is refused instead of read through or wedged
	// on. Any read failure — including a refusal — lands in the same
	// "press Connect once first" hint as before.
	recorded, err := datafile.ReadFile(client.KnownHostsPath(clientDir))
	if err != nil {
		return "", fmt.Errorf("press Connect once first: the gateway key is recorded on the first connection")
	}
	prefix := fmt.Sprintf("%s:%d ", cs.Host, cs.Port)
	var keyLine string
	for _, line := range strings.Split(string(recorded), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		pk, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(strings.TrimPrefix(line, prefix)))
		if perr == nil && ssh.FingerprintSHA256(pk) == cs.Fingerprint {
			keyLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk)))
			break
		}
	}
	if keyLine == "" {
		return "", fmt.Errorf("press Connect once first: no recorded gateway key matches the saved connection")
	}
	// An IPv6 gateway is saved as "[addr]"; OpenSSH wants the bare address
	// as the destination and one pair of brackets in known_hosts (IAMT-231).
	host := strings.TrimSuffix(strings.TrimPrefix(cs.Host, "["), "]")
	hostPattern := host
	if cs.Port != 22 {
		hostPattern = fmt.Sprintf("[%s]:%d", host, cs.Port)
	}
	agentKnownHosts := filepath.Join(clientDir, "agent_known_hosts")
	// WriteFileAtomic, not the flat write this was (IAMT-332 round 9): the
	// GUI may run elevated, and the client directory is not exempt from the
	// planted-name rule (SPEC §3.1) — a symlink (POSIX) or hard link
	// (Windows, no privilege needed) planted at this predictable name used
	// to aim the write at somebody else's file. The rename acts on the
	// entry, never through it.
	if err := datafile.WriteFileAtomic(agentKnownHosts, []byte(hostPattern+" "+keyLine+"\n"), datafile.WithMode(0o600)); err != nil {
		return "", fmt.Errorf("could not write %s: %w", agentKnownHosts, err)
	}
	sshLine := fmt.Sprintf(`ssh -i "%s" -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="%s" -p %d -l %s:%s %s "hostname"`,
		client.KeyPath(clientDir), agentKnownHosts, cs.Port, cs.Person, machine, host)
	return fmt.Sprintf(`You have temporary, recorded SSH access to the Windows machine %q through the iamtunnel gateway. Everything you run and everything it prints is recorded, and the administrator can end the access at any moment.

Run each command as one non-interactive ssh call:

  %s

Replace the last quoted argument ("hostname") with your command. On the machine it runs in the default OpenSSH shell (usually Windows PowerShell), so write Windows commands.

Files: scp and sftp are not available. Send data as base64 on standard input and read it with $input (not [Console]::In, which hangs on Windows OpenSSH for larger input):

  upload:   base64 of the local file | <the ssh call above with this command>  '$b = -join $input; [IO.File]::WriteAllBytes("C:\Users\Public\file.bin", [Convert]::FromBase64String($b))'
  download: <the ssh call above with this command>  '[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\path\file.bin"))'  > file.b64, then decode it locally (PowerShell ends the output with CR LF: strip it first, e.g. tr -d '\r\n' < file.b64 | base64 -d > file.bin)

Check the SHA-256 of both copies. A note that the session is recorded is printed to standard error, never into a command's output.

Rules:
- One command per call; you have no interactive terminal.
- If ssh is refused or the host key does not match, stop and tell the person. Do not retry with other names, keys, ports or options, and never turn host key checking off.
- Do not change accounts, services, firewall or security settings on the machine unless the person explicitly asked for exactly that.
`, machine, sshLine), nil
}

// guiClientRiskApprove lifts one pending "ask"-mode refusal (IAMT-394):
// the same "risk.approve" the CLI verb sends, over the same command-login
// connection the window already uses for everything else. It approves the
// id and nothing more -- re-running the command is the window's next,
// separate act, and the gateway checks the command string again then.
// guiSessionsHistory reads one page of the past for the History tab
// (21.09.2026). The journal has held all of it since 1.0; nothing in the
// window ever showed it.
func guiSessionsHistory(clientDir, person, machine, from, to string, limit, offset int) (ui.HistoryPage, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return ui.HistoryPage{}, err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return ui.HistoryPage{}, err
	}
	defer conn.Close()
	page, err := conn.SessionsHistory(person, machine, from, to, limit, offset)
	if err != nil {
		return ui.HistoryPage{}, err
	}
	out := ui.HistoryPage{Total: page.Total, Offset: page.Offset, Limit: page.Limit}
	for _, r := range page.Sessions {
		out.Rows = append(out.Rows, ui.HistoryRow{
			SessionID:  r.SessionID,
			Person:     r.Person,
			Machine:    r.Machine,
			Started:    r.Started,
			Ended:      r.Ended,
			Kind:       r.Kind,
			Command:    r.Command,
			Goal:       r.Goal,
			Outcome:    r.Outcome,
			Risks:      r.Risks,
			RiskLevel:  r.RiskLevel,
			RiskRule:   r.RiskRule,
			RiskReason: r.RiskReason,
		})
	}
	return out, nil
}

// guiClientRiskPending and guiClientRiskDeny are the other two halves of
// settling a held command from the window (21.09.2026). Approving already
// had a wire; asking WHAT is held, and saying no to it, did not -- which
// is why the only way to find out was to read it off an agent's refusal.
func guiClientRiskPending(clientDir string) ([]ui.HeldCommand, error) {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return nil, err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	held, err := conn.RiskPending()
	if err != nil {
		return nil, err
	}
	out := make([]ui.HeldCommand, 0, len(held))
	for _, h := range held {
		// A deadline that will not parse becomes the zero time, and the
		// window prints no countdown for it. Guessing "five minutes from
		// now" would be worse than saying nothing: the person would act
		// on a number the gateway never gave.
		expires, _ := time.Parse(time.RFC3339, h.ExpiresAt)
		out = append(out, ui.HeldCommand{
			ApprovalID: h.ApprovalID,
			Machine:    h.Machine,
			Command:    h.Command,
			Rule:       h.Rule,
			Reason:     h.Reason,
			Level:      h.Level,
			Expires:    expires,
		})
	}
	return out, nil
}

func guiClientRiskDeny(clientDir, approvalID string) error {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return err
	}
	defer conn.Close()
	return conn.RiskDeny(approvalID)
}

func guiClientRiskApprove(clientDir, approvalID string) error {
	cs, signer, err := loadClientIdentity(clientDir)
	if err != nil {
		return err
	}
	conn, err := guiAdminLink.get(cs, signer)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.RiskApprove(approvalID)
	return err
}

// guiClientPublicKey is the person's own public key for Client → Key -
// shown whether or not a connection string is saved (R4 F-14). The key is
// this machine's identity, created on first need as "client key" does; an
// administrator needs it BEFORE the person exists, and waiting for a
// connection string the product only gives existing people was a circle.
func guiClientPublicKey(clientDir string) string {
	// Creating the key is a write: an elevated window pointed at a data
	// directory somebody else owns shows no key rather than writing one
	// there (IAMT-333; review finding R4 N-01). The window has no override flag.
	if err := refuseForeignDataDir(nil, "client key", clientDir, false); err != nil {
		return ""
	}
	signer, err := client.EnsureKey(clientDir)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}
