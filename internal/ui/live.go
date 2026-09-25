//go:build windows || linux || darwin

package ui

// The live half of the window (IAMT-149, IAMT-151): the one exported way
// a new reality reaches the screens, the per-control state the screens
// need in order to be more than a showcase (an editor, a status line, a
// "this is running" flag), and the small runner that keeps a network
// operation off the drawing goroutine.
//
// What is deliberately NOT here: role logic. The window never dials a
// gateway, never opens a data directory and never parses a protocol
// shape. It calls the function values in Actions, which cmd/iamtunnel
// fills from the very code its CLI verbs already run, and it words the
// outcome. That keeps SPEC §7.1 ("the GUI holds no role logic") true
// with the buttons live, and keeps internal/ui's import list free of
// internal/client, internal/admin and internal/config.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gioui.org/layout"
	"gioui.org/widget"

	"github.com/ultrathinker/iamtunnel/internal/paste"
	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// Control names. One name per thing a person can press or type into;
// the button, the editor and the status line under it all share it, so
// there is no way for a screen to show the outcome of one control under
// another.
const (
	ctlSetupRegister      = "setup/register"
	ctlClientSave         = "client/connect-string"
	ctlClientName         = "client/connect-string/name"
	ctlClientGateways     = "client/gateways"
	ctlClientRefresh      = "client/machines"
	ctlRestartAdmin       = "notice/restart-admin"
	ctlHeldOpen           = "notice/held-open"
	ctlServerStart        = "server/start"
	ctlServerStop         = "server/stop"
	ctlAdminGrant         = "admin/grant"
	ctlAdminRiskMode      = "admin/risk-mode"
	ctlAdminClassifierKey = "admin/classifier-key"

	// The Admin tab's pairing and issuing cards (IAMT-327, SPEC §7.1).
	ctlAdminPairJoin     = "admin/pair-join"
	ctlAdminForget       = "admin/forget"
	ctlAdminRefresh      = "admin/refresh"
	ctlAdminPairingStart = "admin/pairing-start"
	ctlAdminPairingStop  = "admin/pairing-stop"
	ctlAdminPeopleAdd    = "admin/people-add"
	ctlAdminEnrolCode    = "admin/enrol-code"

	// The Session tab's controls (IAMT-341, contract §4, §5).
	ctlSessionExport = "session/export"
)

// Actions is the work the window may ASK for, and the way it asks for a
// repaint when that work has finished somewhere else. Every field is a
// plain function value supplied by the caller that opens the window
// (cmd/iamtunnel), and every one of them may be nil: a frame built
// without them draws exactly as before and refuses each press with a
// visible sentence instead of doing half of something.
type Actions struct {
	// Repaint asks the window for another frame. A background operation
	// that has just finished has no other way to be seen: the drawing
	// goroutine is asleep until something wakes it. (*app.Window).Invalidate
	// is what the live window passes; the offscreen shot and the tests
	// pass nothing, because they draw exactly one frame on purpose.
	Repaint func()

	// Enrol registers THIS machine from a one-time enrol code (SPEC §3.4)
	// and returns the machine id the gateway assigned and the OS account
	// the registration was bound to. It is the same work "iamtunnel enrol
	// <code>" performs, in this process.
	//
	// The account comes back through the RETURN VALUE (21.09.2026). It
	// used to be read from the record on the caller's side and posted
	// into a shadow copy of the window state kept beside the window --
	// and so the window itself, the thing that draws it, never learned
	// it. A result an action produces is the action's to return.
	Enrol func(code string) (machine, osUser string, err error)

	// SaveConnection remembers the connection string a person was given
	// (SPEC §3.1), makes that gateway the current one, and returns one
	// line describing what is now saved. name is the label it will be
	// known by; empty means "name it after its host".
	//
	// replace repeats the CLI's --replace, and since 22.09.2026 it
	// guards a narrower thing: not "a different gateway is saved" --
	// several may be -- but the SAME gateway presenting a different host
	// key, which is the same address with a new lock.
	SaveConnection func(connString, name string, replace bool) (string, error)

	// ClientGateways reads the gateways this machine remembers and which
	// one is current. It touches no network: the list is a fact about
	// this machine, and the one party with no business knowing it is a
	// gateway.
	ClientGateways func() ([]GatewayRef, string, error)

	// ClientUseGateway switches to a remembered gateway and returns one
	// line saying what is now in use.
	//
	// Nothing is dialled and nothing is asked. Authentication here is
	// the key in the client directory, one per machine, and every
	// gateway that knows this person already holds its public half --
	// so a prompt of any kind would be a ceremony we invented.
	ClientUseGateway func(name string) (string, error)

	// ClientForgetGateway drops one remembered gateway. The key stays,
	// and so does the person record on that gateway.
	ClientForgetGateway func(name string) (string, error)

	// GatewayStatus, GatewayInstall and GatewayUninstall are the Gateway
	// tab's half of "iamtunnel gateway status / install / uninstall"
	// (IAMT-434).
	//
	// They run the CLI's own functions rather than a second copy of the
	// logic. Installing a gateway means an ACL on the data directory, a
	// service under an account that can read the binary, a host key and
	// a one-time bootstrap token; a window with its own version of that
	// would be a second thing to keep correct, and the half that is
	// pressed less often is the half that rots.
	GatewayStatus    func() (GatewayState, error)
	GatewayInstall   func(host string, port int) (string, error)
	GatewayUninstall func() (string, error)

	// GatewayCopyExe puts this program where a Windows service account
	// can read it, and returns where that is.
	//
	// It exists because the refusal it answers is correct and useless to
	// the person meeting it: a service account cannot read another
	// account's profile, so an .exe run from Downloads installs a
	// service that later fails to start. The console's answer is "copy
	// it to Program Files yourself", which is the console this screen
	// exists to avoid.
	GatewayCopyExe func() (string, error)

	// Machines asks the gateway which machines this person may enter
	// right now (PROTOCOL §6 "machines.mine"), already in the window's
	// own shape. The context is cancelled when the operation is given up.
	Machines func(ctx context.Context) ([]MachineAccess, error)

	// ClientExec runs one command on machine through an exec grant
	// (SPEC §6.5) — the same work "iamtunnel client exec
	// <machine> -- <command>" performs. It is the Client tab's exec-only
	// row's Run button (client_exec.go). Like AdminRiskCheck, it hands
	// back plain strings rather than a window-shaped type (ClientExecResult):
	// stdout and stderr are kept apart on purpose so client_exec.go's
	// classifyExecStderr can read the
	// gateway's verdict out of stderr alone, the same way it always has —
	// the action stays ignorant of window/color concerns, exactly as
	// AdminRiskCheck's own (level, rule, reason) does.
	ClientExec func(ctx context.Context, machine, command string) (stdout, stderr string, err error)

	// ClientRiskApprove lifts one pending "ask"-mode refusal (IAMT-394).
	// It approves exactly the command the refusal named and nothing
	// else; the caller then re-runs that command, which the gateway
	// lets through once before the approval is burnt.
	ClientRiskApprove func(ctx context.Context, approvalID string) error

	// ServerStart asks this machine's own "server start" to come up —
	// the window never becomes the server process itself (IAMT-181): a
	// nil error here means the attempt was made, not that the tunnel is
	// already up. The Server screen's own facts catch up on their own
	// once UpdateSnapshot next reports it (IAMT-182).
	ServerStart func() (string, error)

	// ServerStop cuts the door and the tunnel off — the control that must
	// work from every tab, on the first screenful. It is the
	// same control-port request "iamtunnel server stop" makes.
	ServerStop func() (string, error)

	// AdminGrant hands one person access to one machine, until the given
	// deadline (empty means indefinite) — the same work "admin grants
	// grant" performs.
	AdminGrant func(person, machine, until string) (string, error)

	// AdminGrantWithCaps is the capability-aware form of AdminGrant. It is
	// separate so older embedded frames keep the shell-default grant action.
	AdminGrantWithCaps func(person, machine, until, capability string) (string, error)

	// AdminRevoke takes access back and reports how many live sessions
	// that ended — the same work "admin grants revoke" performs.
	AdminRevoke func(person, machine string) (string, error)

	// SessionsHistory reads one page of the past, newest first. The
	// filters are the gateway's: person, machine and a time range, with
	// limit and offset for the page.
	SessionsHistory func(ctx context.Context, person, machine, from, to string, limit, offset int) (HistoryPage, error)

	// ClientRiskPending asks the gateway what it is holding for this
	// person. Polled, because a held command arrives while nobody is
	// looking at this window.
	ClientRiskPending func(ctx context.Context) ([]HeldCommand, error)

	// ClientRiskDeny settles one held command with a no.
	ClientRiskDeny func(ctx context.Context, approvalID string) error

	// AdminSetGrantCaps changes what one grant permits -- "shell" or
	// "exec" -- without taking the grant away and issuing a new one. It
	// is an ADMINISTRATOR's action even though the client's machine row
	// is where it is reached from: the person entering must never be able
	// to widen their own access, or the narrow mode protects nothing.
	AdminSetGrantCaps func(person, machine, capability string) (string, error)

	// AdminExtend moves the deadline of one existing grant -- the same
	// work "admin grants extend" performs. A later deadline (or "until
	// revoked", making the grant indefinite) touches no live session;
	// a shorter one follows revoke rules and closes the sessions opened
	// on the grant right now, which the returned message reports.
	AdminExtend func(person, machine, until string) (string, error)

	// AdminRenamePerson renames one person -- the same work "admin
	// people rename" performs. The gateway moves the person's grants
	// and goals to the new name in one write and closes the sessions
	// opened under the old name (the key follows the person); the
	// returned message reports what closed, or repeats what refused it.
	AdminRenamePerson func(from, to string) (string, error)

	// AdminRenameMachine changes one machine's display label -- the
	// same work "admin machines rename" performs. Only the label
	// changes: the machine's id, its grants and the journal keep
	// pointing at the same machine.
	AdminRenameMachine func(id, name string) (string, error)

	// AdminRemovePerson deletes a person from the gateway, with every
	// grant and goal that named them -- the same work "admin people
	// remove" performs. The gateway refuses to remove its last
	// administrator, and that refusal arrives here as an ordinary error
	// for the row to print.
	AdminRemovePerson func(name string) (string, error)

	// AdminRemoveMachine deletes a machine the same way. Its grants go
	// with it, and anyone inside it right now is put out.
	AdminRemoveMachine func(id string) (string, error)

	// AdminGrantGoal claims (or replaces) the working goal of one
	// grant (SPEC IAMT-402): the words a context-aware classifier reads
	// a command against instead of judging it alone. It is keyed by the
	// same person+machine pair AdminGrant and AdminRevoke already take —
	// the goal belongs to that grant, not to a screen — and the
	// window expects AdminList's next Grant.Goal and
	// Grant.RecentGoals for this pair to reflect whatever the gateway
	// just accepted; there is no separate read action.
	AdminGrantGoal func(person, machine, goal string) (string, error)

	// AdminSetClassifierKey replaces the typesafe.ai classifier key (SPEC
	// IAMT-403). The gateway trials the new key with one real request
	// before switching to it, so a refusal never touches an
	// already-working key — see AdminSetClassifierKeyResult for the three
	// outcomes that trial can end in. The key text is the one argument
	// this action ever sees; it is not returned, logged by the window or
	// echoed back in any result field.
	AdminSetClassifierKey func(key string) (AdminSetClassifierKeyResult, error)

	// AdminPairClaim spends a pairing PIN (SPEC §3.5, IAMT-323): this
	// machine's own client key becomes a PERMANENT administrator — the
	// same work "iamtunnel admin pair <ref> <pin>" performs, the GUI
	// form of it. A wrong PIN, a closed window or a lockout is the
	// gateway's own refusal, worded by the wire error.
	//
	// It returns the identity this machine now carries, read back from
	// the connection the claim has just written, so the window stops
	// offering to join a gateway it has already joined (22.09.2026).
	AdminPairClaim func(ref, pin string) (string, *AdminIdentity, error)

	// AdminClaim spends the one-time BOOTSTRAP token of SPEC §3.3 — the
	// other way a key becomes an administrator, and the FIRST one: it is
	// how a gateway that has no administrator at all gets its first.
	// "iamtunnel admin claim" performs the same work.
	//
	// It is separate from AdminPairClaim on purpose. Both arrive through
	// the same box and both end with this machine's key being an admin
	// key, but nothing else about them is shared: the bootstrap token is
	// not a six-digit PIN, the login role on the wire is "bootstrap"
	// rather than "pairing", and the gateway answers a different command.
	// Routing a claim string into the pairing action is what 19.09.2026
	// looked like from the maintainer's chair: the line above the button said
	// "This will make THIS machine the first administrator", and the
	// button answered "the PIN must be exactly 6 decimal digits".
	//
	// Like AdminPairClaim it returns the identity this machine now
	// carries: the card it is pressed from otherwise goes on offering the
	// same one-time token for up to three seconds after it was spent, and
	// a second press spends nothing and is refused.
	AdminClaim func(ref, token string) (string, *AdminIdentity, error)

	// AdminList fetches what the Admin tab shows: people, machines and
	// grants, in one connection (IAMT-357).
	//
	// Until 19.09.2026 there was no such action at all. Every list on the
	// Admin tab was drawn from a snapshot field nothing ever wrote, so
	// People, Machines and Access were permanently empty and the pickers
	// on the grant form had nothing to offer -- on a gateway with a
	// person and a machine already on it. The maintainer had to read a name
	// off a terminal and type it back in.
	AdminList func(ctx context.Context) (AdminLists, error)

	// AdminSessionsActive, AdminSessionTail and AdminSessionKill are the
	// window's half of "sessions active", "sessions tail" and "sessions
	// kill" (IAMT-360). The gateway answers all three: it is the only
	// party that knows what is happening on a machine it stands in front
	// of, and a window that summarised its own guess about a live
	// session would be the most dangerous kind of wrong.
	//
	// chunk is the recording's own bytes, base64 already undone. What
	// the gateway sends is asciicast: a header line and one JSON array
	// per write. It is NOT text, and showing it as text is what the
	// maintainer saw on 19.09.2026 -- a screenful of base64, and under it,
	// had it been decoded, would have been a screenful of JSON. It goes
	// through the same terminal emulator the Session tab uses.
	//
	// mode is how chunk is read (IAMT-453): "exec" for an exec session's
	// recording, anything else for asciicast - see record.ParserFor.
	AdminSessionTail func(ctx context.Context, id string, offset int64) (chunk []byte, next, total int64, live bool, mode string, err error)
	AdminSessionKill func(id string) (string, error)

	// AdminRecordings lists the recordings the gateway still holds --
	// "recordings.list". It is the other half of the history: the
	// journal says a visit happened, this says whether its transcript
	// survives. Recordings are pruned at ninety days and sooner when the
	// disk fills, and the journal is not pruned with them, so a row can
	// outlive its bytes and the screen must be able to say so.
	//
	// It is also what turns a history row into something readable at
	// all: a row carries the id the SESSION ran under, and only this
	// list maps that to the id recordings.fetch accepts.
	AdminRecordings func(ctx context.Context, machine, from, to string) ([]RecordingRef, error)

	// AdminRecordingFetch reads one finished recording off the gateway's
	// disk -- "recordings.fetch". part is "cast" for a terminal session,
	// "exec" for a single command, "txt" for the plain-text rendering
	// the gateway keeps beside a terminal recording.
	//
	// Not to be confused with AdminSessionTail above, which follows a
	// session that is still running and can answer nothing at all about
	// one that has finished (transcript_window.go, transcriptFeed).
	AdminRecordingFetch func(ctx context.Context, id, part string, offset int64) (chunk []byte, next, total int64, err error)

	// AdminRiskCheck asks what the gateway would make of one command,
	// without running it anywhere. The gateway and not a copy of the
	// rules in this binary: the answer is only worth having if it is the
	// answer the machine would actually get.
	AdminRiskCheck func(command string) (level, rule, reason string, err error)

	// AdminRiskMode reads or changes the gateway's live safety mode. The
	// current value is fetched with AdminList; this action is only for the
	// three explicit mode buttons.
	AdminRiskMode func(mode string) (RiskModeResult, error)

	// AdminRiskSource reads or changes WHICH checkers judge a command --
	// rules, ai or both (21.09.2026). Its twin above decides what is
	// done with a red verdict; this one decides who reaches it. The
	// gateway refuses "ai" and "both" when it holds no classifier key,
	// and the window says so before the press rather than after.
	AdminRiskSource func(classifier string) (RiskSourceResult, error)

	// AdminForget drops the identity this machine carries on its gateway
	// (IAMT-356) -- the local half of leaving. It removes the saved
	// connection and nothing else: the person record on the gateway
	// survives, and only an administrator there can take it away.
	AdminForget func() (string, error)

	// AdminPairingStart opens a new pairing window over the network —
	// "iamtunnel admin pairing start"'s work; the result is exactly what
	// the card shows: the PIN, the ready reference and the moment the
	// window closes itself.
	AdminPairingStart func() (PairingWindow, error)

	// AdminPairingStop closes the pairing window and reports whether one
	// was actually open — "iamtunnel admin pairing stop"'s work.
	AdminPairingStop func() (bool, error)

	// AdminPeopleAdd creates a person with one public key — the same
	// work "admin people add" performs. The role is "user" or "admin".
	AdminPeopleAdd func(name, role, key string) (string, error)

	// AdminMachinesEnrolCode mints one machine invitation — the same work
	// "admin machines enrol-code" performs; the string is what the new
	// machine's own Set up screen consumes. It takes the NAME the
	// administrator chooses for this registration and nothing else: the
	// OS account is the machine's own report, made when it redeems the
	// code (SPEC §3.4).
	//
	// It returns the code and the moment it expires as two strings, not
	// one sentence: the code is pasted verbatim into another window, and
	// anything glued to it travels with it into the paste (IAMT-355).
	AdminMachinesEnrolCode func(name string) (code, expires string, err error)

	// The rest of SPEC §3.3 in the window (IAMT-499): "the tab and the
	// console do the same thing". Each is the same dialAdmin + admin.Conn
	// call its CLI verb makes, named after it, and each returns the
	// sentence its row prints. Until 24.09.2026 none of them was drawn, so
	// a machine whose sshd key had changed could only be let back in from
	// a terminal.
	//
	// AdminMachineVerify runs the gateway's sshd probe now ("machines
	// verify"); AdminMachineSetUser changes the OS account ("machines
	// set-user"), which shuts the door and re-probes; AdminMachineRekey
	// accepts the sshd host key the gateway observed ("machines rekey"),
	// given back as the fingerprint the administrator has confirmed.
	AdminMachineVerify  func(id string) (string, error)
	AdminMachineSetUser func(id, osUser string) (string, error)
	AdminMachineRekey   func(id, confirmFingerprint string) (string, error)

	// AdminPersonKeyAdd and AdminPersonKeyRemove are "people keys add" and
	// "people keys remove"; AdminPersonConnectionString is "people
	// connection-string" -- the line handed to the person, returned alone
	// so the row can put it in a box that copies.
	AdminPersonKeyAdd           func(name, pubkey string) (string, error)
	AdminPersonKeyRemove        func(name, fingerprint string) (string, error)
	AdminPersonConnectionString func(name string) (string, error)

	// AdminGatewayFingerprint, AdminGatewayBackup and
	// AdminGatewayRotateHostkey are "gateway fingerprint", "gateway
	// backup" and "gateway rotate-hostkey". The last cuts every client and
	// machine off at once (SPEC §6.2: no transition period in v1), so the
	// window asks twice before it sends it.
	AdminGatewayFingerprint   func() ([]string, error)
	AdminGatewayBackup        func() (string, error)
	AdminGatewayRotateHostkey func() (string, error)

	// ClientConnect opens a terminal window with a session on one machine
	// (IAMT-223) — "iamtunnel client connect <machine>" in its own console.
	ClientConnect func(machine string) (string, error)

	// AgentPrompt returns the text an AI agent needs to run commands on one
	// machine with the stock OpenSSH client (IAMT-223).
	AgentPrompt func(machine string) (string, error)

	// RestartAsAdmin starts this program again with administrator rights
	// (Windows asks for consent) and ends this copy. It returns only on
	// failure — the person said No, or the start did not happen.
	RestartAsAdmin func() error

	// SessionTail fetches a chunk of the .cast stream for an active or finished
	// session (contract §1 sessions.tail).
	SessionTail func(ctx context.Context, req SessionTailReq) (SessionTailResp, error)

	// SessionList asks for the list of active sessions (contract §4).
	// For an admin this lists all active sessions (sessions.active);
	// for a machine owner it returns sessions on this machine.
	SessionList func(ctx context.Context) ([]SessionInfo, error)

	// SessionExport exports the recorded session to disk (contract §5).
	SessionExport func(sessionID string) (string, error)
}

// SessionTailReq is the input for Actions.SessionTail.
type SessionTailReq struct {
	ID     string `json:"id"`
	Offset uint64 `json:"offset"`
	Limit  uint32 `json:"limit"`
}

// SessionTailResp is the result of Actions.SessionTail.
type SessionTailResp struct {
	ID     string `json:"id"`
	Offset uint64 `json:"offset"`
	Total  uint64 `json:"total"`
	Live   bool   `json:"live"`
	Data   []byte `json:"data"`
	// Mode is how Data is read, as the gateway said (IAMT-453): "exec" or
	// asciicast - see record.ParserFor.
	Mode string `json:"mode"`
}

// RecordingRef is one finished recording as the gateway lists it.
//
// TWO IDENTIFIERS, and they are not interchangeable. ID is the gateway's
// handle for the file -- a hash of its path, opaque, and the only thing
// recordings.fetch accepts. SessionID is what the session was called
// while it ran, which is what History shows and what a person reads off
// the screen. A window that has a history row holds the second and needs
// the first, and nothing but this list can get it there.
type RecordingRef struct {
	ID        string
	SessionID string
	Person    string
	Machine   string

	// Mode is "exec" for a single command recorded line by line and
	// empty (or anything else) for a terminal session in asciicast.
	// The reader must be chosen by this and never by the bytes.
	Mode string

	Started  string
	Ended    string
	BytesIn  int64
	BytesOut int64
}

// Part names the file inside a recording that carries the transcript.
func (r RecordingRef) Part() string {
	if r.Mode == "exec" {
		return "exec"
	}
	return "cast"
}

// SessionInfo describes an active session for the Session tab switcher.
type SessionInfo struct {
	ID      string    `json:"id"`
	Person  string    `json:"person"`
	Machine string    `json:"machine"`
	Started time.Time `json:"started"`
	Until   time.Time `json:"until"`
}

// saying is one status line under a control: the words, and the KIND of
// news they are. The kind picks the color, so the same sentence reads on
// a light desktop and a dark one (umtunnel's EnrolView.Say).
type saying struct {
	text string
	key  design.ColorKey

	// give is the string this action HANDED the person, when it handed
	// one: an enrol code, a connection line. It is kept apart from text
	// because the two are read differently -- text is a sentence to
	// understand and forget, give is a token to carry away exactly, and
	// only the second belongs in a box that can be selected and copied.
	// Before 19.09.2026 the enrol code arrived inside text, was drawn as
	// a status line, and could not be copied at all.
	give string
}

// takeSnapshot picks up a handed-over snapshot at the start of a frame.
func (f *Frame) takeSnapshot() {
	f.mu.Lock()
	var arrived bool
	if f.pending != nil {
		// A HELD command that was not there before is the one piece of
		// state this window must not wait to be noticed (21.09.2026): an
		// agent is stopped mid-work and the offer lapses in five minutes.
		// So the taskbar button flashes and the system's notification
		// sound plays -- once per new request, keyed by approval id, so a
		// poll every few seconds does not become a metronome.
		known := f.heldSeen
		if known == nil {
			known = make(map[string]bool)
			f.heldSeen = known
		}
		for _, h := range f.pending.Client.Held {
			if !known[h.ApprovalID] {
				known[h.ApprovalID] = true
				arrived = true
			}
		}
		live := make(map[string]bool, len(f.pending.Client.Held))
		for _, h := range f.pending.Client.Held {
			live[h.ApprovalID] = true
		}
		for id := range known {
			if !live[id] {
				delete(known, id)
			}
		}
		f.snap = *f.pending
		f.pending = nil
	}
	hwnd := f.hwnd
	settled := len(f.snap.Client.Held) == 0
	f.mu.Unlock()

	switch {
	case arrived:
		callForAttention(hwnd)
	case settled:
		// Nothing is waiting any more, so nothing should still be asking.
		stopCallingForAttention(hwnd)
	}
}

// setWindowHandle records the main window's OS handle so the frame can
// ask for attention when a command is held. It is set from the one place
// gio offers the handle, and is zero everywhere that has no such notion.
func (f *Frame) setWindowHandle(hwnd uintptr) {
	f.mu.Lock()
	f.hwnd = hwnd
	f.mu.Unlock()
}

// reviseSnapshot edits the reality the window will draw next. It writes
// the same single field UpdateSnapshot writes, through the same handover,
// and exists so a finished action (an enrolment, a machines refresh) can
// report its result as STATE rather than only as a sentence.
func (f *Frame) reviseSnapshot(edit func(*Snapshot)) {
	f.mu.Lock()
	next := f.snap
	if f.pending != nil {
		next = *f.pending
	}
	edit(&next)
	f.pending = &next
	f.mu.Unlock()
	f.repaint()
}

// repaint asks the window for a fresh frame, if anybody is listening.
func (f *Frame) repaint() {
	if r := f.cfg.Actions.Repaint; r != nil {
		r()
	}
}

// editor returns the text field of a named control, creating it on first
// use — the same discipline btn() uses for buttons, so the content of a
// box survives a tab switch and a theme change.
// sel is the selection state of one copyable box, created on first
// sight and kept for as long as the window lives (IAMT-355).
func (f *Frame) sel(name string) *widget.Selectable {
	s, ok := f.sels[name]
	if !ok {
		s = &widget.Selectable{}
		f.sels[name] = s
	}
	return s
}

func (f *Frame) editor(name string) *widget.Editor {
	e, ok := f.eds[name]
	if !ok {
		// Submit: Enter asks for the action instead of inserting a
		// newline. Neither an enrol code nor a connection string ever
		// contains one, and somebody who has just pasted one and pressed
		// Enter means "go".
		e = &widget.Editor{Submit: true}
		f.eds[name] = e
	}
	return e
}

// submitted reports whether Enter was pressed inside a named box during
// this frame. The editor's events must be drained every frame anyway;
// this is where that happens.
func (f *Frame) submitted(gtx layout.Context, name string) bool {
	ed := f.editor(name)
	sent := false
	for {
		ev, ok := ed.Update(gtx)
		if !ok {
			break
		}
		if _, isSubmit := ev.(widget.SubmitEvent); isSubmit {
			sent = true
		}
	}
	return sent
}

// saidUnder returns the status line under a named control.
func (f *Frame) saidUnder(name string) saying {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.said[name]
}

// say puts one immediate sentence under a control — a refusal that
// needed no network, most of the time.
func (f *Frame) say(name, text string, key design.ColorKey) {
	f.mu.Lock()
	f.said[name] = saying{text: text, key: key}
	f.mu.Unlock()
	f.repaint()
}

// begin starts one named operation off the drawing goroutine, refusing
// to start a second copy of the same one while the first is still
// running. Gio lays out on a single goroutine and must never block: a
// dial to the gateway takes seconds, and a window that stops repainting
// for seconds is a window Windows paints grey and offers to close.
//
// The status line is the whole progress report: "working" the moment the
// press is accepted, the outcome when the work returns — and an outcome
// even when the work panics, because a swallowed panic in a detached
// goroutine would otherwise take the whole window down with it.
func (f *Frame) begin(name, working string, work func() (string, design.ColorKey)) {
	f.mu.Lock()
	if f.working[name] {
		f.mu.Unlock()
		return
	}
	f.working[name] = true
	f.said[name] = saying{text: working, key: design.BusyKey}
	f.mu.Unlock()
	f.repaint()

	go func() {
		text, key := "", design.MutedKey
		defer func() {
			if r := recover(); r != nil {
				text = fmt.Sprintf("the operation stopped unexpectedly: %v", r)
				key = design.BadKey
			}
			f.mu.Lock()
			f.working[name] = false
			f.said[name] = saying{text: text, key: key}
			f.mu.Unlock()
			f.repaint()
		}()
		text, key = work()
	}()
}

// beginGiving is begin for an action whose whole point is to hand the
// person a string: the invitation, the connection line. The work returns
// what to GIVE separately from what to SAY, so the layout can put the
// first in a box that selects and copies and the second in a status line
// (IAMT-355).
func (f *Frame) beginGiving(name, working string, work func() (give, text string, key design.ColorKey)) {
	f.mu.Lock()
	if f.working[name] {
		f.mu.Unlock()
		return
	}
	f.working[name] = true
	f.said[name] = saying{text: working, key: design.BusyKey}
	f.mu.Unlock()
	f.repaint()

	go func() {
		give, text, key := "", "", design.MutedKey
		defer func() {
			if r := recover(); r != nil {
				give, text, key = "", fmt.Sprintf("the operation stopped unexpectedly: %v", r), design.BadKey
			}
			f.mu.Lock()
			f.working[name] = false
			f.said[name] = saying{text: text, key: key, give: give}
			f.mu.Unlock()
			f.repaint()
		}()
		give, text, key = work()
	}()
}

// refreshAdminLists asks the gateway what it holds and replaces the
// three lists with exactly that -- including empty ones, which are
// answers and not failures (IAMT-357).
func (f *Frame) refreshAdminLists() {
	ask := f.cfg.Actions.AdminList
	if ask == nil {
		f.say(ctlAdminRefresh, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlAdminRefresh, "Asking the gateway.", func() (string, design.ColorKey) {
		var lists AdminLists
		err := f.forCurrentGateway(func(ctx context.Context) (func(*Snapshot), error) {
			got, err := ask(ctx)
			if err != nil {
				return nil, err
			}
			lists = got
			return func(s *Snapshot) {
				s.Admin.People = got.People
				s.Admin.Machines = got.Machines
				s.Admin.Grants = got.Grants
				s.Admin.ActiveSessions = got.Sessions
				s.Admin.RiskMode = got.RiskMode
				s.Admin.AuditProblem = got.AuditProblem
				// The gateway's word about its pairing window rides along
				// with the status (IAMT-331): a window ended from the far
				// side must die on THIS screen too, the moment the answer
				// lands, instead of at whatever its local timer says.
				if got.Pairing != nil {
					s.Admin.Pairing = adminPairingAfterStatus(s.Admin.Pairing, *got.Pairing, time.Now())
				}
			}, nil
		})
		if err != nil {
			return err.Error(), design.BadKey
		}
		// A journal that is not being written is the one success that is
		// not silent: every change on this tab will be refused, and the
		// reason goes in the row a failed fetch would use (IAMT-451).
		if lists.AuditProblem != "" {
			return "Gateway: " + lists.AuditProblem, design.BadKey
		}
		// Silence on success. The three lists ARE the answer, and a
		// sentence repeating them in words would cost a row on a tab
		// that gate 17 already measures against the window's edge.
		return "", design.GoodKey
	})
}

// disclosedForm reports whether the form under a control is open, and
// closes it the moment its action has SUCCEEDED (IAMT-359).
//
// Closing on success rather than on a second press is the maintainer's
// own
// rule -- press Add, the fields appear, fill them in, press OK, and the
// grid shows the new entry -- and it is right: the form's whole purpose is
// spent. What the action HANDED BACK is not closed with it; a one-time
// enrol code that vanished the instant it was minted would be a worse
// defect than the form that would not go away.
func (f *Frame) disclosedForm(ctl string) bool {
	if !f.disclosed[ctl] {
		return false
	}
	if !f.busy(ctl) && f.saidUnder(ctl).key == design.GoodKey {
		f.disclosed[ctl] = false
		return false
	}
	return true
}

// toggleForm opens or closes a form, and clears whatever the last run of
// it said: a refusal from the previous attempt hanging over a freshly
// opened form belongs to a question nobody asked again.
func (f *Frame) toggleForm(ctl string) {
	open := !f.disclosed[ctl]
	f.disclosed[ctl] = open
	if open {
		f.say(ctl, "", design.MutedKey)
	}
}

// busy reports whether a named operation is running right now.
func (f *Frame) busy(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.working[name]
}

// forgetAdminIdentity is the Join card's second press: the first press
// only arms it (IAMT-356).
//
// Two presses, because on a gateway with ONE administrator this is how a
// person locks themselves out. Forgetting is local and instant; getting
// back in needs a claim line from a fresh install or a pairing PIN from
// an administrator -- and if the administrator who could issue that PIN
// was this machine, there is nobody left to ask.
func (f *Frame) forgetAdminIdentity() {
	if !f.confirming[ctlAdminForget] {
		f.confirming[ctlAdminForget] = true
		f.say(ctlAdminForget,
			"Press again to confirm. This machine will stop being anybody on that gateway, "+
				"and getting back in needs a claim line or a pairing PIN from an administrator.",
			design.WarnKey)
		return
	}
	f.confirming[ctlAdminForget] = false
	forget := f.cfg.Actions.AdminForget
	if forget == nil {
		f.say(ctlAdminForget, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlAdminForget, "Forgetting.", func() (string, design.ColorKey) {
		msg, err := forget()
		if err != nil {
			return err.Error(), design.BadKey
		}
		// At once, rather than on the next poll tick. The tick would
		// correct it within three seconds anyway -- it re-reads the saved
		// connection from disk, which this has just emptied -- but three
		// seconds of a window still naming the gateway this machine has
		// just been made to forget is three seconds of it saying
		// something untrue about a security decision the person took
		// deliberately, and had to confirm twice.
		f.wroteIdentity(func(s *Snapshot) {
			s.Admin.ThisMachine = nil
			s.Client.Configured = false
		})
		return msg, design.GoodKey
	})
}

// noRuntime is what every control says when the frame was built without
// Actions: the offscreen shot and the tests draw the same buttons, and
// pressing one there must state plainly that nothing happened rather
// than look like it worked.
const noRuntime = "This window was opened without a runtime — the control is drawn but performs nothing."

// -------------------------------------------------------------------------
// The three things a person can actually do (IAMT-149)
// -------------------------------------------------------------------------

// registerThisMachine is the Set up screen's one action: take the code
// out of the box and hand it to the enrolment the CLI's "enrol" verb
// runs. The Setup state moves with it — "working" while the gateway is
// being asked, then "enrolled" or "failed" — so the screen's headline
// and its status line tell the same story.
func (f *Frame) registerThisMachine() {
	code := strings.TrimSpace(f.editor(ctlSetupRegister).Text())
	if code == "" {
		f.say(ctlSetupRegister,
			"Paste the one-time enrol code your administrator gave you into the box above first.",
			design.BadKey)
		return
	}
	enrol := f.cfg.Actions.Enrol
	if enrol == nil {
		f.say(ctlSetupRegister, noRuntime, design.BadKey)
		return
	}
	f.reviseSnapshot(func(s *Snapshot) {
		s.Setup.Status = "working"
		s.Setup.Detail = "talking to the gateway"
	})
	f.begin(ctlSetupRegister, "Talking to the gateway — 10–20 seconds.",
		func() (string, design.ColorKey) {
			machine, osUser, err := enrol(code)
			if err != nil {
				// A refused code is not spent (SPEC §3.4): say so, because
				// the alternative is somebody asking for a second code they
				// do not need and will not get.
				detail := err.Error()
				f.reviseSnapshot(func(s *Snapshot) {
					s.Setup.Status = "failed"
					s.Setup.Detail = detail
				})
				return detail, design.BadKey
			}
			f.reviseSnapshot(func(s *Snapshot) {
				s.Setup.MachineName = machine
				s.Setup.Status = "enrolled"
				s.Setup.Detail = EnrolledDetail
				// Only when the caller actually learned it: an empty
				// account is "could not read the record", not "bound to
				// nobody", and the Set up card reads the two as the same
				// thing.
				if osUser != "" {
					s.Setup.OSUser = osUser
				}
			})
			return "Registered as " + machine + ". Open the Server tab and press START.", design.GoodKey
		})
}

// saveConnectionString is the Client screen's first action: remember the
// line an administrator handed over, so this copy knows which gateway it
// belongs to and as whom, and switch to it.
//
// Since 22.09.2026 it ADDS rather than replaces: a person may keep a
// personal gateway and a work one, and neither is a threat to the other.
// replace still repeats the CLI's --replace, for the one case that was
// always the dangerous one -- the same gateway presenting a different
// host key.
func (f *Frame) saveConnectionString(replace bool) {
	line := strings.TrimSpace(f.editor(ctlClientSave).Text())
	if line == "" {
		f.say(ctlClientSave,
			"Paste the connection string your administrator gave you into the box above first.",
			design.BadKey)
		return
	}
	save := f.cfg.Actions.SaveConnection
	if save == nil {
		f.say(ctlClientSave, noRuntime, design.BadKey)
		return
	}
	name := strings.TrimSpace(f.editor(ctlClientName).Text())
	f.begin(ctlClientSave, "Saving.", func() (string, design.ColorKey) {
		what, err := save(line, name, replace)
		if err != nil {
			return err.Error(), design.BadKey
		}
		// The boxes empty themselves: what they held is now a row in the
		// list above, and a form still showing it invites a second press
		// that would do nothing.
		f.editor(ctlClientSave).SetText("")
		f.editor(ctlClientName).SetText("")
		// A new gateway is a new world, exactly as switching to one is.
		f.forgetTheOtherGatewaysAnswers()
		f.refreshGateways()
		f.afterGatewayChange()
		return what, design.GoodKey
	})
}

// refreshMachines is the Client screen's second action: ask the gateway
// which machines this person may enter right now. Only the gateway knows
// the live grants, so the list is replaced with exactly what it says —
// including an empty one, which is an answer and not a failure.
func (f *Frame) refreshMachines() {
	ask := f.cfg.Actions.Machines
	if ask == nil {
		f.say(ctlClientRefresh, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlClientRefresh, "Asking the gateway.", func() (string, design.ColorKey) {
		var list []MachineAccess
		err := f.forCurrentGateway(func(ctx context.Context) (func(*Snapshot), error) {
			got, err := ask(ctx)
			if err != nil {
				return nil, err
			}
			list = got
			return func(s *Snapshot) {
				s.Client.Configured = true
				s.Client.Machines = got
			}, nil
		})
		if err != nil {
			return err.Error(), design.BadKey
		}
		if len(list) == 0 {
			return "The gateway granted you no machines at the moment.", design.MutedKey
		}
		return "The gateway lists " + plural(len(list), "machine", "machines") + ".", design.GoodKey
	})
}

// connectMachine is a machine row's Connect button (IAMT-223).
func (f *Frame) connectMachine(m MachineAccess) {
	open := f.cfg.Actions.ClientConnect
	if open == nil {
		f.say(ctlClientRefresh, noRuntime, design.BadKey)
		return
	}
	// SAY WHY IT CANNOT WORK, HERE, RATHER THAN OPEN A TERMINAL THAT
	// FAILS (21.09.2026). The row already draws the two facts -- a grey
	// dot for offline, "sshd not listening" beside the name -- and then
	// offered a Connect button that looked exactly as live as the one on
	// a reachable machine. Pressing it spent ten seconds and came back
	// with a connection error from the far side, when the near side had
	// known the answer before the press.
	//
	// The button is NOT greyed out. A greyed control invites hunting for
	// the way to un-grey it, and the honest answer here is not "you may
	// not" but "the machine is not there yet" -- which is a sentence,
	// and belongs where the other sentences are.
	if !m.Online {
		f.say(ctlClientRefresh,
			m.Name+" is offline — its own iamtunnel is not connected to the gateway right now. "+
				"Nothing here can reach it until somebody starts it on that machine.",
			design.BadKey)
		return
	}
	if !m.SshdListening {
		f.say(ctlClientRefresh,
			m.Name+" is connected to the gateway, but its SSH service is not listening — "+
				"a terminal has nothing to attach to. On that machine: open the Server tab and press START.",
			design.BadKey)
		return
	}
	f.begin(ctlClientRefresh, "Opening a terminal.", func() (string, design.ColorKey) {
		what, err := open(m.Name)
		if err != nil {
			return err.Error(), design.BadKey
		}
		return what, design.GoodKey
	})
}

// -------------------------------------------------------------------------
// Server Start/Stop, Admin Grant/Revoke (IAMT-181)
// -------------------------------------------------------------------------

// startServer is the Server screen's Start action. Success only means the
// attempt was made — the window is never the server process itself, so
// it cannot know the tunnel is up any sooner than the next poll of
// UpdateSnapshot does (IAMT-182).
func (f *Frame) startServer() {
	// The elevation refusal is said HERE since 1.3, not on a permanent
	// strip under the tabs (SPEC §7.1). Opening the door is the one thing
	// on this screen that needs Administrator, so this is the one place
	// the missing right is worth a sentence — and it is a sentence the
	// person actually reads, because they just asked for the thing it
	// blocks. The masthead button beside it is how they fix it.
	if !f.cfg.HasAdminRights {
		f.say(ctlServerStart,
			"Administrator rights are required to open the door. "+restartAdminNotice,
			design.WarnKey)
		return
	}
	start := f.cfg.Actions.ServerStart
	if start == nil {
		f.say(ctlServerStart, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlServerStart, "Starting.", func() (string, design.ColorKey) {
		msg, err := start()
		if err != nil {
			return err.Error(), design.BadKey
		}
		return msg, design.GoodKey
	})
}

// stopServer is the door-cutting action: the Server screen's own Stop
// button and the recording strip's "Stop now" button (visible on every
// tab) both call this same method, so there is exactly one
// place that decides what stopping means.
func (f *Frame) stopServer() {
	stop := f.cfg.Actions.ServerStop
	if stop == nil {
		f.say(ctlServerStop, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlServerStop, "Stopping.", func() (string, design.ColorKey) {
		msg, err := stop()
		if err != nil {
			return err.Error(), design.BadKey
		}
		return msg, design.GoodKey
	})
}

// grantAccess is the Admin screen's Grant action: person, machine and
// until come out of their own three boxes; until empty means indefinite,
// exactly as the CLI's positional argument does.
//
// The until box holds a word since IAMT-391 (a preset, or "" for "until
// revoked") rather than a raw instant, so it is turned back into what the
// gateway reads before it travels: untilFromPreset resolves a recognised
// word, and passes anything else — a pasted RFC 3339 instant — through
// exactly as typed.
func (f *Frame) grantAccess() {
	person := strings.TrimSpace(f.editor(ctlAdminGrant + "/person").Text())
	machine := strings.TrimSpace(f.editor(ctlAdminGrant + "/machine").Text())
	until := strings.TrimSpace(f.editor(ctlAdminGrant + "/until").Text())
	if resolved, ok := untilFromPreset(until, f.now()); ok {
		until = resolved
	}
	capability := f.grantCapability()
	if person == "" || machine == "" {
		f.say(ctlAdminGrant, "Fill in both the person and the machine above first.", design.BadKey)
		return
	}
	grant := f.cfg.Actions.AdminGrant
	grantWithCaps := f.cfg.Actions.AdminGrantWithCaps
	if grant == nil && grantWithCaps == nil {
		f.say(ctlAdminGrant, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlAdminGrant, "Asking the gateway.", func() (string, design.ColorKey) {
		var msg string
		var err error
		if grantWithCaps != nil {
			msg, err = grantWithCaps(person, machine, until, capability)
		} else {
			msg, err = grant(person, machine, until)
		}
		if err != nil {
			return err.Error(), design.BadKey
		}
		// The Access list is now one grant out of date (IAMT-357).
		f.refreshAdminLists()
		return msg, design.GoodKey
	})
}

// grantCapability defaults to exec (IAMT-391): a grant an administrator
// opens without touching this box is far more often meant for one
// command than for an interactive shell, and exec is also the capability
// the risk classifier actually grades — the default now matches the case
// the rest of the Admin tab (the command checker, "safety mode") already
// assumes.
func (f *Frame) grantCapability() string {
	if capability := strings.TrimSpace(f.editor(ctlAdminGrant + "/capability").Text()); capability == "shell" {
		return capability
	}
	return "exec"
}

// revokeAccess is one Grants row's Revoke action. ctl names THIS row's
// own status line (screens.go passes it the same string the
// row's button already uses), so revoking one grant never overwrites
// what a different row's button just said.
func (f *Frame) revokeAccess(ctl, person, machine string) {
	revoke := f.cfg.Actions.AdminRevoke
	if revoke == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.begin(ctl, "Asking the gateway.", func() (string, design.ColorKey) {
		defer f.refreshAdminLists() // the row this just removed (IAMT-357)
		msg, err := revoke(person, machine)
		if err != nil {
			return err.Error(), design.BadKey
		}
		return msg, design.GoodKey
	})
}

// removePerson and removeMachine are the Remove control of one row on
// Admin/People and Admin/Machines (21.09.2026). The maintainer found the
// hole
// by looking for the button: how does one delete a person on this form?
// Both verbs had worked on the gateway and in the CLI since 1.0; neither
// was ever drawn.
//
// Both confirm twice, the way Forget does. Removal here is not a local
// forgetting -- it takes the record away on the gateway for everybody,
// with the grants and goals that named it, and it puts out anyone who is
// inside that machine right now. A single press for that is the wrong
// weight, and the second press is the moment to notice the row is the
// one above the one you meant.
func (f *Frame) removePerson(ctl, name string) {
	f.removeThing(ctl, f.cfg.Actions.AdminRemovePerson, name,
		"Remove "+name+" from the gateway? Their grants and goals go too. Press again to confirm.")
}

func (f *Frame) removeMachine(ctl, id string) {
	f.removeThing(ctl, f.cfg.Actions.AdminRemoveMachine, id,
		"Remove machine "+id+"? Its grants go too, and anyone inside it right now is put out. Press again to confirm.")
}

func (f *Frame) removeThing(ctl string, act func(string) (string, error), subject, question string) {
	if !f.confirming[ctl] {
		f.confirming[ctl] = true
		f.say(ctl, question, design.WarnKey)
		return
	}
	f.confirming[ctl] = false
	if act == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.begin(ctl, "Asking the gateway.", func() (string, design.ColorKey) {
		defer f.refreshAdminLists()
		msg, err := act(subject)
		if err != nil {
			return err.Error(), design.BadKey
		}
		if msg == "" {
			msg = "Removed " + subject + "."
		}
		return msg, design.GoodKey
	})
}

// openGoalForm opens (or closes) one grant's claim form and, on the
// way open, clears its box (SPEC IAMT-402 point 4) — pulled out of the
// disclose button's own click handler so the no-stale-goal guarantee
// is testable without a rendered frame. The maintainer's own words,
// choosing
// this over an expiry: a deadline is a guess, while resetting to empty
// guarantees one cannot accidentally keep working under yesterday's
// goal.
func (f *Frame) openGoalForm(ctl string) {
	if !f.disclosedForm(ctl) {
		f.editor(ctl + "/box").SetText("")
	}
	f.toggleForm(ctl)
}

// extendForm opens (or closes) one grant's extend form and, on the way
// open, clears its box — the same no-stale-value rule openGoalForm
// follows: a deadline left over from a previous open must never sit in
// the box looking like the one being applied now.
func (f *Frame) extendForm(ctl string) {
	if !f.disclosedForm(ctl) {
		f.editor(ctl + "/box").SetText("")
	}
	f.toggleForm(ctl)
}

// extendAccess is one grant row's Apply-deadline action (M-10). ctl
// names this row's own form and status line, keyed by the person+machine
// pair rather than by list position, exactly as claimGoal's ctl is — a
// grants list that re-sorts between fetches must never let one row's
// deadline land under a different pair's button.
//
// An EMPTY box is refused rather than read as indefinite: making access
// indefinite by accident, with one press on a form that was maybe open
// from another row, is the one outcome here that cannot be undone from
// the same screen. The word "until revoked", picked or typed, is the
// deliberate way to say indefinite — it resolves to the empty string
// the gateway reads so, through the same untilFromPreset the grant
// form itself uses.
func (f *Frame) extendAccess(ctl, person, machine string) {
	until := strings.TrimSpace(f.editor(ctl + "/box").Text())
	if until == "" {
		f.say(ctl, "Pick or type the new deadline first; \"until revoked\" makes the grant indefinite.", design.BadKey)
		return
	}
	if resolved, ok := untilFromPreset(until, f.now()); ok {
		until = resolved
	}
	extend := f.cfg.Actions.AdminExtend
	if extend == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.begin(ctl, "Asking the gateway.", func() (string, design.ColorKey) {
		defer f.refreshAdminLists() // the row's "until ..." is one fetch out of date otherwise (IAMT-357)
		msg, err := extend(person, machine, until)
		if err != nil {
			return err.Error(), design.BadKey
		}
		return msg, design.GoodKey
	})
}

// renameForm opens (or closes) one row's rename form and, on the way
// open, clears its box -- the same no-stale-value rule extendForm
// follows: a name left over from a previous open must never sit in the
// box looking like the one being applied now. The row itself shows the
// name being changed, so an empty-handed open costs nothing.
func (f *Frame) renameForm(ctl string) {
	if !f.disclosedForm(ctl) {
		f.editor(ctl + "/box").SetText("")
	}
	f.toggleForm(ctl)
}

// renamePerson is one people row's Apply-rename action (D-2a). ctl is
// the person-keyed name the row's own disclose button, box and status
// line use; from is the name the gateway knows this person by now. An
// EMPTY box or the unchanged name is refused before anything travels --
// the first is a press with nothing typed, the second a press that can
// only be a miscount.
func (f *Frame) renamePerson(ctl, from string) {
	to := strings.TrimSpace(f.editor(ctl + "/box").Text())
	if to == "" {
		f.say(ctl, "Type the new name first.", design.BadKey)
		return
	}
	if to == from {
		f.say(ctl, "That is already this person's name.", design.BadKey)
		return
	}
	rename := f.cfg.Actions.AdminRenamePerson
	if rename == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.begin(ctl, "Asking the gateway.", func() (string, design.ColorKey) {
		defer f.refreshAdminLists() // the person's name is one fetch out of date otherwise (IAMT-357)
		msg, err := rename(from, to)
		if err != nil {
			return err.Error(), design.BadKey
		}
		return msg, design.GoodKey
	})
}

// renameMachine is one machines row's Apply-rename action (D-2a), keyed
// by the machine's ID -- the thing every durable reference carries, and
// the thing the gateway verb takes. The label is the one field here a
// wrong press cannot hurt: the id, grants and journal stay with the
// machine, so a refusal-free rename only redraws this list.
func (f *Frame) renameMachine(ctl, id string) {
	name := strings.TrimSpace(f.editor(ctl + "/box").Text())
	if name == "" {
		f.say(ctl, "Type the new label first.", design.BadKey)
		return
	}
	current := f.machineName(id)
	if name == current {
		f.say(ctl, "That is already this machine's label.", design.BadKey)
		return
	}
	rename := f.cfg.Actions.AdminRenameMachine
	if rename == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.begin(ctl, "Asking the gateway.", func() (string, design.ColorKey) {
		defer f.refreshAdminLists() // the machine's label is one fetch out of date otherwise (IAMT-357)
		msg, err := rename(id, name)
		if err != nil {
			return err.Error(), design.BadKey
		}
		return msg, design.GoodKey
	})
}

// machineName is what the admin snapshot currently calls this machine,
// or the id itself when the snapshot has not caught up with a rename
// another row just made.
func (f *Frame) machineName(id string) string {
	for _, m := range f.snap.Admin.Machines {
		if m.ID == id {
			return m.Name
		}
	}
	return id
}

// claimGoal is one grant row's Save goal action (SPEC IAMT-402). ctl
// is the same "admin/goal/<person>/<machine>" name the row's own
// disclose button, box and status line use, keyed by the pair rather
// than by list position — the goal belongs to the grant, and a grants
// list that re-sorts between fetches must never let one row's answer
// land under a different pair's button.
func (f *Frame) claimGoal(ctl, person, machine string) {
	goal := strings.TrimSpace(f.editor(ctl + "/box").Text())
	if goal == "" {
		f.say(ctl, "Describe what this access is for before saving.", design.BadKey)
		return
	}
	claim := f.cfg.Actions.AdminGrantGoal
	if claim == nil {
		f.say(ctl, noRuntime, design.BadKey)
		return
	}
	f.begin(ctl, "Asking the gateway.", func() (string, design.ColorKey) {
		msg, err := claim(person, machine, goal)
		if err != nil {
			return err.Error(), design.BadKey
		}
		// The row's own Goal and RecentGoals are one fetch out of
		// date otherwise (IAMT-357's own rule for every action here).
		f.refreshAdminLists()
		return msg, design.GoodKey
	})
}

// classifierIgnoresGoal reports whether the gateway's current
// classifier cannot use a claimed goal at all (SPEC IAMT-402 point 6):
// rules parse text, not context, so a goal reaches only an external
// classifier ("ai" or "both"). An unknown classifier — the gateway has
// not said, or an older one that predates IAMT-401 — reads as "rules":
// that was the truth for every grant before external classification
// existed, and understating what a goal does is the safer of the two
// ways to be wrong about it.
func (f *Frame) classifierIgnoresGoal() bool {
	return classifierIgnoresGoalWord(f.snap.Admin.RiskMode.Classifier)
}

// setClassifierKey is the Classifier sub-tab's Replace key action (SPEC
// IAMT-403). The box is cleared BEFORE the gateway is even asked, not
// after it answers (point 1): the key must be off the screen the instant
// it is sent, whether the trial that follows takes a second or times out
// after ten.
//
// The outcome is one of three words, first in the sentence and each its
// own color, so a person reads which happened without parsing prose
// (the same shape checkRisk's own outcome-first answer already uses):
// ACCEPTED (Good — the gateway now uses this key), REFUSED (Bad —
// typesafe.ai rejected it, the old key still works), UNAVAILABLE (Warn —
// the gateway could not even run the trial, inconclusive about the key
// itself, the old key still works). The key never appears in any of the
// three; Detail and Fingerprint are the gateway's own words and its own
// fact, never the secret.
func (f *Frame) setClassifierKey() {
	ed := f.editor(ctlAdminClassifierKey)
	key := strings.TrimSpace(ed.Text())
	ed.SetText("")
	if key == "" {
		f.say(ctlAdminClassifierKey, "Paste the new typesafe.ai key first.", design.BadKey)
		return
	}
	set := f.cfg.Actions.AdminSetClassifierKey
	if set == nil {
		f.say(ctlAdminClassifierKey, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlAdminClassifierKey, "Asking the gateway.", func() (string, design.ColorKey) {
		result, err := set(key)
		if err != nil {
			return err.Error(), design.BadKey
		}
		color := design.BadKey
		switch result.Outcome {
		case "accepted":
			color = design.GoodKey
		case "unavailable":
			color = design.WarnKey
		}
		msg := strings.ToUpper(result.Outcome)
		if result.Detail != "" {
			msg += " — " + result.Detail
		}
		if result.Outcome == "accepted" && result.Fingerprint != "" {
			msg += " · fingerprint " + result.Fingerprint
		}
		return msg, color
	})
}

// -------------------------------------------------------------------------
// The Admin tab's pairing and issuing cards (IAMT-327, SPEC §7.1)
// -------------------------------------------------------------------------

// joinAsAdmin is the "Become an administrator" card's Join action: the
// reference and PIN a pairing window printed, spent on this machine's
// own client key. The window does not know without asking whether this
// key is an administrator already, so the card is always live and the
// gateway's refusal (already an admin, wrong PIN, closed window,
// lockout) is the honest outcome under the button.
func (f *Frame) joinAsAdmin() {
	// One box, not two (SPEC §3.6, maintainer's decision 17.09.2026). The
	// gateway prints a ready command line; on 17.09 the maintainer copied it
	// whole, as anyone would, and the two-box form refused it — while the
	// pairing window it belonged to lived two minutes and expired during
	// the puzzling. paste.Parse takes whatever was actually handed over.
	parsed, err := f.pastedJoin()
	if err != nil {
		f.say(ctlAdminPairJoin, err.Error(), design.BadKey)
		return
	}
	// The box takes both kinds; the work behind them is not the same one.
	join := f.cfg.Actions.AdminPairClaim
	if parsed.Kind == paste.Claim {
		join = f.cfg.Actions.AdminClaim
	}
	if join == nil {
		f.say(ctlAdminPairJoin, noRuntime, design.BadKey)
		return
	}
	ref := parsed.Addr() + "#" + parsed.Fingerprint
	pin := parsed.Secret
	f.begin(ctlAdminPairJoin, "Asking the gateway.", func() (string, design.ColorKey) {
		msg, who, err := join(ref, pin)
		if err != nil {
			return err.Error(), design.BadKey
		}
		// The card must stop offering what has just been spent. A claim
		// line and a pairing PIN are each good once; leaving "Become an
		// administrator" on screen for another three seconds invites a
		// second press that can only be refused, by a gateway that is
		// right to refuse it.
		if who != nil {
			f.wroteIdentity(func(s *Snapshot) {
				s.Admin.ThisMachine = who
				s.Client.Configured = true
			})
		}
		// And the lists, so an Admin tab already open fills without
		// waiting for the person to press Refresh.
		f.refreshAdminLists()
		return msg, design.GoodKey
	})
}

// pastedJoin reads the single box and refuses anything that is not a
// pairing string. The refusal for a well-formed string of the WRONG kind
// is its own sentence: pasting a machine invitation here is an easy
// mistake with three kinds of string in circulation, and "not a valid
// reference" would leave the person staring at a string that is perfectly
// valid — just not for this.
// The four errors below break Go's error-string convention on purpose,
// and staticcheck's ST1005 is silenced for each of them by hand rather
// than for the file. They are not error strings: nothing wraps them into
// a larger sentence, no caller prefixes them with context. Each one is
// printed verbatim, on its own, under the box the person is looking at,
// where a lower-case fragment ending in no full stop would read as
// something that lost its beginning.
//
// Anything here that DOES get wrapped keeps the convention. The line
// above — paste.Parse's own refusal — is passed through untouched for
// exactly that reason.
func (f *Frame) pastedJoin() (paste.Parsed, error) {
	raw := strings.TrimSpace(f.editor(ctlAdminPairJoin).Text())
	if raw == "" {
		//lint:ignore ST1005 shown verbatim to a person, not wrapped
		return paste.Parsed{}, errors.New("Paste the line the administrator gave you into the box above first.")
	}
	p, err := paste.Parse(raw)
	if err != nil {
		return paste.Parsed{}, err
	}
	switch p.Kind {
	case paste.Pair, paste.Claim:
		return p, nil
	case paste.Enrol:
		//lint:ignore ST1005 shown verbatim to a person, not wrapped
		return paste.Parsed{}, errors.New("That is an invitation for a MACHINE, not for a person — run it on the machine you are registering, on its Set up tab.")
	case paste.Connect:
		//lint:ignore ST1005 shown verbatim to a person, not wrapped
		return paste.Parsed{}, errors.New("That is a connection string, not a pairing line — save it on the Client tab instead.")
	default:
		//lint:ignore ST1005 shown verbatim to a person, not wrapped
		return paste.Parsed{}, errors.New("That line is not a pairing line.")
	}
}

// joinPreview is the sentence under the box: what pressing the button
// would do, named before it is done (SPEC §3.6: the preview is
// mandatory). It is the only moment the gateway's fingerprint is put in
// front of a person's eyes — there is no TOFU in any role (§6.2) — and it
// is also what catches a string pasted into the wrong window. An empty
// box previews nothing rather than an error: a box nobody has typed in
// yet has done nothing wrong.
func (f *Frame) joinPreview() (string, design.ColorKey) {
	raw := strings.TrimSpace(f.editor(ctlAdminPairJoin).Text())
	if raw == "" {
		return "", design.MutedKey
	}
	p, err := f.pastedJoin()
	if err != nil {
		return err.Error(), design.WarnKey
	}
	return p.Preview(), design.InkKey
}

// openPairingWindow is the "Pairing window" card's Start action. On
// success the result becomes STATE (Admin.Pairing), not only a sentence,
// so the facts above the button show the PIN, the reference and the
// expiry the gateway named.
func (f *Frame) openPairingWindow() {
	start := f.cfg.Actions.AdminPairingStart
	if start == nil {
		f.say(ctlAdminPairingStart, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlAdminPairingStart, "Asking the gateway.", func() (string, design.ColorKey) {
		gen, _ := f.gatewayNow()
		w, err := start()
		if err != nil {
			return err.Error(), design.BadKey
		}
		// The PIN of the gateway this was asked of, and of no other: a
		// switch while it was on its way leaves the new gateway's card
		// alone (R1-CX F-16).
		f.reviseForGateway(gen, func(s *Snapshot) { s.Admin.Pairing = &w })
		return "The pairing window is open until " + untilText(w.Expires) +
			" — hand the PIN over a different channel than the reference.", design.GoodKey
	})
}

// closePairingWindow is the card's Stop action. Success clears the
// state even when no window was open (the command is idempotent); a
// refusal leaves it exactly as it was.
func (f *Frame) closePairingWindow() {
	stop := f.cfg.Actions.AdminPairingStop
	if stop == nil {
		f.say(ctlAdminPairingStop, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlAdminPairingStop, "Asking the gateway.", func() (string, design.ColorKey) {
		gen, _ := f.gatewayNow()
		wasOpen, err := stop()
		if err != nil {
			return err.Error(), design.BadKey
		}
		f.reviseForGateway(gen, func(s *Snapshot) { s.Admin.Pairing = nil })
		if !wasOpen {
			return "No pairing window was open.", design.MutedKey
		}
		return "The pairing window is closed — the PIN it showed no longer works.", design.GoodKey
	})
}

// addPerson is the "Add person" card's action: name, role and public
// key. An empty role box means "user", exactly as the CLI verb's
// default does.
func (f *Frame) addPerson() {
	name := strings.TrimSpace(f.editor(ctlAdminPeopleAdd + "/name").Text())
	role := strings.TrimSpace(f.editor(ctlAdminPeopleAdd + "/role").Text())
	key := strings.TrimSpace(f.editor(ctlAdminPeopleAdd + "/key").Text())
	if name == "" || key == "" {
		f.say(ctlAdminPeopleAdd,
			"Fill in the person's name and paste their public key into the boxes above first.",
			design.BadKey)
		return
	}
	add := f.cfg.Actions.AdminPeopleAdd
	if add == nil {
		f.say(ctlAdminPeopleAdd, noRuntime, design.BadKey)
		return
	}
	f.begin(ctlAdminPeopleAdd, "Asking the gateway.", func() (string, design.ColorKey) {
		msg, err := add(name, role, key)
		if err != nil {
			return err.Error(), design.BadKey
		}
		return msg, design.GoodKey
	})
}

// mintEnrolCode is the "Invite machine" card's action: a name in, one
// invitation out — shown under the button, where it can be selected and
// copied.
//
// The name is the only thing asked for, and it is the only thing the
// administrator is in a position to answer (SPEC §3.4, 1.4). The OS
// account comes from the machine when it redeems the code — asking for
// that was the 1.3 defect, and it is not coming back.
func (f *Frame) mintEnrolCode() {
	name := strings.TrimSpace(f.editor(ctlAdminEnrolCode + "/name").Text())
	if name == "" {
		f.say(ctlAdminEnrolCode,
			"Give this registration a name first — it is what you will grant access against and revoke by.",
			design.BadKey)
		return
	}
	mint := f.cfg.Actions.AdminMachinesEnrolCode
	if mint == nil {
		f.say(ctlAdminEnrolCode, noRuntime, design.BadKey)
		return
	}
	f.beginGiving(ctlAdminEnrolCode, "Asking the gateway.", func() (string, string, design.ColorKey) {
		code, expires, err := mint(name)
		if err != nil {
			return "", err.Error(), design.BadKey
		}
		f.refreshAdminLists() // the invitation is a machine row now (IAMT-357)
		return code, "Hand this to " + name + ". It expires " + expires + ".", design.GoodKey
	})
}

// plural words a small count without the "1 machines" that gives a
// program away.
func plural(n int, one, many string) string {
	word := many
	if n == 1 {
		word = one
	}
	return fmt.Sprintf("%d %s", n, word)
}
