//go:build windows || linux || darwin

package ui

import "time"

// This file is the blind cast (a snapshot) through which reality reaches the
// screens: plain data, no Gio, no callbacks, no role logic. The runtime
// fills a Snapshot and hands it to NewFrame; today the tests fill it.
// A zero Snapshot must render as an honest idle machine — never a blank
// or a broken layout — so every screen formats missing values as "—".

// Snapshot is everything the five screens draw, in one immutable value.
// It is data, not a live object: the window never reaches back into the
// roles, and the roles never touch the window except by handing over a
// new Snapshot (SPEC §7.1 — the GUI holds no role logic).
type Snapshot struct {
	// Gateway is what this computer is as a gateway (IAMT-434).
	Gateway GatewayState

	Server   ServerState   // what is happening on THIS machine right now
	Client   ClientState   // this machine as the one who enters elsewhere
	Admin    AdminState    // people, machines, grants (role: admin)
	Setup    SetupState    // first-run enrolment of THIS machine
	Settings SettingsState // the few facts a person may look at here
	History  HistoryPage   // one page of past sessions (role: admin)
}

// HistoryPage is one page of the session history plus the size of the
// whole answer, so the screen can say "1-20 of 137" without asking twice.
type HistoryPage struct {
	Rows   []HistoryRow
	Total  int
	Offset int
	Limit  int
}

// HistoryRow is one past VISIT: who, where, from when to when, and what
// happened in between. Not one journal event -- a session writes several,
// and a reader wants a line per visit.
type HistoryRow struct {
	SessionID  string
	Person     string
	Machine    string
	Started    string
	Ended      string
	Kind       string
	Command    string
	Goal       string
	Outcome    string
	Risks      int
	RiskLevel  string
	RiskRule   string
	RiskReason string
}

// ServerState is the machine owner's view of the machine the window runs on.
// The three facts the machine's owner must see without hunting: is anyone in, who
// exactly, until when — and is the session being recorded.
type ServerState struct {
	// Waiting reports that Start was pressed and the tunnel to the
	// gateway is up: the machine is reachable for a booked specialist.
	Waiting bool
	// SshdRunning reports the Windows OpenSSH service is running and
	// listening (SPEC §3.2 checks it before Start).
	SshdRunning bool
	// Running reports that the machine's own server PROCESS is up --
	// separate from Waiting, which is about its tunnel to the gateway
	// (IAMT-358).
	//
	// The two came as one until 19.09.2026, and the window could not
	// tell "nothing is running" from "running, but the gateway cannot
	// be reached". It drew START in both, and pressing it got the
	// refusal "a server is already running for this machine -- stop it
	// first", from a screen that offered no way to stop anything. The
	// maintainer found it with a server process visible in Task Manager
	// and could not reach from the product.
	Running bool

	// Door is the current door automaton state; zero value = shut.
	Door DoorState
	// Sessions lists the people working on this machine right now.
	Sessions []Session
	// Notice carries the one human-readable reason the gateway is
	// currently refusing this machine even though it may reconnect on
	// its own - or "" when there is nothing to explain. It is how the
	// IAMT-69 verdict reaches the machine's owner: after a door.close the gateway
	// could not confirm, the tunnel is cut and a new epoch (reconnect)
	// is required, and the window says so instead of silently showing
	// an ordinary offline machine. Empty draws nothing - a zero
	// snapshot stays an honest idle machine.
	Notice string

	// Unknown reports that this machine's own status could not be
	// learned at all: administrator/root rights are missing, or the
	// local status source (the control port) is unreachable for a
	// reason other than "no server is running" (IAMT-311 — a live run
	// found an unprivileged window reading a permission-denied
	// control.json as a confident "sshd not running" / "tunnel
	// offline", while the same machine was in fact reachable). Every
	// other field of this struct is then a bare Go zero value —
	// indistinguishable from "definitely not, definitely closed,
	// definitely nobody" — and every screen that reads this state must
	// draw "could not find out" instead, never a negative fact: the two
	// are different claims, and only one of them is safe to make when a
	// door might in fact be open.
	Unknown bool

	// UnknownReason is the one sentence every fact falls back to while
	// Unknown is true — normally the exact words the CLI's own
	// equivalent command already used for the same missing right, so an
	// administrator reads the identical sentence whether they asked from a
	// terminal or from this window.
	UnknownReason string
}

// unknownText is the sentence a fact draws in place of a value it could
// not learn: UnknownReason, verbatim, or a safe generic fallback for a
// caller that set Unknown without setting the reason (an older snapshot,
// a test).
func (s ServerState) unknownText() string {
	if s.UnknownReason != "" {
		return s.UnknownReason
	}
	return "unknown — this machine's own status could not be checked"
}

// AccessOpen reports whether the way in to this machine is open right
// now — the door is up and somebody may enter. When a live session is
// also on the air it is always recorded (SPEC principle 3).
//
// IT WAS CALLED Recording() UNTIL 21.09.2026, AND THAT NAME WAS A LIE.
// What the control port actually answers is `doorOpen`, and the window
// turned that single boolean into one nameless, deadline-less Session
// (serverStateFromControlReply in cmd/iamtunnel). So on a real install
// "recording" meant "the door is up", and the strip above the tabs read
// "Recording — — is working on this machine until —".
//
// The cost was not the em-dashes. It was that the same window said, on
// the Session tab and on Admin -> Live, "nobody is inside any machine at
// this moment" — because THOSE screens ask the gateway about attached
// terminals, which is a different question. Three screens, two opposite
// answers to "is anybody in?", and no way for a person to tell which one
// was lying. Reading only the screenshots found it in minutes.
//
// The name now says what the boolean is. The strip says it too.
func (s ServerState) AccessOpen() bool { return len(s.Sessions) > 0 }

// Busy reports that the machine is reachable: waiting, door open or
// sessions live. The Stop control is offered in exactly these states.
func (s ServerState) Busy() bool {
	return s.Waiting || s.Door.IsOpen() || s.AccessOpen()
}

// MaybeBusy reports whether the server might be reachable right now:
// either it demonstrably is (Busy), or the window could not check at
// all (Unknown). F-GUI-2: Busy/AccessOpen read a Go zero value when the
// status could not be learned, so a screen that gates the Stop control
// or the access strip on Busy()/AccessOpen() alone silently draws
// "definitely idle" over a server that may in fact have a session live,
// a door open and a recording running — the same "unknown rendered as
// false" mistake IAMT-311 fixed for the facts, one layer deeper, and it
// breaks the project's hard rule that the Stop control and the
// recording warning must be reachable whenever a session may be active.
// Every screen decision about WHETHER to offer stopping (never about
// what the stopped state used to be) must gate on this, not on Busy()
// alone.
func (s ServerState) MaybeBusy() bool {
	return s.Unknown || s.Busy()
}

// DoorState mirrors the door fields of machine{} in gateway state.json
// (SPEC §4.3): State is one of "", "closed", "opening", "open", "closing".
type DoorState struct {
	State        string
	Opened       time.Time
	IdleDeadline time.Time
	HardDeadline time.Time
}

// IsOpen reports whether the door admits anyone right now.
func (d DoorState) IsOpen() bool { return d.State == "open" || d.State == "opening" }

// Session is one person currently working on this machine (or in gateway sessions.active).
type Session struct {
	ID      string
	Person  string
	Machine string
	Started time.Time
	Until   time.Time
}

// ClientState is the view of the machine as the one who enters other
// machines (SPEC §3.1): the saved connection string, the machines list,
// the person's own public key to hand to the administrator.
type ClientState struct {
	// Configured reports a connection string was saved at least once.
	Configured bool

	// Gateways are the gateways this machine remembers, and Current is
	// the name of the one everything else acts on (IAMT-431).
	//
	// The maintainer keeps a personal gateway and will keep a work one. They
	// are not two configurations of one product -- they are two separate
	// worlds, each with its own machines, people, grants and history,
	// and the only thing they share is the key in this directory. So the
	// list is state, not a setting: the window has to show which world
	// it is looking at before anything else on the screen means
	// anything.
	Gateways []GatewayRef
	Current  string
	// Connected reports this person is inside a remote machine now.
	Connected bool
	// ActiveMachine and ActiveUntil describe the current session.
	ActiveMachine string
	ActiveUntil   time.Time
	// PublicKey is this client's public key line (Copy button, §3.1).
	PublicKey string
	// Machines lists the machines this person may enter.
	Machines []MachineAccess
	// Held lists the commands the gateway stopped and is waiting on this
	// person to settle (21.09.2026). Until it existed, the only way to
	// learn that something was being held was to read the refusal the
	// agent got and copy an id out of it into a terminal -- which is how
	// the maintainer ended up waiting on a gate nobody could see.
	Held []HeldCommand
}

// GatewayState is what this computer is, as a gateway (IAMT-434).
//
// The Server tab answers "is this computer a machine people enter"; this
// answers the other role the same binary can hold, "is this computer the
// meeting point". Until 22.09.2026 the second question had no screen at
// all: the gateway was installed from a console, on Linux, by somebody
// who already knew the verb -- and the maintainer's actual plan was to copy
// one .exe onto a Windows server and press a button.
type GatewayState struct {
	// Supported is whether this operating system has a service
	// integration at all. Without one there is nothing to press.
	Supported bool
	Platform  string

	// Installed is whether a gateway was ever set up here: a host key
	// exists in the data directory. Running is whether it is answering
	// now. The two are separate because a gateway that was installed and
	// is stopped is a different sentence from one that never existed,
	// and the person needs a different button for each.
	Installed bool
	Running   bool

	// Unknown means the status could not be read at all. Kept apart from
	// "not installed" for the reason IAMT-311 cost us twice: an unknown
	// rendered as false is a screen confidently saying no.
	Unknown bool

	// Detail is what the command itself printed, kept verbatim. The
	// screen shows the fields it understands and this underneath, so a
	// case the window has not learned to read is still legible.
	Detail string

	DataDir     string
	Fingerprint string

	// Claim is the one-time string that makes somebody the first
	// administrator, while it is still unspent. It is the whole point of
	// the screen right after install: it goes from this computer to
	// another one, by hand.
	Claim string

	// ClaimPending says whether that one-time entry still exists and is
	// still in date, and it is read from the gateway's own state --
	// NOT inferred from whether Claim came out empty.
	//
	// 22.09.2026: the screen said "already claimed" on a gateway whose
	// token was untouched, because the string could not be RENDERED
	// (the address had not been written yet) and absence was read as
	// spent. Two different facts had been collapsed into one, and the
	// screen picked the alarming reading of the two.
	ClaimPending bool

	// ClaimExpired is the THIRD state, and it was missing on the day the
	// second one was added (23.09.2026). An entry can be still there and
	// out of date: the one-time string has a deadline, and past it the
	// gateway will not take it. With only Pending and its absence, that
	// case fell into the absence and the screen called it "already
	// claimed" -- telling a person somebody else took their gateway when
	// in fact nobody did and the clock ran out.
	//
	// The remedy differs too, which is why the distinction has to reach
	// the screen: a spent string means find the administrator who spent
	// it, an expired one means re-issue it here.
	//
	// "iamtunnel gateway status" has always drawn this line, and a
	// DEADLINE THAT IS NOT SET counts as expired there -- state.validate
	// refuses a bootstrapPending without one, so a zero is a broken
	// entry, not an eternal one. The window now reads it the same way;
	// before, it read a zero as "still good", which is the one answer
	// the command would never give.
	ClaimExpired bool

	// Elevated is whether this copy of the program may install a service
	// at all. Install is refused without it, and the screen says so
	// BEFORE the press rather than after.
	Elevated bool

	// ExePath, ExeReachable and WantedExeDir are the Windows trap: a
	// service account cannot read another account's profile, so an .exe
	// sitting in Downloads would install a service that fails to start
	// later, with an error about a missing file. The screen answers it
	// before it happens, and offers to move the program itself.
	ExePath      string
	ExeReachable bool
	WantedExeDir string

	// AuditKnown is whether the running gateway has said anything about
	// its audit journal (a gateway from before 1.14 says nothing), and
	// AuditProblem is what is wrong with it, "" when it is being written
	// (IAMT-451). Read from the file the gateway keeps in its data
	// directory for this, the same way the lock and the host key are.
	AuditKnown   bool
	AuditProblem string

	// JournalKnown is whether the journal's hash chain was looked at on
	// this refresh (IAMT-467); JournalChain says what came of it in one
	// sentence. JournalIntact is the good answer; JournalBroken is the bad
	// one - a line not what was written, or written without the chain
	// after it began. Neither is set when the check itself could not run.
	JournalKnown  bool
	JournalChain  string
	JournalIntact bool
	JournalBroken bool
}

// GatewayRef is one remembered gateway as the window shows it.
//
// It carries the fingerprint because the Client tab is where a person
// compares it with what an administrator read out to them, and it
// carries Person because "which of my identities is this" is half the
// answer to "which gateway am I on".
type GatewayRef struct {
	Name        string
	Person      string
	Where       string
	Fingerprint string
}

// HeldCommand is one stopped command awaiting a yes or a no. The command
// is whole, never abbreviated in the state: shortening belongs to the row
// that draws it, and a person opening the detail must see exactly what
// would run.
type HeldCommand struct {
	ApprovalID string
	Machine    string
	Command    string
	Rule       string
	Reason     string
	Level      string
	Expires    time.Time
}

// MachineAccess is one row of the client machines list: name, reachability,
// and the exact moment access ends (USER.md §3 step 3).
type MachineAccess struct {
	Name          string
	Online        bool
	SshdListening bool
	Until         time.Time
	// Caps is this person's own grant capability on this machine
	// (["shell"] or ["exec"]) — added 1.8, so the Client tab can tell
	// an exec-only grant apart from a shell grant before ever
	// offering Connect. See internal/client.Machine.Caps for the wire
	// origin.
	Caps []string
}

// AdminState lists what the admin role hands out and takes back
// (SPEC §3.3): people, machines, grants — and, with 1.2 (IAMT-323),
// the open pairing window.
type AdminState struct {
	People         []Person
	Machines       []AdminMachine
	Grants         []Grant
	ActiveSessions []Session // live sessions from gateway sessions.active (contract §4)
	RiskMode       RiskMode  // gateway's live safety mode and its source
	// AuditProblem is set while the gateway's audit journal is not being
	// written: then it refuses every change, and the tab says why before
	// anybody presses anything (IAMT-451).
	AuditProblem string

	// ThisMachine is the identity THIS machine already carries on a
	// gateway, or nil when it carries none (IAMT-356). It is read from
	// the saved connection record, so it is knowable without the
	// network -- which matters, because the question it answers ("do I
	// still have to join?") is asked exactly when joining is failing.
	ThisMachine *AdminIdentity

	// Pairing is the gateway's open pairing window (SPEC §3.5), or nil
	// when there is none — or when nobody has asked yet; the card draws
	// the same "—" for both, because the window cannot tell them apart
	// and must not pretend it can. The pointer is replaced, never
	// written through: a Snapshot is an immutable value.
	Pairing *PairingWindow
}

// AdminIdentity is the identity this machine carries on one gateway: the
// person name the gateway issued, where that gateway is, and the host key
// this machine pinned for it.
//
// It deliberately does NOT carry the role. The saved record does not hold
// one, and the gateway is the only thing that knows it; a window that
// guessed "administrator" from the presence of a file would be lying on
// any machine that had joined as an ordinary user.
type AdminIdentity struct {
	Person  string
	Gateway string
	HostKey string
}

// PairingWindow is what the "Pairing window" card shows after Start
// (SPEC §3.5, IAMT-323): the PIN the new administrator types next to the
// reference — handed over a side channel, never journaled — the
// ready-to-paste reference the gateway printed, and the moment the
// window closes itself.
type PairingWindow struct {
	Pin     string
	Ref     string
	Expires time.Time
	// Gone says the gateway itself no longer has this window: another
	// client stopped it, another administrator's pair consumed it, or a
	// new Start from the far side replaced it. The PIN it shows is dead
	// whatever the wall clock says (IAMT-331) — the one end of the
	// window's life no timer in this process can see.
	Gone bool
	// Elsewhere marks a window the gateway reports open but THIS window
	// did not mint: it carries no PIN and no reference — those went to
	// whoever opened it — only the moment it closes itself.
	Elsewhere bool
}

// PairingStatus is the gateway's own word about its pairing window
// (IAMT-331): whether one is open right now, and when it closes itself.
// It never carries the PIN — the PIN travels once, in pairing.start's
// reply, and is not journaled or repeated anywhere.
type PairingStatus struct {
	Active  bool
	Expires time.Time
}

// Person is one human in the system: role and how many keys they carry.
type Person struct {
	Name  string
	Admin bool
	Keys  int

	// KeyList is the keys themselves, as far as an administrator needs
	// them (IAMT-499): the fingerprint a key is read out and removed by,
	// and when it was added. Keys stays the count the row prints.
	KeyList []PersonKey
}

// PersonKey is one public key of one person as the gateway lists it.
type PersonKey struct {
	Fingerprint string
	Added       string
}

// AdminMachine is one row of the admin machines list (§3.3 machines list):
// enrolment state, door state, reachability.
type AdminMachine struct {
	// ID is what the gateway knows this machine by and what its verbs
	// take. It equals Name from enrolment until a rename parts them
	// (D-2a), and every action on the row must then carry the ID --
	// the label is what changed, not the machine.
	ID        string
	Name      string
	State     string // "verified" | "enrolled"
	DoorState string // "" | "closed" | "opening" | "open" | "closing"
	Online    bool

	// OSUser is the account the gateway logs into on this machine, and
	// OSUserStatus how far the gateway has confirmed it (IAMT-499): the
	// facts "set-user" changes, shown beside the control that changes
	// them.
	OSUser       string
	OSUserStatus string

	// HostKeyStatus is "mismatch" when the machine's sshd presented a key
	// other than the one pinned at enrolment; the door stays shut until an
	// administrator confirms the new one (SPEC §6.2). ObservedFingerprint
	// is that new key's fingerprint, the value "rekey" must be given back.
	HostKeyStatus       string
	ObservedFingerprint string
}

// Grant is one permission "person X → machine Y, until T" (§4.3).
type Grant struct {
	Person  string
	Machine string
	Until   time.Time

	// Goal is the working purpose claimed for this grant (SPEC
	// IAMT-402): the words the person deals with elsewhere, so a
	// context-aware classifier can judge a command against what it is
	// FOR rather than in isolation. Empty means nobody has claimed one
	// yet. It belongs to the grant — this exact person-machine pair —
	// not to a screen, because that is what makes the classifier's read
	// of it honest: "stop the site" is routine work for the grant that
	// claimed "reinstalling this IIS site" and a red flag for one that
	// claimed "copying a directory".
	Goal string

	// RecentGoals are up to 20 of this grant's own most recently
	// claimed goals, most recent first, offered as a picker beside the
	// box a fresh claim always opens empty (SPEC IAMT-402 point 5) — so
	// re-stating a purpose already used for this exact grant costs a
	// press, not retyping, while a goal claimed a moment ago is
	// deliberately still absent until chosen.
	RecentGoals []string

	// Caps is what this grant lets the person DO -- a full shell, or
	// single commands only ("exec"). It arrived from the gateway in
	// grants.list from the day capabilities existed and was dropped on
	// the floor while building this struct, so the Admin tab's grant row
	// never said which of the two kinds of access it was showing
	// (21.09.2026). That is the product's central distinction: an
	// exec-only grant is the reason the classifier can see a command at
	// all. The client's own machine row has said it for a while; the
	// screen where an administrator GRANTS it did not.
	Caps []string
}

// AdminLists is everything the Admin tab SHOWS, fetched in one go
// (IAMT-357).
//
// It is one type because it is one question -- "what does the gateway
// hold right now" -- answered over one connection. Three separate
// actions would mean three dials and three chances to show a page half
// from one moment and half from another.
type AdminLists struct {
	People   []Person
	Machines []AdminMachine
	Grants   []Grant
	Sessions []Session
	RiskMode RiskMode
	// AuditProblem is the gateway's audit journal trouble in one sentence,
	// or "" when there is none to report (IAMT-451).
	AuditProblem string
	// Pairing is the gateway's live word about its pairing window, or nil
	// when the gateway does not say — one from before this field — which
	// is not the same as saying none is open (IAMT-331).
	Pairing *PairingStatus
}

// EnrolledDetail is the sentence under a freshly registered machine's
// status.
//
// It is exported, and a constant, because TWO places must say it: the
// window writes it the moment enrolment succeeds, and cmd/iamtunnel
// writes the same value into the base snapshot the status poll hands
// over a few seconds later. A base that does not carry a field the
// window revised overwrites it with nothing -- which is what blanked the
// History tab on 21.09.2026 -- and two copies of the same sentence would
// drift the first time one of them was reworded.
const EnrolledDetail = "registered — the first entry check has not passed yet"

// RiskMode is the gateway's effective command-safety mode. Source is
// "config" when it came from settings and "live" after the admin switch.
type RiskMode struct {
	Mode   string
	Source string

	// Classifier is the gateway's current verdict source: "rules" | "ai"
	// | "both" (internal/gateway's own RiskClassifier, IAMT-401), read
	// verbatim off "admin gateway status"'s own classifier field. A
	// goal claimed on a grant (IAMT-402) only reaches an EXTERNAL
	// classifier — rules parse text, not context — so this is what
	// decides whether the Access sub-tab's honest caveat about that
	// shows. Empty means the gateway has not said, which this window
	// reads the same as "rules": that was the truth for every grant
	// before IAMT-401 existed, and claiming a goal does something is
	// worse than claiming it does nothing when unsure which is true.
	Classifier string

	// ClassifierSource is "config" or "live", the same distinction
	// Source draws for the mode, and ClassifierKey says whether this
	// gateway holds an AI key at all. Both arrived with the settings
	// window (21.09.2026): the choice of checkers became switchable at
	// runtime, so a window showing it has to say where the current value
	// came from, and has to know whether "ai" and "both" can be offered.
	ClassifierSource string
	ClassifierKey    bool

	// ClassifierKeyFingerprint is the key's fingerprint, empty when the
	// gateway holds none (21.09.2026). The gateway has reported it in
	// gateway.status since the key existed, and the window dropped it on
	// the floor -- while the Classifier sub-tab's own paragraph promised
	// "only whether the gateway now has one, and its fingerprint" and
	// then showed neither. A screen that describes a fact it does not
	// display is worse than one that says nothing.
	ClassifierKeyFingerprint string
}

// RiskSourceResult is returned by the live classifier-choice action, the
// twin of RiskModeResult.
type RiskSourceResult struct {
	Classifier string
	Source     string
	Changed    bool
	Previous   string
}

// RiskModeResult is returned by the live mode action so the window can
// update the selected value and say exactly what the gateway accepted.
type RiskModeResult struct {
	Mode     string
	Source   string
	Changed  bool
	Previous string
}

// AdminSetClassifierKeyResult is the outcome of trying a new typesafe.ai
// classifier key (SPEC IAMT-403). The gateway trials the NEW key with a
// real request before switching to it, so there are three different
// truths afterward, not the usual two — a refusal never touches an
// already-working key:
//
//   - "accepted"    — the trial succeeded; the gateway now uses this key.
//   - "refused"     — the trial reached typesafe.ai and typesafe.ai
//     rejected the key (wrong key, revoked key…); the OLD key keeps
//     working.
//   - "unavailable" — the gateway could not even run the trial (network,
//     typesafe.ai down); inconclusive about the key itself, and the OLD
//     key keeps working too.
//
// The key text itself never travels back in any of the three: Fingerprint
// is the gateway's own fact proving a key is configured, never the key.
type AdminSetClassifierKeyResult struct {
	Outcome     string // "accepted" | "refused" | "unavailable"
	Fingerprint string // set when Outcome == "accepted"; never the key itself
	Detail      string // the gateway's own sentence, shown verbatim
}

// SetupState is the enrolment progress of THIS machine (SPEC §3.4).
// Status is "", "working", "enrolled", "verified" or "failed"; the tab
// stays until restart with the result, including a failure.
type SetupState struct {
	MachineName string
	Status      string
	Detail      string

	// OSUser is the account this registration is bound to — the
	// DOMAIN\user the gateway verified by logging in as it during
	// enrolment (SPEC §3.4 step 3), and the account whose
	// authorized_keys the door line lives in.
	//
	// It is shown beside the name rather than instead of it because
	// since 1.4 a registration IS the pair: one physical machine holds
	// one registration per person who works on it, and the name alone
	// no longer says which of them this window is driving. On a shared
	// box where two people are signed in at once over Remote Desktop,
	// this is the fact that tells each of them they are looking at
	// their own registration and not their colleague's.
	//
	// Empty means the enrolment record does not carry it — either the
	// machine has never registered, or it registered under a build from
	// before 1.4. Both draw as the name alone, which is exactly what
	// those builds always showed.
	OSUser string

	// MachineNameUnknown reports that the machine id could not be read
	// for a reason other than "not enrolled yet" — a permission-style
	// failure (F-GUI-6: the server data directory is root-owned 0700,
	// exactly IAMT-311's own scenario, one layer over: an unprivileged
	// window cannot even stat the file). MachineName is then a bare Go
	// zero value, and the Server tab's "machine" fact must draw
	// "unknown", never the dash it would otherwise share with a
	// genuinely absent name — those are different claims, the same
	// distinction every other tri-state fact on this screen already
	// makes since round 3 (F-GUI-2).
	MachineNameUnknown bool
}

// SettingsState is the few facts the window may show about itself and
// the deployment. There is deliberately nothing here a person can flip:
// port, directories and retention live in the configuration file, and
// the theme follows Windows automatically (SPEC §7.1).
type SettingsState struct {
	Version         string
	Platform        string
	ConfigPath      string
	DataDir         string
	Port            int
	RetentionDays   int
	DiskStopPercent int
}
