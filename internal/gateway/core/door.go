package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/proto"
)

// DoorState is the complete externally observable state set from PROTOCOL §5.2.
type DoorState string

const (
	Closed  DoorState = "closed"
	Opening DoorState = "opening"
	Open    DoorState = "open"
	Closing DoorState = "closing"
)

// DoorEvent is the complete event alphabet of PROTOCOL §5.2.  Epoch replacement
// is a transport loss: in both cases the old epoch is invalid and all its work dies.
type DoorEvent uint8

const (
	Status DoorEvent = iota // initial or reconciliation door.status reply/error
	Reservation
	CancelReservation
	Success
	Failure
	Timeout
	TransportLost // includes control loss and epoch replacement
	LateReply
	NestedFailure // failed/timed-out nested SSH handshake
)

// Command is an operation that the SSH/control owner must serialize on the one
// control channel. The state is changed before the command is returned, so a
// concurrent reservation can never manufacture a second door.
type Command struct {
	Op     string // door.open, door.close, door.status
	Door   Door
	DoorID string
	Reason string
}

// Door is the short-lived gateway key. PrivateKey intentionally never leaves this
// package except to the nested SSH client; the machine receives PublicKey only.
type Door struct {
	ID           string
	PublicKey    string
	PrivateKey   ssh.Signer
	Opened       time.Time
	IdleDeadline time.Time
	HardDeadline time.Time
}

// Input describes one received outcome. Installed/DoorID are meaningful for
// Status; Own says that a successful close belongs to this epoch's door; Retired
// marks a reply for an id already retired after timeout/cancellation.
type Input struct {
	Event     DoorEvent
	Installed bool
	DoorID    string
	Own       bool
	Retired   bool
}

// Snapshot is a race-safe observation for admin status and tests.
type Snapshot struct {
	State            DoorState
	Reservations     uint32
	Sessions         uint32
	Online           bool
	ReconcilePending bool
	DoorID           string
	HasPrivateKey    bool
	CloseTimeouts    uint8
}

// Config contains policy supplied by the gateway process. These dependencies are
// values, not package switches: production uses the fixed defaults and tests merely
// provide a clock/door source to observe deterministic outcomes.
type Config struct {
	Now      func() time.Time
	NewDoor  func(now time.Time) (Door, error)
	DoorIdle time.Duration
	DoorHard time.Duration
}

// ProtocolError is returned for a combination forbidden by the complete table.
// It is a value type rather than a mutable exported sentinel variable.
type ProtocolError struct{}

func (ProtocolError) Error() string { return "core: event is invalid in this door state" }

func protocolErr() error { return ProtocolError{} }

// Machine owns one machine's §5.2 state. All mutations use its one mutex; callers
// must send returned commands in order on the control channel.
type Machine struct {
	mu  sync.Mutex
	cfg Config

	state                  DoorState
	reservations, sessions uint32
	online, reconcile      bool
	door                   Door
	closeTimeouts          uint8

	// closingOp/closingReason remember which closing operation is in flight
	// (PROTOCOL §5.2, "closing" row: the first timeout must repeat "the same
	// operation", not always door.close). They are state of the machine, not
	// an event parameter: Timeout stays the single event it always was.
	closingOp     closingOp
	closingReason string
}

// closingOp names the one closing-state operation the automaton is waiting
// on, so a bare Timeout event can repeat exactly that operation instead of
// always assuming door.close.
type closingOp uint8

const (
	closingOpClose closingOp = iota
	closingOpSanitize
)

func NewMachine(cfg Config) (*Machine, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.NewDoor == nil {
		cfg.NewDoor = defaultDoor(cfg)
	}
	if cfg.DoorIdle <= 0 {
		cfg.DoorIdle = 15 * time.Minute
	}
	if cfg.DoorHard <= cfg.DoorIdle {
		cfg.DoorHard = 8 * time.Hour
	}
	if cfg.DoorHard <= cfg.DoorIdle {
		return nil, errors.New("core: hard door deadline must exceed idle deadline")
	}
	return &Machine{cfg: cfg, state: Closed}, nil
}

func defaultDoor(cfg Config) func(time.Time) (Door, error) {
	return func(now time.Time) (Door, error) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return Door{}, fmt.Errorf("generate door key: %w", err)
		}
		signer, err := ssh.NewSignerFromKey(private)
		if err != nil {
			return Door{}, err
		}
		idRaw := make([]byte, 16)
		if _, err = rand.Read(idRaw); err != nil {
			return Door{}, fmt.Errorf("generate door id: %w", err)
		}
		// UUID version/variant are set so the server-side §5.1 UUID validation accepts it.
		idRaw[6] = idRaw[6]&0x0f | 0x40
		idRaw[8] = idRaw[8]&0x3f | 0x80
		id := hex.EncodeToString(idRaw)
		id = id[:8] + "-" + id[8:12] + "-" + id[12:16] + "-" + id[16:20] + "-" + id[20:]
		return Door{ID: id, PublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), PrivateKey: signer,
			Opened: now.UTC(), IdleDeadline: now.UTC().Add(cfg.DoorIdle), HardDeadline: now.UTC().Add(cfg.DoorHard)}, nil
	}
}

// Apply performs exactly one cell of the transition table. A missing cell is an init
// panic, rather than an accidental permissive default in a security state machine.
func (m *Machine) Apply(in Input) ([]Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fn, ok := doorTransition(m.state, in.Event)
	if !ok {
		panic("core: incomplete door transition table")
	}
	return fn(m, in)
}

func (m *Machine) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Snapshot{m.state, m.reservations, m.sessions, m.online, m.reconcile, m.door.ID, m.door.PrivateKey != nil, m.closeTimeouts}
}

// FinishSession removes one established session. It is deliberately not an event
// in the 4×9 door table: §5.2 defines that table's reservation/control events,
// while a finished nested SSH session only changes the sessions counter. It still
// takes the same mutex, which makes the idle check atomic with a new reservation.
//
// The counter is the machine's, not one door's: a session outlives the door it
// came in through (a door closed at its hard deadline, or found closed by the
// machine itself, IAMT-461), and its end is counted in whatever state the door
// is in - "a session during closing only decrements the counter" (§5.3, race 6).
// Only an open door is closed for idleness.
func (m *Machine) FinishSession() ([]Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions == 0 {
		return nil, protocolErr()
	}
	m.sessions--
	if m.state != Open {
		return nil, nil
	}
	return m.idleClose()
}

// Recheck is the question the gateway asks when sshd refused the key of door
// doorID (IAMT-461): is that door still on the machine? The machine closes its
// door on its own - maxDoorIdle without bytes, maxDoorHard - and has no message
// to say so (§5.1); the gateway learns it only by asking. The answer is the
// open row's door.status cell (openStatus).
//
// It returns the door.status to send while the door is open and still the one
// the handshake used. Nothing is returned when the door has moved on: another
// caller already found it gone, or it is closing or opening - the caller then
// waits for the door the automaton is already bringing. Asking changes no
// state: the caller's reservation is still counted, which is what keeps the
// door from closing for idleness while the question is on the wire.
func (m *Machine) Recheck(doorID string) []Command {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != Open || m.door.ID != doorID {
		return nil
	}
	return m.status()
}

// HardDeadline ends an open door whose hard deadline has come on the gateway's
// own clock (IAMT-461). The machine keeps its own ceiling as well (§5.1); this
// is the other half of "both sides watch the hard deadline, whoever acts first
// closes" (§8), so the gateway does not go on handing out a door the machine has
// already removed.
//
// A reservation in flight defers it: that person's nested handshake is using
// the door right now, and the close is taken at the next call once the
// handshake has ended one way or the other (the setup budget bounds how long
// that is). Established sessions do not defer it: the door is an entrance,
// they are already in, and their ends are still counted (FinishSession).
func (m *Machine) HardDeadline(now time.Time) []Command {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != Open || m.reservations > 0 || m.door.HardDeadline.IsZero() || now.Before(m.door.HardDeadline) {
		return nil
	}
	m.state = Closing
	return m.close(proto.DoorCloseHard)
}

// ForceClose ends the current door cycle for an administrative identity change.
// It deliberately discards reservations and sessions: a subsequently issued
// door must never inherit access that was established for another OS account.
// The caller still drives the returned command and therefore gets the normal
// retry, terminal-cut and journal behaviour of the closing row.
//
// The close says "stop", the machine's word for a door its gateway ends by
// decision rather than by timer. It took a reason from its caller, which
// passed one no machine accepts, and a refused close cuts the machine off
// (IAMT-469).
func (m *Machine) ForceClose() ([]Command, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch m.state {
	case Closed:
		return nil, nil
	case Closing:
		return nil, nil
	case Opening, Open:
		if m.door.ID == "" {
			return nil, protocolErr()
		}
		m.state = Closing
		m.reservations = 0
		m.sessions = 0
		return m.close(proto.DoorCloseStop), nil
	default:
		return nil, protocolErr()
	}
}

func (m *Machine) forgetDoor() { m.door = Door{}; m.closeTimeouts = 0 }
func (m *Machine) close(reason string) []Command {
	m.closingOp, m.closingReason = closingOpClose, reason
	return []Command{{Op: "door.close", DoorID: m.door.ID, Reason: reason}}
}
func (m *Machine) sanitize(reason string) []Command {
	m.closingOp, m.closingReason = closingOpSanitize, reason
	return []Command{{Op: "door.sanitize", Reason: reason}}
}
func (m *Machine) status() []Command { return []Command{{Op: "door.status"}} }

// validDoorID reports whether id is the exact textual form PROTOCOL §1.3
// defines for the uuid type: RFC 4122, lower case, 36 ASCII bytes. A doorId
// reported by the machine (door.status, §5.1) is input from the side the
// gateway does not trust, and is checked against this rule - the same rule
// startOpen's own generated id already satisfies - before it is ever used to
// build an outgoing command. Anything that fails this check, including the
// empty string, is a corrupted marker, not an addressable door (§5.2).
func validDoorID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func (m *Machine) startOpen() ([]Command, error) {
	d, err := m.cfg.NewDoor(m.cfg.Now())
	if err != nil {
		return nil, err
	}
	if d.ID == "" || d.PrivateKey == nil || d.PublicKey == "" || !d.Opened.Before(d.IdleDeadline) || !d.IdleDeadline.Before(d.HardDeadline) {
		return nil, errors.New("core: invalid generated door")
	}
	m.door, m.state = d, Opening
	return []Command{{Op: "door.open", Door: d}}, nil
}

func decrement(v *uint32) error {
	if *v == 0 {
		return protocolErr()
	}
	*v--
	return nil
}

type transition func(*Machine, Input) ([]Command, error)

// doorTransition holds the deliberately rectangular 4×9 table in a local array.
// A caller cannot mutate this security policy through a package variable. It is
// still visibly a table, rather than distributed conditionals, and tests enumerate
// every one of its cells.
func doorTransition(state DoorState, event DoorEvent) (transition, bool) {
	table := [4][9]transition{
		{closedStatus, closedReserve, closedCancel, closedSuccess, closedFailure, closedTimeout, lost, closedLate, closedFailure},
		{invalid, openingReserve, openingCancel, openingSuccess, openingFailure, openingTimeout, lost, ignoreLate, invalid},
		{openStatus, openReserve, openCancel, nestedSuccess, nestedFailure, nestedFailure, lost, ignoreLate, nestedFailure},
		{invalid, closingReserve, closingCancel, closingSuccess, closingFailure, closingTimeout, lost, ignoreLate, invalid},
	}
	if event > NestedFailure {
		return nil, false
	}
	var row int
	switch state {
	case Closed:
		row = 0
	case Opening:
		row = 1
	case Open:
		row = 2
	case Closing:
		row = 3
	default:
		return nil, false
	}
	return table[row][event], true
}

func invalid(*Machine, Input) ([]Command, error)    { return nil, protocolErr() }
func ignoreLate(*Machine, Input) ([]Command, error) { return nil, nil }

func closedStatus(m *Machine, in Input) ([]Command, error) {
	if !in.Installed {
		m.reconcile = false
		m.online = true
		return nil, nil
	}
	m.state = Closing
	if !validDoorID(in.DoorID) {
		// installed:true with no valid doorId is a corrupted marker (PROTOCOL
		// §5.2, "closed" + "installed:true without a valid doorId"): the
		// gateway has neither issued nor can address this line by id, so it
		// cannot use door.close. door.sanitize exists exactly for this cell.
		m.door = Door{}
		return m.sanitize(proto.DoorSanitizeCorrupted), nil
	}
	m.door = Door{ID: in.DoorID}
	return m.close(proto.DoorCloseReconnect), nil
}
func closedReserve(m *Machine, _ Input) ([]Command, error) {
	m.reservations++
	if m.reconcile {
		return nil, nil
	}
	return m.startOpen()
}
func closedCancel(m *Machine, _ Input) ([]Command, error) { return nil, decrement(&m.reservations) }
func closedSuccess(*Machine, Input) ([]Command, error)    { return nil, protocolErr() }
func closedFailure(*Machine, Input) ([]Command, error)    { return nil, nil }
func closedTimeout(m *Machine, _ Input) ([]Command, error) {
	m.reconcile = true
	return m.status(), nil
}
func closedLate(m *Machine, in Input) ([]Command, error) {
	if !in.Retired || in.DoorID == "" {
		return nil, nil
	}
	m.state = Closing
	if !validDoorID(in.DoorID) {
		// A retired door.open's late success reply names a doorId the
		// gateway never installed under its own authority (PROTOCOL §5.2,
		// "closed" row: "do not restore the key"). If that name does not
		// pass the same §1.3 uuid check every other machine-reported doorId
		// must pass, the gateway has a line on the machine it cannot
		// address by id - the corrupted-marker case door.sanitize exists
		// for, exactly as in closedStatus above.
		m.door = Door{}
		return m.sanitize(proto.DoorSanitizeCorrupted), nil
	}
	m.door = Door{ID: in.DoorID}
	return m.close(proto.DoorCloseLateReply), nil
}

func openingReserve(m *Machine, _ Input) ([]Command, error) { m.reservations++; return nil, nil }
func openingCancel(m *Machine, _ Input) ([]Command, error)  { return nil, decrement(&m.reservations) }
func openingSuccess(m *Machine, in Input) ([]Command, error) {
	if in.DoorID != "" && in.DoorID != m.door.ID {
		return nil, protocolErr()
	}
	if m.reservations > 0 {
		m.state = Open
		return nil, nil
	}
	m.state = Closing
	return m.close(proto.DoorCloseIdle), nil
}
func openingFailure(m *Machine, _ Input) ([]Command, error) {
	m.state = Closed
	m.reservations = 0
	m.forgetDoor()
	return nil, nil
}
func openingTimeout(m *Machine, _ Input) ([]Command, error) {
	m.state = Closed
	m.reservations = 0
	m.forgetDoor()
	m.reconcile = true
	return m.status(), nil
}

// openStatus is the answer to Recheck (IAMT-461). The door still installed
// under its id: nothing changes, and sshd's refusal was sshd's own. Anything
// else means the machine no longer holds this door - it closed it itself -
// so its key is forgotten and the door is closed without a door.close (there
// is no line left to remove). A foreign or corrupted line found instead is
// cleaned up exactly as the closed row cleans it; otherwise the reservations
// waiting (the one whose handshake failed among them) get a new door at once.
// Established sessions are left as they are: they are already in.
func openStatus(m *Machine, in Input) ([]Command, error) {
	if in.Installed && in.DoorID == m.door.ID {
		return nil, nil
	}
	m.state = Closed
	m.forgetDoor()
	if in.Installed {
		return closedStatus(m, in)
	}
	if m.reservations > 0 {
		return m.startOpen()
	}
	return nil, nil
}

func openReserve(m *Machine, _ Input) ([]Command, error) { m.reservations++; return nil, nil }
func openCancel(m *Machine, _ Input) ([]Command, error) {
	if err := decrement(&m.reservations); err != nil {
		return nil, err
	}
	return m.idleClose()
}
func nestedSuccess(m *Machine, _ Input) ([]Command, error) {
	if err := decrement(&m.reservations); err != nil {
		return nil, err
	}
	m.sessions++
	return nil, nil
}
func nestedFailure(m *Machine, _ Input) ([]Command, error) {
	if err := decrement(&m.reservations); err != nil {
		return nil, err
	}
	return m.idleClose()
}
func (m *Machine) idleClose() ([]Command, error) {
	if m.sessions == 0 && m.reservations == 0 {
		m.state = Closing
		return m.close(proto.DoorCloseIdle), nil
	}
	return nil, nil
}

func closingReserve(m *Machine, _ Input) ([]Command, error) { m.reservations++; return nil, nil }
func closingCancel(m *Machine, _ Input) ([]Command, error)  { return nil, decrement(&m.reservations) }
func closingSuccess(m *Machine, in Input) ([]Command, error) {
	if in.DoorID != "" && in.DoorID != m.door.ID {
		return nil, protocolErr()
	}
	foreign := !in.Own
	m.state = Closed
	m.forgetDoor()
	if foreign {
		m.reconcile = true
		return m.status(), nil
	}
	if m.reservations > 0 && !m.reconcile {
		return m.startOpen()
	}
	return nil, nil
}
func closingFailure(m *Machine, _ Input) ([]Command, error) {
	m.state = Closed
	m.reservations = 0
	m.forgetDoor()
	m.online = false
	return nil, nil
}
func closingTimeout(m *Machine, _ Input) ([]Command, error) {
	if m.closeTimeouts == 0 {
		m.closeTimeouts = 1
		// PROTOCOL §5.2, "closing" row, first timeout: repeat the same
		// operation that was in flight, not unconditionally door.close - a
		// door.sanitize that never answered must be retried as sanitize
		// (m.door is empty in that case; door.close with an empty id is
		// exactly the forbidden request this table cell exists to avoid).
		if m.closingOp == closingOpSanitize {
			return m.sanitize(m.closingReason), nil
		}
		return m.close(m.closingReason), nil
	}
	return closingFailure(m, Input{})
}
func lost(m *Machine, _ Input) ([]Command, error) {
	m.state = Closed
	m.reservations = 0
	m.sessions = 0
	m.online = false
	m.reconcile = false
	m.forgetDoor()
	return nil, nil
}
