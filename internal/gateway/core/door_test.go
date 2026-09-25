package core

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func testMachine(t *testing.T) *Machine {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	n := 0
	m, err := NewMachine(Config{
		Now: func() time.Time { return now }, DoorIdle: time.Minute, DoorHard: 2 * time.Minute,
		NewDoor: func(t time.Time) (Door, error) {
			n++
			return Door{ID: "door-" + string(rune('0'+n)), PublicKey: "ssh-ed25519 AAAA", PrivateKey: signer, Opened: t, IdleDeadline: t.Add(time.Minute), HardDeadline: t.Add(2 * time.Minute)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func apply(t *testing.T, m *Machine, in Input) []Command {
	t.Helper()
	c, err := m.Apply(in)
	if err != nil {
		t.Fatalf("Apply(%+v): %v", in, err)
	}
	return c
}

// This is the gate against a forgotten cell: it enumerates the rectangular
// table, not just the happy path. A nil cell panics in production and fails here.
func TestDoorTransitionTableHasAllFourTimesNineCells(t *testing.T) {
	states := []DoorState{Closed, Opening, Open, Closing}
	for _, s := range states {
		for e := Status; e <= NestedFailure; e++ {
			fn, ok := doorTransition(s, e)
			if !ok || fn == nil {
				t.Fatalf("missing cell %s/%d", s, e)
			}
		}
	}
}

// The preceding test proves the shape. This one exercises every actual cell in
// its source state and checks the next state, so a present-but-wrong row cannot
// hide behind the rectangular type.
func TestDoorTransitionTableCellBehaviour(t *testing.T) {
	want := map[DoorState][9]struct {
		state DoorState
		err   bool
	}{
		Closed:  {{Closed, false}, {Opening, false}, {Closed, false}, {Closed, true}, {Closed, false}, {Closed, false}, {Closed, false}, {Closed, false}, {Closed, false}},
		Opening: {{Opening, true}, {Opening, false}, {Opening, false}, {Open, false}, {Closed, false}, {Closed, false}, {Closed, false}, {Opening, false}, {Opening, true}},
		Open:    {{Closed, false}, {Open, false}, {Open, false}, {Open, false}, {Open, false}, {Open, false}, {Closed, false}, {Open, false}, {Open, false}},
		Closing: {{Closing, true}, {Closing, false}, {Closing, false}, {Closed, false}, {Closed, false}, {Closing, false}, {Closed, false}, {Closing, false}, {Closing, true}},
	}
	for _, state := range []DoorState{Closed, Opening, Open, Closing} {
		for event := Status; event <= NestedFailure; event++ {
			t.Run(string(state)+"/"+string(rune('0'+event)), func(t *testing.T) {
				m := testMachine(t)
				m.state, m.online = state, true
				if state != Closed {
					m.door = Door{ID: "door-1", PublicKey: "ssh-ed25519 AAAA", PrivateKey: testSigner(t), Opened: time.Now(), IdleDeadline: time.Now().Add(time.Minute), HardDeadline: time.Now().Add(2 * time.Minute)}
				}
				// A pending reservation/surviving session makes cancel and nested
				// outcomes meaningful without changing the state being tested.
				if event == CancelReservation || (state == Opening && event == Success) || (state == Open && (event == Success || event == Failure || event == Timeout || event == NestedFailure)) {
					m.reservations = 1
				}
				if state == Open {
					m.sessions = 1
				}
				_, err := m.Apply(Input{Event: event, Own: true})
				got := m.Snapshot().State
				if (err != nil) != want[state][event].err || got != want[state][event].state {
					t.Fatalf("cell %s/%d: state=%s err=%v; want state=%s err=%v", state, event, got, err, want[state][event].state, want[state][event].err)
				}
			})
		}
	}
}

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, ed25519.SeedSize))
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestTwoReservationsShareDoorAndLastSessionClosesIt(t *testing.T) {
	m := testMachine(t)
	apply(t, m, Input{Event: Status})
	cmd := apply(t, m, Input{Event: Reservation})
	if len(cmd) != 1 || cmd[0].Op != "door.open" {
		t.Fatalf("first reservation commands=%+v", cmd)
	}
	if cmd = apply(t, m, Input{Event: Reservation}); len(cmd) != 0 {
		t.Fatalf("second reservation opened a second door: %+v", cmd)
	}
	apply(t, m, Input{Event: Success, DoorID: "door-1"})
	apply(t, m, Input{Event: Success})
	apply(t, m, Input{Event: Success})
	s := m.Snapshot()
	if s.State != Open || s.Reservations != 0 || s.Sessions != 2 {
		t.Fatalf("after two handshakes: %+v", s)
	}
	if c := mustFinish(t, m); len(c) != 0 {
		t.Fatalf("first completed session closed shared door: %+v", c)
	}
	c := mustFinish(t, m)
	if len(c) != 1 || c[0].Op != "door.close" || m.Snapshot().State != Closing {
		t.Fatalf("last session did not close door: %+v %+v", c, m.Snapshot())
	}
}

func mustFinish(t *testing.T, m *Machine) []Command {
	t.Helper()
	c, e := m.FinishSession()
	if e != nil {
		t.Fatal(e)
	}
	return c
}

func TestRevocationDuringOpeningCancelsReservationAndLateOpenIsClosed(t *testing.T) {
	m := testMachine(t)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation})
	apply(t, m, Input{Event: CancelReservation}) // revoke wins before handshake
	c := apply(t, m, Input{Event: Success, DoorID: "door-1"})
	if m.Snapshot().State != Closing || len(c) != 1 || c[0].Reason != "idle" {
		t.Fatalf("open after revoke must close: state=%+v commands=%+v", m.Snapshot(), c)
	}
}

func TestOpenTimeoutForgetsKeyAndReconcilesWithoutDroppingTransport(t *testing.T) {
	m := testMachine(t)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation})
	c := apply(t, m, Input{Event: Timeout})
	s := m.Snapshot()
	if s.State != Closed || s.HasPrivateKey || s.Reservations != 0 || !s.ReconcilePending || !s.Online || len(c) != 1 || c[0].Op != "door.status" {
		t.Fatalf("timeout result=%+v commands=%+v", s, c)
	}
	apply(t, m, Input{Event: LateReply, Retired: true, DoorID: validForeignDoorID})
	if s = m.Snapshot(); s.State != Closing || s.HasPrivateKey || s.DoorID != validForeignDoorID {
		t.Fatalf("late success was not cleanup-only: %+v", s)
	}
}

// validForeignDoorID is a syntactically valid PROTOCOL §1.3 uuid that does not
// belong to this epoch - the "foreign, but not corrupted" case.
const validForeignDoorID = "0b9e3f2a-6c1d-4e7a-9b3d-1a2b3c4d5e6f"

func TestRestartForeignDoorIsClosedThenReconciled(t *testing.T) {
	m := testMachine(t)
	c := apply(t, m, Input{Event: Status, Installed: true, DoorID: validForeignDoorID})
	if len(c) != 1 || c[0].Op != "door.close" || c[0].Reason != "reconnect" || c[0].DoorID != validForeignDoorID || m.Snapshot().HasPrivateKey {
		t.Fatalf("foreign door cleanup=%+v snapshot=%+v", c, m.Snapshot())
	}
	c = apply(t, m, Input{Event: Success, DoorID: validForeignDoorID, Own: false})
	if m.Snapshot().State != Closed || !m.Snapshot().ReconcilePending || len(c) != 1 || c[0].Op != "door.status" {
		t.Fatalf("foreign close did not demand status: %+v %+v", m.Snapshot(), c)
	}
}

// TestClosedStatusRejectsEveryUnfitMachineSuppliedDoorID pins the doorId
// contract: an empty doorId and every syntactically unfit doorId the
// machine can report on door.status must be treated as a corrupted marker
// (door.sanitize), never as an addressable door (door.close). A
// syntactically valid but foreign id must still take the old
// door.close("reconnect") path unchanged.
func TestClosedStatusRejectsEveryUnfitMachineSuppliedDoorID(t *testing.T) {
	cases := []struct {
		name   string
		doorID string
		valid  bool
	}{
		{"empty", "", false},
		{"not a uuid at all", "orphan", false},
		{"uuid with trailing extra character", validForeignDoorID + "x", false},
		{"uuid with embedded newline", validForeignDoorID[:8] + "\n" + validForeignDoorID[9:], false},
		{"uuid with embedded quote", `"` + validForeignDoorID[1:], false},
		{"very long", strings.Repeat("a", 1<<20), false},
		{"only spaces, uuid length", strings.Repeat(" ", 36), false},
		{"uppercase uuid", strings.ToUpper(validForeignDoorID), false},
		{"valid foreign uuid", validForeignDoorID, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := testMachine(t)
			c := apply(t, m, Input{Event: Status, Installed: true, DoorID: tc.doorID})
			if len(c) != 1 {
				t.Fatalf("doorID=%q: want exactly one command, got %+v", tc.doorID, c)
			}
			if m.Snapshot().State != Closing || m.Snapshot().HasPrivateKey {
				t.Fatalf("doorID=%q: must move to closing without a private key: %+v", tc.doorID, m.Snapshot())
			}
			if tc.valid {
				if c[0].Op != "door.close" || c[0].Reason != "reconnect" || c[0].DoorID != tc.doorID {
					t.Fatalf("doorID=%q: valid foreign id must be closed by its own id, got %+v", tc.doorID, c[0])
				}
				return
			}
			if c[0].Op != "door.sanitize" || c[0].Reason != "corrupted" {
				t.Fatalf("doorID=%q: unfit id must be sanitized, got %+v", tc.doorID, c[0])
			}
		})
	}
}

// TestClosedLateRejectsEveryUnfitMachineSuppliedDoorID is round 3's fix: the
// late-reply-for-a-retired-door path (closedLate) took in.DoorID from the
// machine and built door.close from it without ever checking format - the
// third instance of exactly the defect round 1 fixed in closedStatus. Empty
// and every syntactically unfit doorId must sanitize, not close; a
// syntactically valid one keeps the pre-existing door.close("late-reply").
func TestClosedLateRejectsEveryUnfitMachineSuppliedDoorID(t *testing.T) {
	cases := []struct {
		name   string
		doorID string
		valid  bool
	}{
		{"not a uuid at all", "late-door", false},
		{"path traversal", "../../etc/passwd", false},
		{"uuid with trailing garbage", validForeignDoorID + "ZZZ", false},
		{"uuid with embedded newline", validForeignDoorID[:8] + "\n" + validForeignDoorID[9:], false},
		{"very long", strings.Repeat("a", 1<<20), false},
		{"uppercase uuid", strings.ToUpper(validForeignDoorID), false},
		{"valid foreign uuid", validForeignDoorID, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := testMachine(t)
			c := apply(t, m, Input{Event: LateReply, Retired: true, DoorID: tc.doorID})
			if len(c) != 1 {
				t.Fatalf("doorID=%q: want exactly one command, got %+v", tc.doorID, c)
			}
			if m.Snapshot().State != Closing || m.Snapshot().HasPrivateKey {
				t.Fatalf("doorID=%q: must move to closing without a private key: %+v", tc.doorID, m.Snapshot())
			}
			if tc.valid {
				if c[0].Op != "door.close" || c[0].Reason != "late-reply" || c[0].DoorID != tc.doorID {
					t.Fatalf("doorID=%q: valid retired id must be closed by its own id, got %+v", tc.doorID, c[0])
				}
				return
			}
			if c[0].Op != "door.sanitize" || c[0].Reason != "corrupted" {
				t.Fatalf("doorID=%q: unfit id must be sanitized, got %+v", tc.doorID, c[0])
			}
		})
	}
}

// TestNoInvalidDoorNameEverReachesAnOutgoingCommand is the main assertion of
// this work (§4.4, round 1; extended by round 3 §3 item 1: "go over
// every place where a door.close is born"): no invalid door name reported by the
// machine ever reaches an outgoing command, on any path that reads
// Input.DoorID from the untrusted side - closedStatus (initial/reconciliation
// door.status) and closedLate (late reply for a retired door). These are the
// only two places in the package that ever copy in.DoorID into m.door
// (grep -n "Door{ID: in.DoorID}" internal/gateway/core/door.go); openingSuccess
// and closingSuccess also read in.DoorID but only to compare it against the
// gateway's own already-trusted m.door.ID, never to build a command from it.
func TestNoInvalidDoorNameEverReachesAnOutgoingCommand(t *testing.T) {
	invalid := []string{
		"",
		"orphan",
		validForeignDoorID + "x",
		validForeignDoorID[:8] + "\n" + validForeignDoorID[9:],
		`"` + validForeignDoorID[1:],
		strings.Repeat("a", 1<<20),
		strings.Repeat(" ", 36),
		strings.ToUpper(validForeignDoorID),
	}
	entryPoints := []struct {
		name string
		in   func(id string) Input
	}{
		{"closedStatus", func(id string) Input { return Input{Event: Status, Installed: true, DoorID: id} }},
		{"closedLate", func(id string) Input { return Input{Event: LateReply, Retired: true, DoorID: id} }},
	}
	for _, ep := range entryPoints {
		for _, id := range invalid {
			m := testMachine(t)
			cmds := apply(t, m, ep.in(id))
			for _, c := range cmds {
				if id != "" && c.DoorID == id {
					t.Fatalf("%s: invalid doorId %q reached an outgoing command: %+v", ep.name, id, c)
				}
				if c.Op == "door.close" {
					t.Fatalf("%s: invalid doorId %q must never produce door.close, got %+v", ep.name, id, c)
				}
			}
		}
	}
}

func TestControlLossClosesAllState(t *testing.T) {
	m := testMachine(t)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation})
	apply(t, m, Input{Event: Success})
	apply(t, m, Input{Event: Success})
	apply(t, m, Input{Event: TransportLost})
	s := m.Snapshot()
	if s.State != Closed || s.Sessions != 0 || s.Reservations != 0 || s.HasPrivateKey || s.Online {
		t.Fatalf("loss did not erase epoch state: %+v", s)
	}
}

func TestCloseTimeoutRetriesOnlyOnceThenTearsDownEpoch(t *testing.T) {
	m := testMachine(t)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation})
	apply(t, m, Input{Event: Success})
	apply(t, m, Input{Event: CancelReservation})
	c := apply(t, m, Input{Event: Timeout})
	if len(c) != 1 || m.Snapshot().State != Closing || m.Snapshot().CloseTimeouts != 1 {
		t.Fatalf("first timeout=%+v %+v", c, m.Snapshot())
	}
	apply(t, m, Input{Event: Timeout})
	s := m.Snapshot()
	if s.State != Closed || s.Online || s.HasPrivateKey {
		t.Fatalf("second timeout not terminal: %+v", s)
	}
}

// TestSanitizeTimeoutRetriesSanitizeNotClose is round 2, §4.1: after a
// corrupted marker sends the automaton down the door.sanitize path, a first
// Timeout must repeat door.sanitize with the same reason - never door.close,
// which at this point would carry an empty DoorID (m.door was cleared by the
// same closedStatus branch that chose sanitize in the first place).
func TestSanitizeTimeoutRetriesSanitizeNotClose(t *testing.T) {
	m := testMachine(t)
	apply(t, m, Input{Event: Status, Installed: true, DoorID: "not-a-uuid"})
	c := apply(t, m, Input{Event: Timeout})
	if len(c) != 1 || c[0].Op != "door.sanitize" || c[0].Reason != "corrupted" || c[0].DoorID != "" {
		t.Fatalf("first sanitize timeout must retry sanitize with the same reason: %+v", c)
	}
	if s := m.Snapshot(); s.State != Closing || s.CloseTimeouts != 1 {
		t.Fatalf("first sanitize timeout snapshot: %+v", s)
	}
}

// TestSanitizeTimeoutTwiceTearsDownEpoch is §4.2: a second unanswered
// sanitize ends the epoch exactly like a second unanswered close - closed,
// no private key, reservations gone, no longer online.
func TestSanitizeTimeoutTwiceTearsDownEpoch(t *testing.T) {
	m := testMachine(t)
	apply(t, m, Input{Event: Status, Installed: true, DoorID: "not-a-uuid"})
	apply(t, m, Input{Event: Reservation})
	c := apply(t, m, Input{Event: Timeout})
	if len(c) != 1 || c[0].Op != "door.sanitize" {
		t.Fatalf("first timeout=%+v", c)
	}
	c = apply(t, m, Input{Event: Timeout})
	s := m.Snapshot()
	if len(c) != 0 || s.State != Closed || s.Online || s.HasPrivateKey || s.Reservations != 0 {
		t.Fatalf("second sanitize timeout must tear down the epoch: commands=%+v snapshot=%+v", c, s)
	}
}

// TestSanitizeFailureTearsDownEpochLikeCloseFailure is §4.3: an
// explicit sanitize failure reply is the same terminal outcome as a close
// failure or a second timeout - "closing" row, Failure column does not know
// or care which operation was outstanding.
func TestSanitizeFailureTearsDownEpochLikeCloseFailure(t *testing.T) {
	m := testMachine(t)
	apply(t, m, Input{Event: Status, Installed: true, DoorID: "not-a-uuid"})
	c := apply(t, m, Input{Event: Failure})
	s := m.Snapshot()
	if len(c) != 0 || s.State != Closed || s.Online || s.HasPrivateKey {
		t.Fatalf("sanitize failure must tear down the epoch: commands=%+v snapshot=%+v", c, s)
	}
}

// TestCloseTimeoutStillRetriesCloseNotSanitize is §4.4: the fix for
// sanitize retry must not break the pre-existing close retry - symmetry, not
// regression. A foreign-but-valid doorId still takes door.close, and its
// first timeout must repeat door.close with the door's own id, not sanitize.
func TestCloseTimeoutStillRetriesCloseNotSanitize(t *testing.T) {
	m := testMachine(t)
	apply(t, m, Input{Event: Status, Installed: true, DoorID: validForeignDoorID})
	c := apply(t, m, Input{Event: Timeout})
	if len(c) != 1 || c[0].Op != "door.close" || c[0].Reason != "reconnect" || c[0].DoorID != validForeignDoorID {
		t.Fatalf("close timeout must retry door.close with the same id and reason: %+v", c)
	}
}

// TestDoorCloseNeverCarriesAnEmptyDoorID is §4.5, the end-to-end
// invariant: across every scenario that can drive the automaton through
// closing, no door.close command it ever emits carries an empty DoorID. This
// walks scenarios rather than asserting on one, so it survives future edits
// to any of the paths that build door.close (closedStatus, closedLate,
// openingSuccess, idleClose, and the closing/Timeout retry).
func TestDoorCloseNeverCarriesAnEmptyDoorID(t *testing.T) {
	checkAll := func(t *testing.T, cmdSets ...[]Command) {
		t.Helper()
		for _, cmds := range cmdSets {
			for _, c := range cmds {
				if c.Op == "door.close" && c.DoorID == "" {
					t.Fatalf("door.close with an empty DoorID: %+v", c)
				}
			}
		}
	}

	t.Run("corrupted marker then sanitize timeout then close never appears empty", func(t *testing.T) {
		m := testMachine(t)
		c1 := apply(t, m, Input{Event: Status, Installed: true, DoorID: ""})
		c2 := apply(t, m, Input{Event: Timeout})
		c3 := apply(t, m, Input{Event: Timeout})
		checkAll(t, c1, c2, c3)
	})
	t.Run("foreign valid door then close timeout then close timeout again", func(t *testing.T) {
		m := testMachine(t)
		c1 := apply(t, m, Input{Event: Status, Installed: true, DoorID: validForeignDoorID})
		c2 := apply(t, m, Input{Event: Timeout})
		c3 := apply(t, m, Input{Event: Timeout})
		checkAll(t, c1, c2, c3)
	})
	t.Run("own door opened then idle-closed then close timeout retry", func(t *testing.T) {
		m := testMachine(t)
		c1 := apply(t, m, Input{Event: Status})
		c2 := apply(t, m, Input{Event: Reservation})
		c3 := apply(t, m, Input{Event: Success})
		c4 := apply(t, m, Input{Event: CancelReservation})
		c5 := apply(t, m, Input{Event: Timeout})
		checkAll(t, c1, c2, c3, c4, c5)
	})
	// round 3: this subtest used to be named "late reply for a retired door
	// closes by its own reported id" and pass it "late-door" - a name that
	// is not empty but also not valid, so checkAll's "not empty" bar let it
	// through unnoticed. Split in two, each asserting what its name claims:
	// a valid reported id really is used to close, an unfit one is
	// sanitized and never reaches door.close at all.
	t.Run("late reply for a retired door with a valid id closes by its own reported id", func(t *testing.T) {
		m := testMachine(t)
		apply(t, m, Input{Event: Status})
		apply(t, m, Input{Event: Reservation})
		c1 := apply(t, m, Input{Event: Timeout})
		c2 := apply(t, m, Input{Event: LateReply, Retired: true, DoorID: validForeignDoorID})
		c3 := apply(t, m, Input{Event: Timeout})
		checkAll(t, c1, c2, c3)
		if len(c2) != 1 || c2[0].Op != "door.close" || !validDoorID(c2[0].DoorID) {
			t.Fatalf("valid late-reply id must close by its own id: %+v", c2)
		}
	})
	t.Run("late reply for a retired door with an unfit id is sanitized, never closed", func(t *testing.T) {
		m := testMachine(t)
		apply(t, m, Input{Event: Status})
		apply(t, m, Input{Event: Reservation})
		c1 := apply(t, m, Input{Event: Timeout})
		c2 := apply(t, m, Input{Event: LateReply, Retired: true, DoorID: "late-door"})
		c3 := apply(t, m, Input{Event: Timeout})
		checkAll(t, c1, c2, c3)
		if len(c2) != 1 || c2[0].Op != "door.sanitize" || c2[0].Reason != "corrupted" {
			t.Fatalf("unfit late-reply id must be sanitized, not closed by it: %+v", c2)
		}
	})
	t.Run("nested handshake failure idle-closes then close timeout retry", func(t *testing.T) {
		m := testMachine(t)
		apply(t, m, Input{Event: Status})
		apply(t, m, Input{Event: Reservation})
		apply(t, m, Input{Event: Success})
		c1 := apply(t, m, Input{Event: NestedFailure})
		c2 := apply(t, m, Input{Event: Timeout})
		checkAll(t, c1, c2)
	})
}

func TestInvalidTableCellIsExplicitProtocolFailure(t *testing.T) {
	m := testMachine(t)
	var protocol ProtocolError
	if _, err := m.Apply(Input{Event: Success}); !errors.As(err, &protocol) {
		t.Fatalf("closed/success err=%v", err)
	}
}

type memoryStream struct {
	r                   *bytes.Reader
	mu                  sync.Mutex
	w                   bytes.Buffer
	closed, writeClosed bool
	wrote               func()
}

func newMemoryStream(read string) *memoryStream {
	return &memoryStream{r: bytes.NewReader([]byte(read))}
}
func (s *memoryStream) Read(p []byte) (int, error) { return s.r.Read(p) }
func (s *memoryStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.wrote != nil {
		s.wrote()
	}
	return s.w.Write(p)
}
func (s *memoryStream) Close() error { s.mu.Lock(); s.closed = true; s.mu.Unlock(); return nil }
func (s *memoryStream) CloseWrite() error {
	s.mu.Lock()
	s.writeClosed = true
	s.mu.Unlock()
	return nil
}
func (s *memoryStream) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.w.String() }

type memoryRecording struct {
	mu              sync.Mutex
	output          bytes.Buffer
	closed, aborted bool
	order           *[]string
}

func (r *memoryRecording) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.order != nil {
		*r.order = append(*r.order, "record")
	}
	return r.output.Write(p)
}
func (r *memoryRecording) Close() error { r.mu.Lock(); r.closed = true; r.mu.Unlock(); return nil }
func (r *memoryRecording) Abort(string) error {
	r.mu.Lock()
	r.aborted = true
	r.mu.Unlock()
	return nil
}

// AddBytesIn (IAMT-169) is a no-op for this test double: it asserts
// only that Bridge records target -> human output to the recorder,
// without caring about the human -> target counter. IAMT-336 phase 5
// widened the argument from a count to the bytes that were just
// forwarded.
func (r *memoryRecording) AddBytesIn(p []byte) {}

func TestBridgeRecordsTargetBytesBeforeHumanReceivesThem(t *testing.T) {
	human, target := newMemoryStream("input"), newMemoryStream("output")
	var order []string
	human.wrote = func() { order = append(order, "human") }
	rec := &memoryRecording{order: &order}
	if err := Bridge(context.Background(), human, target, rec, nil); err != nil {
		t.Fatal(err)
	}
	if rec.output.String() != "output" || human.String() != "output" || target.String() != "input" || !rec.closed {
		t.Fatalf("bridge result record=%q human=%q target=%q closed=%v", rec.output.String(), human.String(), target.String(), rec.closed)
	}
	if len(order) < 2 || order[0] != "record" || order[1] != "human" {
		t.Fatalf("output was not recorded before delivery: %v", order)
	}
}
