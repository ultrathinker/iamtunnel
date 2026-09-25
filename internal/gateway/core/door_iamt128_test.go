package core

// door_iamt128_test.go — IAMT-128, the other side of the boundary. The
// "one access line per machine" rule lives in two places: (a) in the key
// file (winkeys/doors_iamt128_test.go, byte-level check) and (b) in the
// gateway automaton, which decides the second person's fate in code. This
// file guards (b): it asserts that a second reservation in the queue does
// not produce a second door.open.
//
// Scenario: the first person made a reservation and opened the door; the
// second person arrives while the door is still opening. What must happen:
//   - the second reservation increments m.reservations
//   - the second reservation returns []Command{} (no command)
//   - no second door.open may appear
//   - when the first door.open completes successfully, the automaton stays
//     in Open with the same doorID — the second person goes through the
//     same door
//   - a third person arriving while already open also goes through the
//     same door
//
// CANARY IAMT-128 2 — prediction: if "m.reservations++; return nil, nil" in
// core/door.go:404 (openReserve) is replaced with "return m.startOpen()",
// the existing TestTwoReservationsShareDoorAndLastSessionClosesIt
// (door_test.go:117-119) fails at its assertion line:
//
//   second reservation opened a second door: %+v
//
// The same defect via another belt — openingReserve in core/door.go:377:
// if its body is replaced with "return m.startOpen()", a second request
// during opening also gets its own door, and the key file ends up with two
// of our lines — the same violation through the symmetric belt. The
// defence is held by BOTH places, and canary 2 must take out BOTH,
// otherwise the backup belt keeps the rule intact.

import (
	"testing"
)

// TestIAMT128SecondReservationWaitsNotGeneratesNewDoor pins the openReserve
// branch: a second person arriving at an open door must wait
// (reservations++), and the automaton must NOT generate a second door.open.
// That is the "waits for their turn" requirement of IAMT-128.
//
// The test exercises three successive entry points of the second person:
//  1. at state=opening (the third step of the scenario) — must wait;
//  2. at state=open right after the first open succeeds — must use
//     the same door;
//  3. another reservation at state=open — the same door again.
//
// At each point it asserts that (a) the automaton generated no door.open
// commands, (b) the doorID in the snapshot did not change, (c) reservations
// increased. If the "one access line" rule is broken — the test fails on
// one of these assertion lines, not during setup.
func TestIAMT128SecondReservationWaitsNotGeneratesNewDoor(t *testing.T) {
	m := testMachine(t)

	// Point 0: first reservation in closed → opening, produces door.open.
	apply(t, m, Input{Event: Status})
	if cmd := apply(t, m, Input{Event: Reservation}); len(cmd) != 1 || cmd[0].Op != "door.open" {
		t.Fatalf("first reservation must produce exactly one door.open, got: %+v", cmd)
	}
	firstDoorID := m.Snapshot().DoorID
	if firstDoorID == "" {
		t.Fatalf("after the first reservation the automaton must hold a non-empty doorID (otherwise the later checks are meaningless)")
	}

	// Point 1: second reservation during opening. Per PROTOCOL §5.2, "a
	// reservation arrives — increment reservations; leave it waiting for
	// the same pending open". The returned command set must be [].
	if cmd := apply(t, m, Input{Event: Reservation}); len(cmd) != 0 {
		t.Fatalf("second reservation during opening opened a second door (the \"one access line per machine\" rule is violated): %+v", cmd)
	}
	snap := m.Snapshot()
	if snap.State != Opening {
		t.Fatalf("after the second reservation the state must remain opening, got: %+v", snap)
	}
	if snap.DoorID != firstDoorID {
		t.Fatalf("second reservation must not change the automaton's doorID, got %q, want %q", snap.DoorID, firstDoorID)
	}
	if snap.Reservations != 2 {
		t.Fatalf("reservations counter must be 2 (first + one waiting), got: %+v", snap)
	}

	// The first door.open completes successfully → state Open; the
	// reservation is not yet admitted (it is admitted by the next Success =
	// nested handshake, see PROTOCOL §5.2 nestedSuccess).
	if cmd := apply(t, m, Input{Event: Success, DoorID: firstDoorID}); len(cmd) != 0 {
		t.Fatalf("a successful open with reservations>0 must not produce a close: %+v", cmd)
	}
	if s := m.Snapshot(); s.State != Open || s.DoorID != firstDoorID || !s.HasPrivateKey {
		t.Fatalf("after the successful open, expected state=Open with the same doorID and a private key, got: %+v", s)
	}

	// Point 2: another reservation while open. Per §5.2, "a reservation
	// arrives — increment reservations; use the existing door". The
	// returned command set must be [].
	if cmd := apply(t, m, Input{Event: Reservation}); len(cmd) != 0 {
		t.Fatalf("reservation while open opened a second door (rule violated): %+v", cmd)
	}
	if s := m.Snapshot(); s.State != Open || s.DoorID != firstDoorID {
		t.Fatalf("after the third reservation the state and doorID must not change, got: %+v", s)
	}
	// At this point reservations: the first (original) one is not yet
	// admitted, the second and third are both in the queue. The exact
	// number matters less than the fact that it was not reset.
	if s := m.Snapshot(); s.Reservations < 2 {
		t.Fatalf("reservations counter must be at least 2 (original + two waiting), got: %+v", s)
	}

	// Point 3: another reservation — through the same door again. This
	// guarantees the "one access line" rule holds for the third and any
	// subsequent person, not only for the second one.
	if cmd := apply(t, m, Input{Event: Reservation}); len(cmd) != 0 {
		t.Fatalf("fourth reservation opened a second door (rule violated): %+v", cmd)
	}
	if s := m.Snapshot(); s.DoorID != firstDoorID {
		t.Fatalf("fourth reservation must not change the automaton's doorID, got %q, want %q", s.DoorID, firstDoorID)
	}
}
