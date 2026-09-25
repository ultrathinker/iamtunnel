package core

// door_close_terminal_test.go pins the property the runtime's IAMT-69 fix
// leans on: the terminal cell of the "closing" row (a refused close/sanitize
// or the second timeout of either) is only ever reachable from an EMPTY
// epoch - sessions and reservations are zero when the automaton records the
// verdict the gateway executes as a transport cut. A live session never
// dies of a door.close failure: while a session is in, the state is Open,
// where a Failure is nestedFailure - a dropped reservation, not the
// terminal cell.

import (
	"testing"
)

func closingTerminalSnapshots(t *testing.T) map[string]Snapshot {
	t.Helper()
	out := make(map[string]Snapshot)

	// Route A: a session lived, ended, and the idle close was refused.
	m := testMachine(t)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation}) // -> opening
	apply(t, m, Input{Event: Success})     // -> open (reservation still pending)
	apply(t, m, Input{Event: Success})     // nested handshake: sessions 1, reservations 0
	finishSession(t, m)                    // session 0 -> idle door.close -> closing
	apply(t, m, Input{Event: Failure})
	out["refused idle close after a session"] = m.Snapshot()

	// Route B: the reconnect sweep found a foreign line and its close was
	// refused (the machine is not even online yet here - a "was online"
	// flip would have missed this one).
	m = testMachine(t)
	apply(t, m, Input{Event: Status, Installed: true, DoorID: validForeignDoorID})
	apply(t, m, Input{Event: Failure})
	out["refused foreign close"] = m.Snapshot()

	// Route C: the sweep found a corrupted marker and the sanitize was
	// refused.
	m = testMachine(t)
	apply(t, m, Input{Event: Status, Installed: true, DoorID: "not-a-uuid"})
	apply(t, m, Input{Event: Failure})
	out["refused sanitize"] = m.Snapshot()

	// Route D: a pending reservation was waiting when the sanitize timed
	// out twice.
	m = testMachine(t)
	apply(t, m, Input{Event: Status, Installed: true, DoorID: "not-a-uuid"})
	apply(t, m, Input{Event: Reservation})
	apply(t, m, Input{Event: Timeout})
	apply(t, m, Input{Event: Timeout})
	out["second sanitize timeout with a pending reservation"] = m.Snapshot()

	// Route E: the late-reply cleanup close timed out twice.
	m = testMachine(t)
	apply(t, m, Input{Event: LateReply, Retired: true, DoorID: validForeignDoorID})
	apply(t, m, Input{Event: Timeout})
	apply(t, m, Input{Event: Timeout})
	out["second late-reply close timeout"] = m.Snapshot()

	return out
}

func TestClosingTerminalCellOnlyEndsEmptyEpochs(t *testing.T) {
	for name, s := range closingTerminalSnapshots(t) {
		if s.State != Closed || s.Online || s.HasPrivateKey {
			t.Fatalf("%s: terminal cell did not end the epoch: %+v", name, s)
		}
		// The property the transport cut leans on: nothing live is lost.
		if s.Sessions != 0 || s.Reservations != 0 {
			t.Fatalf("%s: terminal cell reached with sessions=%d reservations=%d - the cut would kill live work", name, s.Sessions, s.Reservations)
		}
	}
}

func TestFailureWithLiveSessionIsNeverTheTerminalCell(t *testing.T) {
	m := testMachine(t)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation}) // -> opening
	apply(t, m, Input{Event: Success})     // -> open, reservation pending
	apply(t, m, Input{Event: Success})     // nested handshake: sessions 1
	apply(t, m, Input{Event: Reservation}) // a second human reserves
	apply(t, m, Input{Event: Failure})     // that second human's handshake fails
	s := m.Snapshot()
	if s.State != Open || !s.Online {
		t.Fatalf("a failure while a session is live must not end the epoch: %+v", s)
	}
	if s.Sessions != 1 {
		t.Fatalf("the live session must survive a door failure: %+v", s)
	}
}

func finishSession(t *testing.T, m *Machine) {
	t.Helper()
	if _, err := m.FinishSession(); err != nil {
		t.Fatalf("FinishSession: %v", err)
	}
}
