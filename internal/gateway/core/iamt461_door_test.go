package core

// IAMT-461 in the automaton: the open row's door.status cell (the answer to
// Recheck), the gateway's own hard deadline, and a session counter that
// outlives the door its sessions came in through.

import (
	"testing"
	"time"
)

// iamt461Open brings a machine to an open door-A with one session inside.
func iamt461Open(t *testing.T) *Machine {
	t.Helper()
	m := advMachine(t, time.Minute, time.Hour)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation})
	apply(t, m, Input{Event: Success, DoorID: "door-A"})
	apply(t, m, Input{Event: Success})
	if s := m.Snapshot(); s.State != Open || s.Sessions != 1 || s.DoorID != "door-A" {
		t.Fatalf("setup: %+v", s)
	}
	return m
}

func TestIAMT461_RecheckAsksOnlyAboutTheDoorThatIsOpen(t *testing.T) {
	m := iamt461Open(t)
	if c := m.Recheck("door-A"); len(c) != 1 || c[0].Op != "door.status" {
		t.Fatalf("Recheck of the open door = %+v, want one door.status", c)
	}
	if c := m.Recheck("door-OLD"); len(c) != 0 {
		t.Fatalf("Recheck of a door already replaced asked again: %+v", c)
	}
	if s := m.Snapshot(); s.State != Open || s.Sessions != 1 {
		t.Fatalf("asking changed the door: %+v", s)
	}
}

func TestIAMT461_TheDoorStillInstalledStaysOpen(t *testing.T) {
	m := iamt461Open(t)
	apply(t, m, Input{Event: Reservation}) // the person whose key sshd refused
	if c := apply(t, m, Input{Event: Status, Installed: true, DoorID: "door-A"}); len(c) != 0 {
		t.Fatalf("an installed door produced commands: %+v", c)
	}
	if s := m.Snapshot(); s.State != Open || s.DoorID != "door-A" || s.Reservations != 1 || !s.HasPrivateKey {
		t.Fatalf("an installed door was not left as it was: %+v", s)
	}
}

func TestIAMT461_ADoorTheMachineClosedIsReplacedForWhoIsWaiting(t *testing.T) {
	m := iamt461Open(t)
	apply(t, m, Input{Event: Reservation})
	c := apply(t, m, Input{Event: Status, Installed: false})
	if len(c) != 1 || c[0].Op != "door.open" || c[0].Door.ID == "door-A" || c[0].Door.PrivateKey == nil {
		t.Fatalf("a door the machine no longer holds was not replaced: %+v", c)
	}
	s := m.Snapshot()
	if s.State != Opening || s.Reservations != 1 || s.Sessions != 1 {
		t.Fatalf("after the door was found gone: %+v, want opening with the reservation and the session kept", s)
	}
	apply(t, m, Input{Event: Success, DoorID: c[0].Door.ID})
	apply(t, m, Input{Event: Success})
	if s := m.Snapshot(); s.State != Open || s.Sessions != 2 || s.Reservations != 0 {
		t.Fatalf("after the retry: %+v", s)
	}
	// Both sessions end; only the last one closes the door.
	finishSession(t, m)
	c = mustFinish(t, m)
	if len(c) != 1 || c[0].Op != "door.close" || c[0].Reason != "idle" {
		t.Fatalf("the last session did not close the new door: %+v", c)
	}
}

func TestIAMT461_AForeignLineFoundInsteadIsCleanedUp(t *testing.T) {
	m := iamt461Open(t)
	apply(t, m, Input{Event: Reservation})
	const foreign = "0b7e1f8c-3a51-4c1e-9d3e-2f6a8b9c0d1e"
	c := apply(t, m, Input{Event: Status, Installed: true, DoorID: foreign})
	if len(c) != 1 || c[0].Op != "door.close" || c[0].DoorID != foreign {
		t.Fatalf("a foreign line was not closed: %+v", c)
	}
	if s := m.Snapshot(); s.State != Closing || s.HasPrivateKey {
		t.Fatalf("after a foreign line: %+v", s)
	}
}

func TestIAMT461_TheHardDeadlineClosesTheDoorNotTheSessions(t *testing.T) {
	m := iamt461Open(t)
	opened := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	if c := m.HardDeadline(opened.Add(59 * time.Minute)); len(c) != 0 {
		t.Fatalf("closed before the hard deadline: %+v", c)
	}
	apply(t, m, Input{Event: Reservation})
	if c := m.HardDeadline(opened.Add(time.Hour)); len(c) != 0 {
		t.Fatalf("closed under a handshake in flight: %+v", c)
	}
	apply(t, m, Input{Event: NestedFailure})
	c := m.HardDeadline(opened.Add(time.Hour))
	if len(c) != 1 || c[0].Op != "door.close" || c[0].Reason != "hard" || c[0].DoorID != "door-A" {
		t.Fatalf("the hard deadline did not close the door: %+v", c)
	}
	if s := m.Snapshot(); s.State != Closing || s.Sessions != 1 {
		t.Fatalf("after the hard deadline: %+v", s)
	}
	// The session inside ends while the close is on the wire (§5.3 race 6).
	if c := mustFinish(t, m); len(c) != 0 {
		t.Fatalf("a session ending during closing sent %+v", c)
	}
	apply(t, m, Input{Event: Success, DoorID: "door-A", Own: true})
	if s := m.Snapshot(); s.State != Closed || s.Sessions != 0 {
		t.Fatalf("after the close: %+v", s)
	}
	if _, err := m.FinishSession(); err == nil {
		t.Fatal("a session that was never counted was finished")
	}
}
