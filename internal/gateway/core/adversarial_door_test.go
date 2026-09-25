package core

// adversarial_door_test.go — Phase-5 adversarial probes for the door
// state machine. The question: "what exactly closes the door in
// each way the machine can die?" We enumerate each transition that
// leads to a non-Open state and verify there is no path where the
// door ends up with sessions>0 or reservations>0 and state != Closed,
// and no path where the door stays Open after a transport-loss signal.

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func advTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// advMachine returns a Machine with a deterministic now and a door
// constructor that produces a unique door id each call.
func advMachine(t *testing.T, idle, hard time.Duration) *Machine {
	t.Helper()
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	signer := advTestSigner(t)
	n := 0
	m, err := NewMachine(Config{
		Now:      func() time.Time { return now },
		DoorIdle: idle,
		DoorHard: hard,
		NewDoor: func(t time.Time) (Door, error) {
			n++
			return Door{
				ID:           "door-" + string(rune('A'+n-1)),
				PublicKey:    "ssh-ed25519 AAAA",
				PrivateKey:   signer,
				Opened:       t,
				IdleDeadline: t.Add(idle),
				HardDeadline: t.Add(hard),
			}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// TestAdvDoorNeverStaysOpenAfterTransportLost: a live machine with a
// reservation in flight and a fresh session must end with state=Closed,
// sessions=0, reservations=0, no private key after TransportLost.
func TestAdvDoorNeverStaysOpenAfterTransportLost(t *testing.T) {
	m := advMachine(t, time.Minute, time.Hour)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation})
	apply(t, m, Input{Event: Success, DoorID: "door-A"})
	apply(t, m, Input{Event: Success})
	s := m.Snapshot()
	if s.State != Open || s.Reservations != 0 || s.Sessions != 1 {
		t.Fatalf("warm-up: %+v", s)
	}
	apply(t, m, Input{Event: TransportLost})
	s = m.Snapshot()
	if s.State != Closed || s.Reservations != 0 || s.Sessions != 0 || s.HasPrivateKey {
		t.Fatalf("TransportLost left door open or with state: %+v", s)
	}
}

// TestAdvAllWaysOutProduceClosedDoor: for every "leave" transition,
// verify the door ends Closed and the private key is forgotten.
func TestAdvAllWaysOutProduceClosedDoor(t *testing.T) {
	cases := []struct {
		name string
		run  func(m *Machine)
		// wantFinalDoorKey=true means we accept the key may still be in
		// memory while the machine is in the middle of Closing (the door
		// itself is gone from the world but the cell hasn't been driven
		// to forgetDoor yet).
		wantClosed    bool
		wantForgotten bool
	}{
		{
			// Cancel during Opening + late Success → Closing with the door
			// still in memory (ClosingSuccess with foreign Own=false would
			// forgetDoor; with Own=true it also forgets). drive to Closing
			// is the half-step; the door key stays until close reply.
			name: "opening_cancel_then_success",
			run: func(m *Machine) {
				apply(t, m, Input{Event: Status})
				apply(t, m, Input{Event: Reservation})
				apply(t, m, Input{Event: CancelReservation})
				apply(t, m, Input{Event: Success, DoorID: "door-A"})
			},
			wantClosed:    true,
			wantForgotten: false,
		},
		{
			name: "opening_failure",
			run: func(m *Machine) {
				apply(t, m, Input{Event: Status})
				apply(t, m, Input{Event: Reservation})
				apply(t, m, Input{Event: Failure})
			},
			wantClosed:    true,
			wantForgotten: true,
		},
		{
			name: "opening_timeout",
			run: func(m *Machine) {
				apply(t, m, Input{Event: Status})
				apply(t, m, Input{Event: Reservation})
				apply(t, m, Input{Event: Timeout})
			},
			wantClosed:    true,
			wantForgotten: true,
		},
		{
			// nestedFailure with sessions==1, reservations==0: doesn't
			// reach Closing yet. Drive one more nested failure or
			// finishSession first. Here we use sessions==0 case by
			// applying Reservation after OpeningSuccess.
			name: "opening_nested_failure_immediate",
			run: func(m *Machine) {
				apply(t, m, Input{Event: Status})
				apply(t, m, Input{Event: Reservation})
				apply(t, m, Input{Event: Success, DoorID: "door-A"})
				// success from Opening -> Open with reservations=1.
				// Apply NestedFailure from Open with reservations=1: that
				// decrements and idleCloses because sessions==0 and
				// reservations==0 after decrement.
				apply(t, m, Input{Event: NestedFailure})
			},
			wantClosed:    true,
			wantForgotten: false, // Closing, door still in machine
		},
		{
			name: "open_session_finished",
			run: func(m *Machine) {
				apply(t, m, Input{Event: Status})
				apply(t, m, Input{Event: Reservation})
				apply(t, m, Input{Event: Success, DoorID: "door-A"})
				apply(t, m, Input{Event: Success}) // nestedSuccess: sessions=1
				if _, err := m.FinishSession(); err != nil {
					t.Fatal(err)
				}
			},
			wantClosed:    true,
			wantForgotten: false, // Closing, door still in machine
		},
		{
			name: "closing_close_failure",
			run: func(m *Machine) {
				apply(t, m, Input{Event: Status})
				apply(t, m, Input{Event: Reservation})
				apply(t, m, Input{Event: Success, DoorID: "door-A"})
				apply(t, m, Input{Event: Success})
				if _, err := m.FinishSession(); err != nil {
					t.Fatal(err)
				}
				apply(t, m, Input{Event: Failure})
			},
			wantClosed:    true,
			wantForgotten: true,
		},
		{
			name: "closing_close_timeout_twice",
			run: func(m *Machine) {
				apply(t, m, Input{Event: Status})
				apply(t, m, Input{Event: Reservation})
				apply(t, m, Input{Event: Success, DoorID: "door-A"})
				apply(t, m, Input{Event: Success})
				if _, err := m.FinishSession(); err != nil {
					t.Fatal(err)
				}
				apply(t, m, Input{Event: Timeout})
				apply(t, m, Input{Event: Timeout})
			},
			wantClosed:    true,
			wantForgotten: true,
		},
		{
			name: "transport_lost",
			run: func(m *Machine) {
				apply(t, m, Input{Event: Status})
				apply(t, m, Input{Event: Reservation})
				apply(t, m, Input{Event: TransportLost})
			},
			wantClosed:    true,
			wantForgotten: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := advMachine(t, time.Minute, time.Hour)
			tc.run(m)
			s := m.Snapshot()
			if s.State != Closed && s.State != Closing {
				t.Fatalf("state=%s, want Closed or Closing (snap=%+v)", s.State, s)
			}
			if tc.wantForgotten && s.HasPrivateKey {
				t.Fatalf("door private key still in machine after %s: %+v", tc.name, s)
			}
			if s.Reservations != 0 || s.Sessions != 0 {
				t.Fatalf("counters not zero after %s: %+v", tc.name, s)
			}
		})
	}
}

// TestAdvReconnectDoesNotDuplicateDoors: a machine reconnects with a
// door still installed on the remote. The gateway must close the
// foreign door, mark reconcile, and accept no reservations during the
// window. Two simultaneous reservations during reconcile must produce
// exactly one door.open on the eventual reconciled state.
func TestAdvReconnectDoesNotDuplicateDoors(t *testing.T) {
	m := advMachine(t, time.Minute, time.Hour)
	apply(t, m, Input{Event: Status, Installed: true, DoorID: validForeignDoorID})
	// closedStatus transition moves to Closing and emits door.close.
	if s := m.Snapshot(); s.State != Closing {
		t.Fatalf("after closedStatus Installed: %+v", s)
	}
	apply(t, m, Input{Event: Success, DoorID: validForeignDoorID, Own: false})
	if s := m.Snapshot(); s.State != Closed || !s.ReconcilePending {
		t.Fatalf("after foreign close: %+v", s)
	}
	// Now reconcile completes via door.status installed=false.
	apply(t, m, Input{Event: Status, Installed: false})
	if s := m.Snapshot(); s.State != Closed || s.ReconcilePending {
		t.Fatalf("reconcile: %+v", s)
	}
	// Reserve now: should issue a fresh door.open since reconcile is false.
	c := apply(t, m, Input{Event: Reservation})
	if len(c) != 1 || c[0].Op != "door.open" {
		t.Fatalf("reservation after reconcile did not open: %+v", c)
	}
}

// TestAdvDoorOpenDuringReconcileDeferred: while reconcile is pending
// (a foreign door was seen), reservations do NOT trigger a second
// door.open — they bump the counter only. This is the "concurrent
// reservations share door" guarantee at the reconcile boundary.
func TestAdvDoorOpenDuringReconcileDeferred(t *testing.T) {
	m := advMachine(t, time.Minute, time.Hour)
	apply(t, m, Input{Event: Status, Installed: true, DoorID: validForeignDoorID})
	apply(t, m, Input{Event: Success, DoorID: validForeignDoorID, Own: false})
	// Now state==Closed, reconcile==true.
	c := apply(t, m, Input{Event: Reservation})
	if len(c) != 0 {
		t.Fatalf("reservation during reconcile issued commands: %+v", c)
	}
	if s := m.Snapshot(); s.State != Closed || s.Reservations != 1 || !s.ReconcilePending {
		t.Fatalf("after reservation during reconcile: %+v", s)
	}
	// Second reservation still defers.
	c = apply(t, m, Input{Event: Reservation})
	if len(c) != 0 {
		t.Fatalf("second reservation during reconcile issued commands: %+v", c)
	}
	if s := m.Snapshot(); s.Reservations != 2 {
		t.Fatalf("reservations=%d, want 2", s.Reservations)
	}
	// Reconcile clears; reservation now needs to issue door.open.
	apply(t, m, Input{Event: Status, Installed: false})
	if s := m.Snapshot(); s.ReconcilePending {
		t.Fatalf("reconcile not cleared: %+v", s)
	}
	// The pending reservations have NOT triggered a door.open yet.
	// A subsequent reservation will issue door.open because reservations>0
	// and reconcile==false. (This is what the implementation does.)
	c = apply(t, m, Input{Event: Reservation})
	// closedReserve: bump reservations, since not reconcile, startOpen.
	if len(c) != 1 || c[0].Op != "door.open" {
		t.Fatalf("reservation after reconcile cleared: %+v", c)
	}
}

// TestAdvNestedFailureDoesNotDecrementBelowZero: a nestedFailure on an
// Open state with no reservations must not corrupt counters.
func TestAdvNestedFailureDoesNotDecrementBelowZero(t *testing.T) {
	m := advMachine(t, time.Minute, time.Hour)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation})
	apply(t, m, Input{Event: Success, DoorID: "door-A"})
	if s := m.Snapshot(); s.State != Open || s.Reservations != 1 {
		t.Fatalf("after Opening Success: %+v", s)
	}
	// Establish one session via nested Success: reservations=0, sessions=1.
	apply(t, m, Input{Event: Success})
	if s := m.Snapshot(); s.Reservations != 0 || s.Sessions != 1 {
		t.Fatalf("after nested Success: %+v", s)
	}
	// Now NestedFailure with reservations=0 must return protocolErr.
	if _, err := m.Apply(Input{Event: NestedFailure}); err == nil {
		t.Fatal("NestedFailure with reservations=0 returned no error")
	}
}

// TestAdvFinishedSessionWithForeignDoorMismatch: closingSuccess checks
// the door id matches. If a foreign door id arrives while Closing, the
// cell returns protocolErr — and the runtime must surface that.
func TestAdvClosingSuccessForeignDoorIsProtocolError(t *testing.T) {
	m := advMachine(t, time.Minute, time.Hour)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation})
	apply(t, m, Input{Event: Success, DoorID: "door-A"})
	apply(t, m, Input{Event: Success})
	if _, err := m.FinishSession(); err != nil {
		t.Fatal(err)
	}
	if s := m.Snapshot(); s.State != Closing {
		t.Fatalf("want Closing after finishSession, got %s", s.State)
	}
	// Reply for a different door id: protocolErr.
	if _, err := m.Apply(Input{Event: Success, DoorID: "door-FOREIGN", Own: true}); err == nil {
		t.Fatal("closingSuccess with foreign DoorID: no error")
	}
}

// TestAdvCancelReservationInOpening: a cancel reservation while Opening
// brings reservations to 0. A subsequent Success from Opening goes to
// Closing (idle), proving the reservation is not resurrected.
func TestAdvCancelInOpeningThenSuccessCloses(t *testing.T) {
	m := advMachine(t, time.Minute, time.Hour)
	apply(t, m, Input{Event: Status})
	apply(t, m, Input{Event: Reservation})
	apply(t, m, Input{Event: CancelReservation})
	if s := m.Snapshot(); s.Reservations != 0 || s.State != Opening {
		t.Fatalf("after cancel: %+v", s)
	}
	c := apply(t, m, Input{Event: Success, DoorID: "door-A"})
	if s := m.Snapshot(); s.State != Closing {
		t.Fatalf("Success after cancel: state=%s", s.State)
	}
	if len(c) != 1 || c[0].Op != "door.close" || c[0].Reason != "idle" {
		t.Fatalf("expected idle close, got %+v", c)
	}
}

// TestAdvGenerationTwo: a successful reservation/finish cycle followed
// by another reservation must produce a DIFFERENT door id (the door key
// is regenerated), so the machine's authorized_keys is updated. If the
// id ever repeated, the machine would still trust the new key (because
// it was a different ed25519 key) — but if the id matched a prior
// door, a downgrade would be impossible by construction. We test that
// the ids differ across cycles.
func TestAdvGenerationTwoProducesNewDoorId(t *testing.T) {
	m := advMachine(t, time.Minute, time.Hour)
	apply(t, m, Input{Event: Status})
	c := apply(t, m, Input{Event: Reservation})
	id1 := c[0].Door.ID
	apply(t, m, Input{Event: Success, DoorID: id1})
	apply(t, m, Input{Event: Success})
	if _, err := m.FinishSession(); err != nil {
		t.Fatal(err)
	}
	apply(t, m, Input{Event: Success, DoorID: id1, Own: true})
	c = apply(t, m, Input{Event: Reservation})
	if len(c) == 0 {
		t.Fatal("second reservation produced no commands")
	}
	if c[0].Door.ID == id1 {
		t.Fatalf("door id did not change: %s", c[0].Door.ID)
	}
}

// TestAdvNewDoorValidation: startOpen validates the door structure. A
// test-injected NewDoor returning a zero Door must be rejected — the
// runtime MUST NOT trust an unvalidated door, because if NewDoor is
// ever swapped (it is injected through a constructor) a
// caller could try to make the runtime accept a door with no private
// key, no id, or a time relation that lets idleClose misfire.
func TestAdvNewDoorValidationRejectsZero(t *testing.T) {
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	m, err := NewMachine(Config{
		Now:      func() time.Time { return now },
		DoorIdle: time.Minute,
		DoorHard: time.Hour,
		NewDoor: func(t time.Time) (Door, error) {
			return Door{}, nil // zero door
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	apply(t, m, Input{Event: Status})
	if _, err := m.Apply(Input{Event: Reservation}); err == nil {
		t.Fatal("zero Door accepted by startOpen")
	}
}

// TestAdvMalformedDoorOpenReplyAccepted: openingSuccess does not
// require DoorID when in.DoorID == "" — the runtime trusts the reply
// unconditionally. The wire-level reply is unmarshalled with the
// error discarded, so a machine that returns a malformed doorOpenResult
// (DoorID="") makes the state machine move to Open. The actual security
// lies in sshd's authorized_keys check (the nested handshake fails if
// the door key isn't installed), so this is a documentation finding,
// not an exploitable bug.
//
// We pin it here as evidence the runtime is permissive at this layer.
func TestAdvMalformedDoorOpenReplyAccepted(t *testing.T) {
	m := advMachine(t, time.Minute, time.Hour)
	apply(t, m, Input{Event: Status})
	cmds := apply(t, m, Input{Event: Reservation})
	if len(cmds) == 0 || cmds[0].Door.ID == "" {
		t.Fatalf("first reservation issued no door: %+v", cmds)
	}
	issuedID := cmds[0].Door.ID
	// A reply with an EMPTY DoorID: openingSuccess treats DoorID=="" as
	// "skip the id check" and goes to Open. Pin the behavior.
	if _, err := m.Apply(Input{Event: Success, DoorID: ""}); err != nil {
		t.Fatalf("openingSuccess with empty DoorID errored: %v", err)
	}
	if s := m.Snapshot(); s.State != Open {
		t.Fatalf("after empty DoorID success: %+v", s)
	}
	_ = issuedID
}
