package gateway

// F-23 (round-1 review, 24.09.2026): core.Machine's own mutex makes
// each transition atomic, but the command a transition returns is written
// to the control channel by whoever holds it, and nothing serialized the
// two halves. A reserve can therefore apply its Reservation (the automaton
// is Opening, door.open is in its hand) and be parked before the write,
// while machines.set-user's closeForOSUserChange ForceCloses the same
// automaton and writes door.close at once. The machine sees close-then-
// open - a close of a door that does not exist yet, answered ok, then a
// late open whose key it installs. The reply to that late open lands on an
// automaton that is already Closed, whose success cell is a protocol
// error: the temporary key stays on the machine, and the reservation's
// ticket is never resolved - the session hangs until its own budget dies.
//
// The test parks the reserve in exactly that window (beforeSendCommandFn,
// a test-only seam) and lets the close overtake it. What it asserts is the
// wire order the fix owes: the door.open the automaton issued first must
// reach the machine first, the close must remove what the open installed,
// and the reservation must be resolved by a ticket outcome, not by its own
// expiry.
//
// reserve and closeForOSUserChange are driven directly because the race
// lives entirely inside machineConn; these are the same entry points the
// human session (human_role.go) and the machines.set-user handler
// (admin_role.go) call.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
)

func TestR1CX_F23_DoorCloseCannotOvertakeTheOpenTheAutomatonIssuedFirst(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("machine did not register")
	}

	// Park the reserve between its Reservation transition and the write of
	// the door.open that transition produced. Only a door.open parks; the
	// sweep's door.status and the close that follows go straight through.
	parked := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	prevSeam := beforeSendCommandFn.Load()
	seam := func(mc *machineConn, cmd core.Command) {
		if cmd.Op != "door.open" {
			return
		}
		once.Do(func() {
			close(parked)
			<-release
		})
	}
	beforeSendCommandFn.Store(&seam)
	t.Cleanup(func() { beforeSendCommandFn.Store(prevSeam) })

	reserved := make(chan bool, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		ok, _ := mc.reserve(ctx)
		reserved <- ok
	}()

	select {
	case <-parked:
	case <-time.After(10 * time.Second):
		t.Fatal("the reserve never reached the window between its Reservation transition and the door.open write")
	}

	// The admin side: machines.set-user's door close, started while the
	// open the automaton issued first is still unwritten.
	closeDone := make(chan struct{})
	go func() {
		mc.closeForOSUserChange()
		close(closeDone)
	}()

	// Give the close its chance to overtake. Once the wire cycle is
	// serialized (the fix), this close cannot even apply its ForceClose
	// while the parked reserve holds the connection's drive lock, so the
	// window simply elapses; before the fix it completes within it.
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
	}

	close(release)

	// The late open must reach the machine before anything is asserted:
	// the wire order is the fact under test, and it is complete only once
	// the parked reserve has finally written its command - and once the
	// close has been written too (before the fix it is already done; with
	// the fix it went after the open cycle, so wait for it here).
	fm.waitDoorOpenReceived(t, 10*time.Second)

	select {
	case <-closeDone:
	case <-time.After(10 * time.Second):
		t.Fatal("closeForOSUserChange never finished")
	}

	var openIdx, closeIdx = -1, -1
	for i, op := range fm.controlOps() {
		switch op {
		case "door.open":
			if openIdx == -1 {
				openIdx = i
			}
		case "door.close":
			if closeIdx == -1 {
				closeIdx = i
			}
		}
	}
	if openIdx == -1 || closeIdx == -1 {
		t.Fatalf("expected one door.open and one door.close on the wire, saw %q", fm.controlOps())
	}
	if closeIdx < openIdx {
		t.Fatalf("door.close reached the machine before the door.open the automaton had issued first (wire order %q) - the control channel can disagree with the automaton's own transition order (F-23)", fm.controlOps())
	}

	select {
	case ok := <-reserved:
		if !ok {
			t.Fatal("the reservation failed even though its door.open reached the machine and was answered with success - the late reply landed on an automaton that had already been Closed by the overtaking close")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the reservation was never resolved - its ticket was left hanging by the late reply and it died of its own budget instead")
	}

	if installed, id := fm.doorInstalled(); installed {
		t.Fatalf("the machine still holds the temporary key %q: the overtaking door.close found no door to remove, and the late door.open's key was never closed off", id)
	}
}
