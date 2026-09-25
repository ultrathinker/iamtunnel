package ui

// Maintainer canaries: the Admin tab must KNOW what the gateway
// holds.
//
// Found by the maintainer on 19.09.2026 while issuing the first
// grant. The instruction was "pick from the list" -- there was no
// list. Neither People, nor Machines, nor Access, nor the pickers on
// the grant form were filled with anything: the window had not a
// single call asking the gateway for people, machines and grants. The
// snapshot fields existed, and nobody wrote into them.
//
// It was visible only by eye, and so it survived into a live pass.
// The existing tests checked that the ACTION cards call the right
// action with the right fields; nobody checked that eternally empty
// lists sit next to them -- an empty list looks like "nothing yet",
// not like "nobody ever asked".

import (
	"context"
	"testing"
	"time"
)

// TestCanary_AdminTabAsksTheGatewayWhenItOpens.
//
// Canary: remove the one-time refreshAdminLists call from
// layoutAdminScreen -- the test will say the tab drew itself without
// asking anything.
func TestCanary_AdminTabAsksTheGatewayWhenItOpens(t *testing.T) {
	f := newBareFrame(t)

	asked := make(chan struct{}, 4)
	f.cfg.Actions.AdminList = func(ctx context.Context) (AdminLists, error) {
		asked <- struct{}{}
		return AdminLists{
			People:   []Person{{Name: "admin", Admin: true, Keys: 1}},
			Machines: []AdminMachine{{Name: "win-test-vm", State: "verified", Online: true}},
			Grants:   []Grant{{Person: "admin", Machine: "win-test-vm"}},
		}, nil
	}

	// Through the TAB BODY, not the screen: since IAMT-365 arriving on a
	// tab is what triggers the fetch, and that decision lives one layer
	// up, with every other tab that shows a list. A canary that called
	// the screen directly would go on passing while the real path was
	// broken.
	gtx := newTestLayoutContext(900, 600)
	admin := f.makeTabBody(TabAdmin)
	_ = admin(gtx)

	select {
	case <-asked:
	case <-time.After(2 * time.Second):
		t.Fatal("the Admin tab drew itself without asking the gateway anything -- exactly how its lists stayed empty on a gateway holding a person and a machine")
	}

	// And the result must reach the snapshot: asking and throwing the
	// answer away is the same as not asking.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.takeSnapshot()
		if len(f.snap.Admin.People) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if len(f.snap.Admin.People) != 1 || f.snap.Admin.People[0].Name != "admin" {
		t.Errorf("people in the snapshot = %+v, want a single admin -- the gateway's answer never reached what gets drawn", f.snap.Admin.People)
	}
	if len(f.snap.Admin.Machines) != 1 || len(f.snap.Admin.Grants) != 1 {
		t.Errorf("machines = %+v, grants = %+v -- all three lists arrive in one answer and must reach together",
			f.snap.Admin.Machines, f.snap.Admin.Grants)
	}

	// Exactly once per draw: asking the gateway on every frame is a
	// network call sixty times a second.
	_ = admin(gtx)
	_ = admin(gtx)
	time.Sleep(50 * time.Millisecond)
	if n := len(asked); n > 0 {
		t.Errorf("the tab asked the gateway %d more times on redraw -- that is a network call per frame", n)
	}
}

// TestCanary_ThePickersOfferWhatTheGatewayHolds: the
// names in the snapshot are the source of the pickers on the grant
// form. The maintainer must pick, not retype a name from somebody
// else's screen.
func TestCanary_ThePickersOfferWhatTheGatewayHolds(t *testing.T) {
	f := newBareFrame(t)
	f.snap.Admin.People = []Person{{Name: "admin", Admin: true}, {Name: "alice"}}
	f.snap.Admin.Machines = []AdminMachine{{Name: "win-test-vm"}, {Name: "ubu-vm"}}

	if got := peopleNames(f.snap.Admin.People); len(got) != 2 || got[0] != "admin" {
		t.Errorf("the people picker offers %v, want the names from the gateway", got)
	}
	if got := machineNames(f.snap.Admin.Machines); len(got) != 2 || got[0] != "win-test-vm" {
		t.Errorf("the machines picker offers %v, want the names from the gateway", got)
	}
}
