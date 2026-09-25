package ui

// iamt390_enrolcode_spent_test.go — IAMT-390's own canary: the "Invite a
// machine" card must stop handing over a one-time code the instant a
// machine by the invited name is already a row in the list below it.
//
// The maintainer hit exactly this on 20.09.2026: the enrol code, its expiry,
// the "Copy enrol code" button and the green "on the clipboard" line all
// still on screen while the very machine that name was minted for sat
// one row below, "win-test-vm verified · door closed · online". A second use
// of the same code can only be refused — the gateway spends it the
// instant the machine registers, which is why enrolCodeSpent checks
// presence in the list by NAME rather than waiting for "verified".
//
// enrolCodeSpent is a pure function so this is testable on every
// platform; the layout that calls it (layoutAdminScreen's Machines
// sub-tab) is windows-only, same as the rest of the render path.

import "testing"

func TestEnrolCodeSpentOnceTheNameIsInTheList(t *testing.T) {
	machines := []AdminMachine{
		{Name: "win-test-vm", State: "verified", DoorState: "closed", Online: true},
	}
	if !enrolCodeSpent("win-test-vm", machines) {
		t.Error(`enrolCodeSpent("win-test-vm", ...) = false, want true once that name is a row in the list`)
	}
	if !enrolCodeSpent("WIN-TEST-VM", machines) {
		t.Error("enrolCodeSpent must compare names case-insensitively, like every other name match on this screen")
	}
	if !enrolCodeSpent("  win-test-vm  ", machines) {
		t.Error("enrolCodeSpent must trim the box's own whitespace before comparing")
	}
}

func TestEnrolCodeSpentEvenBeforeVerification(t *testing.T) {
	// The code is redeemed the instant the machine registers with it —
	// before the entry check that later flips "enrolled" to "verified"
	// ever runs — so a merely "enrolled" row must already mark it spent.
	machines := []AdminMachine{{Name: "win-test-vm", State: "enrolled"}}
	if !enrolCodeSpent("win-test-vm", machines) {
		t.Error(`enrolCodeSpent("win-test-vm", ...) = false for a merely "enrolled" row, want true`)
	}
}

func TestEnrolCodeNotSpentBeforeTheNameAppearsAnywhere(t *testing.T) {
	machines := []AdminMachine{{Name: "some-other-box", State: "verified"}}
	if enrolCodeSpent("win-test-vm", machines) {
		t.Error(`enrolCodeSpent("win-test-vm", ...) = true, but that name is nowhere in the list`)
	}
	if enrolCodeSpent("win-test-vm", nil) {
		t.Error("enrolCodeSpent with no machines at all reported the code as already spent")
	}
	if enrolCodeSpent("", machines) {
		t.Error(`enrolCodeSpent("", ...) = true; an empty invited name (nothing minted yet) must never hide the form`)
	}
}
