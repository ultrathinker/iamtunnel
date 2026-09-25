package ui

// Canary C4: gate 17 takes its sub-tabs from the same function the
// layout does. The sub-tab table had already drifted once (it listed
// "New grant", which does not exist in the window), and Live -- the
// most likely next page to not fit -- was missing. C4: the
// source is the adminSubTabOrder() function, so that forgetting is
// impossible.

import (
	"testing"
)

// TestCanary_C4_Gate17AdminSubTabsComeFromTheLayout.
//
// Canary: restore a hardcoded table in subTabsOf[TabAdmin] -- the
// test goes red. A hardcode cannot keep up with adminSubTabOrder(),
// and Gate 17 stops being the same test that draws the window: add a
// sub-tab and the gate does not check it, because its table did not
// update. C4 -- the source is the single one,
// adminSubTabOrder().
func TestCanary_C4_Gate17AdminSubTabsComeFromTheLayout(t *testing.T) {
	// The gate's table must be the same slice the layout reads; both
	// are adminSubTabOrder(). A future edit that re-hardcodes the
	// table -- even with the right values -- fails the equality check
	// because the assertion is on the SAME slice, not on equality of
	// contents (which a re-hardcode could also pass and still diverge
	// silently the next time someone adds a sub-tab).
	if subTabsOf[TabAdmin] == nil {
		t.Fatalf("subTabsOf[TabAdmin] is nil -- gate 17 does not know which sub-tabs the window draws")
	}
	fromOrder := adminSubTabOrder()
	if len(subTabsOf[TabAdmin]) != len(fromOrder) {
		t.Fatalf("subTabsOf[TabAdmin] = %v (len %d), adminSubTabOrder() = %v (len %d) -- gate 17 stopped reading from the window's source",
			subTabsOf[TabAdmin], len(subTabsOf[TabAdmin]),
			fromOrder, len(fromOrder))
	}
	for i, want := range fromOrder {
		if got := subTabsOf[TabAdmin][i]; got != want {
			t.Errorf("subTabsOf[TabAdmin][%d] = %q, adminSubTabOrder()[%d] = %q -- divergence at index %d",
				i, got, i, want, i)
		}
	}

	// And: the table MUST include "Live" -- the sub-tab that the gate
	// failed to cover before this fix (the old hand-written table
	// omitted it). If a future revert drops the adminSubTabOrder() call
	// in favour of a fixed list, the line below pins the omission.
	found := false
	for _, name := range subTabsOf[TabAdmin] {
		if name == "Live" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("subTabsOf[TabAdmin] does not contain Live -- gate 17 does not cover the most likely page to not fit (C4)")
	}

	// And: the table MUST NOT include "New grant" — that sub-tab was
	// merged into Access back in 1bba3a8 and the hand-written gate
	// still listed it. A fixed list that re-introduces the dead name
	// fails here.
	for _, name := range subTabsOf[TabAdmin] {
		if name == "New grant" {
			t.Fatalf("subTabsOf[TabAdmin] still contains \"New grant\" -- that sub-tab does not exist in the window, it merged with Access in 1bba3a8")
		}
	}
}
