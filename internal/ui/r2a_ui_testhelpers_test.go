//go:build windows || linux || darwin

package ui

import "testing"

// newBareFrame builds a Frame with no runtime behind it — the shape
// every offscreen test in this package works with.
//
// It is declared in its own file carrying gui.go's tag, and for a
// reason (R2, 24.09.2026): it used to live in iamt149_actions_test.go
// under //go:build windows, while tests tagged
// windows || linux || darwin (iamt336, r1cx_f16) and untagged ones
// (risk_mode, iamt453, the zz_canary files) call it on linux and
// darwin too, and the package did not even compile there — vet on a
// Linux container stopped at "undefined: newBareFrame". Same tag as the
// code under test, so the helper is visible wherever the Frame is.
//
// The ThemeSource is a fixed fake (MAC, 24.09.2026). With the field
// unset NewFrame falls back to the production source, which on darwin
// is the live macOS probe — and that probe's own seam refuses to run in
// a test binary ("tests must install a fake outputFn"), by design: an
// offscreen test must never read the operator's real appearance
// settings. The same rule the windows tests keep with fakeThemeSource,
// applied to every offscreen frame at the one door they all walk
// through.
func newBareFrame(t *testing.T) *Frame {
	t.Helper()
	f, err := NewFrame(FrameConfig{
		Enrolled:    true,
		ThemeSource: ThemeSourceFunc(func() bool { return false }),
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	return f
}

// subTabsOf is the sub-tab set of each tab, as the screens declare them.
// Admin is derived from adminSubTabOrder() — the screens' own list — so
// a sub-tab added or renamed in the Admin tab shows up in the gate
// without a second edit. The other tabs' sub-tabs stay
// hand-written because the same comment as before still applies: a
// gap there is a thing a reader can notice.
// Two tabs are deliberately absent, and their absence is the rule
// working rather than a gap in it.
//
// GUIDE is a chart of a process that spans three computers; it is long by
// design and is the page TestGate17TheGateCanActuallyFail uses precisely
// because it must overflow.
//
// HISTORY (21.09.2026) is a paged list. Gate 17's rule is "a sub-tab that
// no longer fits is a signal to divide it further" -- and a history IS
// divided further, into pages of twenty or fifty. Measuring it would
// demand that a list of rows fit the window, which is the same as
// demanding that a history have no rows.
//
// It lives in this three-platform file (R2, 24.09.2026): gate 17's own
// file is windows-tagged — it renders — but the C4 canary
// (zz_canary_gate17source_test.go), which pins this table to
// adminSubTabOrder(), is not, and could not compile without the table.
var subTabsOf = map[string][]string{
	TabSetUp:    {""},
	TabClient:   {"Machines", "Connection", "Key"},
	TabServer:   {""},
	TabSession:  {""},
	TabAdmin:    adminSubTabOrder(),
	TabSettings: {""},
}
