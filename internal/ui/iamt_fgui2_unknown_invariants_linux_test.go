//go:build linux

package ui

// iamt_fgui2_unknown_invariants_linux_test.go — F-GUI-2 (review
// round 20, HIGH, confirmed): the layout-level half of the fix, in the
// same style as invariants_linux_test.go (IAMT-255). An Unknown status
// must present a visible Stop control and an unmissable strip above the
// tabs — never START as the only fact, never a silently absent strip —
// exactly the invariant IAMT-255 already pins for a KNOWN busy server,
// now extended to the case where the window could not check at all.
//
// Run on the Linux host: go test -count=1 ./internal/ui/

import (
	"image"
	"testing"
)

// unknownSnap returns a snapshot whose server status could not be
// learned at all: every other field is a bare Go zero value — the exact
// shape pollServerStatus builds on a permission-denied read (IAMT-311) —
// so a server that is, in fact, busy must still not read as idle here.
func unknownSnap() Snapshot {
	return Snapshot{
		Server: ServerState{Unknown: true, UnknownReason: "unknown — root privileges are required to check: run \"sudo iamtunnel server status\" in a terminal"},
		Setup:  SetupState{MachineName: "lin-ubu-vm"},
	}
}

// TestFGUI2_StopControlShownWhenStatusIsUnknown is THE canary the
// finding asked for.
//
// Canary: gate f.lastStopButtonShown (screens.go) or the STOP/START
// branch on Busy() instead of MaybeBusy(). This test goes red on:
//
//	STOP control not shown while the server status is unknown — an
//	unreachable status must never present START as a fact (F-GUI-2)
func TestFGUI2_StopControlShownWhenStatusIsUnknown(t *testing.T) {
	snap := unknownSnap()
	for _, sz := range []image.Point{{1024, 700}, {800, 600}, {640, 480}, {480, 360}} {
		f := makeLinuxFrame(t, snap)
		callLayout(t, f, sz.X, sz.Y)
		if !f.lastStopButtonShown {
			t.Errorf("%dx%d: STOP control not shown while the server status is unknown — an unreachable status must never present START as a fact (F-GUI-2)", sz.X, sz.Y)
		}
	}
}

// TestFGUI2_UnknownStripShownInsteadOfSilentlyDisappearing pins the
// strip half: the recording strip's own slot must not go blank just
// because Recording() reads false on an Unknown status (Sessions is a
// bare zero value there) — the unknown-status strip takes its place.
//
// Canary: drop layoutUnknownStatusStrip's wiring in frame.go's Layout
// (the switch that picks it over layoutRecordingStrip). This test goes
// red on:
//
//	the recording-strip slot went blank while the server status is
//	unknown — a server that may in fact be recording must not silently
//	lose its unmissable strip (F-GUI-2)
func TestFGUI2_UnknownStripShownInsteadOfSilentlyDisappearing(t *testing.T) {
	snap := unknownSnap()
	for _, sz := range []image.Point{{1024, 700}, {800, 600}, {640, 480}, {480, 360}} {
		f := makeLinuxFrame(t, snap)
		callLayout(t, f, sz.X, sz.Y)
		if !f.lastUnknownStripShown {
			t.Errorf("%dx%d: the recording-strip slot went blank while the server status is unknown — a server that may in fact be recording must not silently lose its unmissable strip (F-GUI-2)", sz.X, sz.Y)
		}
		if f.lastRecordingStripShown {
			t.Errorf("%dx%d: the ordinary recording strip rendered on an Unknown status — it has no Sessions data to show and would draw a fabricated one", sz.X, sz.Y)
		}
	}
}

// TestFGUI2_KnownIdleStateIsUnaffected proves the fix is scoped: a
// genuinely idle, RIGHTS-PRESENT server (Unknown false) must keep
// showing START and no strip at all, exactly as IAMT-255 already pins.
func TestFGUI2_KnownIdleStateIsUnaffected(t *testing.T) {
	f := makeLinuxFrame(t, idleSnap())
	callLayout(t, f, 1024, 700)
	if f.lastStopButtonShown {
		t.Error("a genuinely idle, rights-present server shows STOP — MaybeBusy must not widen the ordinary idle case")
	}
	if f.lastUnknownStripShown || f.lastRecordingStripShown {
		t.Error("a genuinely idle, rights-present server shows a strip — neither Unknown nor Recording is true here")
	}
}

// TestFGUI2_KnownBusyStateIsUnaffected proves the other direction: a
// genuinely busy, rights-present server keeps the ordinary recording
// strip and STOP, not the unknown-status one.
func TestFGUI2_KnownBusyStateIsUnaffected(t *testing.T) {
	f := makeLinuxFrame(t, recordingSnap())
	callLayout(t, f, 1024, 700)
	if !f.lastStopButtonShown {
		t.Error("a genuinely busy server does not show STOP")
	}
	if !f.lastRecordingStripShown {
		t.Error("a genuinely busy server does not show the ordinary recording strip")
	}
	if f.lastUnknownStripShown {
		t.Error("a genuinely busy (KNOWN) server shows the unknown-status strip")
	}
}
