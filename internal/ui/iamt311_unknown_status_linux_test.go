//go:build linux

package ui

// iamt311_unknown_status_linux_test.go — IAMT-311's layout-level pin, in
// the same style as invariants_linux_test.go (IAMT-255): the headless
// GPU renderer stays Windows-only, so this asserts the structural flag
// layoutServerScreen sets from Server.Unknown, not pixels.
//
// Run on the Linux host: go test -count=1 ./internal/ui/

import (
	"testing"
)

// TestServerFactsUnknownFlagFollowsSnapshot pins that layoutServerScreen
// actually reads Server.Unknown on every pass — not merely that
// ServerState carries the field — and that it clears the moment the
// snapshot goes back to a fact the window can vouch for.
//
// CANARY (red text on regression): quoted below. Drop the
// f.lastServerFactsUnknown = s.Unknown assignment in screens.go and the
// first two assertions redden.
func TestServerFactsUnknownFlagFollowsSnapshot(t *testing.T) {
	unknown := Snapshot{
		Server: ServerState{Unknown: true, UnknownReason: "unknown — root privileges are required to check"},
		Setup:  SetupState{MachineName: "lin-ubu-vm"},
	}
	f := makeLinuxFrame(t, unknown)
	callLayout(t, f, 1024, 700)
	if !f.lastServerFactsUnknown {
		t.Fatalf("layoutServerScreen did not record Server.Unknown — a permission-denied status would silently draw as a confident \"not running\"/\"offline\" again (IAMT-311)")
	}

	// The same frame, re-laid-out against a snapshot the window CAN
	// vouch for: the flag must fall back to false, the same
	// "shown this pass, not shown once and stuck" discipline
	// lastRecordingStripShown/lastStopButtonShown already follow.
	known := makeLinuxFrame(t, idleSnap())
	callLayout(t, known, 1024, 700)
	if known.lastServerFactsUnknown {
		t.Fatalf("an ordinary idle (rights-present) snapshot was recorded as Unknown")
	}
}
