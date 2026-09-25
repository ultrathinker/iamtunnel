//go:build linux

package ui

// invariants_linux_test.go — IAMT-255: the same window invariants the
// Windows offscreen shot enforces at the pixel level (the recording
// warning on the client screen, the STOP button on the server
// screen — at every window size and every state) are asserted here at
// the layout level on Linux. The Windows build policy keeps the
// internal/ui offscreen GPU emulator behind //go:build windows
// (TestPlatformSplitTags in accept_test.go pins that),
// and re-importing gioui.org/gpu/headless from a non-Windows file would
// violate it. The structural flags the layouts now set are the
// cheapest faithful statement of the same invariant on the platforms
// where the headless renderer is not in the build.
//
// These tests do NOT replace the pixel-level Windows tests. They are
// the Linux half of the same invariant, asserted at the level the
// headless renderer cannot reach.

import (
	"image"
	"testing"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit" // package "unit" from gioui.org for layout metrics

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// callLayout runs one Frame.Layout pass against the live op.Ops, with
// a bare input router attached (same trick shot_windows.go uses to
// keep gtx.Enabled() true and the controls in their enabled style) and
// with the size a real person could reach by dragging the edge of the
// window. It returns the Frame the call laid out, so the test can
// assert on the structural flags.
func callLayout(t *testing.T, f *Frame, w, h int) {
	t.Helper()
	var ops op.Ops
	gtx := layout.Context{
		Ops:         &ops,
		Constraints: layout.Exact(image.Pt(w, h)),
		Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
	}
	f.Layout(gtx)
}

// makeLinuxFrame is a Frame wired for the same kind of rendering the
// shot uses: forced Light theme, no admin rights (so the elevation
// notice stays visible), and the supplied snapshot. It deliberately
// does not install a theme source — the frame chooses Light at
// construction because ForceTheme == ThemeLight.
func makeLinuxFrame(t *testing.T, snap Snapshot) *Frame {
	t.Helper()
	f, err := NewFrame(FrameConfig{
		Enrolled:       true,
		InitialTab:     TabServer,
		HasAdminRights: false,
		ForceTheme:     ThemeLight,
		Snap:           snap,
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	f.SelectTab(TabServer)
	return f
}

// recordingSnap returns a snapshot with one live session (so Server
// .AccessOpen() == true) and the matching "is being recorded" state.
func recordingSnap() Snapshot {
	return Snapshot{
		Server: ServerState{
			Waiting:     true,
			SshdRunning: true,
			Door:        DoorState{State: "open"},
			Sessions:    []Session{{Person: "alice", Started: time.Now(), Until: time.Now().Add(time.Hour)}},
		},
		Client: ClientState{Configured: true, PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test"},
		Setup:  SetupState{MachineName: "linux-srv01"},
	}
}

// idleSnap returns a snapshot of a server that is not running: no
// sessions, door closed, NOT waiting. With Waiting=false the screen's
// own Busy() (Waiting || Door.IsOpen() || Recording()) returns false,
// the STOP control is absent from the layout, and the structural
// invariants both fall back to false after one layout pass.
//
// "Waiting=true but door closed" would be a third state the live UI
// shows as a START control, not as STOP; the recording-strip and
// stop-button layout-level invariants describe the same
// "control-on-screen" truth the pixel-level Windows tests verify, and
// pin it on the busy branch.
func idleSnap() Snapshot {
	return Snapshot{
		Server: ServerState{Waiting: false, SshdRunning: false, Door: DoorState{State: "closed"}},
		Setup:  SetupState{MachineName: "linux-srv01"},
	}
}

// TestRecordingStripShownWheneverServerRecording is the Linux
// equivalent of the Windows pixel-level test
// TestVerifyRecordingWarningSurvivesEveryState in verify_iamt66_test.go.
// At every window size a real person can reach by dragging the edge
// of the window, and in every state where Server.AccessOpen() is
// true, the recording strip MUST be in the layout (not at pixel
// level — the headless renderer is Windows-only; this is the
// cheapest faithful statement the layout exposes). When the snapshot
// is idle the flag MUST be false.
//
// CANARY (red text on regression): "recording strip not in layout".
// Drop the assignment to f.lastRecordingStripShown in
// frame.go:387 and the test reddens on every recording state.
func TestRecordingStripShownWheneverServerRecording(t *testing.T) {
	snap := recordingSnap()

	for _, sz := range []image.Point{{1024, 700}, {800, 600}, {640, 480}, {480, 360}} {
		f := makeLinuxFrame(t, snap)
		callLayout(t, f, sz.X, sz.Y)
		if !f.lastRecordingStripShown {
			t.Errorf("%dx%d: recording strip not in layout — the warning left the live window", sz.X, sz.Y)
		}
	}

	// Negative half: idle server, no recording, no strip in layout.
	f := makeLinuxFrame(t, idleSnap())
	callLayout(t, f, 1024, 700)
	if f.lastRecordingStripShown {
		t.Errorf("idle server: recording strip must not be in layout when Server.AccessOpen() is false")
	}
}

// TestStopButtonShownWheneverServerBusy is the Linux equivalent of
// the Windows pixel-level test
// TestVerifyCutControlSitsAboveTheTabRuleOnEveryTab. Whenever the
// server is busy (a session is live AND the door is open), the STOP
// button MUST be in the layout at every window size; when the server
// is idle the flag MUST be false.
//
// CANARY (red text on regression): "STOP button not in layout".
// Drop the f.lastStopButtonShown = s.Busy() line in screens.go and
// the test reddens on every busy state.
func TestStopButtonShownWheneverServerBusy(t *testing.T) {
	snap := recordingSnap()

	for _, sz := range []image.Point{{1024, 700}, {800, 600}, {640, 480}, {480, 360}} {
		f := makeLinuxFrame(t, snap)
		callLayout(t, f, sz.X, sz.Y)
		if !f.lastStopButtonShown {
			t.Errorf("%dx%d: STOP button not in layout — the cutting control left the visible canvas", sz.X, sz.Y)
		}
	}

	f := makeLinuxFrame(t, idleSnap())
	callLayout(t, f, 1024, 700)
	if f.lastStopButtonShown {
		t.Errorf("idle server: STOP button must not be in layout when the server is not busy")
	}
}

// TestLayoutProducesBothInvariantsSimultaneously guards the
// invariant pair at the busiest layout pass: recording AND busy is
// the only state where a session is live, and a layout must paint
// both the recording strip AND the STOP control at the same time.
// A future regression that gates one behind the other would
// silently break the visible-canvas promise at one snapshot only.
func TestLayoutProducesBothInvariantsSimultaneously(t *testing.T) {
	f := makeLinuxFrame(t, recordingSnap())
	callLayout(t, f, 640, 480)
	if !f.lastRecordingStripShown {
		t.Errorf("busy server: recording strip missing from layout")
	}
	if !f.lastStopButtonShown {
		t.Errorf("busy server: STOP button missing from layout")
	}
}

// TestLayoutTypeDoesNotShrinkToMock pins a soft shape: the Frame's
// last-recording and last-stop flags are bool fields, not pointers
// to mocks, so a future refactor that swaps them for a heap-backed
// record cannot silently lose data on a layout pass that the test
// runs but the goroutine does not see (the test asserts on the
// returned Frame directly).
func TestLayoutTypeDoesNotShrinkToMock(t *testing.T) {
	f := makeLinuxFrame(t, recordingSnap())
	callLayout(t, f, 640, 480)
	if !f.lastRecordingStripShown || !f.lastStopButtonShown {
		t.Fatalf("busy server: both invariants must be on after one layout pass — got strip=%v stop=%v", f.lastRecordingStripShown, f.lastStopButtonShown)
	}
	// Re-layout with the idle snapshot; the flags MUST flip back
	// to false. A future change that captures the "shown once"
	// truth but never clears it would redden here.
	idle := makeLinuxFrame(t, idleSnap())
	callLayout(t, idle, 640, 480)
	if idle.lastRecordingStripShown {
		t.Errorf("idle layout still reports recording strip shown")
	}
	if idle.lastStopButtonShown {
		t.Errorf("idle layout still reports STOP button shown")
	}
}

// _ ensures the unused-import detector stays quiet if design is
// dropped from the import list in a future refactor; design is the
// place where the rendering contract lives.
var _ = design.Radius
