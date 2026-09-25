//go:build windows

package ui

// iamt330_pairing_wakeup_windows_test.go — the layout half of the round-3
// wake-up fix (IAMT-330): layoutPairingCard must itself ask Gio for the
// frame that flips the card at the expiry instant. The proof goes through
// a real input.Router attached to the layout context — the same seam Gio's
// own TestRouterWakeup uses — so the assertion is about the InvalidateCmd
// the layout actually issued, not about a helper's opinion. The pure
// decision behind the wiring is pinned platform-independently in
// iamt330_pairing_expiry_test.go.

import (
	"image"
	"testing"
	"time"

	"gioui.org/io/input"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
)

// layoutPairingCardInto lays the card out once with a router-backed event
// source and reports the redraw the router was promised.
func layoutPairingCardInto(t *testing.T, f *Frame) (time.Time, bool) {
	t.Helper()

	var ops op.Ops
	router := new(input.Router)
	gtx := layout.Context{
		Ops:         &ops,
		Constraints: layout.Constraints{Max: image.Pt(shotW, shotH)},
		Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
		Source:      router.Source(),
	}
	f.layoutPairingCard(gtx)

	return router.WakeupTime()
}

func TestPairingCardLayoutRequestsTheNextSecond(t *testing.T) {
	before := time.Now()
	expires := before.Add(90 * time.Second)
	f, err := NewFrame(FrameConfig{
		Enrolled: true,
		Snap:     Snapshot{Admin: AdminState{Pairing: &PairingWindow{Pin: "012345", Expires: expires}}},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	at, wake := layoutPairingCardInto(t, f)
	after := time.Now()

	if !wake {
		t.Fatal("layout of an open pairing window requested no redraw — on an idle Admin tab nothing would ever flip the card to \"expired\"")
	}
	// A second from whenever the layout ran. The card draws a countdown
	// now, so the frame it asks for is the next tick of that countdown,
	// not the far-off expiry: the clock has to move while nobody touches
	// the window. The bound is the real clock either side of the call,
	// because the layout reads time.Now() itself.
	if at.Before(before.Add(time.Second)) || at.After(after.Add(time.Second)) {
		t.Fatalf("layout requested a redraw for %v, want about one second from the layout (%v..%v)",
			at, before.Add(time.Second), after.Add(time.Second))
	}
	if !at.Before(expires) {
		t.Fatalf("layout requested %v, which is at or past the expiry %v — the countdown would never tick", at, expires)
	}
}

func TestPairingCardLayoutGoesQuietOnceExpired(t *testing.T) {
	f, err := NewFrame(FrameConfig{
		Enrolled: true,
		Snap: Snapshot{Admin: AdminState{Pairing: &PairingWindow{
			Pin:     "012345",
			Expires: time.Now().Add(-time.Second),
		}}},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	if at, wake := layoutPairingCardInto(t, f); wake {
		t.Fatalf("layout of a lapsed window still asks for a redraw (at %v) — the flip already happened and the card must not spin", at)
	}

	// And the same quietness with no window at all.
	f2, err := NewFrame(FrameConfig{Enrolled: true})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	if at, wake := layoutPairingCardInto(t, f2); wake {
		t.Fatalf("layout with no pairing window asked for a redraw (at %v) — nothing there ever expires", at)
	}
}
