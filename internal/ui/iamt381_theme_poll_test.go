package ui

// IAMT-381/382 canary: N frame passes in a row ask the ThemeSource for
// the system answer exactly once. A frame pass runs many times a
// second; paying an OS/API read on every pass turns every redraw into
// a polling loop for an answer that changes a few times a day. The
// per-frame probe is kept to once a second, while an explicit
// CheckThemeSync call (a settings action, a test) still switches
// instantly — the throttle lives only in the per-frame path.
//
// The test drives the REAL Frame.Layout the way
// TestLiveThemeSwitchEndToEnd does, with a counting source where the
// registry probe would be.

import (
	"image"
	"testing"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
)

// countingThemeSource answers fixed and remembers how many times it
// was asked — the stand-in for the OS theme probe.
type countingThemeSource struct {
	queries int
	dark    bool
}

func (c *countingThemeSource) IsDark() bool {
	c.queries++
	return c.dark
}

func TestIAMT381_NFramePassesAskTheThemeSourceOnce(t *testing.T) {
	src := &countingThemeSource{}
	frame, err := NewFrame(FrameConfig{
		Enrolled:    true,
		ForceTheme:  ThemeAuto,
		ThemeSource: src,
	})
	if err != nil {
		t.Fatalf("NewFrame failed: %v", err)
	}

	before := src.queries
	const passes = 5
	for i := 0; i < passes; i++ {
		var ops op.Ops
		gtx := layout.Context{
			Ops:         &ops,
			Constraints: layout.Exact(image.Pt(400, 200)),
			Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
		}
		frame.Layout(gtx)
	}
	if got := src.queries - before; got != 1 {
		t.Fatalf("%d frame passes asked the ThemeSource %d times — the OS theme probe must be answered at most once a second (IAMT-381/382)", passes, got)
	}

	// The explicit path is NOT throttled: a direct CheckThemeSync asks
	// and switches right now, however recently the per-frame path asked.
	src.dark = true
	if !frame.CheckThemeSync() {
		t.Fatal("an explicit CheckThemeSync did not switch the theme — the throttle must live only in the per-frame path (IAMT-381/382)")
	}
	if !frame.IsDark() {
		t.Fatal("an explicit CheckThemeSync reported a switch but IsDark still says light")
	}
}
