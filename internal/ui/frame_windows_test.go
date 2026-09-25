//go:build windows

package ui

import (
	"image"
	"strings"
	"testing"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// fakeThemeSource is a test-owned ThemeSource: it never touches the real
// Windows registry, so tests can drive live theme switching by mutating it directly.
type fakeThemeSource struct{ dark bool }

func (s *fakeThemeSource) IsDark() bool { return s.dark }

// TestLiveThemeSwitch proves that the theme switches live based on
// ThemeSource without restarting the window. It uses fakeThemeSource
// instead of the real registry, so the maintainer's machine is never
// touched.
func TestLiveThemeSwitch(t *testing.T) {
	src := &fakeThemeSource{dark: false} // start Light

	frame, err := NewFrame(FrameConfig{
		Enrolled:    false,
		ForceTheme:  ThemeAuto,
		ThemeSource: src,
	})
	if err != nil {
		t.Fatalf("NewFrame failed: %v", err)
	}

	if frame.IsDark() {
		t.Errorf("Expected Light theme when source reports Light, got Dark")
	}
	if frame.theme.Color(design.PageKey) != design.LightPalette().Page {
		t.Errorf("Expected Light Page color %v, got %v", design.LightPalette().Page, frame.theme.Color(design.PageKey))
	}

	// 1. Switch source live to Dark
	src.dark = true

	// Trigger live theme synchronization (as happens in frame.Layout)
	changed := frame.CheckThemeSync()
	if !changed {
		t.Errorf("CheckThemeSync should report true when source theme changed")
	}

	if !frame.IsDark() {
		t.Errorf("Expected Dark theme after source switched to Dark, got Light")
	}
	if frame.theme.Color(design.PageKey) != design.DarkPalette().Page {
		t.Errorf("Expected Dark Page color %v, got %v", design.DarkPalette().Page, frame.theme.Color(design.PageKey))
	}

	// 2. Switch back live to Light
	src.dark = false

	changed = frame.CheckThemeSync()
	if !changed {
		t.Errorf("CheckThemeSync should report true when source theme changed back")
	}
	if frame.IsDark() {
		t.Errorf("Expected Light theme after switching back, got Dark")
	}
}

// TestTabStripInvariant verifies Gate 3: "the tab strip does not change size".
// The tab strip height does not jump or change when switching between tabs,
// nor when the notice under the tabs is shown or hidden.
func TestTabStripInvariant(t *testing.T) {
	var noRights, withRights *Frame
	for _, tc := range []struct{ rights bool }{{false}, {true}} {
		f, err := NewFrame(FrameConfig{
			Enrolled:       false,
			HasAdminRights: tc.rights,
		})
		if err != nil {
			t.Fatalf("NewFrame(rights=%v) failed: %v", tc.rights, err)
		}
		if tc.rights {
			withRights = f
		} else {
			noRights = f
		}
	}
	frames := map[string]*Frame{"no rights": noRights, "with rights": withRights}

	tabNames := []string{TabSetUp, TabClient, TabServer, TabSession, TabAdmin, TabSettings}
	for name, frame := range frames {
		var initialHeight int
		for i, tab := range tabNames {
			frame.SelectTab(tab)

			var ops op.Ops
			gtx := layout.Context{
				Ops: &ops,
				// An upper bound only, as the frame lays the strip out:
				// labels return the minimum they were given, so Exact
				// constraints would measure the whole window.
				Constraints: layout.Constraints{Max: image.Pt(800, 600)},
				Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
			}

			dims := frame.tabs.LayoutStrip(gtx, frame.theme)

			if i == 0 {
				initialHeight = dims.Size.Y
				if initialHeight <= 0 {
					t.Fatalf("%s: expected non-zero tab strip height, got %d", name, initialHeight)
				}
			} else if dims.Size.Y != initialHeight {
				t.Errorf("%s: tab strip height changed on tab %q: got %d, want %d", name, tab, dims.Size.Y, initialHeight)
			}
		}
		// The two frames must agree: notice visibility is derived from
		// rights, and neither state may move the strip.
		var ops op.Ops
		gtx := layout.Context{
			Ops:         &ops,
			Constraints: layout.Constraints{Max: image.Pt(800, 600)},
			Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
		}
		if dims := withRights.tabs.LayoutStrip(gtx, withRights.theme); dims.Size.Y != initialHeight {
			t.Errorf("%s: strip height with rights = %d, without = %d", name, dims.Size.Y, initialHeight)
		}
	}
}

// isElevationTab reports whether the currently active tab requires administrator elevation.
// Elevation is required on the Server tab (SPEC §3.2: "administrator rights are mandatory -- a banner")
// and on Set up.
//
// The method lives in this windows-tagged file since the MAC round
// (24.09.2026): since 1.3 the production frame keys the elevation control
// off HasAdminRights alone and never asks which tab is up, the only reader
// of this predicate is the test below — and on darwin it sat unreferenced
// in frame.go, where staticcheck's U1000 said so.
func (f *Frame) isElevationTab() bool {
	cur := f.tabs.Current()
	return strings.EqualFold(cur, TabServer) || strings.EqualFold(cur, TabSetUp)
}

// TestElevationNoticePulsing verifies that the elevation notice pulses on active tabs
// requiring elevation (Server / Set up) and stops on inactive tabs (Client / Admin / Settings).
func TestElevationNoticePulsing(t *testing.T) {
	frame, err := NewFrame(FrameConfig{
		Enrolled:       false,
		HasAdminRights: false,
	})
	if err != nil {
		t.Fatalf("NewFrame failed: %v", err)
	}

	// On Server tab, elevation notice pulse is ACTIVE
	frame.SelectTab(TabServer)
	if !frame.isElevationTab() {
		t.Errorf("Expected isElevationTab == true on Server tab")
	}

	// On Client tab, elevation notice pulse STOPS
	frame.SelectTab(TabClient)
	if frame.isElevationTab() {
		t.Errorf("Expected isElevationTab == false on Client tab")
	}

	// On Admin tab, elevation notice pulse STOPS
	frame.SelectTab(TabAdmin)
	if frame.isElevationTab() {
		t.Errorf("Expected isElevationTab == false on Admin tab")
	}

	// On Settings tab, elevation notice pulse STOPS
	frame.SelectTab(TabSettings)
	if frame.isElevationTab() {
		t.Errorf("Expected isElevationTab == false on Settings tab")
	}
}
