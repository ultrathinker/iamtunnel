//go:build windows

package design

import (
	"image"
	"testing"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
)

// TestScaleValuesMatchesOriginal verifies that the type scale, spacings,
// and component numbers match Design.cs value for value.
func TestScaleValuesMatchesOriginal(t *testing.T) {
	// 1. Five text sizes from Design.cs lines 56-68
	if Display != 58.0 {
		t.Errorf("Display: got %v, want 58.0", Display)
	}
	if Title != 26.0 {
		t.Errorf("Title: got %v, want 26.0", Title)
	}
	if Head != 15.0 {
		t.Errorf("Head: got %v, want 15.0", Head)
	}
	if Body != 14.0 {
		t.Errorf("Body: got %v, want 14.0", Body)
	}
	if Small != 11.5 {
		t.Errorf("Small: got %v, want 11.5", Small)
	}

	// 2. Five spacings from Design.cs lines 72-76
	if Tight != 5.0 {
		t.Errorf("Tight: got %v, want 5.0", Tight)
	}
	if Gap != 10.0 {
		t.Errorf("Gap: got %v, want 10.0", Gap)
	}
	if Pad != 16.0 {
		t.Errorf("Pad: got %v, want 16.0", Pad)
	}
	if Wide != 30.0 {
		t.Errorf("Wide: got %v, want 30.0", Wide)
	}
	if Edge != 40.0 {
		t.Errorf("Edge: got %v, want 40.0", Edge)
	}
	if Radius != 0.0 {
		t.Errorf("Radius: got %v, want 0.0", Radius)
	}

	// 3. Specific component numbers from Design.cs
	if DotSize != 9.0 {
		t.Errorf("DotSize: got %v, want 9.0", DotSize)
	}
	// TabSpacing was 26 until 21.09.2026, when tabs got padding of their
	// own so the hover tint had room. The design's number was never
	// "TabSpacing" as such -- it was the distance between one tab WORD
	// and the next, and once part of that distance belongs to the hit
	// areas, the token alone stops being that distance.
	//
	// So the composed value is what is checked, and it must not fall
	// below what the design asked for. Trading the gap away for padding
	// would make two neighbouring tints read as one wide button.
	if gap := TabSpacing + 2*TabPadX; gap < 26.0 {
		t.Errorf("word-to-word tab gap: got %v (spacing %v + 2*pad %v), want at least the design's 26",
			gap, TabSpacing, TabPadX)
	}
	if TabIndicatorHeight != 2.0 {
		t.Errorf("TabIndicatorHeight: got %v, want 2.0", TabIndicatorHeight)
	}
	if TabIndicatorMargin != 7.0 {
		t.Errorf("TabIndicatorMargin: got %v, want 7.0", TabIndicatorMargin)
	}
	if FactsColumnWidth != 210.0 {
		t.Errorf("FactsColumnWidth: got %v, want 210.0", FactsColumnWidth)
	}
	if PosterSpacing != -8.0 {
		t.Errorf("PosterSpacing: got %v, want -8.0", PosterSpacing)
	}
	if ButtonMinWidthPrimary != 150.0 {
		t.Errorf("ButtonMinWidthPrimary: got %v, want 150.0", ButtonMinWidthPrimary)
	}
	if ButtonMinWidthSecondary != 120.0 {
		t.Errorf("ButtonMinWidthSecondary: got %v, want 120.0", ButtonMinWidthSecondary)
	}
	if ButtonPadHorizontal != 22.0 || ButtonPadVertical != 10.0 {
		t.Errorf("ButtonPadding: got (%v, %v), want (22.0, 10.0)", ButtonPadHorizontal, ButtonPadVertical)
	}
}

// TestPaletteColorsMatchOriginal verifies that every palette color in Light and Dark
// matches umtunnel's Design.cs lines 143-176 value for value.
func TestPaletteColorsMatchOriginal(t *testing.T) {
	light := LightPalette()
	dark := DarkPalette()

	// Light palette checks
	if light.Ink != rgb(0x111111) {
		t.Errorf("Light.Ink: got %v, want #111111", light.Ink)
	}
	if light.Muted != rgb(0x6E6E6E) {
		t.Errorf("Light.Muted: got %v, want #6E6E6E", light.Muted)
	}
	if light.Faint != rgb(0x9A968D) {
		t.Errorf("Light.Faint: got %v, want #9A968D", light.Faint)
	}
	if light.Page != rgb(0xFAF8F4) {
		t.Errorf("Light.Page: got %v, want #FAF8F4", light.Page)
	}
	if light.Surface != rgb(0xF0EDE5) {
		t.Errorf("Light.Surface: got %v, want #F0EDE5", light.Surface)
	}
	if light.Line != rgb(0xD5D2C9) {
		t.Errorf("Light.Line: got %v, want #D5D2C9", light.Line)
	}
	if light.Spot != rgb(0xE8651A) {
		t.Errorf("Light.Spot: got %v, want #E8651A", light.Spot)
	}
	if light.OnSpot != rgb(0xFFFFFF) {
		t.Errorf("Light.OnSpot: got %v, want #FFFFFF", light.OnSpot)
	}
	if light.SpotDim != rgb(0xC8530F) {
		t.Errorf("Light.SpotDim: got %v, want #C8530F", light.SpotDim)
	}
	if light.Good != rgb(0x1F6B3A) {
		t.Errorf("Light.Good: got %v, want #1F6B3A", light.Good)
	}
	if light.Warn != rgb(0x8A5200) {
		t.Errorf("Light.Warn: got %v, want #8A5200", light.Warn)
	}
	if light.Bad != rgb(0xB3261E) {
		t.Errorf("Light.Bad: got %v, want #B3261E", light.Bad)
	}
	if light.Busy != rgb(0x1A5FB4) {
		t.Errorf("Light.Busy: got %v, want #1A5FB4", light.Busy)
	}

	// Dark palette checks
	if dark.Ink != rgb(0xF0EDE3) {
		t.Errorf("Dark.Ink: got %v, want #F0EDE3", dark.Ink)
	}
	if dark.Muted != rgb(0x8C8C8C) {
		t.Errorf("Dark.Muted: got %v, want #8C8C8C", dark.Muted)
	}
	if dark.Faint != rgb(0x6A6A6A) {
		t.Errorf("Dark.Faint: got %v, want #6A6A6A", dark.Faint)
	}
	if dark.Page != rgb(0x111111) {
		t.Errorf("Dark.Page: got %v, want #111111", dark.Page)
	}
	if dark.Surface != rgb(0x1C1C1C) {
		t.Errorf("Dark.Surface: got %v, want #1C1C1C", dark.Surface)
	}
	if dark.Line != rgb(0x2C2C2C) {
		t.Errorf("Dark.Line: got %v, want #2C2C2C", dark.Line)
	}
	if dark.Spot != rgb(0xF48430) {
		t.Errorf("Dark.Spot: got %v, want #F48430", dark.Spot)
	}
	if dark.OnSpot != rgb(0x17130A) {
		t.Errorf("Dark.OnSpot: got %v, want #17130A", dark.OnSpot)
	}
	if dark.SpotDim != rgb(0xD86F20) {
		t.Errorf("Dark.SpotDim: got %v, want #D86F20", dark.SpotDim)
	}
	if dark.Good != rgb(0x5CD18E) {
		t.Errorf("Dark.Good: got %v, want #5CD18E", dark.Good)
	}
	if dark.Warn != rgb(0xF0B43C) {
		t.Errorf("Dark.Warn: got %v, want #F0B43C", dark.Warn)
	}
	if dark.Bad != rgb(0xFF7A6B) {
		t.Errorf("Dark.Bad: got %v, want #FF7A6B", dark.Bad)
	}
	if dark.Busy != rgb(0x79B8FF) {
		t.Errorf("Dark.Busy: got %v, want #79B8FF", dark.Busy)
	}
}

// TestMissingKeysSelftest verifies that MissingKeys reports 0 missing keys.
func TestMissingKeysSelftest(t *testing.T) {
	missing := MissingKeys()
	if len(missing) > 0 {
		t.Fatalf("MissingKeys selftest failed: %v", missing)
	}
}

// TestPulseKeyframes verifies the exact animation curve of Pulse (Design.cs lines 720-748).
func TestPulseKeyframes(t *testing.T) {
	approxEqual := func(a, b float32) bool {
		diff := a - b
		if diff < 0 {
			diff = -diff
		}
		return diff < 1e-4
	}

	// Period is 1.5s (1500ms)
	// At t = 0s (0%): opacity = 1.0
	if op := PulseOpacity(0); !approxEqual(op, 1.0) {
		t.Errorf("at t=0s: got %v, want 1.0", op)
	}

	// At t = 1.05s (70%): opacity = 1.0
	if op := PulseOpacity(1050 * time.Millisecond); !approxEqual(op, 1.0) {
		t.Errorf("at t=1.05s (70%%): got %v, want 1.0", op)
	}

	// At t = 1.1625s (77.5%, midway down): opacity = 0.625
	if op := PulseOpacity(1162500 * time.Microsecond); !approxEqual(op, 0.625) {
		t.Errorf("at midway down: got %v, want ~0.625", op)
	}

	// At t = 1.275s (85%, dip trough): opacity = 0.25
	if op := PulseOpacity(1275 * time.Millisecond); !approxEqual(op, 0.25) {
		t.Errorf("at t=1.275s (85%%): got %v, want 0.25", op)
	}

	// At t = 1.3875s (92.5%, midway up): opacity = 0.625
	if op := PulseOpacity(1387500 * time.Microsecond); !approxEqual(op, 0.625) {
		t.Errorf("at midway up: got %v, want ~0.625", op)
	}

	// At t = 1.5s (100% / cycle restart): opacity = 1.0
	if op := PulseOpacity(1500 * time.Millisecond); !approxEqual(op, 1.0) {
		t.Errorf("at t=1.5s: got %v, want 1.0", op)
	}
}

// TestTabsStripGeometryDoesNotChange verifies Gate 3: "the tab strip does not change size".
// The tab strip height and width must be completely invariant regardless of which tab is active.
func TestTabsStripGeometryDoesNotChange(t *testing.T) {
	th := NewTheme(LightPalette(), nil)
	tabs := NewTabs()
	tabs.Add("Set up", func(gtx layout.Context) layout.Dimensions {
		return layout.Dimensions{}
	})
	tabs.Add("Client", func(gtx layout.Context) layout.Dimensions {
		return layout.Dimensions{}
	})
	tabs.Add("Server", func(gtx layout.Context) layout.Dimensions {
		return layout.Dimensions{}
	})
	tabs.Add("Admin", func(gtx layout.Context) layout.Dimensions {
		return layout.Dimensions{}
	})
	tabs.Add("Settings", func(gtx layout.Context) layout.Dimensions {
		return layout.Dimensions{}
	})

	var initialDims layout.Dimensions

	tabNames := []string{"Set up", "Client", "Server", "Admin", "Settings"}
	for i, name := range tabNames {
		tabs.Show(name)

		var ops op.Ops
		gtx := layout.Context{
			Ops: &ops,
			// An upper bound only, as the frame lays the strip out:
			// labels return the minimum they were given, so Exact
			// constraints would measure the whole window.
			Constraints: layout.Constraints{Max: image.Pt(800, 600)},
			Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
		}

		dims := tabs.LayoutStrip(gtx, th)

		if i == 0 {
			initialDims = dims
			if dims.Size.Y == 0 {
				t.Fatalf("Tab strip height must be non-zero, got %d", dims.Size.Y)
			}
		} else {
			if dims.Size.Y != initialDims.Size.Y {
				t.Errorf("Tab strip height changed on tab %q: got %d, want %d", name, dims.Size.Y, initialDims.Size.Y)
			}
			if dims.Size.X != initialDims.Size.X {
				t.Errorf("Tab strip width changed on tab %q: got %d, want %d", name, dims.Size.X, initialDims.Size.X)
			}
		}
	}
}
