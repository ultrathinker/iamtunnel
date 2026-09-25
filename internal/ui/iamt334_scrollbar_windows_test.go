//go:build windows

package ui

// iamt334_scrollbar_windows_test.go — a page that continues below the fold
// has to SAY so (IAMT-334).
//
// The defect this file pins was found by the maintainer, not by a test, and it
// cost a live run: the Admin tab's four 1.2 cards — Become an
// administrator, Pairing window, Add person, Enrol machine — sit below
// "Grant access", the window was shorter than the page, and nothing on
// screen said there was anything further down. The page scrolled
// perfectly well; it just never admitted it. Reasonably, the maintainer
// concluded the binary was the wrong one.
//
// So the assertions here are deliberately about PIXELS rather than about
// state. "The list has a scrollbar field" would have been true before the
// fix as well — gio's layout.List has always scrolled, and the pages have
// always been scrollable. What was missing was a mark on the screen, and
// only a rendered frame can testify to that. The tests render the real
// tabs through the same headless path the shot command uses and look at
// the strip the bar occupies.
//
// The detector matches the palette's own colours rather than "anything
// that is not background", and that precision is load-bearing: the pinned
// sections of the Client and Server tabs (the poster, the recording
// notice) are NOT inside the scrolling list, so their boxes span the full
// body width and cross the strip. A looser detector counts that border as
// a scrollbar and reports success on a page that has none.
//
// Red-first: on the pre-fix tree not one pixel of either colour appears
// in the strip on any tab, and every test below fails on its own line.

import (
	"image"
	"image/color"
	"os"
	"strings"
	"testing"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// scrollbarStrip is the column range the page scrollbar occupies, in
// pixels at PxPerDp=1 (renderFrameOffscreen's metric). The page insets its
// body by Edge on each side, and the bar takes its own strip at the inner
// right edge — material.Occupy, so it is beside the content and never on
// top of it. Width is the indicator plus the track's padding on both
// sides, which is what material.ScrollbarStyle.Width() computes.
func scrollbarStrip(width int) (x0, x1 int) {
	const barW = 6 + 2 + 2 // Indicator.MinorWidth + Track.MinorPadding * 2
	x1 = width - int(design.Edge)
	x0 = x1 - barW
	return x0, x1
}

// scrollbarPixels counts, inside the strip, the pixels painted in the two
// colours PageScrollbar gives the bar. Rows above chromeBelow are skipped:
// the tab rule and the elevation notice are window chrome above the page,
// they cross the strip, and they are not what this test is about.
func scrollbarPixels(t *testing.T, img *image.RGBA) (thumb, groove int) {
	t.Helper()
	const chromeBelow = 130
	pal := design.LightPalette()
	same := func(c color.Color, want color.NRGBA) bool {
		r, g, b, _ := c.RGBA()
		return uint8(r>>8) == want.R && uint8(g>>8) == want.G && uint8(b>>8) == want.B
	}
	b := img.Bounds()
	x0, x1 := scrollbarStrip(b.Dx())
	for y := chromeBelow; y < b.Max.Y; y++ {
		for x := x0; x < x1; x++ {
			switch c := img.At(x, y); {
			case same(c, pal.Muted):
				thumb++
			case same(c, pal.Line):
				groove++
			}
		}
	}
	return thumb, groove
}

// TestIAMT334AdminTabShowsItsScrollbarWhenItOverflows is the finding
// itself: the bar must be on screen, thumb and groove both.
//
// The window is 900x480 rather than the 900x787 the defect was found at,
// and the reason is worth recording. Since IAMT-336 the Admin tab is four
// sub-tabs instead of eight cards stacked down one page, and at 787 px it
// no longer overflows at all — gate 17 now REQUIRES it not to. Both
// properties are real and neither replaces the other: a page that fits
// must not claim there is more (gate 17), and a page that does not fit
// must say so (this test). So this one is measured at a height where
// overflow is certain, which is what it was always about.
func TestIAMT334AdminTabShowsItsScrollbarWhenItOverflows(t *testing.T) {
	const w, h = 900, 480

	// The sub-tab is named rather than left to the default: this test is
	// about what an OVERFLOWING page must draw, so it has to open a page
	// that overflows. Leaving it empty tied the test to whichever sub-tab
	// happens to come first, and on 19.09.2026 that order changed (Join
	// moved to the front, where the maintainer needed it) — the test then
	// failed on a short page that was right to fit.
	// GUIDE since IAMT-359: Admin/People stopped overflowing when its
	// form went behind a button, and a test about what an OVERFLOWING
	// page draws needs a page that actually overflows.
	img, err := ShotSub(TabGuide, "", false, w, h, "")
	if err != nil {
		t.Fatalf("Shot(Guide) failed: %v", err)
	}
	thumb, groove := scrollbarPixels(t, img)
	if thumb == 0 {
		x0, x1 := scrollbarStrip(w)
		t.Fatalf("the Guide tab at %dx%d drew no scroll thumb in the strip x=[%d,%d) — "+
			"the steps below the fold are unreachable and nothing on screen says they exist", w, h, x0, x1)
	}
	if groove == 0 {
		t.Errorf("the Admin tab at %dx%d drew a thumb but no track — the empty groove is what a reader sees "+
			"BEFORE touching anything, and it is the part that says the page continues", w, h)
	}
}

// TestIAMT334EveryScreenGetsItsScrollbarFromTheOnePlaceThatDrawsOne is
// the "every tab, not just Admin" half of the maintainer's instruction, and it
// is deliberately a STRUCTURAL test rather than another pixel one.
//
// The pixel route was tried first and abandoned on purpose, which is
// worth recording. To prove by pixels that five different screens all
// grow a bar, every one of them has to be made to overflow at the same
// moment — and they hold different amounts: after the 1.3 split into
// sub-tabs, a window short enough to overflow Set up collapses Client's
// scrolling viewport to nothing (its poster and recording notice are
// pinned, not scrolled), so no bar is drawn there for a reason that has
// nothing to do with the defect. Tuning a size and a fixture per screen
// until all five happen to overflow would produce a test that passes for
// arranged reasons and reddens whenever any screen's content changes.
//
// What actually has to be true is simpler and stronger: there is ONE
// function that draws a page, it draws the bar (proven by pixels in the
// Admin test above), and no screen builds a page any other way. A screen
// that laid out its own list would be the way to lose the bar again, and
// that is what is checked here.
func TestIAMT334EveryScreenGetsItsScrollbarFromTheOnePlaceThatDrawsOne(t *testing.T) {
	src, err := os.ReadFile("screens.go")
	if err != nil {
		t.Fatalf("read screens.go: %v", err)
	}
	text := string(src)

	// Every screen function must hand its sections to the page builder.
	for _, screen := range []string{
		"layoutSetupScreen",
		"layoutClientScreen",
		"layoutServerScreen",
		"layoutAdminScreen",
		"layoutSettingsScreen",
	} {
		i := strings.Index(text, "func (f *Frame) "+screen+"(")
		if i < 0 {
			t.Errorf("screen %s not found — this guard has gone blind", screen)
			continue
		}
		body := text[i:]
		if j := strings.Index(body[1:], "\nfunc "); j >= 0 {
			body = body[:j+1]
		}
		if !strings.Contains(body, "design.Page(") &&
			!strings.Contains(body, "design.PinnedPage(") &&
			!strings.Contains(body, "design.SubTabPage(") {
			t.Errorf("%s builds its page without design.Page/PinnedPage/SubTabPage — "+
				"the scrollbar is drawn there and nowhere else, so this screen has none", screen)
		}
	}

	// And no screen may lay out a raw list of its own: that is how a page
	// scrolls with nothing to say it does.
	if strings.Contains(text, "layout.List{") {
		t.Error("screens.go constructs a layout.List directly — a page's scrolling belongs to " +
			"design.PinnedPage, which also draws the bar; a hand-rolled list scrolls silently")
	}
}

// TestIAMT334NoScrollbarOnAPageThatFits is the other half of the maintainer's
// rule -- "if it is needed". A bar drawn down a page with nothing below the
// fold lies about the content, and it would also eat a strip of width on
// every screen for nothing. Rendered tall enough that the tab fits, the
// strip must hold no bar at all.
func TestIAMT334NoScrollbarOnAPageThatFits(t *testing.T) {
	const w, h = 900, 2400

	for _, tab := range []string{TabClient, TabAdmin, TabSettings} {
		t.Run(tab, func(t *testing.T) {
			img, err := Shot(tab, false, w, h, "")
			if err != nil {
				t.Fatalf("Shot(%q) failed: %v", tab, err)
			}
			// A handful of stray thumb-coloured pixels is antialiasing on
			// some glyph that happens to reach the strip, not a bar: a real
			// one is hundreds of pixels tall. The tolerance is far below
			// anything a bar can be and far above what drifting text can
			// produce — on the pre-fix tree this tab measured three.
			const strayTolerance = 8
			if thumb, _ := scrollbarPixels(t, img); thumb > strayTolerance {
				t.Errorf("tab %q at %dx%d — taller than its own content — still drew %d thumb pixels; "+
					"a page that fits must not claim there is more below", tab, w, h, thumb)
			}
		})
	}
}

// TestIAMT334ScrollbarTakesItsOwnStripRatherThanFloating pins the layout
// decision, which is not cosmetic: these pages put full-width text boxes
// and buttons against the right edge of the body, and an overlay bar
// would sit on top of their ends — the reference field of "Become an
// administrator" is exactly such a box. material.Occupy is what keeps the
// bar beside the content.
func TestIAMT334ScrollbarTakesItsOwnStripRatherThanFloating(t *testing.T) {
	th := design.NewTheme(design.LightPalette(), nil)
	list := &widget.List{List: layout.List{Axis: layout.Vertical}}
	st := design.PageScrollbar(th, list)

	if st.AnchorStrategy != material.Occupy {
		t.Errorf("the page scrollbar floats over the content (anchor %v) — it must occupy its own strip, "+
			"or it covers the right end of the text boxes it sits next to", st.AnchorStrategy)
	}
	if st.Track.Color == (color.NRGBA{}) {
		t.Error("the scrollbar track is invisible — the empty groove is what tells a reader the page continues, " +
			"before they have touched anything; the thumb alone only says where they already are")
	}
	if st.Indicator.Color == st.Track.Color {
		t.Error("the scrollbar thumb is the same colour as its track — nothing distinguishes the position from the groove")
	}
}

// TestIAMT334APageAlwaysScrollsDownwards pins the axis PinnedPage forces.
// A page handed a horizontal list would grow a bar along its bottom edge
// and read nothing like the other four tabs; the correction belongs in
// the one place every page goes through, not in five call sites.
func TestIAMT334APageAlwaysScrollsDownwards(t *testing.T) {
	th := design.NewTheme(design.LightPalette(), nil)
	list := &widget.List{List: layout.List{Axis: layout.Horizontal}}

	var ops op.Ops
	gtx := layout.Context{
		Ops:         &ops,
		Constraints: layout.Exact(image.Pt(400, 200)),
		Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
	}
	design.PinnedPage(gtx, th, list, 0, func(gtx layout.Context) layout.Dimensions {
		return layout.Dimensions{Size: image.Pt(400, 900)}
	})

	if list.Axis != layout.Vertical {
		t.Errorf("a page laid out with a horizontal list kept axis %v — pages scroll down, and the bar would "+
			"otherwise run along the bottom edge", list.Axis)
	}
}
