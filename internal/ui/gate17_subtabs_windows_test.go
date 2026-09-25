//go:build windows

package ui

// gate17_subtabs_windows_test.go — GATE 17: no sub-tab needs scrolling in
// a window of the default size (SPEC §8, §7.1; IAMT-336).
//
// The rule this enforces is §7.1's: "a sub-tab that no longer fits is a
// signal to divide it further, not a reason to hope for the scrollbar."
// Without a gate that rule survives exactly until the next card somebody
// adds — which is how the Admin tab grew to eight cards down one page and
// hid the entry point to the whole pairing flow from the maintainer during
// their first live run.
//
// The measurement is the scrollbar itself, rendered: if the page
// overflows, PageScrollbar draws a thumb, and this test counts its pixels.
// That is deliberately the same evidence the person has. A cheaper check —
// a computed content height against the window height — would measure the
// layout code's opinion of itself rather than what reached the screen, and
// in this project those two have already disagreed once.
//
// The window is the real default (WindowWidth × WindowHeight from gui.go),
// not the shot's 1024×700, because the promise is about the window people
// actually get. The snapshot is the busy one: a machine with somebody
// working shows the recording strip, which costs vertical space, and a
// promise that holds only on an idle machine is not the promise.

import (
	"image"
	"testing"
)

// subTabsOf — see r2a_ui_testhelpers_test.go: the table is shared with
// the C4 canary, which is not windows-tagged, so the table itself may
// not be either (R2, 24.09.2026).

// renderSubTab draws one tab with one of its sub-tabs open, at the given
// size, through the same offscreen path the shot command uses.
func renderSubTab(t *testing.T, tab, sub string, w, h int) *image.RGBA {
	return renderSubTabSnap(t, tab, sub, w, h, exampleSnapshot())
}

func renderSubTabSnap(t *testing.T, tab, sub string, w, h int, snap Snapshot) *image.RGBA {
	t.Helper()
	frame, err := NewFrame(FrameConfig{
		Enrolled:       false, // every tab present, including Set up
		InitialTab:     tab,
		HasAdminRights: false, // the masthead button is on screen too
		StillFrame:     true,
		ForceTheme:     ThemeLight,
		Snap:           snap,
	})
	if err != nil {
		t.Fatalf("NewFrame(%s): %v", tab, err)
	}
	frame.SelectTab(tab)
	if sub != "" {
		frame.subTabs = map[string]string{tab: sub}
	}
	img, err := renderFrameOffscreen(frame, w, h)
	if err != nil {
		t.Fatalf("render %s/%s: %v", tab, sub, err)
	}
	return img
}

func TestGate17NoSubTabNeedsScrollingAtTheDefaultWindowSize(t *testing.T) {
	for tab, subs := range subTabsOf {
		for _, sub := range subs {
			tab, sub := tab, sub
			name := tab
			if sub != "" {
				name = tab + "/" + sub
			}
			t.Run(name, func(t *testing.T) {
				img := renderSubTab(t, tab, sub, WindowWidth, WindowHeight)
				thumb, _ := scrollbarPixels(t, img)
				if thumb > 0 {
					t.Errorf("%s overflows a %dx%d window — %d scroll-thumb pixels. "+
						"A sub-tab that no longer fits is a signal to divide it further (SPEC §7.1), "+
						"not a reason to lean on the scrollbar: the page below the fold is the page "+
						"nobody finds.", name, WindowWidth, WindowHeight, thumb)
				}
			})
		}
	}
}

// TestGate17JoinedAdminPeopleFits measures the one state the table above
// cannot reach (21.09.2026).
//
// exampleSnapshot() carries no administrator identity, so every rendering
// of Admin/People above is of a machine that has NOT joined -- which on
// that tab means the claim form and nothing else. The tab a working
// administrator actually looks at, with the identity card and the list of
// people under it, was measured by nothing.
//
// It mattered the same hour: merging Join into People passed the gate and
// overflowed the joined view by 1954 scroll-thumb pixels. A gate that
// measures only the empty state grades the page nobody uses.
func TestGate17JoinedAdminPeopleFits(t *testing.T) {
	snap := exampleSnapshot()
	snap.Admin.ThisMachine = &AdminIdentity{
		Person:  "admin",
		Gateway: "gw.example.net:2022",
		HostKey: "SHA256:kBsu7N/L4FBnKpFTZ75V966Brmi0ZaYlKRp9W2Sz254",
	}
	img := renderSubTabSnap(t, TabAdmin, "People", WindowWidth, WindowHeight, snap)
	if thumb, _ := scrollbarPixels(t, img); thumb > 0 {
		t.Errorf("Admin/People on a JOINED machine overflows a %dx%d window — %d scroll-thumb pixels. "+
			"This is the state an administrator works in; the table above only ever renders the "+
			"unjoined one, where the tab is a claim form and nothing else.",
			WindowWidth, WindowHeight, thumb)
	}
}

// TestGate17TheGateCanActuallyFail is the gate's own canary. A pixel gate
// that silently stopped finding the scrollbar — a changed palette, a
// changed strip position, a renderer that draws nothing — would report
// "all clear" forever, which is worse than having no gate. So the same
// detector is pointed at a window deliberately too short for any page,
// where a scrollbar MUST be present.
func TestGate17TheGateCanActuallyFail(t *testing.T) {
	// 500, not 320. Below roughly 420 the masthead, the recording strip,
	// the tab row, the poster and the sub-tab strip consume the window
	// outright, the scrolling viewport collapses to nothing, and no bar is
	// drawn because there is nowhere to draw one. A canary must fail for
	// the reason it is testing, not because the window stopped having a
	// page in it — 500 is short enough that every page overflows and tall
	// enough that a scrollbar still has room to exist.
	//
	// The page is GUIDE since IAMT-359. It used to be Admin/People, and
	// that stopped overflowing the day the add-a-person form went behind
	// a button -- which is the gate working, not the canary breaking.
	// The canary needs a page that is long BY DESIGN rather than long by
	// accident, and the guide is exactly that: six steps of a process
	// that spans three computers, and nothing to divide it into.
	const shortEnough = 500
	img := renderSubTab(t, TabGuide, "", WindowWidth, shortEnough)
	if thumb, _ := scrollbarPixels(t, img); thumb == 0 {
		t.Fatalf("the detector found no scroll thumb in a %d px tall window, where every page overflows — "+
			"gate 17 is blind and would pass anything", shortEnough)
	}
}
