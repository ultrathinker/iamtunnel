//go:build windows

package ui

import (
	"fmt"
	"path/filepath"
	"testing"
)

// TestIAMT341_Gate17SessionTabFitsDefaultWindow verifies that the Session tab
// does NOT produce a page scrollbar thumb in the default window size (Gate 17, SPEC §7.1, §8).
//
// Gate 17 invariant: The terminal panel occupies the available height and scrolls
// inside itself rather than growing downward and pulling the window page.
//
// Canary: modify `layoutSessionScreen` to wrap its content in an unbounded `design.PinnedPage`
// with 2000px height. The test fails because scrollbarPixels detects thumb pixels > 0.
func TestIAMT341_Gate17SessionTabFitsDefaultWindow(t *testing.T) {
	img := renderSubTab(t, TabSession, "", WindowWidth, WindowHeight)
	thumb, _ := scrollbarPixels(t, img)
	if thumb > 0 {
		t.Fatalf("%s overflows a %dx%d window — %d scroll-thumb pixels. "+
			"The terminal must scroll inside itself and occupy available height, not grow the page.",
			TabSession, WindowWidth, WindowHeight, thumb)
	}
}

// TestIAMT341_ScreenshotSessionTab verifies that Shot produces valid screenshots of
// the Session tab in both Light and Dark themes (Gate 4).
//
// Canary: return an empty image or error in Shot for TabSession.
// The test fails because the resulting image is missing or has only 1 color.
func TestIAMT341_ScreenshotSessionTab(t *testing.T) {
	tempDir := t.TempDir()

	for _, dark := range []bool{false, true} {
		name := "light"
		if dark {
			name = "dark"
		}
		outPath := filepath.Join(tempDir, fmt.Sprintf("shot_session_%s.png", name))

		img, err := Shot(TabSession, dark, DefaultShotWidth, DefaultShotHeight, outPath)
		if err != nil {
			t.Fatalf("Shot(TabSession, dark=%v) failed: %v", dark, err)
		}
		if img == nil {
			t.Fatalf("Shot(TabSession, dark=%v) returned nil image", dark)
		}
		if b := img.Bounds(); b.Dx() != DefaultShotWidth || b.Dy() != DefaultShotHeight {
			t.Fatalf("unexpected image bounds: %v", b)
		}
	}
}
