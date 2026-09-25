//go:build windows

package ui

// notice_theme_test.go: two guards that live next to the screens.
//
//   - TestServerScreenShowsGatewayNotice is the server-screen leg of
//     IAMT-69 item 7: the reason the gateway cut the machine must reach
//     the maintainer's screen, and it must reach it only when it exists.
//   - TestNoSecondThemeOracle keeps IAMT-75 dead: CurrentPalette was a
//     second way to read the system theme, next to the Frame's live
//     ThemeSource - exactly the kind of exported, ready-to-use duplicate
//     that ends up in production. It was removed; this test fails if a
//     second theme oracle is ever reintroduced under that (or any other)
//     name in this package. The stronger proof that nothing outside the
//     package called it is the build itself: go build ./... for
//     windows/amd64 and linux/amd64 compiles every potential caller.

import (
	"image"
	"image/color"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// gatewayNotice is the wording the runtime hands over when a door.close
// could not be confirmed and the epoch was cut (IAMT-69): what happened,
// what happens next, and where the duty engineer reads more.
const gatewayNotice = "The gateway cut this machine's tunnel: the door line could not be confirmed closed. " +
	"The machine must reconnect and pass its door check before anyone can be let in " +
	"(runbook, incident 5.7: door.close requires a new epoch)."

func TestServerScreenShowsGatewayNotice(t *testing.T) {
	warn := design.LightPalette().Warn
	whole := image.Rect(0, 0, shotW, shotH)

	// Without a notice the example server screen - good facts, admin
	// rights, so no elevation banner either - has no Warn anywhere. A
	// notice must not appear out of thin air.
	plain := renderFrame(t, renderCfg{screen: "server", rights: true, snap: exampleSnapshot()})
	if n := countColor(plain, warn, whole); n != 0 {
		t.Fatalf("empty notice drew %d warn pixels; the block must exist only when a reason exists", n)
	}

	// With the IAMT-69 verdict in the snapshot, the reason is on the
	// screen: Warn dot, Warn border, Warn text.
	snap := exampleSnapshot()
	snap.Server.Notice = gatewayNotice
	with := renderFrame(t, renderCfg{screen: "server", rights: true, snap: snap})
	if n := countColor(with, warn, whole); n < 50 {
		t.Fatalf("reason did not reach the server screen: only %d warn pixels with a notice in the snapshot", n)
	}

	// A notice of any length must wrap inside the window, never leave it.
	long := exampleSnapshot()
	long.Server.Notice = strings.Repeat("blocked — reconnect required — ", 80)
	img := renderFrame(t, renderCfg{screen: "server", rights: true, snap: long})
	page := design.LightPalette().Page
	for y := furnitureBottom(img, false); y < shotH; y++ {
		for _, x := range []int{0, 1, 2, 3, shotW - 4, shotW - 3, shotW - 2, shotW - 1} {
			if got := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA); got != page {
				t.Fatalf("long notice left the window at (%d,%d): #%02X%02X%02X", x, y, got.R, got.G, got.B)
			}
		}
	}
}

func TestNoSecondThemeOracle(t *testing.T) {
	// Every .go file of the package must be free of a second theme
	// reader: the one source is the Frame's ThemeSource (live-checked by
	// TestLiveThemeSwitch), and the palettes are built from what IT says.
	const self = "notice_theme_test.go" // this file names the symbol to search for
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || e.Name() == self {
			continue
		}
		b, err := os.ReadFile(filepath.Join(".", e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if strings.Contains(string(b), "CurrentPalette") {
			t.Errorf("%s reintroduces CurrentPalette - a second theme oracle that can drift from the ThemeSource the frame actually renders with (IAMT-75)", e.Name())
			found = true
		}
	}
	if found {
		t.Fatal("remove the duplicate reader: theme follows the Frame's ThemeSource only")
	}
}
