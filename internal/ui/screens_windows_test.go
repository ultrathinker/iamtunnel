//go:build windows

package ui

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
	"github.com/ultrathinker/iamtunnel/internal/ui/winfonts"
)

// The invariant checks live here. Every one of them asserts an outcome
// visible in the picture or in the layout geometry — not merely that the
// code did not panic. Pixel verdicts read exact palette colors, so a
// regression cannot pass by drawing "something".

// renderCfg describes one offscreen pass.
type renderCfg struct {
	screen string             // canonical screen name ("setup"…"settings")
	dark   bool               // force the dark palette
	rights bool               // process runs as administrator (banner hidden)
	snap   Snapshot           // the reality the screens draw
	fonts  *winfonts.Resolver // nil = system registry
}

const (
	shotW = 1024
	shotH = 700
)

// renderFrame builds the frame for rc and draws it offscreen.
func renderFrame(t *testing.T, rc renderCfg) *image.RGBA {
	t.Helper()
	force := ThemeLight
	if rc.dark {
		force = ThemeDark
	}
	f, err := NewFrame(FrameConfig{
		Enrolled:       false, // every tab present, as the shot command shows them
		InitialTab:     tabForScreen(rc.screen),
		HasAdminRights: rc.rights,
		ForceTheme:     force,
		Snap:           rc.snap,
		resolver:       rc.fonts,
	})
	if err != nil {
		t.Fatalf("NewFrame(%s, dark=%v): %v", rc.screen, rc.dark, err)
	}
	f.SelectTab(tabForScreen(rc.screen))
	img, err := renderFrameOffscreen(f, shotW, shotH)
	if err != nil {
		t.Fatalf("render %s (dark=%v): %v", rc.screen, rc.dark, err)
	}
	return img
}

// renderToDisk renders rc and writes the picture as a PNG, then decodes
// the file BACK FROM DISK — the verdict rests on the file, not on memory.
func renderToDisk(t *testing.T, rc renderCfg) image.Image {
	t.Helper()
	img := renderFrame(t, rc)
	path := filepath.Join(t.TempDir(), rc.screen+".png")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		t.Fatalf("encode %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
	back, err := os.Open(path)
	if err != nil {
		t.Fatalf("reopen %s: %v", path, err)
	}
	defer back.Close()
	decoded, err := png.Decode(back)
	if err != nil {
		t.Fatalf("decoded %s: %v", path, err)
	}
	return decoded
}

// countColor counts pixels of exactly c inside the region.
func countColor(img image.Image, c color.NRGBA, region image.Rectangle) int {
	n := 0
	for y := region.Min.Y; y < region.Min.Y+region.Dy() && y < img.Bounds().Max.Y; y++ {
		for x := region.Min.X; x < region.Min.X+region.Dx() && x < img.Bounds().Max.X; x++ {
			if got := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA); got == c {
				n++
			}
		}
	}
	return n
}

// distinctColors counts distinct colors, capped at max.
func distinctColors(img image.Image, max int) int {
	seen := make(map[uint32]struct{})
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y && len(seen) < max; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			r, g, bl, a := img.At(x, y).RGBA()
			seen[uint32(r>>8)<<24|uint32(g>>8)<<16|uint32(bl>>8)<<8|a>>8] = struct{}{}
			if len(seen) >= max {
				break
			}
		}
	}
	return len(seen)
}

func paletteOf(dark bool) design.Palette {
	if dark {
		return design.DarkPalette()
	}
	return design.LightPalette()
}

// longNames is a snapshot whose every name is far beyond what the §4.3
// grammar allows — the layout must survive what the runtime could hand
// over before validation rejects it.
func longNames() Snapshot {
	long := func(c byte, n int) string { return strings.Repeat(string(c), n) }
	return Snapshot{
		Server: ServerState{
			Waiting:     true,
			SshdRunning: true,
			Door:        DoorState{State: "open"},
			Sessions: []Session{
				{Person: long('p', 200) + "." + long('q', 200), Until: time.Date(2026, 9, 12, 18, 0, 0, 0, time.UTC)},
			},
		},
		Client: ClientState{
			Configured:    true,
			ActiveMachine: long('m', 200),
			Machines: []MachineAccess{
				{Name: long('x', 120) + "-" + long('y', 120), Online: true, SshdListening: true,
					Until: time.Date(2026, 9, 12, 18, 0, 0, 0, time.UTC)},
			},
			PublicKey: long('k', 300),
		},
		Admin: AdminState{
			People:   []Person{{Name: long('n', 200), Admin: true, Keys: 3}},
			Machines: []AdminMachine{{Name: long('w', 200), State: "verified", DoorState: "open", Online: true}},
			Grants:   []Grant{{Person: long('n', 200), Machine: long('w', 200), Until: time.Date(2026, 9, 12, 18, 0, 0, 0, time.UTC)}},
		},
		Setup:    SetupState{MachineName: long('s', 200), Status: "enrolled"},
		Settings: SettingsState{Version: long('v', 100), Port: 2222},
	}
}

// -------------------------------------------------------------------------
// §4.1 — every screen renders in both themes as a real, non-blank PNG.
// -------------------------------------------------------------------------

func TestAllScreensRenderRealPicturesInBothThemes(t *testing.T) {
	for _, screen := range []string{"setup", "client", "server", "admin", "settings"} {
		for _, dark := range []bool{false, true} {
			rc := renderCfg{screen: screen, dark: dark, rights: true, snap: exampleSnapshot()}
			t.Run(screen+"/"+themeName(dark), func(t *testing.T) {
				img := renderToDisk(t, rc)
				b := img.Bounds()
				if b.Dx() != shotW || b.Dy() != shotH {
					t.Errorf("picture is %dx%d, want %dx%d", b.Dx(), b.Dy(), shotW, shotH)
				}
				if n := distinctColors(img, 50); n <= 1 {
					t.Errorf("picture is a blank canvas: %d distinct color(s)", n)
				}
				// The state word of the screen is drawn in Ink: text is
				// actually on the canvas, not just the background fill.
				ink := paletteOf(dark).Ink
				if n := countColor(img, ink, image.Rect(0, 0, shotW, shotH)); n < 200 {
					t.Errorf("only %d ink-colored pixels — the screens drew no text", n)
				}
			})
		}
	}
}

func themeName(dark bool) string {
	if dark {
		return "dark"
	}
	return "light"
}

// -------------------------------------------------------------------------
// §4.2 — screens differ from each other; dark differs from light.
// -------------------------------------------------------------------------

func TestScreensDifferAndThemesDiffer(t *testing.T) {
	screens := []string{"setup", "client", "server", "admin", "settings"}
	light := make(map[string]*image.RGBA, len(screens))
	dark := make(map[string]*image.RGBA, len(screens))
	for _, s := range screens {
		light[s] = renderFrame(t, renderCfg{screen: s, rights: true, snap: exampleSnapshot()})
		dark[s] = renderFrame(t, renderCfg{screen: s, dark: true, rights: true, snap: exampleSnapshot()})
	}
	for i, a := range screens {
		if bytes.Equal(light[a].Pix, dark[a].Pix) {
			t.Errorf("dark shot of %q is identical to its light shot", a)
		}
		for _, b := range screens[i+1:] {
			if bytes.Equal(light[a].Pix, light[b].Pix) {
				t.Errorf("light shots of %q and %q are identical — the two screens drew the same picture", a, b)
			}
			if bytes.Equal(dark[a].Pix, dark[b].Pix) {
				t.Errorf("dark shots of %q and %q are identical — the two screens drew the same picture", a, b)
			}
		}
	}
}

// -------------------------------------------------------------------------
// §4.3 — the tab strip keeps its height across themes and missing fonts.
// -------------------------------------------------------------------------

func TestTabStripHeightStableAcrossThemesAndFonts(t *testing.T) {
	noFonts := winfonts.NewMockResolver(map[string]string{}, t.TempDir())

	measure := func(t *testing.T, dark bool, fonts *winfonts.Resolver) int {
		t.Helper()
		force := ThemeLight
		if dark {
			force = ThemeDark
		}
		f, err := NewFrame(FrameConfig{
			Enrolled:       false,
			HasAdminRights: true,
			ForceTheme:     force,
			Snap:           exampleSnapshot(),
			resolver:       fonts,
		})
		if err != nil {
			t.Fatalf("NewFrame: %v", err)
		}
		var height int
		for _, tab := range []string{TabSetUp, TabClient, TabServer, TabSession, TabAdmin, TabSettings} {
			f.SelectTab(tab)
			var ops op.Ops
			gtx := layout.Context{
				Ops: &ops,
				// The way the frame actually lays the strip out: an upper
				// bound only, no minimum — a label inside returns the
				// minimum it was given, so Exact constraints would measure
				// the whole window instead of the strip.
				Constraints: layout.Constraints{Max: image.Pt(shotW, shotH)},
				Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
			}
			dims := f.tabs.LayoutStrip(gtx, f.theme)
			if dims.Size.Y <= 0 {
				t.Fatalf("tab %q: strip height %d, want > 0", tab, dims.Size.Y)
			}
			if height == 0 {
				height = dims.Size.Y
			}
			if dims.Size.Y != height {
				t.Fatalf("tab %q: strip height %d, want stable %d", tab, dims.Size.Y, height)
			}
		}
		return height
	}

	base := measure(t, false, nil)
	if got := measure(t, true, nil); got != base {
		t.Errorf("dark theme strip height %d != light %d", got, base)
	}
	if got := measure(t, false, noFonts); got != base {
		t.Errorf("missing-font strip height %d != system-font %d", got, base)
	}
	if got := measure(t, true, noFonts); got != base {
		t.Errorf("missing-font dark strip height %d != system-font light %d", got, base)
	}
}

// -------------------------------------------------------------------------
// §4.4 — a missing font is a substitution, never a refusal.
// -------------------------------------------------------------------------

func TestMissingFontsFallBackInsteadOfRefusing(t *testing.T) {
	// An empty registry: no Sitka, no Cambria, no Consolas — nothing.
	empty := winfonts.NewMockResolver(map[string]string{}, t.TempDir())
	img := renderFrame(t, renderCfg{screen: "client", rights: true, snap: exampleSnapshot(), fonts: empty})

	// The picture must still carry readable text: thousands of glyph-core
	// pixels in the Ink color, drawn with the embedded gofont.
	ink := design.LightPalette().Ink
	if n := countColor(img, ink, image.Rect(0, 0, shotW, shotH)); n < 500 {
		t.Errorf("fallback render has only %d ink pixels — text did not survive the font substitution", n)
	}
	if n := distinctColors(img, 50); n <= 1 {
		t.Errorf("fallback render is blank: %d distinct color(s)", n)
	}
}

// -------------------------------------------------------------------------
// §4.5 — long names do not break the layout and do not leave the window.
// -------------------------------------------------------------------------

func TestLongNamesStayInsideTheWindow(t *testing.T) {
	snap := longNames()
	screens := []string{"setup", "client", "server", "admin", "settings"}
	for _, s := range screens {
		for _, dark := range []bool{false, true} {
			img := renderFrame(t, renderCfg{screen: s, dark: dark, rights: true, snap: snap})
			page := paletteOf(dark).Page

			// Below the masthead and the full-width tab rule, nothing may
			// cross the window edge: the left and right margin strips stay
			// pure Page color. Every content element stops at the Edge
			// inset (40 dp), far from these strips.
			for y := furnitureBottom(img, dark); y < shotH; y++ {
				for _, x := range []int{0, 1, 2, 3, shotW - 4, shotW - 3, shotW - 2, shotW - 1} {
					if got := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA); got != page {
						t.Fatalf("%s/%s: pixel at (%d,%d) is #%02X%02X%02X, want the page color — content left the window",
							s, themeName(dark), x, y, got.R, got.G, got.B)
					}
				}
			}

			// And the picture is not empty: the long-named content drew.
			ink := paletteOf(dark).Ink
			if n := countColor(img, ink, image.Rect(0, 0, shotW, shotH)); n < 200 {
				t.Errorf("%s/%s: long-name render has only %d ink pixels — content did not draw", s, themeName(dark), n)
			}
		}
	}
}

// -------------------------------------------------------------------------
// §4.6 — the elevation offer follows the rights, and it is a button in
// the masthead rather than a standing warning (SPEC §7.1 as of 1.3).
// -------------------------------------------------------------------------

func TestElevationOfferFollowsRights(t *testing.T) {
	rc := renderCfg{screen: "server", rights: false, snap: exampleSnapshot()}
	missing := renderFrame(t, rc)
	rc.rights = true
	present := renderFrame(t, rc)

	// The offer is present exactly when the rights are missing. Detected
	// by difference, not by colour: the button is styled like every other
	// secondary control, and a colour probe would have to be retuned every
	// time the design changes.
	changed := pixelsDiffering(missing, present, image.Rect(0, 0, shotW, shotH))
	if changed < 200 {
		t.Errorf("only %d pixels differ between missing and present rights — the elevation offer is not drawn at all", changed)
	}

	// The example facts are all good, so on this screen the Warn colour
	// would belong to the old standing banner alone. There must be none of
	// it: the fact that rights are missing is no longer announced on a
	// screen the person did not ask anything of.
	warnLight := design.LightPalette().Warn
	if n := countColor(missing, warnLight, image.Rect(0, 0, shotW, shotH)); n != 0 {
		t.Errorf("%d warn pixels on the server screen while rights are missing — the standing elevation banner is back", n)
	}
}

// TestStartWithoutRightsSaysSoUnderTheButton is the other half of moving
// the banner out: the fact still has to reach the person, but at the
// moment it matters. Pressing Start without Administrator must answer
// under Start — not silently, and not on a strip they stopped reading.
func TestStartWithoutRightsSaysSoUnderTheButton(t *testing.T) {
	f, err := NewFrame(FrameConfig{Enrolled: true, HasAdminRights: false})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	f.startServer()

	got := f.saidUnder(ctlServerStart)
	if got.text == "" {
		t.Fatalf("pressing Start without administrator rights said nothing at all — the person is left with a dead button")
	}
	if !strings.Contains(got.text, "Administrator rights are required") {
		t.Errorf("saidUnder(%q) = %q, want it to name the missing right", ctlServerStart, got.text)
	}
	if !strings.Contains(got.text, restartAdminNotice) {
		t.Errorf("saidUnder(%q) = %q, want it to also say how to fix it (%q)", ctlServerStart, got.text, restartAdminNotice)
	}
	if got.key != design.WarnKey {
		t.Errorf("saidUnder(%q) key = %v, want WarnKey — a missing right is a condition to fix, not a failure of the command", ctlServerStart, got.key)
	}
}

// -------------------------------------------------------------------------
// The button that cuts everything off is not hidden behind
// tabs: with a live session it stands above the tab strip on every tab.
// -------------------------------------------------------------------------

func TestStopReachableFromEveryTab(t *testing.T) {
	for _, s := range []string{"setup", "client", "server", "admin", "settings"} {
		img := renderFrame(t, renderCfg{screen: s, rights: true, snap: exampleSnapshot()})
		bad := design.LightPalette().Bad
		top := image.Rect(0, 0, shotW, 150)
		if n := countColor(img, bad, top); n < 100 {
			t.Errorf("tab %q: no cutting control above the tabs (%d bad-colored pixels in the top strip)", s, n)
		}
	}
}

// -------------------------------------------------------------------------
// §4.8 — rendering never touches the owner's theme setting.
// -------------------------------------------------------------------------

func TestOwnerThemeSettingUnchangedByRendering(t *testing.T) {
	before := ReadSystemThemeIsDark()

	// Build and lay out the whole matrix the product can produce. The
	// frames read the theme source they are given — here the real one —
	// and none of the passes may write anything back.
	noFonts := winfonts.NewMockResolver(map[string]string{}, t.TempDir())
	for _, s := range []string{"setup", "client", "server", "admin", "settings"} {
		for _, dark := range []bool{false, true} {
			for _, fonts := range []*winfonts.Resolver{nil, noFonts} {
				force := ThemeLight
				if dark {
					force = ThemeDark
				}
				f, err := NewFrame(FrameConfig{
					Enrolled:       false,
					InitialTab:     tabForScreen(s),
					HasAdminRights: true,
					ForceTheme:     force,
					Snap:           exampleSnapshot(),
					resolver:       fonts,
				})
				if err != nil {
					t.Fatalf("NewFrame(%s): %v", s, err)
				}
				var ops op.Ops
				gtx := layout.Context{
					Ops:         &ops,
					Constraints: layout.Exact(image.Pt(shotW, shotH)),
					Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
				}
				f.Layout(gtx)
			}
		}
	}

	after := ReadSystemThemeIsDark()
	if before != after {
		t.Errorf("theme setting changed during rendering: before=%v after=%v", before, after)
	}
}

// -------------------------------------------------------------------------
// The state helpers behind the screens.
// -------------------------------------------------------------------------

func TestScreenStateHelpers(t *testing.T) {
	if got := clipStr("abcdef", 4); got != "abc…" {
		t.Errorf("clipStr(abcdef,4) = %q, want %q", got, "abc…")
	}
	if got := clipStr("abc", 4); got != "abc" {
		t.Errorf("clipStr(abc,4) = %q, want unchanged", got)
	}
	if got := orDash("  "); got != "—" {
		t.Errorf("orDash(blank) = %q, want —", got)
	}
	if got := untilText(time.Time{}); got != "—" {
		t.Errorf("untilText(zero) = %q, want —", got)
	}
	want := "2026-09-12 18:00 UTC"
	if got := untilText(time.Date(2026, 9, 12, 18, 0, 0, 0, time.UTC)); got != want {
		t.Errorf("untilText = %q, want %q", got, want)
	}
	if got := intOrDash(0); got != "—" {
		t.Errorf("intOrDash(0) = %q, want —", got)
	}
	// "Open", not "Recording" (21.09.2026). What a session in this slice
	// reports is that the door is up -- serverStateFromControlReply
	// builds it from one boolean -- and the same window answers "nobody
	// is inside any machine at this moment" on Session and Admin -> Live,
	// which ask the gateway about attached terminals. The recording is
	// still promised, in the lead line beside the word, where it is true
	// of the open door rather than of a person.
	if lead, word, _ := serverHeadline(ServerState{Sessions: []Session{{Person: "x"}}}); word != "Open" {
		t.Errorf("serverHeadline(open door) word = %q, want Open (lead was %q)", word, lead)
	}
	if lead, _, _ := serverHeadline(ServerState{Sessions: []Session{{Person: "x"}}}); !strings.Contains(lead, "recorded") {
		t.Errorf("serverHeadline(open door) lead = %q — it must still promise the recording", lead)
	}
	if _, word, _ := serverHeadline(ServerState{Waiting: true}); word != "Waiting" {
		t.Errorf("serverHeadline(waiting) word = %q, want Waiting", word)
	}
	if _, word, _ := serverHeadline(ServerState{}); word != "At rest" {
		t.Errorf("serverHeadline(idle) word = %q, want At rest", word)
	}
	if _, word, _ := clientHeadline(ClientState{Connected: true, ActiveMachine: "m"}); word != "Connected" {
		t.Errorf("clientHeadline(connected) word = %q, want Connected", word)
	}
	var zero Snapshot
	if zero.Server.Busy() || zero.Server.AccessOpen() {
		t.Error("zero snapshot must be an idle machine: not busy, not recording")
	}
	if zero.Server.Door.IsOpen() {
		t.Error("zero door must not be open")
	}
}
