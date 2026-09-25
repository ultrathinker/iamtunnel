//go:build windows

package ui

// verify_iamt66_test.go — independent acceptance tests for IAMT-66 (the
// five screens), kept apart from the author's suite. Every test here
// asserts a pixel, geometry or structure verdict — never "did not
// panic". Each one has been shown to be sensitive by breaking the exact
// product code it guards, watching the test redden, and restoring that
// code byte for byte.

import (
	"image"
	"image/color"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
	"github.com/ultrathinker/iamtunnel/internal/ui/winfonts"
)

// -------------------------------------------------------------------------
// Independent-review helpers (local on purpose: the verdicts must not
// rest on the author's helpers).
// -------------------------------------------------------------------------

// renderSize draws one full frame of rc at an arbitrary canvas size.
func renderSize(t *testing.T, rc renderCfg, w, h int) *image.RGBA {
	t.Helper()
	force := ThemeLight
	if rc.dark {
		force = ThemeDark
	}
	f, err := NewFrame(FrameConfig{
		Enrolled:       false,
		InitialTab:     tabForScreen(rc.screen),
		HasAdminRights: rc.rights,
		ForceTheme:     force,
		Snap:           rc.snap,
		resolver:       rc.fonts,
	})
	if err != nil {
		t.Fatalf("NewFrame(%s, %dx%d): %v", rc.screen, w, h, err)
	}
	f.SelectTab(tabForScreen(rc.screen))
	img, err := renderFrameOffscreen(f, w, h)
	if err != nil {
		t.Fatalf("render %s at %dx%d: %v", rc.screen, w, h, err)
	}
	return img
}

// edgeRuleRow finds the first row within the top `limit` rows that is one
// solid run of color c touching BOTH window edges — the tab strip's
// full-width hairline. Card rules are inset by the Edge margin, so they
// never qualify; a row found here is the furniture line itself.
func edgeRuleRow(img image.Image, c color.NRGBA, limit int) (int, bool) {
	b := img.Bounds()
	w := b.Dx()
	for y := 0; y < limit && y < b.Dy(); y++ {
		full := true
		for x := 0; x < w; x++ {
			if got := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA); got != c {
				full = false
				break
			}
		}
		if full {
			return y, true
		}
	}
	return 0, false
}

// diffShare returns the share of pixels (0..1) that differ between two
// same-size pictures.
func diffShare(a, b image.Image) float64 {
	total, diff := 0, 0
	for y := 0; y < a.Bounds().Dy() && y < b.Bounds().Dy(); y++ {
		for x := 0; x < a.Bounds().Dx() && x < b.Bounds().Dx(); x++ {
			ar, ag, ab, aa := a.At(a.Bounds().Min.X+x, a.Bounds().Min.Y+y).RGBA()
			br, bg, bb, ba := b.At(b.Bounds().Min.X+x, b.Bounds().Min.Y+y).RGBA()
			total++
			if ar != br || ag != bg || ab != bb || aa != ba {
				diff++
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(diff) / float64(total)
}

// allGoodSnapshot is the example reality with the one status that would
// itself paint Warn (Setup "enrolled") neutralized, so on every tab the
// Warn color belongs to the elevation banner alone.
func allGoodSnapshot() Snapshot {
	snap := exampleSnapshot()
	snap.Setup.Status = ""
	return snap
}

// -------------------------------------------------------------------------
// 2. The cutting control of the server screen — above the tabs, on
// every tab, whenever a session is live. Verified against the
// furniture: pixels of the strip's button must sit strictly ABOVE the
// tab strip's full-width hairline.
// -------------------------------------------------------------------------

func TestVerifyCutControlSitsAboveTheTabRuleOnEveryTab(t *testing.T) {
	snap := exampleSnapshot() // Recording() == true: a session is live
	light := design.LightPalette()
	tabs := []string{TabSetUp, TabClient, TabServer, TabSession, TabAdmin, TabSettings}

	for _, w := range []int{1024, 640, 480} {
		for _, tab := range tabs {
			img := renderSize(t, renderCfg{screen: tab, rights: true, snap: snap}, w, 700)
			ruleY, ok := edgeRuleRow(img, light.Line, 400)
			if !ok {
				t.Fatalf("w=%d tab %s: the tab strip's full-width hairline not found in the top of the frame", w, tab)
			}
			above := image.Rect(0, 0, w, ruleY)
			if n := countColor(img, light.Bad, above); n < 1000 {
				t.Errorf("w=%d tab %s: cutting control not above the tabs — only %d bad pixels above the rule at y=%d", w, tab, n, ruleY)
			}
			// And below the rule the tab row itself must have painted: the
			// rule y must sit below the masthead, i.e. the strip really is
			// in the top band where an alarmed owner looks first.
			if ruleY < 80 || ruleY > 400 {
				t.Errorf("w=%d tab %s: tab rule at y=%d, outside the expected top band", w, tab, ruleY)
			}
		}
	}
}

// -------------------------------------------------------------------------
// 3. The elevation offer — one button at the right of the masthead,
// present exactly when rights are missing, and NO standing banner under
// the tab strip on any tab (SPEC §7.1 as of 1.3, maintainer's decision of
// 17.09.2026, IAMT-336).
//
// Until 1.3 this was the reverse: a two-line warning under the tab strip
// on every tab, including the four where elevation changes nothing. A
// warning that is always on screen is furniture, and the maintainer's own live
// run walked straight past it. The test asserts BOTH halves — the offer
// moved up, and the standing warning is gone — because deleting the
// banner without providing the button, and adding the button without
// deleting the banner, are each a way to get this wrong.
// -------------------------------------------------------------------------

func TestVerifyElevationOfferSitsInTheMastheadAndNowhereElse(t *testing.T) {
	light := design.LightPalette()
	tabs := []string{TabSetUp, TabClient, TabServer, TabSession, TabAdmin, TabSettings}

	// NO OPEN ACCESS in this snapshot (21.09.2026). The rect this test
	// calls "the masthead's left side" runs from the top of the window
	// down to the tab hairline, and when the access strip is drawn it
	// sits inside that band -- so the check was comparing the strip's
	// own text as well as the wordmark. Text rasterises a shade
	// differently between two renders of the same words, and a few
	// glyph pixels two steps out of 255 then read as "the wordmark
	// moved". Taking the strip out of the picture makes the rect mean
	// what the sentence below says it means; the strip has its own test
	// (TestVerifyCutControlSitsAboveTheTabRuleOnEveryTab).
	quiet := allGoodSnapshot()
	quiet.Server.Sessions = nil
	quiet.Server.Door = DoorState{}

	for _, tab := range tabs {
		without := renderSize(t, renderCfg{screen: tab, rights: true, snap: quiet}, shotW, shotH)
		with := renderSize(t, renderCfg{screen: tab, rights: false, snap: quiet}, shotW, shotH)

		ruleY, ok := edgeRuleRow(without, light.Line, 400)
		if !ok {
			t.Fatalf("tab %s: tab hairline not found", tab)
		}
		// (a) No standing warning under the tab strip — in EITHER state.
		band := image.Rect(0, ruleY+1, shotW, ruleY+90)
		if n := countColor(with, light.Warn, band); n != 0 {
			t.Errorf("tab %s: %d warn pixels under the tab rule while rights are missing — the standing banner is back; "+
				"since 1.3 the refusal belongs under the button that needed the rights, not on every screen", tab, n)
		}
		if n := countColor(without, light.Warn, band); n != 0 {
			t.Errorf("tab %s: %d warn pixels under the tab rule although rights are present", tab, n)
		}

		// (b) The button is in the masthead's right half, exactly when
		// rights are missing. Detected by DIFFERENCE rather than by colour,
		// so restyling the button does not silently blind this test.
		right := image.Rect(shotW/2, 0, shotW, ruleY)
		if n := pixelsDiffering(with, without, right); n < 200 {
			t.Errorf("tab %s: only %d pixels differ in the right of the masthead between rights and no rights — "+
				"the elevation button is not being drawn there", tab, n)
		}

		// (c) And the masthead's left side — the wordmark — is untouched by
		// the button's presence. If it moves, the button is pushing the
		// furniture around instead of taking space reserved for it.
		left := image.Rect(0, 0, shotW/2, ruleY)
		if n := pixelsDiffering(with, without, left); n != 0 {
			t.Errorf("tab %s: %d pixels of the masthead's left side moved when the elevation button appeared — "+
				"the wordmark must not shift", tab, n)
		}
	}
}

// pixelsDiffering counts pixels where two renders of the same window
// disagree inside r by more than rounding. It is how a control's presence
// is detected without knowing its colours: render the window with and
// without the reason for the control, and look at what changed.
//
// The one-step tolerance is not slack. Two renders of the SAME glyph came
// back differing by a single unit in a single channel — {92,91,90} against
// {91,91,89} — which is the GPU rasteriser rounding an antialiased edge,
// not the window moving. What this test needs to catch is furniture
// shifting, and a shift moves whole glyphs by whole pixels: hundreds of
// pixels changing by far more than one step. Counting rounding as motion
// would make the test fail for reasons nobody can fix.
func pixelsDiffering(a, b image.Image, r image.Rectangle) int {
	// 257, not 256: RGBA() widens an 8-bit channel by multiplying by 257
	// (0xff → 0xffff), so one 8-bit step IS 257 in this space. 256 misses
	// it by one and the tolerance does nothing at all.
	const tolerance = 257
	near := func(x, y uint32) bool {
		if x > y {
			x, y = y, x
		}
		return y-x <= tolerance
	}
	n := 0
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			ar, ag, ab, _ := a.At(x, y).RGBA()
			br, bg, bb, _ := b.At(x, y).RGBA()
			if !near(ar, br) || !near(ag, bg) || !near(ab, bb) {
				n++
			}
		}
	}
	return n
}

// TestVerifyNoSecondWayToFlipTheBanner locks the derivation in: the frame
// must expose no exported member that reaches the notice or the tabs, and
// the product sources must contain exactly one visibility call site, fed
// from HasAdminRights.
func TestVerifyNoSecondWayToFlipTheBanner(t *testing.T) {
	frame, err := NewFrame(FrameConfig{Enrolled: false, HasAdminRights: false})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	// Every field of Frame must be unexported: a caller outside the
	// package must have no path to the tabs or the notice at all.
	ft := reflect.TypeOf(frame).Elem()
	for i := 0; i < ft.NumField(); i++ {
		if ft.Field(i).PkgPath == "" {
			t.Errorf("Frame has an exported field %q — an outside caller can reach the furniture", ft.Field(i).Name)
		}
	}
	// And no exported method may even sound like a notice/banner setter:
	// the visibility is derived once, in NewFrame. The method set of the
	// POINTER type is what a caller sees — every Frame method has a
	// pointer receiver, so that is the set that must be scanned.
	reBad := regexp.MustCompile(`(?i)(notice|banner|elevation|recording|warning)`)
	pt := reflect.TypeOf((*Frame)(nil))
	if pt.NumMethod() == 0 {
		t.Fatalf("reflection sees no Frame methods — the guard itself would be blind")
	}
	for i := 0; i < pt.NumMethod(); i++ {
		name := pt.Method(i).Name
		if reBad.MatchString(name) {
			t.Errorf("Frame exports method %q — a second way to touch the notice", name)
		}
	}
	// FrameConfig: the rights fact is the only lever; no field may be
	// added that carries a ready visibility.
	reLever := regexp.MustCompile(`(?i)(notice|banner|elevation|show|visible|hide)`)
	cfgT := reflect.TypeOf(FrameConfig{})
	for i := 0; i < cfgT.NumField(); i++ {
		name := cfgT.Field(i).Name
		if name != "HasAdminRights" && reLever.MatchString(name) {
			t.Errorf("FrameConfig field %q looks like a second lever over the banner", name)
		}
	}

	// The product sources must hold NO writer of the elevation visibility.
	// Before 1.3 this guard counted call sites of SetNoticeVisible, because
	// visibility was separate state that could drift from the fact. Since
	// 1.3 there is no such state: layoutElevationButton asks
	// f.cfg.HasAdminRights on every frame, so the only way to reintroduce
	// the bug is to make the fact itself writable — and that is what is
	// banned here now.
	ban := map[string]bool{"SetNoticeVisible": true, "noticeVisible =": true, "cfg.HasAdminRights =": true}
	sites := 0
	err = filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(b)
		if strings.Contains(src, "func (t *Tabs) SetNoticeVisible") {
			return nil // the definition lives in the design package
		}
		for tok := range ban {
			if strings.Contains(src, tok) {
				sites++
				t.Errorf("%s writes the elevation visibility (%q) — since 1.3 it is derived on every frame, never stored", path, tok)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if sites != 0 {
		t.Errorf("found %d writer(s) of the elevation visibility in the product code — there is no stored visibility to write, "+
			"and anything that writes it is a way to switch the invariant off", sites)
	}
}

// -------------------------------------------------------------------------
// 4. The tab strip's height — furniture that must not move across
// themes, missing fonts and the banner's presence. Measured
// three ways: the strip's own height (LayoutStrip), the within-strip
// geometry in the composed picture (active underline to hairline), and
// the composed rule position across the states that may not move it
// (theme, banner, snapshot, tab).
// -------------------------------------------------------------------------

func TestVerifyTabStripHeightNeverMoves(t *testing.T) {
	light := design.LightPalette()
	noFonts := winfonts.NewMockResolver(map[string]string{}, t.TempDir())

	type variant struct {
		name   string
		dark   bool
		rights bool
		fonts  *winfonts.Resolver
		snap   Snapshot
		tab    string
	}
	variants := []variant{
		{"light", false, true, nil, exampleSnapshot(), TabServer},
		{"dark", true, true, nil, exampleSnapshot(), TabServer},
		{"no-fonts", false, true, noFonts, exampleSnapshot(), TabServer},
		{"no-fonts-dark", true, true, noFonts, exampleSnapshot(), TabServer},
		{"banner", false, false, nil, exampleSnapshot(), TabServer},
		{"banner-dark", true, false, nil, exampleSnapshot(), TabServer},
		{"banner-nofonts", false, false, noFonts, exampleSnapshot(), TabServer},
		{"long-names", false, true, nil, longNames(), TabServer},
		{"zero", false, true, nil, Snapshot{}, TabServer},
		{"client-tab", false, true, nil, exampleSnapshot(), TabClient},
		{"admin-tab", false, true, nil, exampleSnapshot(), TabAdmin},
		{"session-tab", false, true, nil, exampleSnapshot(), TabSession},
		{"settings-tab", false, true, nil, exampleSnapshot(), TabSettings},
		{"setup-tab", false, true, nil, exampleSnapshot(), TabSetUp},
	}

	// (1) The strip's own height, over every tab of every variant.
	var baseDims image.Point
	for _, v := range variants {
		force := ThemeLight
		if v.dark {
			force = ThemeDark
		}
		f, err := NewFrame(FrameConfig{
			Enrolled: false, HasAdminRights: v.rights, ForceTheme: force,
			Snap: v.snap, resolver: v.fonts,
		})
		if err != nil {
			t.Fatalf("%s: NewFrame: %v", v.name, err)
		}
		for _, tab := range []string{TabSetUp, TabClient, TabServer, TabSession, TabAdmin, TabSettings} {
			f.SelectTab(tab)
			var ops op.Ops
			gtx := layout.Context{
				Ops:         &ops,
				Constraints: layout.Constraints{Max: image.Pt(shotW, shotH)},
				Metric:      unit.Metric{PxPerDp: 1, PxPerSp: 1},
			}
			dims := f.tabs.LayoutStrip(gtx, f.theme)
			// The number is COMPOSED from the design's own tokens, not
			// written out. What this invariant is for is that the strip's
			// height comes from the tokens and never from font metrics --
			// a substituted gofont must not move the window's furniture
			// -- and the copied literal tested that only until
			// somebody deliberately changed a token, at which point it
			// failed for the one reason that is not a defect. The
			// font-independence half is the baseDims comparison below,
			// which runs across every theme, font set and tab.
			wantY := int(design.TabPadY + design.TabWordHeight +
				design.TabIndicatorMargin + design.TabIndicatorHeight + 1)
			if dims.Size.Y != wantY {
				t.Errorf("%s/%s: strip height %d, want %d (pad %v + cell %v + indicator %v+%v + rule 1)",
					v.name, tab, dims.Size.Y, wantY,
					design.TabPadY, design.TabWordHeight,
					design.TabIndicatorMargin, design.TabIndicatorHeight)
			}
			if baseDims == (image.Point{}) {
				baseDims = dims.Size
			}
			if dims.Size != baseDims {
				t.Errorf("%s/%s: strip size %v moved from %v", v.name, tab, dims.Size, baseDims)
			}
		}
	}

	// (2) Within-strip geometry in the composed picture: the active tab's
	// 2px underline must sit directly on the full-width hairline, at the
	// same offset in every variant — the strip's internals never reflow.
	wantGap := -1
	for _, v := range variants {
		img := renderSize(t, renderCfg{screen: v.tab, dark: v.dark, rights: v.rights, snap: v.snap, fonts: v.fonts}, shotW, shotH)
		line := light.Line
		if v.dark {
			line = design.DarkPalette().Line
		}
		ruleY, ok := edgeRuleRow(img, line, 400)
		if !ok {
			t.Fatalf("%s: the tab strip's hairline not found", v.name)
		}
		underlineTop := -1
		for y := ruleY - 1; y >= ruleY-12 && y >= 0; y-- {
			if rowHasRun(img, paletteOf(v.dark).Ink, y, 15) {
				underlineTop = y
				break
			}
		}
		if underlineTop < 0 {
			t.Fatalf("%s: the active tab's underline not found above the rule at y=%d", v.name, ruleY)
		}
		gap := ruleY - underlineTop
		if wantGap < 0 {
			wantGap = gap
			if gap < 1 || gap > 3 {
				t.Errorf("%s: underline sits %d rows above the rule — not the 2px indicator + 1px rule of the design", v.name, gap)
			}
		}
		if gap != wantGap {
			t.Errorf("%s: underline sits %d rows above the rule, want the invariant %d", v.name, gap, wantGap)
		}
	}

	// (3) The composed rule position across the states that may not move
	// it: theme, banner and the tab in front add nothing above the tabs.
	// (The recording strip and the masthead's font metrics legitimately
	// change what sits above the strip; they are not the strip — and the
	// zero snapshot removes the strip by design.)
	fixed := func(v variant) int {
		img := renderSize(t, renderCfg{screen: v.tab, dark: v.dark, rights: v.rights, snap: v.snap, fonts: v.fonts}, shotW, shotH)
		line := light.Line
		if v.dark {
			line = design.DarkPalette().Line
		}
		y, ok := edgeRuleRow(img, line, 400)
		if !ok {
			t.Fatalf("%s: hairline not found", v.name)
		}
		return y
	}
	ref := fixed(variants[0])
	for _, v := range []variant{variants[1], variants[4], variants[5], variants[9], variants[10], variants[11], variants[12]} {
		if got := fixed(v); got != ref {
			t.Errorf("%s: composed tab rule at y=%d, want %d — theme/banner/tab state moved the furniture", v.name, got, ref)
		}
	}
}

// rowHasRun reports whether row y contains at least run pixels of color c.
func rowHasRun(img image.Image, c color.NRGBA, y, run int) bool {
	best, cur := 0, 0
	for x := 0; x < img.Bounds().Dx(); x++ {
		if got := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA); got == c {
			cur++
			if cur > best {
				best = cur
			}
		} else {
			cur = 0
		}
	}
	return best >= run
}

// -------------------------------------------------------------------------
// 5. Long and hostile text. Machine and person names arrive
// from the gateway — input the owner does not control. Nothing may
// panic, nothing may leave the window, and the clipper must hand the
// labels valid, bounded text.
// -------------------------------------------------------------------------

func hostileSnapshot() Snapshot {
	rtl := "מחשב-ראשי של המנהל — התחברות מרחוק"
	emoji := "🖥️win💻-srv🖥️"
	esc := "\x1b[31;1mRED\x1b[0m"
	osc := "\x1b]0;pwned\x07"
	ctrl := "\x7f\x08\x1b[2J\u200d\u0301"
	invalid := "bad\xff\xfeutf"
	huge := strings.Repeat("\u0416", 5000)

	return Snapshot{
		Server: ServerState{
			Waiting:     true,
			SshdRunning: true,
			Door:        DoorState{State: "open"},
			Notice:      "gateway says: " + esc + osc + ctrl + " — reconnect " + strings.Repeat("required — ", 60),
			Sessions: []Session{
				{Person: rtl + " " + emoji + " " + osc + " " + strings.Repeat("i", 300), Until: time.Date(2026, 9, 12, 18, 0, 0, 0, time.UTC)},
			},
		},
		Client: ClientState{
			Configured:    true,
			ActiveMachine: esc + rtl,
			PublicKey:     "ssh-ed25519 " + strings.Repeat("A/", 200) + " comment\x1b[0m",
			Machines: []MachineAccess{
				{Name: rtl, Online: true, SshdListening: true, Until: time.Date(2026, 9, 12, 18, 0, 0, 0, time.UTC)},
				{Name: emoji + ctrl, Online: false, Until: time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC)},
				{Name: invalid, Online: true, Until: time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC)},
				{Name: huge, Online: false, Until: time.Date(2026, 9, 12, 20, 0, 0, 0, time.UTC)},
			},
		},
		Admin: AdminState{
			People:   []Person{{Name: "bob" + ctrl + rtl, Admin: true, Keys: 2}},
			Machines: []AdminMachine{{Name: emoji + esc, State: "verified", DoorState: "open", Online: true}},
			Grants:   []Grant{{Person: rtl, Machine: emoji, Until: time.Date(2026, 9, 12, 18, 0, 0, 0, time.UTC)}},
		},
		Setup: SetupState{
			MachineName: huge,
			Status:      "failed",
			Detail:      "the gateway refused: " + esc + osc,
		},
		Settings: SettingsState{
			Version:    "1.0\x1b[31m-beta",
			ConfigPath: "C:\\ProgramData\n..\\..\\windows\\system32",
			DataDir:    invalid,
		},
	}
}

// furnitureBottom reports the first row BELOW the masthead's furniture:
// the row after the tab strip's hairline, which is drawn edge to edge and
// therefore colours x=0 legitimately.
//
// It replaces the constant 150 that three separate tests had copied. On
// 21.09.2026 the tab strip grew padding, the hairline slid past 150, and
// all three reported the hairline as content escaping the window. A
// boundary retuned by hand every time the masthead changes is a boundary
// that will one day be retuned in the wrong direction.
func furnitureBottom(img *image.RGBA, dark bool) int {
	if ruleY, ok := edgeRuleRow(img, paletteOf(dark).Line, 400); ok {
		return ruleY + 1
	}
	return 150
}

func TestVerifyHostileNamesStayInside(t *testing.T) {
	snap := hostileSnapshot()
	screens := []string{"setup", "client", "server", "admin", "settings"}
	for _, s := range screens {
		for _, dark := range []bool{false, true} {
			name := s + "/" + themeName(dark)
			img := renderSize(t, renderCfg{screen: s, dark: dark, rights: true, snap: snap}, shotW, shotH)

			// Nothing may cross the window edge below the furniture.
			//
			// Where the furniture ends is ASKED, not assumed. It was the
			// constant 150 until 21.09.2026, when the tab strip grew
			// padding and the strip's own hairline -- which is drawn edge
			// to edge and is furniture, not content -- slid past it and
			// reported itself as escaped text. A boundary that has to be
			// retuned every time the masthead changes is a boundary that
			// will one day be retuned in the wrong direction.
			page := paletteOf(dark).Page
			for y := furnitureBottom(img, dark); y < shotH; y++ {
				for _, x := range []int{0, 1, 2, 3, shotW - 4, shotW - 3, shotW - 2, shotW - 1} {
					if got := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA); got != page {
						t.Fatalf("%s: pixel (%d,%d) is #%02X%02X%02X — hostile text left the window",
							name, x, y, got.R, got.G, got.B)
					}
				}
			}
			// And the content drew at all.
			ink := paletteOf(dark).Ink
			if n := countColor(img, ink, image.Rect(0, 0, shotW, shotH)); n < 200 {
				t.Errorf("%s: only %d ink pixels — the hostile content pushed the text off the canvas", name, n)
			}
		}
	}
}

// TestVerifyClipperHandsValidBoundedText pins the exact property the
// window's safety rests on: valid text in, valid bounded text out, cut
// marked with the ellipsis, never a split rune.
func TestVerifyClipperHandsValidBoundedText(t *testing.T) {
	inputs := []string{
		"מחשב-ראשי של המנהל — התחברות מרחוק",
		"🖥️win💻-srv🖥️",
		"\x1b[31;1mRED\x1b[0m and \x1b]0;pwned\x07",
		"\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416\u0416",
		strings.Repeat("\u0416", 5000),
		strings.Repeat("🖥", 100),
		"plain-name-01",
	}
	for _, in := range inputs {
		if !utf8.ValidString(in) {
			t.Fatalf("test bug: input must be valid UTF-8")
		}
		for _, n := range []int{4, 24, 32, 96} {
			got := clipStr(in, n)
			if !utf8.ValidString(got) {
				t.Errorf("clipStr(%q, %d) returned invalid UTF-8 — a split rune reaches the shaper", in, n)
			}
			if utf8.RuneCountInString(got) > n {
				t.Errorf("clipStr(…, %d) returned %d runes — over the bound", n, utf8.RuneCountInString(got))
			}
			if utf8.RuneCountInString(in) > n && !strings.HasSuffix(got, "…") {
				t.Errorf("clipStr cut without the ellipsis mark: %q", got)
			}
			if utf8.RuneCountInString(in) <= n && got != in {
				t.Errorf("clipStr altered a short name: got %q, want %q", got, in)
			}
		}
	}
	// An empty or blank name must never become whitespace noise on the
	// screen: it becomes the dash.
	for _, blank := range []string{"", "  ", "\t\n"} {
		if got := orDash(blank); got != "—" {
			t.Errorf("orDash(%q) = %q, want the dash", blank, got)
		}
	}
}

// -------------------------------------------------------------------------
// 6. Screens differ from each other and dark differs from light — in
// substance, not by one pixel.
// -------------------------------------------------------------------------

func TestVerifyScreensAndThemesDifferInSubstance(t *testing.T) {
	screens := []string{"setup", "client", "server", "admin", "settings"}
	light := make(map[string]*image.RGBA, len(screens))
	dark := make(map[string]*image.RGBA, len(screens))
	for _, s := range screens {
		light[s] = renderSize(t, renderCfg{screen: s, rights: true, snap: exampleSnapshot()}, shotW, shotH)
		dark[s] = renderSize(t, renderCfg{screen: s, dark: true, rights: true, snap: exampleSnapshot()}, shotW, shotH)
	}

	const pairMin = 0.02  // observed in acceptance: 0.073..0.098
	const themeMin = 0.20 // observed in acceptance: ~1.0 — backgrounds differ everywhere

	for i, a := range screens {
		if got := diffShare(light[a], dark[a]); got < themeMin {
			t.Errorf("%s: dark vs light differ in only %.4f of pixels — the theme does not reach the picture", a, got)
		}
		for _, b := range screens[i+1:] {
			if got := diffShare(light[a], light[b]); got < pairMin {
				t.Errorf("light %s vs %s differ in only %.4f of pixels — the screens drew substantially the same picture", a, b, got)
			}
			if got := diffShare(dark[a], dark[b]); got < pairMin {
				t.Errorf("dark %s vs %s differ in only %.4f of pixels — the screens drew substantially the same picture", a, b, got)
			}
		}
	}
}

// -------------------------------------------------------------------------
// 6b. The theme follows the SUBSTITUTED source, live, through the real
// Layout path — the mechanism that keeps every test (and the window)
// away from the maintainer's registry.
// -------------------------------------------------------------------------

func TestVerifyThemeFollowsTheSubstitutedSource(t *testing.T) {
	dark := false
	f, err := NewFrame(FrameConfig{
		Enrolled:    true,
		ThemeSource: ThemeSourceFunc(func() bool { return dark }),
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}

	pageAt := func() color.NRGBA {
		t.Helper()
		img, err := renderFrameOffscreen(f, shotW, shotH)
		if err != nil {
			t.Fatalf("render: %v", err)
		}
		return color.NRGBAModel.Convert(img.At(2, shotH-2)).(color.NRGBA)
	}

	if got := pageAt(); got != design.LightPalette().Page {
		t.Fatalf("with the source reporting light, page corner is %v, want %v", got, design.LightPalette().Page)
	}
	// IAMT-381/382: the per-frame probe is throttled to once a second, so
	// each flip below lets its throttle window elapse (backdating the
	// stamp, the way a real second of wall time would) before the next
	// render — the same convention TestLiveThemeSwitchEndToEnd states.
	letWindowElapse := func() { f.lastThemePoll = f.lastThemePoll.Add(-time.Second) }
	dark = true // flip the substituted reality, no rebuild
	letWindowElapse()
	if got := pageAt(); got != design.DarkPalette().Page {
		t.Fatalf("after the source flipped to dark, page corner is %v, want %v — the window did not follow", got, design.DarkPalette().Page)
	}
	dark = false
	letWindowElapse()
	if got := pageAt(); got != design.LightPalette().Page {
		t.Fatalf("after flipping back, page corner is %v, want %v", got, design.LightPalette().Page)
	}
}

// -------------------------------------------------------------------------
// 7. No fourth switch. The author removed SetTabBody, the
// exported Tabs() and former live Theme() accessor; this test locks the
// shape of everything a caller can still reach.
// -------------------------------------------------------------------------

func TestVerifyNoFourthInvariantSwitch(t *testing.T) {
	// Frame's exported method set is closed: switching a tab is the only
	// mutation a caller may perform after construction.
	allowed := map[string]bool{
		"CheckThemeSync": true,
		"CurrentTab":     true,
		"IsDark":         true,
		"Layout":         true,
		"SelectTab":      true,
		// IAMT-151, the maintainer's decision: the window had no way to learn
		// that a session had started, because the snapshot was fixed at
		// construction and this very list forbade a setter. The list is
		// widened by EXACTLY one method, and only for the snapshot — what
		// it may and may not touch is nailed down by
		// TestLiveUpdateMovesOnlyTheSnapshot in
		// iamt151_update_snapshot_test.go, which would redden if it ever
		// reached the theme, the tabs or the rights.
		//
		// It was called UpdateSnapshot and took a whole Snapshot until
		// 21.09.2026. The door is the same door and the guarantee is the
		// same guarantee; what changed is that it can now be handed only
		// the three facts the poll behind it actually learns, instead of
		// a whole window state assembled from a shadow copy nobody could
		// keep in step. See internal/ui/live_update.go.
		"ApplyLiveUpdate": true,
	}
	ft := reflect.TypeOf((*Frame)(nil))
	if _, ok := ft.MethodByName("Theme"); ok {
		t.Fatalf("Frame exposes Theme() and would let callers mutate the live design.Theme")
	}
	for i := 0; i < ft.NumMethod(); i++ {
		name := ft.Method(i).Name
		if !allowed[name] {
			t.Errorf("Frame grew an exported method %q — a candidate fourth switch over the invariants", name)
		}
	}

	// The three removed switches must stay removed in the sources.
	banned := []string{
		"SetTabBody",           // tab bodies must be built from the snapshot only
		"func (f *Frame) Tabs", // no exported handle on the tabs
		"ThemeOverride{",       // the override is a plain constant type again
		"func (t *Tabs) SetBody",
		"func (f *Frame) SetSnap",
	}
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(b)
		if strings.HasSuffix(path, "verify_iamt66_test.go") {
			return nil // this file quotes the banned tokens themselves
		}
		for _, tok := range banned {
			if strings.Contains(src, tok) {
				t.Errorf("%s reintroduces %q — a switch over an invariant", path, tok)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// ThemeOverride must remain a plain constant kind (the author's fix
	// for the struct sentinel flagged in review).
	k := reflect.TypeOf(ThemeAuto).Kind()
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.String:
	default:
		t.Fatalf("ThemeOverride kind = %v — no longer a plain constant type", k)
	}
}
