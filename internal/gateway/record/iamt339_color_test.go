package record

// iamt339_color_test.go — tests for IAMT-339 (vt.go keeps colour, not
// strips it). The hard contract: Transcript() stays byte-for-byte
// identical to what it produced before SGR was stored, every other
// IAMT-215 / IAMT-170 / IAMT-332 canary keeps being green, and a fresh
// consumer (Screen() / History()) can see the colour the machine sent.
//
// Each test pins one piece of that contract and ships a comment naming
// the line of product code that must be broken to make the test go red
// - never an env var, a build tag or a `ForTest` knob in product code.

import (
	"strings"
	"testing"
)

// TestIAMT339_ColorArrivesInScreen is the headline: a basic SGR sequence
// (red FG) followed by ASCII text ends up visible through Screen() with
// the FG colour glued to the runes it was emitted under. The test
// intentionally uses the smallest possible screen (80x24) so a reader
// can hand-trace which cell carries which attr, and it asserts both the
// default state outside the SGR region and the coloured state inside it.
//
// Canary: delete the line in handleGround's `default:` branch that
// does `v.screenAttr[v.cursorY][v.cursorX] = v.curAttr` (the line that
// mirrors the `v.screen[v.cursorY][v.cursorX] = r` assignment immediately
// above it) and the second Attrs assertion fails: the cells hold the
// zero Attr{} instead of the red FG, and the diff prints
//
//	Attrs[0] = {FG:{Kind:ColorDefault ...} ...}   want {FG:{Kind:ColorNamed Index:1 ...} ...}
func TestIAMT339_ColorArrivesInScreen(t *testing.T) {
	vt := NewVT(80, 24)
	if _, err := vt.Write([]byte("\x1b[31mred\x1b[0m plain")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	screen := vt.Screen()
	if len(screen) != 24 {
		t.Fatalf("screen rows: got %d, want 24", len(screen))
	}

	// Top row is the only one with content.
	want := "red plain"
	if screen[0].Text != want {
		t.Fatalf("row 0 text:\n got %q\nwant %q", screen[0].Text, want)
	}

	// Only the "red" prefix carries an attribute: the reset SGR before
	// " plain" makes the trailing 6 runes default, so rowAttrSlice trims
	// the slice to the last non-default cell (the "d" of "red"). The
	// per-rune asserts below use the Attrs length as the bound on the
	// coloured prefix and read default for everything past it.
	red := Color{Kind: ColorNamed, Index: 1}
	for i, r := range want {
		var wantAttr Attr
		if i < 3 {
			wantAttr = Attr{FG: red}
		}
		var got Attr
		if i < len(screen[0].Attrs) {
			got = screen[0].Attrs[i]
		}
		if got != wantAttr {
			t.Errorf("rune %d (%q): got %+v, want %+v", i, r, got, wantAttr)
		}
	}

	// Every other row is untouched: blank text AND a nil Attrs slice -
	// the contract that Screen() agrees with Transcript() about "blank
	// means truly nothing happened here" (see rowAttrSlice's doc).
	for r := 1; r < 24; r++ {
		if screen[r].Text != "" {
			t.Errorf("row %d text not blank: %q", r, screen[r].Text)
		}
		if screen[r].Attrs != nil {
			t.Errorf("row %d Attrs not nil: %+v", r, screen[r].Attrs)
		}
	}
}

// TestIAMT339_TranscriptByteForByteUnchanged is the IAMT-339 contract
// guard: Transcript() must produce exactly the same string the pre-SGR
// parser did. The input here covers every code path the parser
// previously threw away - SGR 0 reset, bold, named FG, 256-palette,
// 24-bit RGB, BG, default-FG/BG - so if any of those escape into the
// transcript (e.g. someone re-adds a `curAttr.String()` call), this
// test's exact-string compare fails with a 3-line diff.
//
// Canary: any change to Transcript(), rowToString(), or the parts of
// handleGround/executeCSI/processRune that those two rely on, that
// causes an SGR-related byte to land in the returned string. The most
// likely accidental regression is moving the new `screenAttr` write
// next to the existing `screen` write in handleGround and inadvertently
// letting the attr leak into Transcript - fix would be a stray
// `v.curAttr.FG.String()` call somewhere; this assertion fires first.
func TestIAMT339_TranscriptByteForByteUnchanged(t *testing.T) {
	vt := NewVT(80, 24)
	input := "\x1b[31mRed \x1b[1;32mGreenBold \x1b[4;33mUnderlineYellow " +
		"\x1b[38;5;196m256Color \x1b[38;2;100;200;255mRGBColor \x1b[0mPlain"
	if _, err := vt.Write([]byte(input)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	want := "Red GreenBold UnderlineYellow 256Color RGBColor Plain"
	got := vt.Transcript()
	if got != want {
		t.Fatalf("Transcript must stay byte-for-byte identical to the SGR-stripped output:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(got, "\x1b") || strings.Contains(got, "[31m") || strings.Contains(got, "[0m") {
		t.Fatalf("escape sequences leaked into transcript: %q", got)
	}
}

// TestIAMT339_PaletteAndRGB pin the two extended-colour branches of
// applySGR (38/48 with `5;n` and `2;r;g;b`). A real terminal gets
// those all the time - PSReadLine's syntax highlighting, ls --color,
// prompt themes - and Screen() must report them faithfully, palette as
// Color256 and RGB as ColorRGB with the exact channel bytes.
//
// Canary: in applySGR's 38 (and 48) arm, replace the
// `Color{Kind: Color256, Index: ...}` and
// `Color{Kind: ColorRGB, R: ..., G: ..., B: ...}` constructions with
// `Color{Kind: ColorDefault}` (or just `Color{}`); the assertions on
// Kind / Index / R / G / B fail with the diff spelling out the wrong
// kind and the wrong payload:
//
//	Attrs[0].FG.Kind = ColorDefault   want Color256
//	Attrs[0].FG.Index = 0             want 196
func TestIAMT339_PaletteAndRGB(t *testing.T) {
	vt := NewVT(80, 24)
	if _, err := vt.Write([]byte("\x1b[38;5;196mP\x1b[38;2;10;20;30mR\x1b[48;5;21mB\x1b[48;2;1;2;3mG\x1b[0mZ")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	screen := vt.Screen()
	row := screen[0]
	if row.Text != "PRBGZ" {
		t.Fatalf("row text: got %q, want %q", row.Text, "PRBGZ")
	}

	// Index 0 = palette 196, Index 1 = RGB (10,20,30), Index 2 = BG palette 21,
	// Index 3 = BG RGB (1,2,3). The trailing "Z" carries no attribute
	// because it was emitted after \x1b[0m reset, so Attrs is trimmed
	// to length 4 (not 5) - that is the Attrs-shorter-than-Text contract
	// for default-rune tails.
	cases := []struct {
		i    int
		want Attr
		desc string
	}{
		{0, Attr{FG: Color{Kind: Color256, Index: 196}}, "FG palette 196"},
		{1, Attr{FG: Color{Kind: ColorRGB, R: 10, G: 20, B: 30}}, "FG RGB 10/20/30"},
		{2, Attr{FG: Color{Kind: ColorRGB, R: 10, G: 20, B: 30}, BG: Color{Kind: Color256, Index: 21}}, "FG RGB + BG palette 21"},
		{3, Attr{FG: Color{Kind: ColorRGB, R: 10, G: 20, B: 30}, BG: Color{Kind: ColorRGB, R: 1, G: 2, B: 3}}, "FG RGB + BG RGB 1/2/3"},
	}
	if got, want := len(row.Attrs), 4; got != want {
		t.Fatalf("Attrs length: got %d, want %d (P, R, B, G coloured; Z reset, trimmed)", got, want)
	}
	for _, c := range cases {
		if row.Attrs[c.i] != c.want {
			t.Errorf("%s: Attrs[%d] = %+v, want %+v", c.desc, c.i, row.Attrs[c.i], c.want)
		}
	}
}

// TestIAMT339_AttributesSurviveResize covers IAMT-339's
// "Resize moves the content; the attributes must travel with it".
// The session writes a red FG, triggers a scroll so the line lands in
// history with its colour, then resizes the screen; the resize reflow
// must keep the colour on the same cells, and Screen()/History() must
// report it through both views.
//
// Canary: in Resize, omit the `copy(v.screen[r], v.screen[r+n])` line's
// parallel `copy(v.screenAttr[r], v.screenAttr[r+n])` - the colour of
// the surviving row's cells flips back to default and the assertion on
// History() fails; or, in the same function, forget to set
// `v.screenAttr = newScreenAttr` and Screen() still reports the old
// dimensions' attr grid (test panics on `len(screen) != newRows`).
func TestIAMT339_AttributesSurviveResize(t *testing.T) {
	// Tiny screen so every line is forced through history on the way
	// to the resize - a 3-row buffer makes the layout deterministic
	// without depending on the larger scrollback math.
	vt := NewVT(80, 3)
	vt.Write([]byte("first\n"))
	vt.Write([]byte("second\n"))
	// RED-ROW lands on the last row of the (then-3-row) screen.
	vt.Write([]byte("\x1b[31mRED-ROW\x1b[0m"))
	// Three more newlines push all three lines off the top into
	// history: each \n triggers advanceLine, which scrolls because
	// cursorY is on the last row, and each scrollUp commits one line.
	vt.Write([]byte("\n\n\n"))

	red := Color{Kind: ColorNamed, Index: 1}

	// History must contain the red row, with the FG on every rune of
	// the visible text. The Attrs slice may be shorter than the text -
	// that's the contract for non-default attribute lines.
	hist := vt.History(0, vt.HistoryTotal())
	var redLine *Line
	for i := range hist {
		if hist[i].Text == "RED-ROW" {
			redLine = &hist[i]
			break
		}
	}
	if redLine == nil {
		t.Fatalf("RED-ROW not found in history: %+v", hist)
	}
	if len(redLine.Attrs) < len("RED-ROW") {
		t.Fatalf("RED-ROW Attrs too short: got %d, want >= %d", len(redLine.Attrs), len("RED-ROW"))
	}
	for i, r := range "RED-ROW" {
		if redLine.Attrs[i] != (Attr{FG: red}) {
			t.Errorf("history RED-ROW rune %d (%q): got %+v, want %+v", i, r, redLine.Attrs[i], Attr{FG: red})
		}
	}

	// Now resize. The new screen still carries its cells' colours if
	// the resize path copied attrs along with runes; the transcript
	// view stays byte-for-byte identical regardless.
	vt.Resize(40, 10)
	if cols, rows := vt.Size(); cols != 40 || rows != 10 {
		t.Fatalf("size after resize: got %dx%d, want 40x10", cols, rows)
	}
	screen := vt.Screen()
	if len(screen) != 10 {
		t.Fatalf("screen rows after resize: got %d, want 10", len(screen))
	}
	for r := 0; r < 10; r++ {
		if len(screen[r].Attrs) > 40 {
			t.Errorf("row %d: Attrs len %d > 40 (cols)", r, len(screen[r].Attrs))
		}
	}

	// Transcript() is the IAMT-215 / IAMT-170 contract: byte-for-byte
	// unchanged from the SGR-stripping era, regardless of how the
	// resize reflowed the contents.
	if got, want := vt.Transcript(), "first\nsecond\nRED-ROW"; got != want {
		t.Fatalf("Transcript after resize:\n got %q\nwant %q", got, want)
	}

	// After the resize, RED-ROW may still be on the (now larger) screen
	// or in history. Either way it must still carry its colour. The
	// easiest place to look is the history slice - it has a deterministic
	// shape by now.
	for _, line := range vt.History(0, vt.HistoryTotal()) {
		if line.Text != "RED-ROW" {
			continue
		}
		if len(line.Attrs) < len("RED-ROW") {
			t.Fatalf("RED-ROW Attrs too short after resize: got %d, want >= 7",
				len(line.Attrs))
		}
		for i, r := range "RED-ROW" {
			if line.Attrs[i] != (Attr{FG: red}) {
				t.Errorf("post-resize RED-ROW rune %d (%q): got %+v, want %+v",
					i, r, line.Attrs[i], Attr{FG: red})
			}
		}
		return
	}
	t.Fatalf("RED-ROW not found in history after resize")
}

// TestIAMT339_AttributesEvictedWithHistory covers the scrollback cap
// contract: "The scrollback is already capped (maxHistoryLines = 10000) and
// there is a counter for the evicted lines (DroppedHistoryLines). Attributes
// must be evicted together with their lines, or memory will leak."
//
// The session pushes well over maxHistoryLines coloured rows through a
// 1-row screen: every line scrolls into history immediately, and the
// scrollback cap then evicts the oldest ones together with their attrs.
// The test then reads the surviving slice and verifies (a) its length
// honours the cap, (b) DroppedHistoryLines reports the right count, and
// (c) each surviving line's first-rune attr matches the colour that
// row was written with (a per-line check that catches a missing-attr
// eviction: a History() that returns the right text but the wrong
// colour because historyAttr was sliced independently of history).
//
// Canary: in appendHistoryLines, drop the parallel handling of
// `v.historyAttr` (the parallel append, the parallel copy/slice on
// overflow, the parallel cap check). Two distinct failure modes:
//   - if the eviction forgets to slice historyAttr, it grows without
//     bound: the final vt.HistoryTotal() returns > maxHistoryLines
//     and the assertion fires ("HistoryTotal after eviction: got %d,
//     want %d").
//   - if append forgets to append, the Attrs land in the wrong index
//     and History() returns Lines whose Text says "red 9999" but whose
//     Attrs come from an older line; the per-line attr assertion
//     fires with the wrong colour.
func TestIAMT339_AttributesEvictedWithHistory(t *testing.T) {
	vt := NewVT(80, 1)
	// A 1-row screen makes every \n an immediate scroll: the line we
	// just wrote is committed to history on the same Write call.
	// Writing maxHistoryLines+128 lines guarantees the eviction runs
	// at least once.
	total := maxHistoryLines + 128
	for i := 0; i < total; i++ {
		// Per-line distinct colour to make mismatched Attrs impossible
		// to confuse with a happy-path coincidence: index 0..7 wraps.
		vt.Write([]byte("\x1b[3" + string(rune('0'+i%8)) + "mred " +
			(itoaSmall(i)) + "\x1b[0m\n"))
	}

	if got, want := vt.HistoryTotal(), maxHistoryLines; got != want {
		t.Fatalf("HistoryTotal after eviction: got %d, want %d", got, want)
	}
	if got, want := vt.DroppedHistoryLines(), int64(total-maxHistoryLines); got != want {
		t.Fatalf("DroppedHistoryLines: got %d, want %d", got, want)
	}

	hist := vt.History(0, vt.HistoryTotal())
	if len(hist) != maxHistoryLines {
		t.Fatalf("History returned %d lines, want %d", len(hist), maxHistoryLines)
	}
	// history holds the LAST maxHistoryLines of the total writes, i.e.
	// lines `total-maxHistoryLines .. total-1` (0-based by write index).
	firstKept := total - maxHistoryLines
	for i, line := range hist {
		wantWriteIdx := firstKept + i
		wantIdx := uint8(wantWriteIdx % 8)
		// The "red " prefix carries the colour; what comes after is
		// default. Attrs must be at least 1 long (and never longer
		// than the text - the Attrs-shorter-than-Text contract).
		if len(line.Attrs) == 0 {
			t.Fatalf("history[%d] %q: Attrs empty, want at least 1", i, line.Text)
		}
		if len(line.Attrs) > len(line.Text) {
			t.Fatalf("history[%d] %q: Attrs %d > Text %d",
				i, line.Text, len(line.Attrs), len(line.Text))
		}
		// First rune ("r") carries the colour.
		if got := line.Attrs[0].FG; got != (Color{Kind: ColorNamed, Index: wantIdx}) {
			t.Errorf("history[%d] %q (write %d): Attrs[0].FG = %+v, want {Kind:ColorNamed Index:%d}",
				i, line.Text, wantWriteIdx, got, wantIdx)
		}
	}
}

// itoaSmall turns 0..99999 into a string without pulling in strconv just
// for this test - the whole point of the eviction test is the memory
// side, and "fmt.Sprintf" in a hot loop would muddle any future
// profiling that touches it.
func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestIAMT339_UnknownSGRDoesNotPoison is the "an unknown-parameter SGR does
// not break parsing" guarantee. applySGR consumes only the named codes; a
// sequence that mixes a recognised one (1 = bold) with several
// unknowns (2, 3, 5, 6, 8, 9, 21, 23, 25, 26, 28, 29, 51, 52, 53)
// must still set bold, must still produce a clean Transcript, and must
// hand the consumer a sane Attrs slice (bold bit set, no FG/BG set,
// no spurious garbage left over from the unknowns).
//
// Canary: in applySGR, change the trailing `default:`-style fall-through
// to `default: v.curAttr = Attr{}` (a copy-paste from the reset path):
// the bold assertion below fires because bold gets wiped. Or remove the
// "consume the introducer's sub-params" `i += 2` / `i += 4` lines, and
// the 38/48 fallback would mistake the introducer mode byte for a
// foreground index - the test that follows this one (PaletteAndRGB)
// would also fail, but here we get a clean diff:
//
//	Attrs[0] = {FG:{Kind:ColorDefault ...} ...}   want {FG:{Kind:ColorNamed Index:1 ...} ...
func TestIAMT339_UnknownSGRDoesNotPoison(t *testing.T) {
	vt := NewVT(80, 24)
	// 2,3,5,6,8,9,21,23,25,26,28,29,51,52,53 are real SGR codes that the
	// product's parser has no business understanding; they must be
	// skipped silently. Then 1 (bold) takes effect, then 31 (red FG),
	// then back to default.
	in := "\x1b[2;3;5;6;8;9;21;23;25;26;28;29;51;52;53;1;31mAB\x1b[0m"
	if _, err := vt.Write([]byte(in)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	want := "AB"
	if got := vt.Transcript(); got != want {
		t.Fatalf("Transcript after unknown SGRs:\n got %q\nwant %q", got, want)
	}

	screen := vt.Screen()
	if screen[0].Text != want {
		t.Fatalf("Screen row 0 text: got %q, want %q", screen[0].Text, want)
	}
	wantAttr := Attr{FG: Color{Kind: ColorNamed, Index: 1}, Bold: true}
	if len(screen[0].Attrs) < 2 {
		t.Fatalf("Screen row 0 Attrs too short: got %d, want >= 2", len(screen[0].Attrs))
	}
	if screen[0].Attrs[0] != wantAttr || screen[0].Attrs[1] != wantAttr {
		t.Fatalf("Screen row 0 Attrs: got [%+v %+v], want [%+v %+v]",
			screen[0].Attrs[0], screen[0].Attrs[1], wantAttr, wantAttr)
	}
}

// TestIAMT339_StyleFlags covers the four flag bits of Attr that the
// palette/RGB branches do not exercise: bold (1), underline (4),
// reverse (7), and their off-codes 22, 24, 27. Each must be applied
// independently and combined correctly with FG/BG so the consumer can
// reconstruct the cell's appearance.
//
// Canary: in applySGR, accidentally swap `case p == 22: v.curAttr.Bold = false`
// with `case p == 24: v.curAttr.Underline = false`; the assertions on
// the off-codes fail with a per-bit diff:
//
//	Attrs[0] = {Bold:false Underline:true Reverse:false ...}   want {Bold:true Underline:false Reverse:false ...}
func TestIAMT339_StyleFlags(t *testing.T) {
	vt := NewVT(80, 24)
	if _, err := vt.Write([]byte(
		"\x1b[1mB\x1b[22mX" + // bold on, off; second rune must be non-bold
			"\x1b[4mU\x1b[24mY" + // underline on, off
			"\x1b[7mR\x1b[27mZ", // reverse on, off
	)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	screen := vt.Screen()
	if screen[0].Text != "BXUYRZ" {
		t.Fatalf("row 0 text: got %q, want %q", screen[0].Text, "BXUYRZ")
	}
	// Each "on" rune carries the flag; each "off" rune is a default
	// cell that rowAttrSlice trims away past the last non-default.
	// That is why Attrs has 4 entries (the B/U/R positions), not 6,
	// and why we read X/Y/Z by index past Attrs's length: they are
	// default by the Attrs-shorter-than-Text contract.
	if got, want := len(screen[0].Attrs), 5; got != want {
		t.Fatalf("Attrs length: got %d, want %d (B, X, U, Y, R included; Z reset, trimmed)", got, want)
	}
	cases := []struct {
		i    int
		want Attr
		desc string
	}{
		{0, Attr{Bold: true}, "bold on"},
		{2, Attr{Underline: true}, "underline on"},
		{4, Attr{Reverse: true}, "reverse on"},
	}
	for _, c := range cases {
		if screen[0].Attrs[c.i] != c.want {
			t.Errorf("%s: Attrs[%d] = %+v, want %+v", c.desc, c.i, screen[0].Attrs[c.i], c.want)
		}
	}
}

// TestIAMT339_HistoryPagination pins the History(from, max) paging
// contract: out-of-range `from` clamps, `max <= 0` returns nil,
// `from > total` returns nil, and the slice never aliases the internal
// buffer (a caller mutating an entry must not corrupt a later call).
//
// Canary: drop the `append([]Attr(nil), ...)` defensive copy in
// History() and the aliasing assertion fires: the consumer's mutation
// reaches back into v.historyAttr and the second call observes the
// mutated entry.
func TestIAMT339_HistoryPagination(t *testing.T) {
	// 1-row screen so every \n scrolls the just-written line straight
	// into history; 5 coloured writes give us a 5-line scrollback to
	// page through.
	vt := NewVT(80, 1)
	for i := 0; i < 5; i++ {
		vt.Write([]byte("\x1b[3" + string(rune('1'+i)) + "mL" + string(rune('A'+i)) + "\x1b[0m\n"))
	}

	// History is now [LA, LB, LC, LD, LE].
	// from < 0 clamps to 0, so the first page is the first 2 lines.
	page := vt.History(-3, 2)
	if len(page) != 2 || page[0].Text != "LA" || page[1].Text != "LB" {
		t.Fatalf("from<0 clamp: got %+v", page)
	}

	// max <= 0 returns nil.
	if got := vt.History(0, 0); got != nil {
		t.Errorf("max=0: got %+v, want nil", got)
	}
	if got := vt.History(0, -1); got != nil {
		t.Errorf("max<0: got %+v, want nil", got)
	}

	// from > total returns nil.
	if got := vt.History(100, 5); got != nil {
		t.Errorf("from>total: got %+v, want nil", got)
	}

	// Partial tail: from + max > total, must clamp end to total. Asking
	// for index 3.. yields LD, LE - the last two lines.
	page = vt.History(3, 100)
	if len(page) != 2 {
		t.Fatalf("tail clamp: got %d entries, want 2 (history total=%d)",
			len(page), vt.HistoryTotal())
	}
	if page[0].Text != "LD" || page[1].Text != "LE" {
		t.Fatalf("tail content: got %+v", page)
	}

	// Aliasing: mutating the returned slice must not change a second
	// call's output. first[0].Attrs[0].FG carries the "31"-style
	// colour from the first SGR; mutating its Index must not bleed
	// back into the underlying buffer.
	first := vt.History(0, 5)
	if len(first[0].Attrs) == 0 {
		t.Fatalf("first[0] has no Attrs; aliasing test inconclusive")
	}
	first[0].Attrs[0].FG.Index = 99
	second := vt.History(0, 5)
	if second[0].Attrs[0].FG.Index == 99 {
		t.Fatalf("History aliased internal buffer: second call observed mutation")
	}
}
