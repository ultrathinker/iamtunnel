package record

import (
	"strings"
	"testing"
)

func TestVTLineFeedAndCarriageReturn(t *testing.T) {
	vt := NewVT(80, 24)

	// Simulates an in-place progress counter using \r, then \r\n to finish
	input := "Downloading: 10%\rDownloading: 50%\rDownloading: 100%\r\nDone!\r\n"
	if _, err := vt.Write([]byte(input)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	lines := strings.Split(vt.Transcript(), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines, got %d: %q", len(lines), vt.Transcript())
	}

	if lines[0] != "Downloading: 100%" {
		t.Errorf("expected line 0 to be 'Downloading: 100%%', got %q", lines[0])
	}
	if lines[1] != "Done!" {
		t.Errorf("expected line 1 to be 'Done!', got %q", lines[1])
	}
}

func TestVTBackspace(t *testing.T) {
	vt := NewVT(80, 24)

	// User types "Hello Worldx", realizes mistake, presses backspace, types "!"
	input := "Hello Worldx\b!"
	if _, err := vt.Write([]byte(input)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	expected := "Hello World!"
	actual := vt.Transcript()
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}

// TestVTClearScreen — SPEC §6.5 (round 3, IAMT-215): a screen clear (ED)
// must not delete text the transcript has already shown; erased rows are
// preserved exactly as content scrolled off the top already is. This test
// used to assert the opposite (old text vanishes) - that was the very
// contract IAMT-215 round 3 replaced (see docs/SPEC.md §6.5, commit
// 4d5852e: conhost's real "cls" output erases the
// visible screen the same way, and a command typed before cls used to
// disappear from the audit transcript entirely).
func TestVTClearScreen(t *testing.T) {
	vt := NewVT(80, 24)

	// Write old text, clear entire screen (2J) and move home (H), then write new text
	input := "Old obsolete text\x1b[H\x1b[2JNew clean screen"
	if _, err := vt.Write([]byte(input)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Exact match (not just Contains) so this also pins the ORDER: the
	// erased text must appear where it was shown, before the new text that
	// replaced it - SPEC §6.5 (round 4, IAMT-215).
	actual := vt.Transcript()
	if want := "Old obsolete text\nNew clean screen"; actual != want {
		t.Errorf("2J must preserve already-shown text, in order, per SPEC §6.5:\n want %q\n got  %q", want, actual)
	}

	// Partial display clear: 0J (from cursor to end) - column 1 means the
	// erase covers all of "Line 2", not just part of it, so it must be
	// preserved exactly like "Line 3" below it, and in the ORDER it was
	// shown: Line 1, then Line 2, then Line 3 (not Line 2/3 reordered
	// before Line 1's neighbour, and not duplicated).
	vt2 := NewVT(80, 5)
	vt2.Write([]byte("Line 1\nLine 2\nLine 3"))
	vt2.Write([]byte("\x1b[2;1H\x1b[0J")) // Move to line 2 column 1, clear to end of screen
	actual2 := vt2.Transcript()
	if want := "Line 1\nLine 2\nLine 3"; actual2 != want {
		t.Errorf("0J erasing whole lines from column 1 must preserve them in order per SPEC §6.5:\n want %q\n got  %q", want, actual2)
	}
}

func TestVTClearLine(t *testing.T) {
	vt := NewVT(80, 24)

	// Write "Prefix ToBeCleared", move cursor back before "ToBeCleared", clear to end of line (0K)
	input := "Prefix ToBeCleared\x1b[8G\x1b[K"
	if _, err := vt.Write([]byte(input)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	actual := vt.Transcript()
	if actual != "Prefix" {
		t.Fatalf("expected 'Prefix', got %q", actual)
	}

	// Clear from start to cursor (1K): clears indices 0..9, leaving "uffix"
	// preceded by the blanked columns (exact match pins both content and
	// that nothing is reordered or duplicated).
	vt2 := NewVT(80, 5)
	vt2.Write([]byte("ClearThisSuffix\x1b[10G\x1b[1K"))
	actual2 := vt2.Transcript()
	if want := "          uffix"; actual2 != want {
		t.Errorf("1K clear failed:\n want %q\n got  %q", want, actual2)
	}

	// Clear entire line (2K) - SPEC §6.5 (round 3/4, IAMT-215): 2K erases the
	// whole line unconditionally, so it must be preserved in the transcript
	// exactly like a scrolled-away line, not dropped, and in the ORDER it
	// was shown - between "Line 1" and "Line 3", with no spurious blank
	// lines left behind by the erased-then-committed row bookkeeping (this
	// assertion used to require the opposite; see TestVTClearScreen's doc
	// comment).
	vt3 := NewVT(80, 5)
	vt3.Write([]byte("Line 1\nWhole line to erase\x1b[2K\nLine 3"))
	actual3 := vt3.Transcript()
	if want := "Line 1\nWhole line to erase\nLine 3"; actual3 != want {
		t.Errorf("2K must preserve the fully-erased line, in order, per SPEC §6.5:\n want %q\n got  %q", want, actual3)
	}
}

func TestVTCursorMovements(t *testing.T) {
	vt := NewVT(40, 10)

	// Write grid using cursor movements
	// 1. Move to (col 5, row 3): CSI 3;5H
	vt.Write([]byte("\x1b[3;5HCenter"))
	// 2. Cursor up by 2: CSI 2A -> row 1
	vt.Write([]byte("\x1b[2ATop"))
	// 3. Cursor down by 4: CSI 4B -> row 5
	vt.Write([]byte("\x1b[4BBottom"))
	// 4. Move to next line and horizontal absolute to col 15: CSI 1E CSI 15G
	vt.Write([]byte("\x1b[1E\x1b[15GRight"))

	trans := vt.Transcript()
	if !strings.Contains(trans, "Center") || !strings.Contains(trans, "Top") ||
		!strings.Contains(trans, "Bottom") || !strings.Contains(trans, "Right") {
		t.Fatalf("cursor movements produced unexpected transcript:\n%s", trans)
	}

	// Test Next Line (E) and Prev Line (F)
	vt2 := NewVT(40, 10)
	vt2.Write([]byte("First\x1b[2ESecond\x1b[1FAbove"))
	trans2 := vt2.Transcript()
	lines := strings.Split(trans2, "\n")
	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines, got %d: %q", len(lines), trans2)
	}
	if lines[0] != "First" {
		t.Errorf("expected 'First', got %q", lines[0])
	}
	if lines[1] != "Above" {
		t.Errorf("expected 'Above', got %q", lines[1])
	}
	if lines[2] != "Second" {
		t.Errorf("expected 'Second', got %q", lines[2])
	}
}

func TestVTCursorSaveRestore(t *testing.T) {
	vt := NewVT(40, 10)

	// Write "Hello ", save cursor (ESC 7), move away, write "far away", restore cursor (ESC 8), write "World"
	vt.Write([]byte("Hello \x1b7\x1b[5;10Hfar away\x1b8World"))

	lines := strings.Split(vt.Transcript(), "\n")
	if !strings.HasPrefix(lines[0], "Hello World") {
		t.Fatalf("expected line 0 to start with 'Hello World', got %q", lines[0])
	}

	// Test CSI s and CSI u
	vt2 := NewVT(40, 10)
	vt2.Write([]byte("Start \x1b[s\x1b[4;4HOther\x1b[uEnd"))
	lines2 := strings.Split(vt2.Transcript(), "\n")
	if !strings.HasPrefix(lines2[0], "Start End") {
		t.Fatalf("expected line 0 to start with 'Start End', got %q", lines2[0])
	}
}

func TestVTScrollingOnOverflow(t *testing.T) {
	// Small screen: 40 cols, 4 rows
	vt := NewVT(40, 4)

	// Write 8 lines, causing lines 1-4 to scroll off into history
	input := "Line 1\nLine 2\nLine 3\nLine 4\nLine 5\nLine 6\nLine 7\nLine 8"
	if _, err := vt.Write([]byte(input)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	transcript := vt.Transcript()
	lines := strings.Split(transcript, "\n")

	if len(lines) != 8 {
		t.Fatalf("expected 8 lines in transcript after scrolling, got %d:\n%s", len(lines), transcript)
	}

	for i := 0; i < 8; i++ {
		expected := "Line " + string(rune('1'+i))
		if lines[i] != expected {
			t.Errorf("line %d mismatch: expected %q, got %q", i, expected, lines[i])
		}
	}
}

func TestVTLongLineWrap(t *testing.T) {
	// Screen width 10 cols
	vt := NewVT(10, 5)

	// Write 25 characters without newlines
	vt.Write([]byte("0123456789ABCDEFGHIJKLMNO"))

	transcript := vt.Transcript()
	lines := strings.Split(transcript, "\n")

	if len(lines) < 3 {
		t.Fatalf("expected at least 3 wrapped lines, got %d: %q", len(lines), transcript)
	}

	if lines[0] != "0123456789" {
		t.Errorf("line 0 expected '0123456789', got %q", lines[0])
	}
	if lines[1] != "ABCDEFGHIJ" {
		t.Errorf("line 1 expected 'ABCDEFGHIJ', got %q", lines[1])
	}
	if lines[2] != "KLMNO" {
		t.Errorf("line 2 expected 'KLMNO', got %q", lines[2])
	}
}

func TestVTColorSequencesStripped(t *testing.T) {
	vt := NewVT(80, 24)

	// Standard 16-color, 256-color, 24-bit RGB, bold, underline, invert, reset
	input := "\x1b[31mRed \x1b[1;32mGreenBold \x1b[4;33mUnderlineYellow \x1b[38;5;196m256Color \x1b[38;2;100;200;255mRGBColor \x1b[0mPlain"
	if _, err := vt.Write([]byte(input)); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	expected := "Red GreenBold UnderlineYellow 256Color RGBColor Plain"
	actual := vt.Transcript()
	if actual != expected {
		t.Fatalf("expected color-stripped text %q, got %q", expected, actual)
	}

	if strings.Contains(actual, "\x1b") || strings.Contains(actual, "[31m") || strings.Contains(actual, "[0m") {
		t.Errorf("escape sequences leaked into transcript: %q", actual)
	}
}

func TestVTPartialSequenceAcrossChunks(t *testing.T) {
	vt := NewVT(80, 24)

	// Escape sequence "\x1b[32m" and "\x1b[0m" split across multiple Write calls
	chunk1 := []byte("Result: \x1b[")
	chunk2 := []byte("32")
	chunk3 := []byte("mSUCCESS\x1b")
	chunk4 := []byte("[0m")

	for i, chunk := range [][]byte{chunk1, chunk2, chunk3, chunk4} {
		if _, err := vt.Write(chunk); err != nil {
			t.Fatalf("Write chunk %d failed: %v", i, err)
		}
	}

	expected := "Result: SUCCESS"
	actual := vt.Transcript()
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}

func TestVTGarbageBytes(t *testing.T) {
	vt := NewVT(80, 24)

	// Mix of control characters, malformed escape codes, huge sequence buffer, and normal text
	garbage := []byte{0x01, 0x02, 0x03, 0x05, 0x0e, 0x0f, 0x18, 0x1a, 0x7f}
	vt.Write(garbage)

	// Overflow sequence buffer with garbage digits
	longSeq := "\x1b[" + strings.Repeat("9;", 300) + "m"
	vt.Write([]byte(longSeq))

	// Followed by valid output
	vt.Write([]byte("RecoveredCleanly"))

	actual := vt.Transcript()
	if !strings.Contains(actual, "RecoveredCleanly") {
		t.Fatalf("parser failed to recover after garbage bytes, got: %q", actual)
	}
}

func TestVTTabStops(t *testing.T) {
	vt := NewVT(80, 24)

	vt.Write([]byte("A\tB\tC"))

	actual := vt.Transcript()
	// 'A' at col 0, 'B' at col 8, 'C' at col 16
	if len(actual) < 17 {
		t.Fatalf("expected line of at least 17 chars, got %d: %q", len(actual), actual)
	}

	if actual[0] != 'A' || actual[8] != 'B' || actual[16] != 'C' {
		t.Errorf("tab stops not at 0, 8, 16. Actual: %q", actual)
	}
}

func TestVTOSCSequencesStripped(t *testing.T) {
	vt := NewVT(80, 24)

	// Window title OSC sequences with BEL and ST terminators
	input := "\x1b]0;iamtunnel terminal title\x07Prompt: \x1b]2;Another Title\x1b\\done"
	vt.Write([]byte(input))

	expected := "Prompt: done"
	actual := vt.Transcript()
	if actual != expected {
		t.Fatalf("expected %q, got %q", expected, actual)
	}
}

func TestVTInsertDeleteChars(t *testing.T) {
	vt := NewVT(40, 5)

	// Write "AC", move left, insert 'B' (CSI 1 @)
	vt.Write([]byte("AC\x1b[2G\x1b[1@B"))
	trans := vt.Transcript()
	if trans != "ABC" {
		t.Errorf("insert char failed: expected 'ABC', got %q", trans)
	}

	// Delete 'B' (CSI 1 P)
	vt.Write([]byte("\x1b[2G\x1b[1P"))
	trans2 := vt.Transcript()
	if trans2 != "AC" {
		t.Errorf("delete char failed: expected 'AC', got %q", trans2)
	}
}

func TestVTInsertDeleteLines(t *testing.T) {
	vt := NewVT(40, 5)

	vt.Write([]byte("Line 1\nLine 3"))
	// Move to line 2, insert line (CSI 1 L), write "Line 2"
	vt.Write([]byte("\x1b[2;1H\x1b[1LLine 2"))

	trans := vt.Transcript()
	lines := strings.Split(trans, "\n")
	if len(lines) < 3 || lines[0] != "Line 1" || lines[1] != "Line 2" || lines[2] != "Line 3" {
		t.Fatalf("insert line failed, got:\n%s", trans)
	}

	// Delete line 2 (CSI 1 M)
	vt.Write([]byte("\x1b[2;1H\x1b[1M"))
	trans2 := vt.Transcript()
	lines2 := strings.Split(trans2, "\n")
	if len(lines2) < 2 || lines2[0] != "Line 1" || lines2[1] != "Line 3" {
		t.Fatalf("delete line failed, got:\n%s", trans2)
	}
}

func TestVTResize(t *testing.T) {
	vt := NewVT(80, 24)
	vt.Write([]byte("Testing Resize"))

	vt.Resize(40, 10)
	c, r := vt.Size()
	if c != 40 || r != 10 {
		t.Fatalf("expected size 40x10, got %dx%d", c, r)
	}

	actual := vt.Transcript()
	if actual != "Testing Resize" {
		t.Fatalf("content lost after resize: %q", actual)
	}
}
