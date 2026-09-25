package record

import (
	"strings"
	"testing"
)

// TestIAMT215_SGRAtRightMarginDoesNotEatNextChar is the canary for IAMT-215's
// "progress" corpus finding: on the real corpus session
// (a recorded progress.cast), PSReadLine's syntax-highlighting
// redraw puts an SGR colour change ("\x1b[38;5;15m" / "\x1b[m") exactly at the
// point where a line has just filled the last column (deferred/"pending"
// autowrap, ECMA-48). The parser used to treat ANY escape or CSI byte as a
// reason to drop the pending wrap (handleGround's ESC case, handleEscape's
// and handleCSI's own entry, and executeCSI's top all did `v.wrapPending =
// false` unconditionally). That meant the character immediately following
// such a mid-sequence SGR was written on top of the last cell of the
// already-full line instead of wrapping to column 0 of the next line,
// silently destroying the true last character of that line - reproduced
// here with "$i -le 100" landing exactly on the 80th column: the parser used
// to turn it into "$i -le 10;" (the second "0" of "100" got overwritten by
// the ';' that should have wrapped to the next line).
//
// Canary: reinstate an unconditional `v.wrapPending = false` at the top of
// handleGround's `case 0x1B` (or handleEscape/handleCSI/executeCSI) and this
// test's transcript assertion fails, reproducing exactly the corpus's
// "$i -le 10;" corruption instead of "$i -le 100".
func TestIAMT215_SGRAtRightMarginDoesNotEatNextChar(t *testing.T) {
	vt := NewVT(80, 5)

	// 76 filler columns, then "100" lands on columns 76-78... adjusted so the
	// final '0' of "100" is exactly the 80th (last, 0-indexed 79) column.
	filler := make([]byte, 77)
	for i := range filler {
		filler[i] = 'X'
	}
	if _, err := vt.Write(filler); err != nil {
		t.Fatalf("write filler: %v", err)
	}

	// Exactly what the corpus sends: an SGR right after the line-filling
	// digit, then another SGR, then the next word - reproducing PSReadLine's
	// per-token colour changes.
	seg := "\x1b[38;5;15m100\x1b[m; \x1b[38;5;10m$i\x1b[38;5;8m+=\x1b[38;5;15m10\x1b[m) "
	if _, err := vt.Write([]byte(seg)); err != nil {
		t.Fatalf("write segment: %v", err)
	}

	got := vt.Transcript()
	want := strings.Repeat("X", 77) + "100\n; $i+=10)"
	if got != want {
		t.Fatalf("IAMT-215 canary: SGR at the right margin must not eat the wrapped character; got %q, want %q", got, want)
	}
}
