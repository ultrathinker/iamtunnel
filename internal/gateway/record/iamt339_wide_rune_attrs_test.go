package record

// iamt339_wide_rune_attrs_test.go — a cell is not a rune.
//
// The review of IAMT-339 found this and it is the kind of defect
// that hides for a long time: attributes are stored per CELL, the text
// is built per RUNE, and the two are the same thing right up until a
// double-width character appears. A CJK rune occupies two cells, the
// second holding rune 0 as a trailing-half marker; rowToString skips
// that cell, and the attribute walk originally did not. From the first
// wide rune onward every attribute on the line was shifted by one, so
// the character AFTER a coloured CJK rune was painted in its colour.
//
// Cyrillic would never have shown it — it is single-width. A Russian
// operator watching somebody `cat` a file with Chinese in it would.

import "testing"

// TestIAMT339_AWideRuneDoesNotShiftTheAttributesAfterIt.
//
// Canary: make rowAttrSlice ignore the rune row again (walk `row` alone,
// as it did before the fix) and this goes red on the second rune
// carrying a colour that was explicitly reset before it was printed.
func TestIAMT339_AWideRuneDoesNotShiftTheAttributesAfterIt(t *testing.T) {
	v := NewVT(20, 3)
	// Red, one double-width rune, reset, then a plain ASCII letter.
	v.Write([]byte("\x1b[31m你\x1b[0mX"))
	v.Flush()

	line := v.Screen()[0]
	runes := []rune(line.Text)
	if string(runes) != "你X" {
		t.Fatalf("text = %q, want the wide rune followed by X", line.Text)
	}
	if len(line.Attrs) > len(runes) {
		t.Fatalf("Attrs has %d entries for %d runes — the trailing half-cell of the wide rune is being counted as a rune", len(line.Attrs), len(runes))
	}
	if len(line.Attrs) == 0 {
		t.Fatal("the wide rune lost its colour entirely")
	}
	if line.Attrs[0].FG.Kind == ColorDefault {
		t.Errorf("the wide rune itself is not red: %+v", line.Attrs[0])
	}
	// X was printed after a reset. Either there is no entry for it (the
	// contract's "shorter than Text means default from here") or the
	// entry is the default. Anything else means the shift is back.
	if len(line.Attrs) > 1 && line.Attrs[1] != (Attr{}) {
		t.Errorf("the rune after the double-width character carries %+v, want the default — every attribute after a wide rune is shifted by one, so a renderer paints the wrong characters", line.Attrs[1])
	}
}

// TestIAMT339_TwoWideRunesShiftByTwo is the same defect at the scale
// where it stops being subtle: with several wide runes on a line the
// colours drift further and further from the characters they belong to.
func TestIAMT339_TwoWideRunesShiftByTwo(t *testing.T) {
	v := NewVT(20, 3)
	v.Write([]byte("\x1b[31m你好\x1b[0mab"))
	v.Flush()

	line := v.Screen()[0]
	runes := []rune(line.Text)
	if len(runes) != 4 {
		t.Fatalf("text = %q, want four runes", line.Text)
	}
	if len(line.Attrs) > 4 {
		t.Fatalf("Attrs has %d entries for 4 runes: the two trailing half-cells are being counted", len(line.Attrs))
	}
	for i := 2; i < len(line.Attrs); i++ {
		if line.Attrs[i] != (Attr{}) {
			t.Errorf("rune %d ('%c') carries %+v, want the default: it was printed after the reset", i, runes[i], line.Attrs[i])
		}
	}
}
