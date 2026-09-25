package export

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"
)

// mustSplit wraps Split with the error reported loudly: every test
// below is about the SHAPE of the parts, and an unexpected refusal
// must stop the test before any shape assertion can pass vacuously.
func mustSplit(t *testing.T, data []byte, limit int) [][]byte {
	t.Helper()
	parts, err := Split(data, limit)
	if err != nil {
		t.Fatalf("Split(%d bytes, limit %d): %v", len(data), limit, err)
	}
	return parts
}

// checkReassembly is the property every cut must keep no matter which
// rule produced it: the parts concatenate back to the input byte for
// byte. It also refuses any part over the limit — the property rule 1
// exists to protect.
func checkReassembly(t *testing.T, data []byte, limit int, parts [][]byte) {
	t.Helper()
	if got, want := len(bytes.Join(parts, nil)), len(data); got != want {
		t.Fatalf("parts reassemble to %d bytes, input is %d", got, want)
	}
	if !bytes.Equal(bytes.Join(parts, nil), data) {
		t.Fatal("parts reassemble to different bytes than the input")
	}
	for i, p := range parts {
		if len(p) > limit {
			t.Fatalf("part %d is %d bytes, over the limit of %d", i+1, len(p), limit)
		}
	}
}

// TestSplitBreaksAtLineBoundaries covers rule 1: lines of 4 bytes, a
// limit that holds exactly two — the part ends right after the second
// '\n', never inside a line. A transcript of complete lines must
// produce parts that all end with '\n'.
func TestSplitBreaksAtLineBoundaries(t *testing.T) {
	const in = "aaa\nbbb\nccc\n"
	parts := mustSplit(t, []byte(in), 8)
	if len(parts) != 2 {
		t.Fatalf("got %d parts, want 2: %q", len(parts), parts)
	}
	if string(parts[0]) != "aaa\nbbb\n" {
		t.Fatalf("part 1 = %q, want %q — the break must fall right after a newline", parts[0], "aaa\nbbb\n")
	}
	if string(parts[1]) != "ccc\n" {
		t.Fatalf("part 2 = %q, want %q", parts[1], "ccc\n")
	}
	for i, p := range parts {
		if !bytes.HasSuffix(p, []byte("\n")) {
			t.Fatalf("part %d ends mid-line: %q does not end with a newline", i+1, p)
		}
	}
	checkReassembly(t, []byte(in), 8, parts)
}

// TestSplitExactLimitHoldsOnePart covers the threshold at its exact
// boundary: input of exactly limit bytes fits in one part; one byte
// more (a third line) forces a second part, and no part ever exceeds
// the limit. The off-by-one here — >= instead of > — is the classic
// silent break.
func TestSplitExactLimitHoldsOnePart(t *testing.T) {
	const twoLines = "aaaa\nbbbb\n" // exactly 10 bytes
	parts := mustSplit(t, []byte(twoLines), 10)
	if len(parts) != 1 {
		t.Fatalf("input of exactly the limit must hold in one part, got %d: %q", len(parts), parts)
	}
	parts = mustSplit(t, []byte(twoLines), 9)
	if len(parts) != 2 {
		t.Fatalf("input one byte over the limit must split, got %d parts: %q", len(parts), parts)
	}
	checkReassembly(t, []byte(twoLines), 9, parts)
}

// TestSplitDefaultLimitIsFiveMegabytes covers the named constant at
// its real value: exactly DefaultPartLimit bytes is one part;
// DefaultPartLimit+2 forces a second part while the first part stays
// at exactly DefaultPartLimit bytes.
func TestSplitDefaultLimitIsFiveMegabytes(t *testing.T) {
	line := string(bytes.Repeat([]byte("x"), DefaultPartLimit-1)) + "\n" // exactly DefaultPartLimit bytes
	parts := mustSplit(t, []byte(line), 0)                               // 0 — the default limit
	if len(parts) != 1 {
		t.Fatalf("exactly %d bytes must hold in one part, got %d", DefaultPartLimit, len(parts))
	}
	oneMore := line + "y\n"
	parts = mustSplit(t, []byte(oneMore), 0)
	if len(parts) != 2 {
		t.Fatalf("DefaultPartLimit+2 bytes must split into 2 parts, got %d", len(parts))
	}
	if len(parts[0]) != DefaultPartLimit {
		t.Fatalf("first part is %d bytes, want exactly %d", len(parts[0]), DefaultPartLimit)
	}
	checkReassembly(t, []byte(oneMore), DefaultPartLimit, parts)
}

// TestSplitKeepsMultibyteRunesWhole covers rule 2: the naive cut at
// byte 7 would land in the middle of the 4th Cyrillic rune (each rune
// is two bytes; the limit is odd ON PURPOSE — an even limit would let
// the byte cut coincide with a rune boundary and the test would pass
// with the walk-back removed); the part boundary must step back to the
// rune start, so every part stays valid UTF-8.
func TestSplitKeepsMultibyteRunesWhole(t *testing.T) {
	in := strings.Repeat("\u0430", 5) + "\n" // 10 bytes of runes + newline = 11 > limit
	parts := mustSplit(t, []byte(in), 7)
	if len(parts) < 2 {
		t.Fatalf("the line does not fit in one part, got %d part(s)", len(parts))
	}
	for i, p := range parts {
		if !utf8.Valid(p) {
			t.Fatalf("part %d tears a rune: %q is not valid UTF-8", i+1, p)
		}
	}
	checkReassembly(t, []byte(in), 7, parts)
}

// TestSplitCutsOverlongLineAtRunes covers rule 3: one line longer
// than the limit (cat on a binary) is cut into pieces, and the cut is
// VISIBLE — a part ends without a newline, the signature a reader of
// the text files sees.
func TestSplitCutsOverlongLineAtRunes(t *testing.T) {
	const in = "abcdefghij\n" // one 10-byte line, limit 8
	parts := mustSplit(t, []byte(in), 8)
	if len(parts) != 2 {
		t.Fatalf("a line over the limit must be cut, got %d part(s): %q", len(parts), parts)
	}
	if string(parts[0]) != "abcdefgh" {
		t.Fatalf("part 1 = %q, want the first %d bytes of the line", parts[0], 8)
	}
	if bytes.HasSuffix(parts[0], []byte("\n")) {
		t.Fatal("the overlong-line cut must be visible: part 1 must not end with a newline")
	}
	if string(parts[1]) != "ij\n" {
		t.Fatalf("part 2 = %q, want %q", parts[1], "ij\n")
	}
	checkReassembly(t, []byte(in), 8, parts)
}

// TestSplitMangledBinaryStillMakesProgress covers the defensive branch
// of runeSafeCut: a run of bare continuation bytes offers no rune
// boundary, the cut falls after the first byte, and — the regression
// this test exists for — the splitter never loops forever on it.
func TestSplitMangledBinaryStillMakesProgress(t *testing.T) {
	in := []byte{'a', 0x80, 0x80, 0x80, 0x80, 'b', '\n'}
	parts := mustSplit(t, in, MinPartLimit)
	checkReassembly(t, in, MinPartLimit, parts)
	if len(parts) < 2 {
		t.Fatalf("7 bytes at limit %d must be cut, got %d part(s)", MinPartLimit, len(parts))
	}
}

// TestSplitEmptyTranscriptIsOneEmptyPart covers the documented choice:
// an empty transcript exports as exactly one EMPTY part, not as no
// parts at all — the layout promises a 0001.txt.
func TestSplitEmptyTranscriptIsOneEmptyPart(t *testing.T) {
	parts := mustSplit(t, nil, 8)
	if len(parts) != 1 {
		t.Fatalf("empty transcript must give exactly one part, got %d", len(parts))
	}
	if len(parts[0]) != 0 {
		t.Fatalf("the part must be empty, got %d bytes", len(parts[0]))
	}
}

// TestSplitRefusesLimitBelowRuneMaximum covers the floor: a limit
// below utf8.UTFMax cannot guarantee progress of the rune-safe cut
// and must be refused, not silently accepted.
func TestSplitRefusesLimitBelowRuneMaximum(t *testing.T) {
	if _, err := Split([]byte("x\n"), MinPartLimit-1); err == nil {
		t.Fatal("a limit below utf8.UTFMax must be refused")
	}
}

// TestSplitRefusesBeyondFourDigits covers the numbering guard: more
// than maxParts parts would sort 0010 before 0002, so Split must
// refuse rather than silently break lexicographic order. The limit is
// MinPartLimit (not something smaller) so the refusal is really the
// part-count guard, not the rune-floor check; two lines of "x\n" fill
// one part at that limit.
func TestSplitRefusesBeyondFourDigits(t *testing.T) {
	// At MinPartLimit (four bytes) a part holds exactly two "x\n" lines,
	// so N lines make ceil(N/2) parts. The first version of this test
	// used 2*maxParts lines and called them "10000 full parts" - that is
	// 9999 parts, one short of the guard, and it went red against correct
	// code the first time it was ever run.
	over := bytes.Repeat([]byte("x\n"), 2*(maxParts+1)) // maxParts+1 parts
	if _, err := Split(over, MinPartLimit); err == nil {
		t.Fatalf("more than %d parts must be refused: the zero-padded numbering would stop sorting", maxParts)
	}
	fits := bytes.Repeat([]byte("x\n"), 2*maxParts) // exactly maxParts parts
	if parts, err := Split(fits, MinPartLimit); err != nil {
		t.Fatalf("exactly %d parts must still be allowed: %v", maxParts, err)
	} else if len(parts) != maxParts {
		t.Fatalf("the boundary case split into %d parts, want exactly %d - the test aims at the wrong number and would pass for the wrong reason", len(parts), maxParts)
	}
}
