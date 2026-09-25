package export

import (
	"bytes"
	"testing"
	"unicode/utf8"
)

// Canary: one line longer than a whole part, made of multi-byte runes
// only. Every cut must land on a rune boundary, and every piece must be
// valid UTF-8 on its own - a part file is opened by a human in a text
// editor, and a torn rune shows up as a replacement character right
// where the interesting output was.
func TestCanary_NoCutTearsARune(t *testing.T) {
	line := bytes.Repeat([]byte("\u044f"), 500) // 1000 bytes of Cyrillic U+044F
	parts, err := Split(append(line, '\n'), 7)  // 7 is not a multiple of 2
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(parts) < 2 {
		t.Fatalf("the fixture did not split at all: %d parts", len(parts))
	}
	for i, p := range parts {
		if !utf8.Valid(p) {
			t.Fatalf("part %d is not valid UTF-8 on its own: %q", i+1, p)
		}
	}
	if got := bytes.Join(parts, nil); !bytes.Equal(got, append(line, '\n')) {
		t.Fatalf("the parts do not rejoin into the original: %d bytes vs %d", len(got), len(line)+1)
	}
}
