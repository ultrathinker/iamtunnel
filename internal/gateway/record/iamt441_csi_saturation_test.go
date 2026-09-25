package record

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

// IAMT-441. A CSI parameter is whatever number the machine printed, up to
// math.MaxInt: parseParams clamps only a number that does not fit in an int
// at all. The cursor moves added that parameter to the cursor coordinate,
// the sum wrapped to a negative number, min() kept the negative, and the
// next printable character indexed the screen at -9223372036854775808. The
// panic happened in the bridge goroutine and took the gateway down, and
// every session on it, from one command in any shell:
//
//	printf 'A\033[9223372036854775807CX'
//
// The review that read exactly this code called it safe. These tests are
// the answer to that: every cursor operation that combines a parameter with
// a coordinate, at the int limits and their neighbours, in one chunk and
// byte by byte, must keep 0 <= x < cols and 0 <= y < rows and land where a
// terminal would put it.

var (
	iamt441Max  = strconv.Itoa(math.MaxInt)
	iamt441Max1 = strconv.Itoa(math.MaxInt - 1)
	iamt441Min  = strconv.Itoa(math.MinInt)
	iamt441Min1 = strconv.Itoa(math.MinInt + 1)
	// Does not fit in an int: parseParams clamps it to 1000000.
	iamt441Huge = "99999999999999999999999"
)

// iamt441Write feeds s and returns what the VT panicked with, if anything,
// so that a panic is reported on the test's own line instead of killing the
// test binary before any assertion runs.
func iamt441Write(v *VT, s string) (panicked any) {
	defer func() { panicked = recover() }()
	_, _ = v.Write([]byte(s))
	return nil
}

func TestIAMT441_CursorMovesStayOnScreenAtIntLimits(t *testing.T) {
	const cols, rows = 80, 24
	cases := []struct {
		name         string
		fromX, fromY int
		seq          string
		wantX, wantY int
	}{
		{"CUF MaxInt from column 1, the reported crash", 1, 0, "\x1b[" + iamt441Max + "C", 79, 0},
		{"CUF MaxInt-1 from column 2", 2, 0, "\x1b[" + iamt441Max1 + "C", 79, 0},
		{"CUF MaxInt from the last column", 79, 0, "\x1b[" + iamt441Max + "C", 79, 0},
		{"CUF MaxInt from column 0", 0, 0, "\x1b[" + iamt441Max + "C", 79, 0},
		{"CUF with a parameter too big for int", 1, 0, "\x1b[" + iamt441Huge + "C", 79, 0},
		{"CUF MinInt is a one-column move", 1, 0, "\x1b[" + iamt441Min + "C", 2, 0},
		{"CUD MaxInt from row 1", 0, 1, "\x1b[" + iamt441Max + "B", 0, 23},
		{"CUD MaxInt-1 from row 2", 3, 2, "\x1b[" + iamt441Max1 + "B", 3, 23},
		{"CUD MaxInt from the last row", 3, 23, "\x1b[" + iamt441Max + "B", 3, 23},
		{"CUD MinInt is a one-row move", 3, 2, "\x1b[" + iamt441Min + "B", 3, 3},
		{"CNL MaxInt from row 1", 5, 1, "\x1b[" + iamt441Max + "E", 0, 23},
		{"CNL MaxInt-1 from row 2", 5, 2, "\x1b[" + iamt441Max1 + "E", 0, 23},
		{"CNL MinInt is a one-line move", 5, 1, "\x1b[" + iamt441Min + "E", 0, 2},
		{"CUU MaxInt", 3, 5, "\x1b[" + iamt441Max + "A", 3, 0},
		{"CUU MinInt+1 is a one-row move", 3, 5, "\x1b[" + iamt441Min1 + "A", 3, 4},
		{"CUB MaxInt", 3, 5, "\x1b[" + iamt441Max + "D", 0, 5},
		{"CUB MinInt is a one-column move", 3, 5, "\x1b[" + iamt441Min + "D", 2, 5},
		{"CPL MaxInt", 3, 5, "\x1b[" + iamt441Max + "F", 0, 0},
		{"CHA MinInt goes to the first column", 10, 3, "\x1b[" + iamt441Min + "G", 0, 3},
		{"CHA MinInt+1 goes to the first column", 10, 3, "\x1b[" + iamt441Min1 + "G", 0, 3},
		{"CHA MaxInt goes to the last column", 10, 3, "\x1b[" + iamt441Max + "G", 79, 3},
		{"CUP MinInt;MinInt goes home", 10, 3, "\x1b[" + iamt441Min + ";" + iamt441Min + "H", 0, 0},
		{"CUP MaxInt;MaxInt goes to the far corner", 10, 3, "\x1b[" + iamt441Max + ";" + iamt441Max + "H", 79, 23},
		{"HVP MinInt;MaxInt goes to the top right", 10, 3, "\x1b[" + iamt441Min + ";" + iamt441Max + "f", 79, 0},
		{"VPA MinInt goes to the first row", 10, 3, "\x1b[" + iamt441Min + "d", 10, 0},
		{"VPA MaxInt goes to the last row", 10, 3, "\x1b[" + iamt441Max + "d", 10, 23},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewVT(cols, rows)
			if p := iamt441Write(v, fmt.Sprintf("\x1b[%d;%dH", tc.fromY+1, tc.fromX+1)); p != nil {
				t.Fatalf("placing the cursor panicked: %v", p)
			}
			if x, y := v.Cursor(); x != tc.fromX || y != tc.fromY {
				t.Fatalf("setup: the cursor is at (%d,%d), want (%d,%d)", x, y, tc.fromX, tc.fromY)
			}
			if p := iamt441Write(v, tc.seq); p != nil {
				t.Fatalf("%q panicked: %v", tc.seq, p)
			}
			x, y := v.Cursor()
			if x < 0 || x >= cols || y < 0 || y >= rows {
				t.Errorf("%q left the cursor off the %dx%d screen, at (%d,%d)", tc.seq, cols, rows, x, y)
			}
			if x != tc.wantX || y != tc.wantY {
				t.Errorf("%q moved the cursor to (%d,%d), want (%d,%d)", tc.seq, x, y, tc.wantX, tc.wantY)
			}
			// The printable character after the move is what used the
			// wrapped coordinate as a screen index.
			if p := iamt441Write(v, "X"); p != nil {
				t.Fatalf("printing after %q panicked: %v", tc.seq, p)
			}
		})
	}
}

// Erase Character adds its count to the cursor column to find where the
// erase ends. The wrapped sum did not panic - it made the loop condition
// false at once - so ECH with a huge count erased nothing at all instead of
// the rest of the line.
func TestIAMT441_EraseCharsAtIntLimitsErasesToTheEndOfTheLine(t *testing.T) {
	cases := []struct {
		name string
		col  int // 1-based column the erase starts at
		n    string
		want string
	}{
		{"ECH MaxInt from column 2", 2, iamt441Max, "A"},
		{"ECH MaxInt-1 from column 3", 3, iamt441Max1, "AB"},
		{"ECH MaxInt-1 from column 2", 2, iamt441Max1, "A"},
		{"ECH too big for int from column 2", 2, iamt441Huge, "A"},
		{"ECH MinInt erases nothing", 2, iamt441Min, "ABCDEF"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := NewVT(80, 24)
			seq := "ABCDEF\x1b[" + strconv.Itoa(tc.col) + "G\x1b[" + tc.n + "X"
			if p := iamt441Write(v, seq); p != nil {
				t.Fatalf("%q panicked: %v", seq, p)
			}
			if got := v.Screen()[0].Text; got != tc.want {
				t.Errorf("row 0 after %q is %q, want %q", seq, got, tc.want)
			}
		})
	}
}

// iamt441Hostile is every limit case in one stream, with a printable
// character after each move so that a wrapped coordinate is used at once.
func iamt441Hostile() string {
	var b strings.Builder
	b.WriteString("A")
	for _, n := range []string{iamt441Max, iamt441Max1, iamt441Min, iamt441Min1, iamt441Huge, "0", "1", "-1"} {
		for _, cmd := range "ABCDEFGHfdXLMP@STJK" {
			b.WriteString("\x1b[" + n + string(cmd) + "x")
		}
		b.WriteString("\x1b[" + n + ";" + n + "Hy\x1b[" + n + ";" + n + "fz")
	}
	return b.String()
}

// A terminal stream arrives in pieces the machine did not choose; the VT
// keeps its parser state across Writes. Feeding the hostile stream one byte
// at a time must hold the invariant after every byte and end exactly where
// the one-chunk feed ends.
func TestIAMT441_ByteByByteFeedKeepsTheInvariantAndMatchesOneChunk(t *testing.T) {
	const cols, rows = 80, 24
	stream := iamt441Hostile()

	whole := NewVT(cols, rows)
	if p := iamt441Write(whole, stream); p != nil {
		t.Fatalf("the hostile stream in one chunk panicked: %v", p)
	}

	split := NewVT(cols, rows)
	for i := 0; i < len(stream); i++ {
		if p := iamt441Write(split, stream[i:i+1]); p != nil {
			t.Fatalf("byte %d (%q) panicked: %v", i, stream[i], p)
		}
		if x, y := split.Cursor(); x < 0 || x >= cols || y < 0 || y >= rows {
			t.Fatalf("after byte %d (%q) the cursor is off the %dx%d screen, at (%d,%d)", i, stream[i], cols, rows, x, y)
		}
	}

	wx, wy := whole.Cursor()
	sx, sy := split.Cursor()
	if wx != sx || wy != sy {
		t.Errorf("the cursor ends at (%d,%d) fed whole and at (%d,%d) fed byte by byte", wx, wy, sx, sy)
	}
	if w, s := whole.Transcript(), split.Transcript(); w != s {
		t.Errorf("the transcript differs between one chunk and byte by byte:\nwhole: %q\nsplit: %q", w, s)
	}
}

// FuzzIAMT441_VT holds the VT to its invariant on any input at all: no
// panic, and the cursor inside the screen after every Write, whether the
// bytes come in one chunk or one at a time, on a screen as small as 1x1.
// The seeds are the limit cases above; a plain `go test` runs them, and
//
//	go test -run '^$' -fuzz FuzzIAMT441_VT ./internal/gateway/record
//
// searches further.
func FuzzIAMT441_VT(f *testing.F) {
	f.Add([]byte("A\x1b[" + iamt441Max + "CX"))
	f.Add([]byte(iamt441Hostile()))
	for _, n := range []string{iamt441Max, iamt441Max1, iamt441Min, iamt441Min1, iamt441Huge} {
		for _, cmd := range "ABCDEFGHfdXLMP@STJK" {
			f.Add([]byte("AB\r\n\x1b[" + n + string(cmd) + "Z"))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, size := range [][2]int{{1, 1}, {3, 2}, {80, 24}} {
			cols, rows := size[0], size[1]

			whole := NewVT(cols, rows)
			if p := iamt441Write(whole, string(data)); p != nil {
				t.Fatalf("%dx%d: %q in one chunk panicked: %v", cols, rows, data, p)
			}
			if x, y := whole.Cursor(); x < 0 || x >= cols || y < 0 || y >= rows {
				t.Fatalf("%dx%d: %q left the cursor off the screen, at (%d,%d)", cols, rows, data, x, y)
			}

			split := NewVT(cols, rows)
			for i := range data {
				if p := iamt441Write(split, string(data[i:i+1])); p != nil {
					t.Fatalf("%dx%d: byte %d of %q panicked: %v", cols, rows, i, data, p)
				}
				if x, y := split.Cursor(); x < 0 || x >= cols || y < 0 || y >= rows {
					t.Fatalf("%dx%d: after byte %d of %q the cursor is off the screen, at (%d,%d)", cols, rows, i, data, x, y)
				}
			}

			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("%dx%d: reading the result of %q panicked: %v", cols, rows, data, p)
					}
				}()
				split.Flush()
				_ = split.Transcript()
				_ = split.Screen()
			}()
		}
	})
}
