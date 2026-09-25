package record

import "testing"

// TestIAMT215_WriteAfterGrowingResizeDoesNotPanic is the deterministic,
// concurrency-free reproduction of the panic round 4 shipped:
//
//	panic: runtime error: index out of range [24] with length 24
//	record.(*VT).beforeWriteToRow(...) vt.go:782
//	record.(*VT).handleGround(...)     vt.go:268
//
// Round 4 kept its erase bookkeeping in three per-row slices
// (pendingErase/pendingSet/committed) sized to the screen, but Resize
// reallocated only two of them - `committed` kept the OLD row count. Any
// Resize that GREW the screen therefore left `committed` short, and the
// first printable character on a row that only exists after the resize
// indexed past its end. TestRev3ConcurrentHammerNoRace found it because it
// resizes to 24+j%10 rows and sends CSI 999;999H, but nothing about it
// needs concurrency: the two lines below are enough.
//
// This is not a test-only crash. A recorded session reaches the same path
// whenever the person enlarges their terminal: window-change ->
// resizeRecording -> Recorder.Resize -> VT.Resize (human_role.go), and the
// next byte of program output then panics the recorder goroutine.
//
// Round 5 removes the whole class rather than lengthening a slice: the
// per-row arrays are gone, replaced by two scalars (pendingRow/pendingText
// and committedRows), so there is no per-row array left to fall out of step
// with the screen.
//
// Canary: reinstate a per-row array indexed by cursor row in
// beforeWriteToRow without resizing it in Resize and this test panics again
// with the same message.
func TestIAMT215_WriteAfterGrowingResizeDoesNotPanic(t *testing.T) {
	cases := []struct {
		name             string
		cols, rows       int
		newCols, newRows int
		input            string
	}{
		{"grow rows then print at the new bottom", 80, 24, 80, 30, "\x1b[999;999HZ"},
		{"grow rows then erase and print", 80, 24, 80, 40, "\x1b[999;1H\x1b[2Kafter"},
		{"grow both dimensions", 20, 5, 120, 50, "\x1b[999;999Hx"},
		{"shrink then grow past the original", 80, 24, 80, 3, "\x1b[999;1Hy"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("VT panicked after a resize: %v", r)
				}
			}()
			vt := NewVT(tc.cols, tc.rows)
			vt.Resize(tc.newCols, tc.newRows)
			if _, err := vt.Write([]byte(tc.input)); err != nil {
				t.Fatalf("Write failed: %v", err)
			}
			vt.Flush()
			_ = vt.Transcript()
		})
	}
}

// TestIAMT215_PendingAndCommittedFollowTheRows pins the bookkeeping that a
// row-index-keyed state has to get right when the screen moves under it.
// Round 4 kept one flag per row and moved none of them: a Resize left the
// `committed` array the wrong length (see the panic test above), and a
// scroll or a reflow left flags pointing at rows that now held something
// else entirely. Round 5 keeps the state in two scalars instead, so a shift
// is an addition or subtraction on one number - but it still has to happen,
// and these are the cases that catch it not happening.
//
// The shared invariant of every case: content the screen has shown appears
// exactly once, in the order it was shown, with no empty line standing in
// for text that already went to history.
func TestIAMT215_PendingAndCommittedFollowTheRows(t *testing.T) {
	cases := []struct {
		name string
		w, h int
		// steps are applied in order; a resize step is written as
		// resizeW/resizeH being non-zero at that index.
		steps []step
		want  string
	}{
		{
			name:  "a pending erase survives a growing resize",
			w:     80,
			h:     5,
			steps: []step{{write: "keep me\nerased line\x1b[2K"}, {resizeW: 80, resizeH: 10}, {write: "\x1b[Hafter"}},
			want:  "keep me\nerased line\nafter",
		},
		{
			name:  "a pending erase survives a shrinking resize",
			w:     80,
			h:     5,
			steps: []step{{write: "keep me\nerased line\x1b[2K"}, {resizeW: 40, resizeH: 3}, {write: "\x1b[Hafter"}},
			want:  "keep me\nerased line\nafter",
		},
		{
			name:  "a logged prefix is not reflowed back onto the new screen",
			w:     80,
			h:     5,
			steps: []step{{write: "r1\nr2\x1b[2K\nlive"}, {resizeW: 80, resizeH: 8}, {write: "\ntail"}},
			want:  "r1\nr2\nlive\ntail",
		},
		{
			name:  "scrolling a logged prefix off screen adds no empty lines",
			w:     80,
			h:     3,
			steps: []step{{write: "h1\nh2\x1b[2K"}, {write: "\nfill1\nfill2\nfill3\nfill4"}},
			want:  "h1\nh2\nfill1\nfill2\nfill3\nfill4",
		},
		{
			name:  "scroll down moves the logged prefix with the rows",
			w:     80,
			h:     5,
			steps: []step{{write: "s1\ns2\x1b[2K\n"}, {write: "\x1b[2Tlow"}},
			want:  "s1\ns2\nlow",
		},
		{
			name:  "delete line inside the logged prefix keeps live text visible",
			w:     80,
			h:     5,
			steps: []step{{write: "d1\nd2\x1b[2K\nlive"}, {write: "\x1b[1;1H\x1b[1M"}},
			want:  "d1\nd2\nlive",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vt := NewVT(tc.w, tc.h)
			for i, s := range tc.steps {
				if s.resizeH != 0 {
					vt.Resize(s.resizeW, s.resizeH)
					continue
				}
				if _, err := vt.Write([]byte(s.write)); err != nil {
					t.Fatalf("step %d Write failed: %v", i, err)
				}
			}
			vt.Flush()
			if got := vt.Transcript(); got != tc.want {
				t.Errorf("transcript mismatch:\n%s", firstDiff(got, tc.want))
			}
		})
	}
}

type step struct {
	write            string
	resizeW, resizeH int
}
