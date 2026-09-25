package record

import "testing"

// TestIAMT215_ClearOrderAndInPlaceRedraw pins the scenarios that the
// round-3 "erased text must survive a clear" fix (SPEC §6.5) got wrong.
// Round 3 preserved erased content, but (a) out of order relative to
// still-live text shown earlier on screen, and (b) it preserved every
// intermediate frame of an in-place redraw (progress bar, PSReadLine line
// edit) instead of just the final state. Round 4 fixed both with a deferred
// commit: a whole-row erase is held pending and only written to history if
// the row is still blank when the cursor leaves it, a screen clear arrives,
// or the stream ends; if new text lands in the row first the pending erase
// is discarded as a redraw. Round 5 fixed the remaining ordering hole:
// round 4 swept upward only while rows were non-blank, so a blank separator
// line stopped the sweep and everything above it stayed on screen, printing
// after the erased row that had already gone to history - and the separator
// itself was lost. Commits now always take the whole screen prefix (see
// commitPrefix in vt.go), keeping interior blank lines and dropping only
// leading ones.
//
// Exact string comparison (not strings.Contains) is used throughout: these
// cases are precisely about ORDER, about interior blank lines, and about
// the absence of leaked intermediate frames - none of which
// strings.Contains can detect.
func TestIAMT215_ClearOrderAndInPlaceRedraw(t *testing.T) {
	cases := []struct {
		name  string
		w, h  int
		input string
		want  string
	}{
		{
			name:  "0J erase preserves screen order, not history-then-tail order",
			w:     80,
			h:     5,
			input: "Line 1\nLine 2\nLine 3\x1b[2;1H\x1b[0J",
			want:  "Line 1\nLine 2\nLine 3",
		},
		{
			name:  "EL2 in-place progress redraw shows final frame only",
			w:     80,
			h:     5,
			input: "start\n\r\x1b[2KDownloading 10%\r\x1b[2KDownloading 20%\r\x1b[2KDownloading 30%\r\x1b[2Kdone\nend",
			want:  "start\ndone\nend",
		},
		{
			name:  "EL0 in-place redraw from column 0 shows final frame only",
			w:     80,
			h:     5,
			input: "start\n\r\x1b[KStep 1\r\x1b[KStep 2\r\x1b[KStep 3\r\x1b[Kfinished\nend",
			want:  "start\nfinished\nend",
		},
		{
			name:  "genuine cls-like clear still preserves erased content",
			w:     80,
			h:     5,
			input: "old A\nold B\x1b[H\x1b[K\r\n\x1b[K\x1b[Hnew\nend",
			want:  "old A\nold B\nnew\nend",
		},
		{
			name:  "blank separator line keeps its place and its order (ED 0)",
			w:     80,
			h:     5,
			input: "A1\n\nB1\x1b[3;1H\x1b[0J",
			want:  "A1\n\nB1",
		},
		{
			name:  "blank separator line keeps its place and its order (EL 2)",
			w:     80,
			h:     5,
			input: "A1\n\nB1\x1b[2K\nC1",
			want:  "A1\n\nB1\nC1",
		},
		{
			name:  "ED 2 then a screenful of fresh output, in order",
			w:     80,
			h:     5,
			input: "a1\na2\na3\x1b[2J\x1b[Hb1\nb2\nb3\nb4\nb5\nb6\nb7",
			want:  "a1\na2\na3\nb1\nb2\nb3\nb4\nb5\nb6\nb7",
		},
		{
			name:  "RIS preserves what the screen had shown",
			w:     80,
			h:     5,
			input: "x1\nx2\x1bcy1",
			want:  "x1\nx2\ny1",
		},
		{
			name:  "ED 1 at the right margin erases the cursor row too",
			w:     80,
			h:     5,
			input: "L1\nL2\nL3\x1b[2;80H\x1b[1J",
			want:  "L1\nL2\nL3",
		},
		{
			name:  "EL 2 of a status line the cursor then leaves",
			w:     80,
			h:     5,
			input: "top\nstatus 1\x1b[2K\nafter",
			want:  "top\nstatus 1\nafter",
		},
		{
			name:  "redraw whose last frame is erased commits that last frame",
			w:     80,
			h:     5,
			input: "top\n\r\x1b[KStep 1\r\x1b[KStep 2\r\x1b[K\nafter",
			want:  "top\nStep 2\nafter",
		},
		{
			name:  "redraw repeating identical text collapses to one line",
			w:     80,
			h:     5,
			input: "top\n\r\x1b[2Kwait\r\x1b[2Kwait\r\x1b[2Kwait\nend",
			want:  "top\nwait\nend",
		},
		{
			name:  "clearing an empty screen twice adds nothing",
			w:     80,
			h:     5,
			input: "\x1b[2J\x1b[H\x1b[2J\x1b[Hhello",
			want:  "hello",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vt := NewVT(tc.w, tc.h)
			if _, err := vt.Write([]byte(tc.input)); err != nil {
				t.Fatalf("Write failed: %v", err)
			}
			vt.Flush()
			got := vt.Transcript()
			if got != tc.want {
				t.Errorf("transcript mismatch:\n%s", firstDiff(got, tc.want))
			}
		})
	}
}
