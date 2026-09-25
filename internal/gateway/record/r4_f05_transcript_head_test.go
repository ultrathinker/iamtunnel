package record

// r4_f05_transcript_head_test.go — R4 F-05.
//
// The .txt transcript was the last 10 000 lines of history: one command
// with a long listing pushed out everything typed before it — exactly the
// case SPEC §6.5 (IAMT-215) promised the transcript would not lose. The
// session's beginning is what an audit reads first. Now the transcript
// keeps the head of the session as well as the tail; only the middle of a
// very long session is left out, a marker says how many lines and where
// the full record is, and .meta carries the count.

import (
	"os"
	"strings"
	"testing"
)

func TestR4F05_TheTranscriptKeepsTheBeginningOfALongSession(t *testing.T) {
	vt := NewVT(80, rev3Rows)
	rev3FeedLines(vt, 0, 25023) // 25 000 lines of history: L00000..L24999
	lines := strings.Split(vt.Transcript(), "\n")
	if len(lines) == 0 || lines[0] != "L00000" {
		t.Fatalf("R4 F-05: the transcript lost the beginning of the session: first line %v, want L00000", firstOf(lines))
	}
	if containsLine(lines, "L12000") {
		t.Fatalf("the middle of the session should be left out, L12000 is still there")
	}
	if !containsLine(lines, "L24999") || !containsLine(lines, "L09999") || !containsLine(lines, "L15000") {
		t.Fatalf("head L09999, tail L15000..L24999 must all be present")
	}
	var marker string
	for i, l := range lines {
		if strings.HasPrefix(l, "[... ") {
			marker = l
			if i == 0 || lines[i-1] != "L09999" || lines[i+1] != "L15000" {
				t.Fatalf("the marker must stand where the lines are missing, between L09999 and L15000; got it at %d", i)
			}
		}
	}
	if !strings.Contains(marker, "5000 lines") || !strings.Contains(marker, ".cast") {
		t.Fatalf("marker %q must count the 5000 missing lines and name the .cast", marker)
	}
	if got := vt.OmittedLines(); got != 5000 {
		t.Fatalf("OmittedLines = %d, want 5000", got)
	}
}

func TestR4F05_MetaCountsTheLinesTheTranscriptLeftOut(t *testing.T) {
	base := t.TempDir()
	rec, err := NewRecorder(SessionConfig{
		BaseDir: base, Machine: "m", Person: "r4f05", SessionID: "r4f05-1",
		Clock: NewSimClock(testBaseTime),
	})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	var sb strings.Builder
	for i := 0; i < 25023; i++ {
		sb.WriteString("L")
		sb.WriteString(strings.Repeat("x", 3))
		sb.WriteString("\r\n")
	}
	if _, err := rec.Write([]byte(sb.String())); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	raw, err := os.ReadFile(rec.Paths().MetaPath)
	if err != nil {
		t.Fatalf("read meta: %v", err)
	}
	if !strings.Contains(string(raw), `"txt_omitted_lines": 5000`) && !strings.Contains(string(raw), `"txt_omitted_lines":5000`) {
		t.Fatalf("R4 F-05: .meta does not say the transcript left 5000 lines out: %s", raw)
	}
}
