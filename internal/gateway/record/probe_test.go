package record

import (
	"strings"
	"testing"
	"time"
)

// The maintainer's own probe. Not part of the delivered suite.
func TestOrchProbeHostile(t *testing.T) {
	cases := []string{
		"\x1b[100M", "\x1b[2000000000M", "\x1b[100L", "\x1b[99999P",
		"\x1b[99999@", "\x1b[99999X", "\x1b[-5A", "\x1b[99999;99999H",
		"\x1b[" + strings.Repeat("9", 40) + "d",
		"\x1b[" + strings.Repeat("1;", 400) + "5m",
		"\x1b]0;" + strings.Repeat("t", 20000),
		"\x1b[" + strings.Repeat("7", 20000) + "m",
	}
	for i, c := range cases {
		v := NewVT(80, 24)
		v.Write([]byte("line0\nline1\nline2\n"))
		v.Write([]byte("\x1b[3;1H"))
		if _, err := v.Write([]byte(c)); err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		v.Flush()
		_ = v.Transcript()
	}
}

func TestOrchProbeNoLeak(t *testing.T) {
	v := NewVT(80, 24)
	v.Write([]byte("\x1b[" + strings.Repeat("7", 20000) + "m" + "OK"))
	v.Flush()
	got := v.Transcript()
	if strings.Contains(got, "7777") {
		t.Fatalf("escape payload leaked into transcript: %q", got[:80])
	}
	if !strings.Contains(got, "OK") {
		t.Fatalf("real text lost: %q", got)
	}
}

func TestOrchProbeBackspace(t *testing.T) {
	v := NewVT(80, 24)
	v.Write([]byte("abc\b\bX"))
	v.Flush()
	if got := strings.TrimRight(v.Transcript(), " \n"); got != "aXc" {
		t.Fatalf("backspace: got %q want %q", got, "aXc")
	}
}

// The maintainer's probe: a LONG-RUNNING live session must survive rotation even
// when a newer completed session is kept. The delivered test is saved by the
// "never empty the archive" rule instead of by the recording guard.
func TestOrchProbeLongLiveSessionSurvives(t *testing.T) {
	tmpDir := t.TempDir()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := NewSimClock(now)

	sLive := createFakeSession(t, tmpDir, "srv1", "u1", "sess-live", now.Add(-3*time.Hour), 15000, "recording")
	createFakeSession(t, tmpDir, "srv1", "u2", "sess-recent", now.Add(-10*time.Minute), 10000, "completed")

	res, err := Rotate(RotateConfig{Dir: tmpDir, MaxTotalBytes: 12000, Clock: clock})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	for _, del := range res.DeletedSessions {
		if del == sLive {
			t.Fatalf("rotation deleted a long-running live session: %s", sLive)
		}
	}
}
