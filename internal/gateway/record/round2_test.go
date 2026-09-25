package record

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -----------------------------------------------------------------------------
// DEFECT 1: Panic in deleteLines and parameter boundary handling
// -----------------------------------------------------------------------------

func TestHostileOutputMustNotPanic(t *testing.T) {
	probes := []struct {
		name  string
		input string
	}{
		{"deleteLines-100M", "\x1b[100M"},
		{"deleteLines-2e9", "\x1b[2000000000M"},
		{"deleteLines-ls-prefix", "ls -la\r\n\x1b[99M"},
		{"insertLines-100L", "\x1b[100L"},
		{"deleteChars-100P", "\x1b[100P"},
		{"insertChars-100@", "\x1b[100@"},
		{"eraseChars-100X", "\x1b[100X"},
		{"scrollUp-100S", "\x1b[100S"},
		{"scrollDown-100T", "\x1b[100T"},
	}

	for _, tc := range probes {
		t.Run(tc.name, func(t *testing.T) {
			vt := NewVT(80, 24)
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("VT panicked on %s: %v", tc.name, r)
				}
			}()
			_, err := vt.Write([]byte(tc.input))
			if err != nil {
				t.Fatalf("unexpected write error: %v", err)
			}
		})
	}

	// Also verify live via Recorder
	tmpDir := t.TempDir()
	rec, err := NewRecorder(SessionConfig{
		BaseDir:   tmpDir,
		Person:    "tester",
		Machine:   "srv",
		SessionID: "hostile-output",
		Cols:      80,
		Rows:      24,
	})
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}
	defer rec.Close()

	for _, tc := range probes {
		if _, err := rec.Write([]byte(tc.input)); err != nil {
			t.Fatalf("rec.Write failed on %s: %v", tc.name, err)
		}
	}
}

// Gate 3: Test-fuzzer running EVERY supported sequence with 6 parameter types:
// 0, 1, screen size, screen size + 1, very large number, and negative value.
func TestAllCSICommandsWithExtremeParams(t *testing.T) {
	commands := []rune{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'f', 'd',
		'J', 'K', 'L', 'M', 'P', '@', 'X', 'S', 'T', 's', 'u',
	}

	paramTypes := []struct {
		name  string
		param string
	}{
		{"zero", "0"},
		{"one", "1"},
		{"screen-size-row", "24"},
		{"screen-size-col", "80"},
		{"screen-size-plus-one-row", "25"},
		{"screen-size-plus-one-col", "81"},
		{"very-large-int", "2000000000"},
		{"huge-20-digits", "99999999999999999999"},
		{"negative-int", "-5"},
	}

	for _, cmd := range commands {
		for _, pt := range paramTypes {
			name := fmt.Sprintf("cmd_%c_%s", cmd, pt.name)
			t.Run(name, func(t *testing.T) {
				vt := NewVT(80, 24)
				// Put some sample text on screen so operations have cells to manipulate
				vt.Write([]byte("Line 1: Sample text to delete or move\r\nLine 2: Second line of text\r\nLine 3: Third line"))

				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("VT panicked on cmd '%c' with param %s: %v", cmd, pt.param, r)
					}
				}()

				seq := fmt.Sprintf("\x1b[%s%c", pt.param, cmd)
				_, _ = vt.Write([]byte(seq))

				// Two-parameter variant for H and f
				if cmd == 'H' || cmd == 'f' {
					seq2 := fmt.Sprintf("\x1b[%s;%s%c", pt.param, pt.param, cmd)
					_, _ = vt.Write([]byte(seq2))
				}
			})
		}
	}
}

// -----------------------------------------------------------------------------
// DEFECT 2: Rotation must not delete live session & cannot wipe entire archive
// -----------------------------------------------------------------------------

func TestRotationMustNotDeleteLiveSession(t *testing.T) {
	tmpDir := t.TempDir()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := NewSimClock(now)

	// Each fake session has .cast + .txt + .meta, so sizePerFile=5000 creates ~10.3 KB per session.
	// Total archive size for 3 sessions is ~30.9 KB.
	// sLive: long-running session actively recording right now (~10.3 KB, started 4 hours ago - OLDEST session)
	sLive := createFakeSession(t, tmpDir, "srv1", "u1", "sess-live", now.Add(-4*time.Hour), 5000, "recording")
	// sOldCompleted: completed 2 hours ago (~10.3 KB)
	sOldCompleted := createFakeSession(t, tmpDir, "srv1", "u2", "sess-old-comp", now.Add(-2*time.Hour), 5000, "completed")
	// sRecentCompleted: completed 10 minutes ago (~10.3 KB)
	sRecentCompleted := createFakeSession(t, tmpDir, "srv1", "u3", "sess-recent-comp", now.Add(-10*time.Minute), 5000, "completed")

	// Limit is 25 KB (total = ~30.9 KB).
	// Under protection: sLive (~10.3 KB) is protected. sOldCompleted (~10.3 KB) is deleted (leaving ~20.6 KB <= 25 KB).
	// sRecentCompleted (~10.3 KB) is kept.
	// CRITICAL INVARIANT: sLive is the OLDEST session in the entire archive.
	// If the "recording" protection is removed, sLive is candidate #0 and is deleted first (30.9 KB - 10.3 KB = 20.6 KB <= 25 KB),
	// leaving both completed sessions intact and proving that the "never empty archive" rule cannot save sLive.
	cfg := RotateConfig{
		Dir:           tmpDir,
		MaxTotalBytes: 25000,
		Clock:         clock,
	}

	res, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	// sLive must NEVER be deleted
	for _, del := range res.DeletedSessions {
		if del == sLive {
			t.Fatalf("CRITICAL REGRESSION: rotation deleted live active session: %s", sLive)
		}
	}

	if _, err := os.Stat(sLive + ".cast"); err != nil {
		t.Fatalf("sLive .cast must remain on disk: %v", err)
	}
	if _, err := os.Stat(sLive + ".meta"); err != nil {
		t.Fatalf("sLive .meta must remain on disk: %v", err)
	}

	// sOldCompleted should be deleted to free space
	if len(res.DeletedSessions) != 1 || res.DeletedSessions[0] != sOldCompleted {
		t.Errorf("expected sOldCompleted deleted, got: %+v", res.DeletedSessions)
	}

	// sRecentCompleted should remain
	if _, err := os.Stat(sRecentCompleted + ".cast"); err != nil {
		t.Fatalf("sRecentCompleted must remain on disk: %v", err)
	}
}

func TestRotationCannotDeleteEverything(t *testing.T) {
	tmpDir := t.TempDir()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := NewSimClock(now)

	// 4 regular completed sessions of 5 KB each
	s1 := createFakeSession(t, tmpDir, "srv1", "u1", "norm-1", now.Add(-5*time.Hour), 5000, "completed")
	s2 := createFakeSession(t, tmpDir, "srv1", "u2", "norm-2", now.Add(-4*time.Hour), 5000, "completed")
	s3 := createFakeSession(t, tmpDir, "srv1", "u3", "norm-3", now.Add(-3*time.Hour), 5000, "completed")
	s4 := createFakeSession(t, tmpDir, "srv1", "u4", "norm-4", now.Add(-2*time.Hour), 5000, "completed")
	// 1 big completed session of 50 KB
	sBig := createFakeSession(t, tmpDir, "srv1", "u5", "big-session", now.Add(-1*time.Hour), 50000, "completed")

	// Limit is 15 KB (smaller than sBig alone); the archive must retain its newest session.
	cfg := RotateConfig{
		Dir:           tmpDir,
		MaxTotalBytes: 15000,
		Clock:         clock,
	}

	res, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	// 4 older sessions should be deleted, but the newest session MUST NOT be deleted!
	// The archive must NOT be wiped to 0!
	if res.RemainingSessions < 1 {
		t.Fatalf("rotation wiped entire archive to 0! RemainingSessions=%d", res.RemainingSessions)
	}
	if !res.OversizedSingleSession {
		t.Errorf("expected OversizedSingleSession to be true")
	}

	if _, err := os.Stat(sBig + ".cast"); err != nil {
		t.Errorf("sBig should have been preserved: %v", err)
	}

	// Verify s1..s4 deleted
	for _, s := range []string{s1, s2, s3, s4} {
		if _, err := os.Stat(s + ".cast"); !os.IsNotExist(err) {
			t.Errorf("expected %s deleted", s)
		}
	}
}

// -----------------------------------------------------------------------------
// DEFECT 3: Rotation must stay inside its configured directory
// -----------------------------------------------------------------------------

func TestRotationMustStayInsideItsDir(t *testing.T) {
	baseDir := t.TempDir()

	// Build directory hierarchy: baseDir/parent/recordings/srv/date/session.*
	parentDir := filepath.Join(baseDir, "parent")
	recordingsDir := filepath.Join(parentDir, "recordings")
	sessionDir := filepath.Join(recordingsDir, "srv", "2026-09-12")
	if err := os.MkdirAll(sessionDir, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	sessionBase := filepath.Join(sessionDir, "120000-user-sess")
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := NewSimClock(now)

	// Create completed session files
	_ = os.WriteFile(sessionBase+".cast", []byte("header\n"), 0644)
	_ = os.WriteFile(sessionBase+".txt", []byte("transcript\n"), 0644)
	meta := Metadata{
		StartedAt: now.Add(-10 * time.Hour),
		Status:    "completed",
	}
	_ = WriteMeta(sessionBase+".meta", meta, 0644)

	cfg := RotateConfig{
		Dir:    recordingsDir, // Configured root is recordingsDir
		MaxAge: 1 * time.Hour, // Expire the session
		Clock:  clock,
	}

	res, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	if len(res.DeletedSessions) != 1 {
		t.Fatalf("expected 1 deleted session, got: %d", len(res.DeletedSessions))
	}

	// Check that empty subdirectories inside recordingsDir are removed
	if _, err := os.Stat(sessionDir); !os.IsNotExist(err) {
		t.Errorf("empty sessionDir %s should have been removed", sessionDir)
	}

	// CRITICAL INVARIANT: recordingsDir ITSELF MUST NOT BE REMOVED!
	if _, err := os.Stat(recordingsDir); os.IsNotExist(err) {
		t.Fatalf("CRITICAL: rotation removed its own configured root directory %s!", recordingsDir)
	}

	// CRITICAL INVARIANT: parentDir MUST NOT BE REMOVED!
	if _, err := os.Stat(parentDir); os.IsNotExist(err) {
		t.Fatalf("CRITICAL: rotation climbed ABOVE its configured root and removed %s!", parentDir)
	}

	// baseDir MUST NOT BE REMOVED!
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		t.Fatalf("CRITICAL: rotation climbed ABOVE and removed baseDir %s!", baseDir)
	}
}

// -----------------------------------------------------------------------------
// DEFECT 4: Transcript loses characters (2 examples: backspace & right-margin/DL)
// -----------------------------------------------------------------------------

func TestTranscriptMustNotLoseCharacters(t *testing.T) {
	// Example 1: Backspace as non-destructive motion
	t.Run("Example1_BackspaceNonDestructive", func(t *testing.T) {
		vt1 := NewVT(80, 24)
		vt1.Write([]byte("abc\b\bX"))
		got1 := vt1.Transcript()
		if got1 != "aXc" {
			t.Errorf("abc\\b\\bX: got %q, want %q", got1, "aXc")
		}

		vt2 := NewVT(80, 24)
		vt2.Write([]byte("abcdef\x1b[3G\b\bQ"))
		got2 := vt2.Transcript()
		if got2 != "Qbcdef" {
			t.Errorf("abcdef\\x1b[3G\\b\\bQ: got %q, want %q", got2, "Qbcdef")
		}
	})

	// Example 2: Right-margin wrap operations and mid-screen delete lines
	t.Run("Example2_RightMarginAndMidScreenDL", func(t *testing.T) {
		// Right-margin operation: cols=10, 10 characters + EL (erase line from cursor)
		vt1 := NewVT(10, 5)
		vt1.Write([]byte("0123456789\x1b[K"))
		got1 := vt1.Transcript()
		if got1 != "012345678" {
			t.Errorf("right margin EL: got %q, want %q", got1, "012345678")
		}

		// Delete lines from middle of screen: 6 rows, cursor on row 5 (1-based), delete 4 lines
		vt2 := NewVT(80, 6)
		vt2.Write([]byte("r0\nr1\nr2\nr3\nr4\nr5\x1b[5;1H\x1b[4M"))
		got2 := vt2.Transcript()
		want2 := "r0\nr1\nr2\nr3"
		if got2 != want2 {
			t.Errorf("mid-screen deleteLines: got %q, want %q", got2, want2)
		}
	})
}

// -----------------------------------------------------------------------------
// DEFECT 5: Transcript adds non-screen data (2 examples: buffer overflow & invalid/DEL)
// -----------------------------------------------------------------------------

func TestNoEscapeDataLeaksIntoTranscript(t *testing.T) {
	// Example 1: Sequence buffer overflow (OSC, CSI, never-terminated CSI)
	t.Run("Example1_BufferOverflowMustNotLeak", func(t *testing.T) {
		// Overlong OSC (600 bytes)
		vt1 := NewVT(80, 24)
		overlongOSC := "\x1b]0;" + strings.Repeat("T", 600) + "\x07CleanOutput"
		vt1.Write([]byte(overlongOSC))
		got1 := vt1.Transcript()
		if strings.Contains(got1, "TTT") {
			t.Errorf("overlong OSC leaked into transcript: %q", got1)
		}
		if got1 != "CleanOutput" {
			t.Errorf("got %q, want %q", got1, "CleanOutput")
		}

		// Overlong CSI (800 bytes of params)
		vt2 := NewVT(80, 24)
		overlongCSI := "\x1b[" + strings.Repeat("1;", 400) + "mCleanCSI"
		vt2.Write([]byte(overlongCSI))
		got2 := vt2.Transcript()
		if strings.Contains(got2, "1;") {
			t.Errorf("overlong CSI leaked into transcript: %q", got2)
		}
		if got2 != "CleanCSI" {
			t.Errorf("got %q, want %q", got2, "CleanCSI")
		}

		// 10 KB unclosed CSI parameter junk
		vt3 := NewVT(80, 24)
		junkCSI := "\x1b[" + strings.Repeat("1;", 5000)
		vt3.Write([]byte(junkCSI))
		got3 := vt3.Transcript()
		if len(got3) > 0 {
			t.Errorf("unclosed 10KB CSI leaked %d bytes into transcript: %q", len(got3), got3[:min(100, len(got3))])
		}
	})

	// Example 2: Invalid intermediate byte and DEL (0x7F) byte
	t.Run("Example2_InvalidIntermediateAndDEL", func(t *testing.T) {
		// ESC[-5A: invalid intermediate byte must not print "5A"
		vt1 := NewVT(80, 24)
		vt1.Write([]byte("\x1b[-5A"))
		got1 := vt1.Transcript()
		if strings.Contains(got1, "5A") {
			t.Errorf("ESC[-5A leaked '5A' into transcript: %q", got1)
		}
		if got1 != "" {
			t.Errorf("expected empty transcript, got %q", got1)
		}

		// 0x7F (DEL): must be ignored like NUL and BEL
		vt2 := NewVT(80, 24)
		vt2.Write([]byte("Hello\x7fWorld"))
		got2 := vt2.Transcript()
		if strings.Contains(got2, "\x7f") {
			t.Errorf("0x7F (DEL) byte leaked into transcript: %q", got2)
		}
		if got2 != "HelloWorld" {
			t.Errorf("got %q, want %q", got2, "HelloWorld")
		}
	})
}

// -----------------------------------------------------------------------------
// DEFECT 6: Session scrollback memory must be bounded
// -----------------------------------------------------------------------------

func TestTranscriptMemoryIsBounded(t *testing.T) {
	vt := NewVT(80, 24)

	// Generate 100,000 lines of scrollback output
	chunk := []byte("Line of log output from process running in terminal session\r\n")
	for i := 0; i < 100000; i++ {
		_, _ = vt.Write(chunk)
	}

	vt.mu.RLock()
	histLen := len(vt.history)
	vt.mu.RUnlock()

	if histLen > maxHistoryLines {
		t.Fatalf("scrollback history exceeded ceiling: %d lines > %d", histLen, maxHistoryLines)
	}

	transcript := vt.Transcript()
	lines := strings.Split(transcript, "\n")
	// The head, one marker, the ring and the screen: bounded at twice the
	// ceiling since R4 F-05 kept the session's beginning.
	if limit := 2*maxHistoryLines + 1 + 24; len(lines) > limit {
		t.Fatalf("transcript has %d lines, expected <= %d", len(lines), limit)
	}
}

// -----------------------------------------------------------------------------
// DEFECT 7: .meta must not claim checksum of missing or failed file
// -----------------------------------------------------------------------------

func TestMetaMustNotClaimChecksumOfMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := NewSimClock(now)

	cfg := SessionConfig{
		BaseDir:   tmpDir,
		Person:    "alice",
		Machine:   "srv1",
		SessionID: "meta-err-test",
		Cols:      80,
		Rows:      24,
		Clock:     clock,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}

	_, _ = rec.Write([]byte("some valid output\r\n"))

	paths := rec.Paths()

	// Make writing .txt fail by creating a directory with the exact same name as TxtPath
	if err := os.Mkdir(paths.TxtPath, 0755); err != nil {
		t.Fatalf("mkdir txt path failed: %v", err)
	}

	// Close should return error because .txt could not be written
	err = rec.Close()
	if err == nil {
		t.Fatalf("expected Close() to return error when txt write fails, got nil")
	}

	// Read .meta from disk
	meta, err := ReadMeta(paths.MetaPath)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

	// Status MUST NOT be "completed"
	if meta.Status == "completed" {
		t.Errorf("expected status != 'completed' when write failed, got %q", meta.Status)
	}
	if meta.Status != "error" {
		t.Errorf("expected status 'error', got %q", meta.Status)
	}

	// TxtFile MUST NOT claim size or sha256 of the unwritten file
	if meta.TxtFile.Size != 0 {
		t.Errorf("expected TxtFile.Size == 0 for failed file, got %d", meta.TxtFile.Size)
	}
	if meta.TxtFile.SHA256 != "" {
		t.Errorf("expected empty TxtFile.SHA256 for failed file, got %q", meta.TxtFile.SHA256)
	}
}

func TestMetaChecksumMatchesActualDiskContent(t *testing.T) {
	tmpDir := t.TempDir()
	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	clock := NewSimClock(now)

	cfg := SessionConfig{
		BaseDir:   tmpDir,
		Person:    "alice",
		Machine:   "srv1",
		SessionID: "checksum-verify",
		Cols:      80,
		Rows:      24,
		Clock:     clock,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}

	_, _ = rec.Write([]byte("First line of audit output\r\nSecond line\r\n"))
	if err := rec.Close(); err != nil {
		t.Fatalf("rec.Close failed: %v", err)
	}

	paths := rec.Paths()
	meta, err := ReadMeta(paths.MetaPath)
	if err != nil {
		t.Fatalf("ReadMeta failed: %v", err)
	}

	// Compute hashes directly from disk
	castSize, castSHA, err := hashFile(paths.CastPath)
	if err != nil {
		t.Fatalf("hashFile cast failed: %v", err)
	}
	txtSize, txtSHA, err := hashFile(paths.TxtPath)
	if err != nil {
		t.Fatalf("hashFile txt failed: %v", err)
	}

	if meta.CastFile.Size != castSize || meta.CastFile.SHA256 != castSHA {
		t.Errorf("cast metadata mismatch: got (%d, %s), want (%d, %s)",
			meta.CastFile.Size, meta.CastFile.SHA256, castSize, castSHA)
	}
	if meta.TxtFile.Size != txtSize || meta.TxtFile.SHA256 != txtSHA {
		t.Errorf("txt metadata mismatch: got (%d, %s), want (%d, %s)",
			meta.TxtFile.Size, meta.TxtFile.SHA256, txtSize, txtSHA)
	}
}

// -----------------------------------------------------------------------------
// DEFECT 8: Content preservation on window resize (shrink)
// -----------------------------------------------------------------------------

func TestResizeShrinkPreservesAllContent(t *testing.T) {
	vt := NewVT(80, 10)
	// Write 8 lines on an 80x10 screen
	content := "row0-leftxxxxxxxxxxx-tail\r\nrow1\r\nrow2\r\nrow3\r\nrow4\r\nrow5\r\nrow6\r\nrow7"
	_, _ = vt.Write([]byte(content))

	// Shrink height from 10 to 3, and width from 80 to 20
	vt.Resize(20, 3)

	transcript := vt.Transcript()

	// All 8 rows must be present in the transcript
	for _, row := range []string{"row0", "row1", "row2", "row3", "row4", "row5", "row6", "row7"} {
		if !strings.Contains(transcript, row) {
			t.Errorf("transcript lost %s after resize: %q", row, transcript)
		}
	}

	// Tail of row 0 must not be lost either (wrapped onto continuation line)
	if !strings.Contains(transcript, "tail") {
		t.Errorf("transcript lost tail of wide row after resize: %q", transcript)
	}
}

// -----------------------------------------------------------------------------
// DEFECT 9: East Asian CJK double-width character wrap
// -----------------------------------------------------------------------------

func TestCJKDoubleWidthWrap(t *testing.T) {
	// Terminal width 6, height 4
	vt := NewVT(6, 4)

	// "日本語テスト" (6 Japanese characters, each width 2 -> 12 cols total)
	// On width 6, exactly 3 characters fit per line
	_, _ = vt.Write([]byte("日本語テスト"))

	transcript := vt.Transcript()
	expected := "日本語\nテスト"
	if transcript != expected {
		t.Fatalf("CJK wrap failed: got %q, want %q", transcript, expected)
	}
}
