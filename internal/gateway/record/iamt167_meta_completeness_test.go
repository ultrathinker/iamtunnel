package record

// iamt167_meta_completeness_test.go — finding H10 of the phase-2 review
// (the r4 report): .meta completeness was covered by a scatter of narrow
// tests (status here, checksums there), and removing an "inconvenient"
// field from Metadata — person or machine, say — broke nothing. After Close
// this test reads the meta from disk and asserts the ENTIRE set of SPEC §6.5
// fields with values known from the session config. Canary: remove the
// assignment of any field in finalMeta (recorder.go, finalize) — that exact
// field's assertion goes red.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIAMT167_MetaCompletenessAfterClose(t *testing.T) {
	baseDir := t.TempDir()
	start := testBaseTime
	clock := NewSimClock(start)

	rec, err := NewRecorder(SessionConfig{
		BaseDir:      baseDir,
		Machine:      "srv9",
		Person:       "bob",
		OSUser:       `MACHINE\bob`,
		SessionID:    "iamt167-meta",
		Cols:         120,
		Rows:         35,
		Term:         "xterm-256color",
		Clock:        clock,
		SubdirLayout: true,
	})
	if err != nil {
		t.Fatalf("NewRecorder: %v", err)
	}
	payload := []byte("whoami\r\nMACHINE\\bob\r\noutput \xe2\x82\xac \xc2\xb1 \xe2\x9c\x93\r\n")
	if n, err := rec.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	clock.Add(1500 * time.Millisecond)
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	meta, err := ReadMeta(rec.Paths().MetaPath)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}

	// Session identity — from the config.
	if meta.Person != "bob" {
		t.Errorf("meta.person = %q, want %q (from session config)", meta.Person, "bob")
	}
	if meta.Machine != "srv9" {
		t.Errorf("meta.machine = %q, want %q (from session config)", meta.Machine, "srv9")
	}
	if meta.OSUser != `MACHINE\bob` {
		t.Errorf("meta.os_user = %q, want %q (from session config)", meta.OSUser, `MACHINE\bob`)
	}
	if meta.SessionID != "iamt167-meta" {
		t.Errorf("meta.session_id = %q, want %q (from session config)", meta.SessionID, "iamt167-meta")
	}

	// Time: the start is the injected clock; the end and duration are its progress.
	if !meta.StartedAt.Equal(start) {
		t.Errorf("meta.started_at = %v, want %v", meta.StartedAt, start)
	}
	wantEnd := start.Add(1500 * time.Millisecond)
	if !meta.EndedAt.Equal(wantEnd) {
		t.Errorf("meta.ended_at = %v, want %v", meta.EndedAt, wantEnd)
	}
	if meta.DurationSeconds != 1.5 {
		t.Errorf("meta.duration_seconds = %v, want 1.5", meta.DurationSeconds)
	}

	// Outcome: Close is a completed session, not an abort.
	if meta.Status != "completed" {
		t.Errorf("meta.status = %q, want %q", meta.Status, "completed")
	}
	if meta.Aborted {
		t.Errorf("meta.aborted = true, want false after Close")
	}
	if meta.ExitReason != "normal exit" {
		t.Errorf("meta.exit_reason = %q, want %q", meta.ExitReason, "normal exit")
	}

	// Window size — from the config (cols x rows).
	if meta.WindowSize.Cols != 120 || meta.WindowSize.Rows != 35 || meta.WindowSize.Width != 120 || meta.WindowSize.Height != 35 {
		t.Errorf("meta.window_size = %+v, want cols/rows/width/height = 120/35/120/35", meta.WindowSize)
	}

	// Files: names, actual sizes and checksums from disk.
	for _, tc := range []struct {
		label string
		file  FileInfo
		path  string
	}{
		{"cast_file", meta.CastFile, rec.Paths().CastPath},
		{"txt_file", meta.TxtFile, rec.Paths().TxtPath},
	} {
		if tc.file.Name != filepath.Base(tc.path) {
			t.Errorf("meta.%s.name = %q, want %q", tc.label, tc.file.Name, filepath.Base(tc.path))
		}
		data, err := os.ReadFile(tc.path)
		if err != nil {
			t.Fatalf("read %s: %v", tc.path, err)
		}
		if tc.file.Size != int64(len(data)) {
			t.Errorf("meta.%s.size = %d, want actual file size %d", tc.label, tc.file.Size, len(data))
		}
		sum := sha256.Sum256(data)
		if tc.file.SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("meta.%s.sha256 = %q, want %q (sha256 of the file on disk)", tc.label, tc.file.SHA256, hex.EncodeToString(sum[:]))
		}
	}

	// The volume of recorded machine→human bytes — whatever was written is what the meta says.
	if meta.TotalBytes != int64(len(payload)) {
		t.Errorf("meta.total_bytes = %d, want %d", meta.TotalBytes, len(payload))
	}
}
