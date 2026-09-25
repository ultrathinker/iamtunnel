package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestExecRecorderWritesDurableOrderedLosslessStream(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewExecRecorder(ExecConfig{SessionConfig: SessionConfig{
		BaseDir: dir, Machine: "machine", Person: "person", OSUser: "operator", SessionID: "exec-unit", SubdirLayout: true,
	}, Command: "powershell -Command Write-Output ok"})
	if err != nil {
		t.Fatalf("NewExecRecorder: %v", err)
	}
	if _, err := rec.Write([]byte{'o', 'u', 't', 0xff}); err != nil {
		t.Fatalf("stdout: %v", err)
	}
	if _, err := rec.WriteStderr([]byte("warn\n")); err != nil {
		t.Fatalf("stderr: %v", err)
	}
	rec.AddBytesIn([]byte("stdin!"))
	if err := rec.ExitStatus(7); err != nil {
		t.Fatalf("exit status: %v", err)
	}
	if err := rec.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	raw, err := os.ReadFile(rec.Paths().ExecPath)
	if err != nil {
		t.Fatalf("read exec JSONL: %v", err)
	}
	var events []execEvent
	for _, line := range splitJSONLines(raw) {
		var event execEvent
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("unmarshal JSONL: %v", err)
		}
		events = append(events, event)
	}
	if len(events) != 5 || events[0].Type != "command" || events[0].Command != "powershell -Command Write-Output ok" || events[1].Stream != "stdout" || events[1].Data != "b3V0/w==" || events[2].Stream != "stderr" || events[2].Data != "d2Fybgo=" || events[3].Type != "exit-status" || events[3].Status == nil || *events[3].Status != 7 || events[4].Type != "eof" {
		t.Fatalf("IAMT-163 canary: JSONL must be command, lossless stdout/stderr chunks, exit-status, EOF in one sequence; got %#v", events)
	}
	for i, event := range events {
		if event.Sequence != uint64(i) {
			t.Fatalf("IAMT-163 canary: sequence[%d]=%d, want %d", i, event.Sequence, i)
		}
	}
	meta, err := ReadMeta(rec.Paths().MetaPath)
	if err != nil {
		t.Fatalf("read exec metadata: %v", err)
	}
	if meta.RecordingMode != "exec" || meta.ExecFile == nil || meta.ExecFile.Name == "" {
		t.Fatalf("IAMT-163 canary: exec metadata must name the .exec.jsonl file and mode; got %#v", meta)
	}
	if meta.BytesIn != 6 || meta.BytesOut != 9 || meta.TotalBytes != meta.BytesOut {
		t.Fatalf("IAMT-163 round-2 canary: exec metadata bytes_in=6, bytes_out=9, total_bytes=bytes_out; got in=%d out=%d total=%d", meta.BytesIn, meta.BytesOut, meta.TotalBytes)
	}
	// IAMT-336 phase 5 canary: stdin fact is recorded next to bytes_in.
	if meta.Stdin == nil {
		t.Fatalf("IAMT-336 canary: exec metadata must carry stdin{bytes, sha256} when stdin was sent; got nil")
	}
	if meta.Stdin.Bytes != 6 {
		t.Fatalf("IAMT-336 canary: stdin.bytes must equal bytes_in (6); got %d", meta.Stdin.Bytes)
	}
	wantHash := sha256.Sum256([]byte("stdin!"))
	if got := meta.Stdin.SHA256; got != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("IAMT-336 canary: stdin.sha256 must equal SHA-256 of \"stdin!\" (%s); got %s", hex.EncodeToString(wantHash[:]), got)
	}
}

func TestExecRecorderDoesNotAcceptByteWhenSyncFails(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewExecRecorder(ExecConfig{SessionConfig: SessionConfig{BaseDir: dir, Machine: "machine", Person: "person", SessionID: "sync-fail", SubdirLayout: true}, Command: "cmd"})
	if err != nil {
		t.Fatalf("NewExecRecorder: %v", err)
	}
	original := fileSyncFn
	fileSyncFn = func(*os.File) error { return errors.New("forced fsync failure") }
	t.Cleanup(func() { fileSyncFn = original })
	if n, err := rec.Write([]byte("must-not-pass")); err == nil || n != 0 {
		t.Fatalf("IAMT-163 canary: fsync failure must reject the unforwarded machine byte, got n=%d err=%v", n, err)
	}
	_ = rec.Abort("forced fsync failure")
}

func TestScanSessionsKeepsExecJSONLWithItsMetadata(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewExecRecorder(ExecConfig{SessionConfig: SessionConfig{BaseDir: dir, Machine: "machine", Person: "person", SessionID: "rotate-exec", SubdirLayout: true}, Command: "cmd"})
	if err != nil {
		t.Fatalf("NewExecRecorder: %v", err)
	}
	if err := rec.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	sessions, err := scanSessions(dir)
	if err != nil {
		t.Fatalf("scanSessions: %v", err)
	}
	if len(sessions) != 1 || len(sessions[0].files) != 2 {
		t.Fatalf("IAMT-163 canary: rotation scan must group .exec.jsonl and .meta as one session; got %#v", sessions)
	}
}

// M-9b (code review 23.09.2026, F-15). The final eof is the
// last event of an exec recording, and it was written BEFORE the
// recorder released anything: on a write/Sync failure finalize returned
// at that line, so the file stayed open, closed stayed false and the
// .meta stayed "recording". The session was already over — the caller
// only recorded bridgeErr, and ExecRecorder.Close is a deliberate
// no-op — so every failed finalization leaked a descriptor and left a
// recording that looks live forever. The resource must be released on
// EVERY outcome, the metadata must say the recording did not finish,
// and the caller must get the original error.
func TestM9bFinalEOFWriteFailureStillClosesAndFinalizesMeta(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewExecRecorder(ExecConfig{SessionConfig: SessionConfig{
		BaseDir: dir, Machine: "machine", Person: "person", SessionID: "finalize-fail", SubdirLayout: true,
	}, Command: "cmd"})
	if err != nil {
		t.Fatalf("NewExecRecorder: %v", err)
	}
	// The session runs normally up to its last moment...
	if _, err := rec.Write([]byte("output\n")); err != nil {
		t.Fatalf("stdout: %v", err)
	}
	// ...and the carrier fails exactly on the final eof.
	original := fileSyncFn
	fileSyncFn = func(*os.File) error { return errors.New("forced fsync failure on the final eof") }
	t.Cleanup(func() { fileSyncFn = original })

	err = rec.Finish()
	if err == nil {
		t.Fatalf("Finish reported success although the final eof never reached the disk — the failure must reach the caller")
	}
	if !strings.Contains(err.Error(), "forced fsync failure") {
		t.Errorf("Finish returned %v — the caller must get the ORIGINAL failure, not a replacement for it", err)
	}
	if rec.file != nil {
		t.Errorf("the recording file is still open after a failed finalization — one descriptor leaks per failure (M-9b, F-15)")
	}
	if !rec.closed {
		t.Errorf("the recorder did not mark itself closed on a failed finalization — the recording is over and must not accept more events")
	}
	meta, merr := ReadMeta(rec.Paths().MetaPath)
	if merr != nil {
		t.Fatalf("the metadata was left unfinalized: %v", merr)
	}
	if meta.Status != "aborted" || !meta.Aborted {
		t.Errorf("metadata status is %q (aborted=%v), want aborted — a recording whose final eof did not land is neither recording nor completed (M-9b, F-15)", meta.Status, meta.Aborted)
	}
	if !strings.Contains(meta.ExitReason, "forced fsync failure") {
		t.Errorf("metadata exit reason is %q — it must carry the failure that ended the recording", meta.ExitReason)
	}
	// Finalizing again is a no-op, not a panic on the released file.
	if aerr := rec.Abort("again"); aerr != nil {
		t.Errorf("Abort after a failed Finish: %v", aerr)
	}
}

func splitJSONLines(raw []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range raw {
		if b == '\n' {
			if i > start {
				lines = append(lines, raw[start:i])
			}
			start = i + 1
		}
	}
	return lines
}
