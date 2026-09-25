package record

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSessionAbortedMidRecording(t *testing.T) {
	tmpDir := t.TempDir()
	clock := NewSimClock(testBaseTime)

	cfg := SessionConfig{
		BaseDir:   tmpDir,
		Machine:   "srv-corp-01",
		Person:    "alex",
		SessionID: "session-aborted-123",
		Clock:     clock,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}

	// Write normal session interactions
	clock.Add(100 * time.Millisecond)
	if _, err := rec.Write([]byte("connecting to internal host...\r\n")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	clock.Add(200 * time.Millisecond)
	if _, err := rec.Write([]byte("host$ rm -rf /tmp/build\r\n")); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Mid-session abort occurs (e.g. network disconnect, power failure or revoked grant)
	clock.Add(300 * time.Millisecond)
	abortReason := "revoked permission: grant expired during session"
	if err := rec.Abort(abortReason); err != nil {
		t.Fatalf("Abort failed: %v", err)
	}

	paths := rec.Paths()

	// 1. Check that all three files exist on disk
	for _, p := range []string{paths.CastPath, paths.TxtPath, paths.MetaPath} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected file %s to exist after abort: %v", p, err)
		}
	}

	// 2. Check that .cast file remains fully valid and readable JSON lines
	castF, err := os.Open(paths.CastPath)
	if err != nil {
		t.Fatalf("failed to open cast file: %v", err)
	}
	defer castF.Close()

	scanner := bufio.NewScanner(castF)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Bytes()
		if lineNum == 1 {
			var hdr CastHeader
			if err := json.Unmarshal(line, &hdr); err != nil {
				t.Fatalf("corrupted cast header in line 1: %v", err)
			}
			if hdr.Version != 2 {
				t.Errorf("expected cast version 2, got %d", hdr.Version)
			}
		} else {
			var entry []any
			if err := json.Unmarshal(line, &entry); err != nil {
				t.Fatalf("corrupted cast event line %d: %v", lineNum, err)
			}
		}
	}
	if lineNum < 2 {
		t.Fatalf("expected at least 2 lines in .cast file, got %d", lineNum)
	}

	// 3. Check that .txt file contains readable transcript up to abort
	txtBytes, err := os.ReadFile(paths.TxtPath)
	if err != nil {
		t.Fatalf("failed to read txt file: %v", err)
	}
	txtContent := string(txtBytes)
	if !strings.Contains(txtContent, "connecting to internal host...") || !strings.Contains(txtContent, "host$ rm -rf /tmp/build") {
		t.Fatalf(".txt missing data written before abort: %q", txtContent)
	}

	// 4. Check that .meta honestly reports session was aborted
	meta, err := ReadMeta(paths.MetaPath)
	if err != nil {
		t.Fatalf("failed to read .meta: %v", err)
	}

	if meta.Status != "aborted" {
		t.Errorf("expected status 'aborted', got %q", meta.Status)
	}
	if !meta.Aborted {
		t.Errorf("expected Aborted to be true, got false")
	}
	if meta.ExitReason != abortReason {
		t.Errorf("expected exit reason %q, got %q", abortReason, meta.ExitReason)
	}
	if meta.DurationSeconds <= 0 {
		t.Errorf("expected positive duration, got %f", meta.DurationSeconds)
	}
	if meta.CastFile.Size == 0 || meta.TxtFile.Size == 0 {
		t.Errorf("expected positive file sizes in meta, got cast=%d txt=%d", meta.CastFile.Size, meta.TxtFile.Size)
	}
}

func TestDiskFullErrorNotLost(t *testing.T) {
	tmpDir := t.TempDir()
	clock := NewSimClock(testBaseTime)

	cfg := SessionConfig{
		BaseDir:   tmpDir,
		Machine:   "srv-corp-01",
		Person:    "alex",
		SessionID: "disk-full-test",
		Clock:     clock,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}

	// First write succeeds
	if _, err := rec.Write([]byte("First chunk\n")); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Simulate disk I/O failure by forcibly closing the underlying file descriptor
	_ = rec.castFile.Close()

	// Next write MUST fail and NOT be swallowed silently
	_, writeErr := rec.Write([]byte("Second chunk after disk failure\n"))
	if writeErr == nil {
		t.Fatalf("expected write error after disk failure simulation, but got nil")
	}

	// Close must also report the error
	closeErr := rec.Close()
	if closeErr == nil {
		t.Fatalf("expected Close() to return error after disk failure, but got nil")
	}
}

func TestFilePermissionsRestricted(t *testing.T) {
	tmpDir := t.TempDir()
	clock := NewSimClock(testBaseTime)

	cfg := SessionConfig{
		BaseDir:      tmpDir,
		Machine:      "srv-secure-01",
		Person:       "bob",
		SessionID:    "perm-test",
		Clock:        clock,
		FileMode:     0600,
		DirMode:      0700,
		SubdirLayout: true,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}

	rec.Write([]byte("secret session data\n"))
	if err := rec.Close(); err != nil {
		t.Fatalf("rec.Close failed: %v", err)
	}

	paths := rec.Paths()

	// Check permissions on POSIX systems (Linux, macOS)
	if runtime.GOOS != "windows" {
		// Files should be 0600 (owner rw only, no group or other access)
		for _, p := range []string{paths.CastPath, paths.TxtPath, paths.MetaPath} {
			info, err := os.Stat(p)
			if err != nil {
				t.Fatalf("stat failed: %v", err)
			}
			perm := info.Mode().Perm()
			if perm&0077 != 0 {
				t.Errorf("file %s has open permissions for group/others: %o", p, perm)
			}
		}

		// Directory should be 0700 (owner rwx only)
		dir := filepath.Dir(paths.CastPath)
		dirInfo, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("stat dir failed: %v", err)
		}
		dirPerm := dirInfo.Mode().Perm()
		if dirPerm&0077 != 0 {
			t.Errorf("directory %s has open permissions for group/others: %o", dir, dirPerm)
		}
	} else {
		t.Skip("POSIX file permissions (0600/0700) cannot be verified on Windows")
	}
}

func TestConcurrentWritersInSameDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	clock := NewSimClock(testBaseTime)

	const numWriters = 10
	const numWritesPerSession = 50

	var wg sync.WaitGroup
	errCh := make(chan error, numWriters)

	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			cfg := SessionConfig{
				BaseDir:   tmpDir,
				Machine:   "shared-target",
				Person:    fmt.Sprintf("user-%d", workerID),
				SessionID: fmt.Sprintf("session-%d", workerID),
				Clock:     clock,
			}

			rec, err := NewRecorder(cfg)
			if err != nil {
				errCh <- fmt.Errorf("worker %d NewRecorder: %w", workerID, err)
				return
			}

			for i := 0; i < numWritesPerSession; i++ {
				payload := fmt.Sprintf("Worker %d message %d\r\n", workerID, i)
				if _, err := rec.Write([]byte(payload)); err != nil {
					errCh <- fmt.Errorf("worker %d write %d: %w", workerID, i, err)
					return
				}
			}

			if err := rec.Close(); err != nil {
				errCh <- fmt.Errorf("worker %d close: %w", workerID, err)
				return
			}
		}(w)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent writer error: %v", err)
	}

	// Verify that all 10 sessions created their respective 3 files cleanly
	for w := 0; w < numWriters; w++ {
		base := filepath.Join(tmpDir, fmt.Sprintf("user-%d-session-%d", w, w))
		for _, ext := range []string{".cast", ".txt", ".meta"} {
			fPath := base + ext
			info, err := os.Stat(fPath)
			if err != nil {
				t.Fatalf("expected file %s to exist: %v", fPath, err)
			}
			if info.Size() == 0 {
				t.Fatalf("file %s is empty", fPath)
			}
		}

		meta, err := ReadMeta(base + ".meta")
		if err != nil {
			t.Fatalf("failed to read meta for worker %d: %v", w, err)
		}
		if meta.Status != "completed" || meta.Aborted {
			t.Errorf("worker %d meta unexpected: %+v", w, meta)
		}
	}
}

func TestRecorderNormalCompletion(t *testing.T) {
	tmpDir := t.TempDir()
	clock := NewSimClock(testBaseTime)

	cfg := SessionConfig{
		BaseDir:   tmpDir,
		Machine:   "srv-normal",
		Person:    "charlie",
		SessionID: "normal-01",
		Clock:     clock,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}

	rec.Write([]byte("echo hello\r\nhello\r\n"))
	clock.Add(2 * time.Second)

	if err := rec.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	meta := rec.Metadata()
	if meta.Status != "completed" {
		t.Errorf("expected status completed, got %q", meta.Status)
	}
	if meta.Aborted {
		t.Errorf("expected aborted=false")
	}
	if meta.DurationSeconds != 2.0 {
		t.Errorf("expected duration 2.0, got %f", meta.DurationSeconds)
	}
}

func TestRecorderChecksumsAndSizes(t *testing.T) {
	tmpDir := t.TempDir()
	clock := NewSimClock(testBaseTime)

	cfg := SessionConfig{
		BaseDir:   tmpDir,
		Machine:   "srv-hash-check",
		Person:    "dave",
		SessionID: "hash-01",
		Clock:     clock,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}

	rec.Write([]byte("Testing checksum accuracy\r\nLine 2\r\n"))
	rec.Close()

	paths := rec.Paths()

	// Read actual file contents from disk
	castData, err := os.ReadFile(paths.CastPath)
	if err != nil {
		t.Fatalf("read cast failed: %v", err)
	}
	actualCastHash := sha256.Sum256(castData)
	expectedCastSHA := hex.EncodeToString(actualCastHash[:])

	txtData, err := os.ReadFile(paths.TxtPath)
	if err != nil {
		t.Fatalf("read txt failed: %v", err)
	}
	actualTxtHash := sha256.Sum256(txtData)
	expectedTxtSHA := hex.EncodeToString(actualTxtHash[:])

	meta, err := ReadMeta(paths.MetaPath)
	if err != nil {
		t.Fatalf("read meta failed: %v", err)
	}

	if meta.CastFile.SHA256 != expectedCastSHA {
		t.Errorf("cast sha256 mismatch in meta:\nexpected %s\ngot      %s", expectedCastSHA, meta.CastFile.SHA256)
	}
	if meta.CastFile.Size != int64(len(castData)) {
		t.Errorf("cast size mismatch in meta: expected %d, got %d", len(castData), meta.CastFile.Size)
	}

	if meta.TxtFile.SHA256 != expectedTxtSHA {
		t.Errorf("txt sha256 mismatch in meta:\nexpected %s\ngot      %s", expectedTxtSHA, meta.TxtFile.SHA256)
	}
	if meta.TxtFile.Size != int64(len(txtData)) {
		t.Errorf("txt size mismatch in meta: expected %d, got %d", len(txtData), meta.TxtFile.Size)
	}
}

func TestRecorderDirectoryStructure(t *testing.T) {
	tmpDir := t.TempDir()
	fixedTime := time.Date(2026, 9, 12, 14, 30, 0, 0, time.UTC)
	clock := NewSimClock(fixedTime)

	cfg := SessionConfig{
		BaseDir:      tmpDir,
		Machine:      "corp-windows-vm",
		Person:       "admin_eve",
		SessionID:    "sess-999",
		Clock:        clock,
		SubdirLayout: true,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}
	rec.Close()

	paths := rec.Paths()

	// Expected path format: recordings/<machine>/<YYYY-MM-DD>/<HHMMSS>-<person>-<session-id>.cast
	expectedSubpath := filepath.Join("corp-windows-vm", "2026-09-12", "143000-admin_eve-sess-999.cast")
	if !strings.HasSuffix(paths.CastPath, expectedSubpath) {
		t.Errorf("path does not match SPEC 6.5 structure.\nExpected suffix: %s\nGot path: %s", expectedSubpath, paths.CastPath)
	}
}

func TestRecorderWriteAfterClose(t *testing.T) {
	tmpDir := t.TempDir()
	clock := NewSimClock(testBaseTime)

	cfg := SessionConfig{
		BaseDir:   tmpDir,
		Machine:   "srv-closed",
		Person:    "frank",
		SessionID: "closed-01",
		Clock:     clock,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}
	rec.Close()

	_, err = rec.Write([]byte("data"))
	if err != ErrRecorderClosed {
		t.Errorf("expected ErrRecorderClosed, got %v", err)
	}
}

func TestRecorderResize(t *testing.T) {
	tmpDir := t.TempDir()
	clock := NewSimClock(testBaseTime)

	cfg := SessionConfig{
		BaseDir:   tmpDir,
		Machine:   "srv-resize",
		Person:    "grace",
		SessionID: "resize-01",
		Cols:      80,
		Rows:      24,
		Clock:     clock,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}

	if err := rec.Resize(120, 40); err != nil {
		t.Fatalf("Resize failed: %v", err)
	}
	rec.Close()

	meta := rec.Metadata()
	if meta.WindowSize.Cols != 120 || meta.WindowSize.Rows != 40 {
		t.Errorf("meta window size not updated on resize: %+v", meta.WindowSize)
	}
}

func TestRecorderDeterministicClock(t *testing.T) {
	tmpDir := t.TempDir()
	clock := NewSimClock(testBaseTime)

	cfg := SessionConfig{
		BaseDir:   tmpDir,
		Machine:   "srv-det",
		Person:    "heidi",
		SessionID: "det-01",
		Clock:     clock,
	}

	rec, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("NewRecorder failed: %v", err)
	}

	// Advance clock deterministically by exactly 1.5s
	clock.Add(1500 * time.Millisecond)
	rec.Write([]byte("deterministic event\n"))
	rec.Close()

	castData, err := os.ReadFile(rec.Paths().CastPath)
	if err != nil {
		t.Fatalf("read cast failed: %v", err)
	}

	lines := strings.Split(string(castData), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected at least 2 lines in cast: %s", string(castData))
	}

	var ev []any
	if err := json.Unmarshal([]byte(lines[1]), &ev); err != nil {
		t.Fatalf("unmarshal event failed: %v", err)
	}

	eventTime, ok := ev[0].(float64)
	if !ok || eventTime != 1.5 {
		t.Fatalf("expected deterministic event time 1.5, got %v", ev[0])
	}
}
