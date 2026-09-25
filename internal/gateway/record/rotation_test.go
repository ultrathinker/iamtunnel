package record

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func createFakeSession(t *testing.T, dir, machine, person, sessID string, startedAt time.Time, sizePerFile int, status string) string {
	t.Helper()
	dateStr := startedAt.Format("2006-01-02")
	sessDir := filepath.Join(dir, machine, dateStr)
	if err := os.MkdirAll(sessDir, 0700); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	baseName := fmt.Sprintf("%s-%s-%s", startedAt.Format("150405"), person, sessID)
	basePath := filepath.Join(sessDir, baseName)

	payload := bytes.Repeat([]byte("X"), sizePerFile)

	castPath := basePath + ".cast"
	txtPath := basePath + ".txt"
	metaPath := basePath + ".meta"

	if err := os.WriteFile(castPath, payload, 0600); err != nil {
		t.Fatalf("write fake cast failed: %v", err)
	}
	if err := os.WriteFile(txtPath, payload, 0600); err != nil {
		t.Fatalf("write fake txt failed: %v", err)
	}

	meta := Metadata{
		Person:    person,
		Machine:   machine,
		SessionID: sessID,
		StartedAt: startedAt,
		Status:    status,
		CastFile: FileInfo{
			Name: filepath.Base(castPath),
			Size: int64(sizePerFile),
		},
		TxtFile: FileInfo{
			Name: filepath.Base(txtPath),
			Size: int64(sizePerFile),
		},
	}
	if err := WriteMeta(metaPath, meta, 0600); err != nil {
		t.Fatalf("write fake meta failed: %v", err)
	}

	// Adjust file modification times to match startedAt
	_ = os.Chtimes(castPath, startedAt, startedAt)
	_ = os.Chtimes(txtPath, startedAt, startedAt)
	_ = os.Chtimes(metaPath, startedAt, startedAt)

	return basePath
}

func TestRotationByAge(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	// Create 3 sessions: 100 days old (expired), 50 days old, 10 days old
	s1 := createFakeSession(t, tmpDir, "srv1", "u1", "old100", now.Add(-100*24*time.Hour), 1000, "completed")
	s2 := createFakeSession(t, tmpDir, "srv1", "u2", "med50", now.Add(-50*24*time.Hour), 1000, "completed")
	s3 := createFakeSession(t, tmpDir, "srv1", "u3", "new10", now.Add(-10*24*time.Hour), 1000, "completed")

	cfg := RotateConfig{
		Dir:    tmpDir,
		MaxAge: 90 * 24 * time.Hour,
		Clock:  clock,
	}

	res, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	if len(res.DeletedSessions) != 1 {
		t.Fatalf("expected 1 deleted session, got %d", len(res.DeletedSessions))
	}
	if res.DeletedSessions[0] != s1 {
		t.Errorf("expected %s deleted, got %s", s1, res.DeletedSessions[0])
	}

	// Check s1 files deleted
	for _, ext := range []string{".cast", ".txt", ".meta"} {
		if _, err := os.Stat(s1 + ext); !os.IsNotExist(err) {
			t.Errorf("expected file %s to be deleted", s1+ext)
		}
	}

	// Check s2 and s3 still exist
	for _, s := range []string{s2, s3} {
		for _, ext := range []string{".cast", ".txt", ".meta"} {
			if _, err := os.Stat(s + ext); err != nil {
				t.Errorf("expected file %s to exist: %v", s+ext, err)
			}
		}
	}
}

func TestRotationByTotalSize(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	// 3 sessions of ~2KB each (total ~6KB)
	s1 := createFakeSession(t, tmpDir, "srv1", "u1", "s1", now.Add(-3*time.Hour), 1000, "completed")
	s2 := createFakeSession(t, tmpDir, "srv1", "u2", "s2", now.Add(-2*time.Hour), 1000, "completed")
	s3 := createFakeSession(t, tmpDir, "srv1", "u3", "s3", now.Add(-1*time.Hour), 1000, "completed")

	// Set limit to 5000 bytes (each session is ~2350 bytes; 3 sessions ~7050 bytes; deleting s1 leaves ~4700 bytes <= 5000)
	cfg := RotateConfig{
		Dir:           tmpDir,
		MaxTotalBytes: 5000,
		Clock:         clock,
	}

	res, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	if len(res.DeletedSessions) != 1 || res.DeletedSessions[0] != s1 {
		t.Fatalf("expected s1 deleted, got: %+v", res.DeletedSessions)
	}

	if res.RemainingBytes > 5000 {
		t.Errorf("expected remaining bytes <= 5000, got %d", res.RemainingBytes)
	}

	// s1 deleted, s2 and s3 remain
	if _, err := os.Stat(s1 + ".cast"); !os.IsNotExist(err) {
		t.Errorf("s1 should be deleted")
	}
	if _, err := os.Stat(s2 + ".cast"); err != nil {
		t.Errorf("s2 should remain")
	}
	if _, err := os.Stat(s3 + ".cast"); err != nil {
		t.Errorf("s3 should remain")
	}
}

func TestRotationSingleSessionExceedsLimitStrict(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	// One single session of ~20KB total
	s1 := createFakeSession(t, tmpDir, "srv1", "u1", "huge-session", now.Add(-1*time.Hour), 10000, "completed")

	// Limit is 5KB (< 20KB session size). Invariant: never delete the archive down to 0.
	cfg := RotateConfig{
		Dir:           tmpDir,
		MaxTotalBytes: 5000,
		Clock:         clock,
	}

	res, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	if !res.OversizedSingleSession {
		t.Errorf("expected OversizedSingleSession to be true")
	}
	if len(res.DeletedSessions) != 0 {
		t.Fatalf("expected s1 preserved (never delete all to 0), got deleted: %+v", res.DeletedSessions)
	}
	if res.RemainingSessions != 1 {
		t.Errorf("expected 1 remaining session, got %d", res.RemainingSessions)
	}
	if res.RemainingBytes == 0 {
		t.Errorf("expected remaining bytes > 0, got %d", res.RemainingBytes)
	}
	if _, err := os.Stat(s1 + ".cast"); err != nil {
		t.Errorf("expected s1 files to remain on disk: %v", err)
	}
}

func TestRotationRetainsNewestSession(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	// s1 is older (~2KB), s2 is newer and huge (~20KB)
	s1 := createFakeSession(t, tmpDir, "srv1", "u1", "old-sess", now.Add(-2*time.Hour), 1000, "completed")
	s2 := createFakeSession(t, tmpDir, "srv1", "u2", "huge-sess", now.Add(-1*time.Hour), 10000, "completed")

	// Limit is 5KB. The unconditional never-wipe invariant keeps the newest session.
	cfg := RotateConfig{
		Dir:           tmpDir,
		MaxTotalBytes: 5000,
		Clock:         clock,
	}

	res, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	if !res.OversizedSingleSession {
		t.Errorf("expected OversizedSingleSession flag to be set")
	}

	// s1 was pruned to free space
	if len(res.DeletedSessions) != 1 || res.DeletedSessions[0] != s1 {
		t.Fatalf("expected s1 pruned, got: %+v", res.DeletedSessions)
	}

	// s2 was retained as single newest session
	if res.RemainingSessions != 1 {
		t.Errorf("expected 1 remaining session, got %d", res.RemainingSessions)
	}
	if _, err := os.Stat(s2 + ".cast"); err != nil {
		t.Errorf("expected s2 to be retained: %v", err)
	}
}

func TestRotationActiveSessionNotPruned(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	// Session is marked "recording" (in progress)
	sActive := createFakeSession(t, tmpDir, "srv1", "u1", "active-sess", now.Add(-2*time.Hour), 1000, "recording")

	cfg := RotateConfig{
		Dir:    tmpDir,
		MaxAge: 1 * time.Hour, // sActive is 2h old
		Clock:  clock,
	}

	res, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	if len(res.DeletedSessions) != 0 {
		t.Fatalf("active session was incorrectly pruned: %+v", res.DeletedSessions)
	}
	if _, err := os.Stat(sActive + ".cast"); err != nil {
		t.Errorf("expected active session to still exist: %v", err)
	}
}

func TestRotationCleansEmptyDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	s1 := createFakeSession(t, tmpDir, "srv1", "u1", "old-sess", now.Add(-100*24*time.Hour), 500, "completed")
	dir := filepath.Dir(s1)

	cfg := RotateConfig{
		Dir:    tmpDir,
		MaxAge: 90 * 24 * time.Hour,
		Clock:  clock,
	}

	_, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	// The date folder containing s1 should be cleaned up
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("expected empty parent dir %s to be cleaned up", dir)
	}
}

func TestRotationFallbackToModTime(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	// Session without .meta file
	castPath := filepath.Join(tmpDir, "nometa-session.cast")
	txtPath := filepath.Join(tmpDir, "nometa-session.txt")
	os.WriteFile(castPath, []byte("cast data"), 0600)
	os.WriteFile(txtPath, []byte("txt data"), 0600)

	oldTime := now.Add(-100 * 24 * time.Hour)
	os.Chtimes(castPath, oldTime, oldTime)
	os.Chtimes(txtPath, oldTime, oldTime)

	cfg := RotateConfig{
		Dir:    tmpDir,
		MaxAge: 90 * 24 * time.Hour,
		Clock:  clock,
	}

	res, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	if len(res.DeletedSessions) != 1 {
		t.Fatalf("expected 1 session pruned via modtime fallback, got %d", len(res.DeletedSessions))
	}
}

func TestRotationEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	res, err := Rotate(RotateConfig{Dir: tmpDir})
	if err != nil {
		t.Fatalf("Rotate on empty dir failed: %v", err)
	}
	if len(res.DeletedSessions) != 0 || res.RemainingSessions != 0 {
		t.Errorf("unexpected result on empty dir: %+v", res)
	}
}

func TestRotationDeletesAllFilesOfSessionTogether(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	s1 := createFakeSession(t, tmpDir, "srv1", "u1", "all-together", now.Add(-100*24*time.Hour), 1000, "completed")

	_, err := Rotate(RotateConfig{Dir: tmpDir, MaxAge: 90 * 24 * time.Hour, Clock: clock})
	if err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	// Verify that none of .cast, .txt, .meta remain
	for _, ext := range []string{".cast", ".txt", ".meta"} {
		if _, err := os.Stat(s1 + ext); !os.IsNotExist(err) {
			t.Errorf("orphan file remained after rotation: %s", s1+ext)
		}
	}
}
