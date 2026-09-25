package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIAMT192_RestoreForeignArchiveIsUserError preserves the pre-IAMT-174
// distinction: a readable archive with a member that our backup format never
// creates is bad operator input, not a broken runtime environment.
func TestIAMT192_RestoreForeignArchiveIsUserError(t *testing.T) {
	archive := writeIAMT192Archive(t, map[string]string{"other.txt": "not a backup member"})
	_, errs, code := drive(t, "gateway", "restore", archive, "--data-dir", t.TempDir(), "--yes")
	if code != exitUser || !strings.Contains(errs, "archive entry") {
		t.Fatalf("IAMT-192 canary: foreign archive exit code = %d, stderr=%q; want exitUser (%d) naming archive entry", code, errs, exitUser)
	}
}

// TestIAMT192_RestoreArchiveWithoutStateIsUserError covers the other
// historical input-validation branch: events.jsonl alone is readable, but it
// is not a backup because the required state.json member is absent.
func TestIAMT192_RestoreArchiveWithoutStateIsUserError(t *testing.T) {
	archive := writeIAMT192Archive(t, map[string]string{"events.jsonl": ""})
	_, errs, code := drive(t, "gateway", "restore", archive, "--data-dir", t.TempDir(), "--yes")
	if code != exitUser || !strings.Contains(errs, "has no state.json") {
		t.Fatalf("IAMT-192 canary: archive without state.json exit code = %d, stderr=%q; want exitUser (%d) naming state.json", code, errs, exitUser)
	}
}

func writeIAMT192Archive(t *testing.T, members map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "restore.tar.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, content := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
			t.Fatalf("archive header %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("archive member %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return path
}
