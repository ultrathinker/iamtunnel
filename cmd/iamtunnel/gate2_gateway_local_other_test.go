//go:build !linux && !darwin

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// backupDeniedByOS is the non-POSIX fallback (Windows): a read-only FILE
// stops the overwrite, because CreateFile refuses GENERIC_WRITE on a
// file with the read-only attribute.
func backupDeniedByOS(t *testing.T, srcDir string) (string, int) {
	t.Helper()
	outPath := filepath.Join(t.TempDir(), "ro.tar.gz")
	if err := os.WriteFile(outPath, []byte("x"), 0o444); err != nil {
		t.Fatalf("seed read-only file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(outPath, 0o600) })
	_, errs, code := drive(t, "gateway", "backup", "--data-dir", srcDir, "--out", outPath)
	return errs, code
}
