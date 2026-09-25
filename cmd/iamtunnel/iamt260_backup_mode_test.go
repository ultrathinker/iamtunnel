package main

// iamt260_backup_mode_test.go — IAMT-260: the backup file's permissions.
// "gateway backup" writes wherever the operator pointed it (--out), often
// OUTSIDE the 0700 data directory, so the archive must be created 0600 —
// the same discipline as state.json (atomicWriteFile): the archive holds
// the full state (people/machines/grants), and world-readable access on
// macOS/Linux would be a leak. On Windows the OS ignores permission
// bits, so a mode check makes no sense there (see the branch inside the
// test).

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestIAMT260_BackupArchiveIsOwnerOnly — the backup archive is created
// with 0600 (the owner reads and writes, everyone else gets nothing) on
// macOS/Linux; on Windows only the fact that the file was written is
// checked, since there are no mode bits there.
//
// Canary: bring os.Create back into gateway.WriteBackupTarGz (the
// archive gets 0666&umask = 0644, readable by everyone) — on a
// macOS/Linux host the Perm() comparison against 0600 turns red: "the
// backup archive must be 0600".
func TestIAMT260_BackupArchiveIsOwnerOnly(t *testing.T) {
	srcDir := t.TempDir()
	// backup requires state.json to exist — seed it the same way as in
	// TestGate2_GatewayBackupRestoreRoundTrip (Open + Update + Close).
	store, err := state.Open(srcDir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	if err := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "alice", Role: "admin"})
		return nil
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	outPath := filepath.Join(t.TempDir(), "b.tar.gz")
	out, errs, code := drive(t, "gateway", "backup", "--data-dir", srcDir, "--out", outPath)
	if code != exitOK || !strings.Contains(out, "wrote") {
		t.Fatalf("gateway backup: code=%d out=%q errs=%q, want exitOK and \"wrote\"", code, out, errs)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	if runtime.GOOS == "windows" {
		// On Windows the 0600/0644 permissions do not exist — the OS
		// ignores mode: there is nothing to check, pinning the mode stays
		// with the POSIX hosts.
		return
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("the backup archive must be 0600 (it holds the full state, and --out is often outside the 0700 data directory), got %o", got)
	}
}
