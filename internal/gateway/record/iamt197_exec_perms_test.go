package record

// iamt197_exec_perms_test.go — candidate #7 of the THREATS audit (IAMT-196):
// the lossless journal of non-interactive exec (.exec.jsonl, IAMT-163) must
// carry the same restricted permissions as .cast/.txt/.meta — file 0600,
// directory 0700 (IAMT-168; THREATS §3.2: session recordings are an asset
// readable by the owner only). The permission code lives in
// exec_recorder.go:61-66 (FileMode 0600, DirMode 0700). The neighbouring
// recorder_test.go:164 covers cast/txt/meta; this test covers exec.jsonl in
// the same way and with the same platform skip: on Windows POSIX permissions
// do not apply — the Linux gate performs the check (§3.5: the gateway runs
// on Linux).

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestExecJSONLRestrictedPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions (0600/0700) cannot be verified on Windows")
	}

	dir := t.TempDir()
	rec, err := NewExecRecorder(ExecConfig{
		SessionConfig: SessionConfig{
			BaseDir:      dir,
			Machine:      "win01",
			Person:       "alice",
			SessionID:    "exec-perms",
			SubdirLayout: true,
		},
		Command: "cmd /c echo perms",
	})
	if err != nil {
		t.Fatalf("NewExecRecorder failed: %v", err)
	}

	paths := rec.Paths()

	// Files must be 0600 (owner rw only, no group or other access):
	// both the lossless stream and its metadata sidecar.
	for _, p := range []string{paths.ExecPath, paths.MetaPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat failed: %v", err)
		}
		if perm := info.Mode().Perm(); perm&0077 != 0 {
			t.Errorf("file %s has open permissions for group/others: %o", p, perm)
		}
	}

	// Directory must be 0700 (owner rwx only).
	dirInfo, err := os.Stat(filepath.Dir(paths.ExecPath))
	if err != nil {
		t.Fatalf("stat dir failed: %v", err)
	}
	if dirPerm := dirInfo.Mode().Perm(); dirPerm&0077 != 0 {
		t.Errorf("directory %s has open permissions for group/others: %o", filepath.Dir(paths.ExecPath), dirPerm)
	}
}
