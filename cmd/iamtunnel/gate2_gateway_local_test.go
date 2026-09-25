package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestGate2_GatewayBackupRestoreRoundTrip: "gateway backup" really
// reads a live state.json (seeded through the same state.Store this
// package's own gatewayServe uses, with a real person in it) and
// produces a tar.gz that "gateway restore" can really put back — into a
// different, freshly empty gateway directory, observed by opening the
// restored state and finding the same person.
func TestGate2_GatewayBackupRestoreRoundTrip(t *testing.T) {
	srcDir := t.TempDir()
	store, err := state.Open(srcDir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	err = store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "alice", Role: "admin"})
		return nil
	})
	if err != nil {
		t.Fatalf("seed state: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	backupPath := filepath.Join(t.TempDir(), "b.tar.gz")
	out, errs, code := drive(t, "gateway", "backup", "--data-dir", srcDir, "--out", backupPath)
	if code != exitOK {
		t.Fatalf("gateway backup: code=%d out=%q errs=%q", code, out, errs)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Fatalf("backup file was not written: %v", err)
	}

	dstDir := t.TempDir()
	// restore needs an existing (even if empty) directory to write into;
	// loadConfig resolves --data-dir as-is, so the dir need not pre-exist
	// on disk — atomicWriteBytes creates it.
	out, errs, code = drive(t, "gateway", "restore", backupPath, "--data-dir", dstDir, "--yes")
	if code != exitOK {
		t.Fatalf("gateway restore: code=%d out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, state.StateFileName) {
		t.Errorf("gateway restore: stdout does not name %s: %q", state.StateFileName, out)
	}

	restored, err := state.Open(dstDir)
	if err != nil {
		t.Fatalf("state.Open(restored): %v", err)
	}
	defer restored.Close()
	st := restored.Get()
	if len(st.People) != 1 || st.People[0].Name != "alice" {
		t.Fatalf("restored state = %+v, want exactly person \"alice\"", st.People)
	}
}

// TestGate2_LocalRotateHostkeyChangesFingerprint: "gateway
// rotate-hostkey" really replaces the on-disk key — "gateway status"
// before and after report two different fingerprints, and the old key
// bytes survive at hostkey.old (PROTOCOL §6.2).
func TestGate2_LocalRotateHostkeyChangesFingerprint(t *testing.T) {
	dir := t.TempDir()
	out1, _, code := drive(t, "gateway", "status", "--data-dir", dir)
	if code != exitOK {
		t.Fatalf("initial status: code=%d out=%q", code, out1)
	}
	if !strings.Contains(out1, "not generated yet") {
		t.Fatalf("initial status: expected no host key yet, got:\n%s", out1)
	}

	out2, _, code := drive(t, "gateway", "rotate-hostkey", "--data-dir", dir, "--yes")
	if code != exitOK {
		t.Fatalf("first rotate: code=%d out=%q", code, out2)
	}
	statusAfterFirst, _, _ := drive(t, "gateway", "status", "--data-dir", dir)

	out3, _, code := drive(t, "gateway", "rotate-hostkey", "--data-dir", dir, "--yes")
	if code != exitOK {
		t.Fatalf("second rotate: code=%d out=%q", code, out3)
	}
	oldPath := filepath.Join(dir, "hostkey.old")
	if _, err := os.Stat(oldPath); err != nil {
		t.Errorf("rotate should keep the previous key at %s: %v", oldPath, err)
	}
	statusAfterSecond, _, _ := drive(t, "gateway", "status", "--data-dir", dir)

	if statusAfterFirst == statusAfterSecond {
		t.Errorf("fingerprint did not change across two rotations:\n1: %s\n2: %s", statusAfterFirst, statusAfterSecond)
	}
}

// TestGate3_DeniedClassOnUnwritableOutput exercises the fourth exit
// class ("no permissions") for real: "gateway backup" with
// an --out path the OS refuses to (re)write reports exitDenied, the
// same classifyPathErr path every other role's file writes go through.
func TestGate3_DeniedClassOnUnwritableOutput(t *testing.T) {
	srcDir := t.TempDir()
	store, err := state.Open(srcDir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	errs, code := backupDeniedByOS(t, srcDir)
	if code != exitDenied {
		t.Fatalf("code=%d errs=%q, want exitDenied (4)", code, errs)
	}
}

// TestGate5_EmptyEnvRefusesInsteadOfRelativePath is the IAMT-76 probe.
// config.DirsFor's Windows branch has a hardcoded
// absolute fallback for ProgramData (so server/gateway can never go
// relative), but the client directory has none: with both LOCALAPPDATA
// and USERPROFILE empty it resolves to the relative "AppData\Local\
// iamtunnel" (the Unix branch has the identical shape with HOME/
// XDG_DATA_HOME). "admin" shares the client directory (see admin.go),
// so both roles are probed; this asserts the CLI refuses with an
// environment-class error naming the cause instead of silently writing
// into the current working directory.
func TestGate5_EmptyEnvRefusesInsteadOfRelativePath(t *testing.T) {
	env := map[string]string{"LOCALAPPDATA": "", "USERPROFILE": ""}
	if runtime.GOOS != "windows" {
		env = map[string]string{"XDG_DATA_HOME": "", "HOME": ""}
	}
	// The refusal's WORDING is per-platform — config.DirsFor's branches
	// each name their own missing variables (the client data directory on
	// Windows; the per-user data directories on Linux/macOS) — so the
	// expected substring branches with them. It used to pin the Windows
	// sentence on every platform and failed the POSIX runs for the wrong
	// reason: the refusal happened, the test just did not recognise it
	// (R2, 24.09.2026).
	want := "cannot determine the client data directory"
	if runtime.GOOS != "windows" {
		want = "cannot determine the per-user data directories"
	}
	for _, args := range [][]string{
		{"client", "connect-string", connStr},
		{"admin", "people", "list"},
	} {
		_, errs, code := driveEnv(t, env, args...)
		if code != exitEnv || !strings.Contains(errs, want) {
			t.Errorf("%v: code=%d errs=%q, want exitEnv naming an unresolved data directory", args, code, errs)
		}
	}
	// selftest does not go through loadConfig (it has no single role),
	// but must reach the same conclusion through its own per-directory
	// checks rather than silently treating a relative path as fine.
	out, errs, code := driveEnv(t, env, "selftest")
	if code != exitEnv {
		t.Errorf("selftest: code=%d, want exitEnv; out=%q errs=%q", code, out, errs)
	}
	if !strings.Contains(out, "which is relative and unsafe") {
		t.Errorf("selftest: did not report the relative-path problem, got:\n%s", out)
	}
}
