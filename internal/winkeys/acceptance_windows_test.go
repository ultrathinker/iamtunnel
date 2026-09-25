//go:build windows

// Windows-only acceptance tests for the winkeys package. These
// exercise the ACL lockdown, the doorwatch with the real built
// binary, and the cross-process file lock. None of these work on
// non-Windows because the package's Windows ACL / OpenProcess /
// WaitForSingleObject / file-share-none primitives are stubbed out
// on Linux. The cross-platform invariant tests are in
// acceptance_test.go.

package winkeys

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ─── Claim 3 — ACL lockdown to two owners, stays after reinstalls ────────

// TestAcceptance_ACLExactlyTwoOwners runs Install five times in a
// row and, after each call, asserts:
//   - the DACL contains exactly two non-inherited ACEs;
//   - both trustees are NT AUTHORITY\SYSTEM and BUILTIN\Administrators;
//   - SE_DACL_PROTECTED is set on the security descriptor.
//
// A red-flag test under any of these regressions:
//   - lockDownACL forgets SE_DACL_PROTECTED — inherited entries
//     leak in on the second Install;
//   - lockDownACL stops being called by Install — file DACL is
//     whatever the OS default was;
//   - lockDownACL widens the trustee list to include the user or
//     Everyone — len(names) != 2.
func TestAcceptance_ACLExactlyTwoOwners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "testkeys")
	if err := os.WriteFile(path, []byte("seed\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := NewDoor(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		id := makeID(t)
		if err := d.Install(id, TestKey); err != nil {
			t.Fatalf("Install #%d: %v", i, err)
		}
		names, err := ReadDACL(path)
		if err != nil {
			t.Fatalf("Install #%d ReadDACL: %v", i, err)
		}
		sort.Strings(names)
		want := []string{`BUILTIN\Administrators`, `NT AUTHORITY\SYSTEM`}
		if len(names) != len(want) {
			t.Fatalf("Install #%d: DACL has %d ACEs, want exactly %d: %v", i, len(names), len(want), names)
		}
		for j := range want {
			if names[j] != want[j] {
				t.Errorf("Install #%d: ACE[%d] = %q, want %q", i, j, names[j], want[j])
			}
		}
		prot, err := DACLProtected(path)
		if err != nil {
			t.Fatalf("Install #%d DACLProtected: %v", i, err)
		}
		if !prot {
			t.Errorf("Install #%d: SE_DACL_PROTECTED not set", i)
		}
	}
}

// ─── Claim 4 — watchdog removes the line, real built program ─────────────

// TestAcceptance_WatchdogRealBinaryAfterTaskkillF rebuilds the real
// iamtunnel binary as the watchdog (the same binary the production
// server role spawns) and a separate parent helper that installs a
// door line. The test then runs taskkill /f against the parent. The
// watchdog MUST remove the door line within the wait budget.
//
// The parent is a separate process so the test process itself is
// not killed by taskkill — the watcher is on the parent's PID.
// The watchdog is the real iamtunnel binary, not a hand-rolled
// helper, so the test exercises the production code path end to
// end. All paths stay inside t.TempDir().
func TestAcceptance_WatchdogRealBinaryAfterTaskkillF(t *testing.T) {
	exe := buildRealBinary(t)
	keyFile := filepath.Join(t.TempDir(), "testkeys")

	foreignBefore := []string{
		`# System administrator key — must never be deleted`,
		`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdminKeyBobForTestingOnlyDoNotUse111 admin@company.org`,
		`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCbackupServiceKeyNightlyRunDoNotTouch backup@company.org`,
	}
	if err := os.WriteFile(keyFile, []byte(strings.Join(foreignBefore, "\r\n")+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	parentExe, _ := buildParentHelper(t)
	cmd := exec.Command(parentExe, keyFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		_ = exec.Command("taskkill", "/f", "/pid", strconv.Itoa(cmd.Process.Pid)).Run()
	}()

	helperPID := waitForPID(t, keyFile+".parent.pid", 5*time.Second)
	if err := waitForOurs(t, keyFile, true, 5*time.Second); err != nil {
		t.Fatalf("setup: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}

	doorID := findOurDoorID(t, keyFile)
	wd, err := SpawnWatchdog(exe, doorID, keyFile, helperPID, 10*time.Minute, "", "", 0, 0)
	if err != nil {
		t.Fatalf("SpawnWatchdog: %v", err)
	}
	defer wd.Stop()

	time.Sleep(500 * time.Millisecond)

	if err := exec.Command("taskkill", "/f", "/pid", strconv.Itoa(helperPID)).Run(); err != nil {
		t.Logf("taskkill warning: %v", err)
	}

	if err := waitForOurs(t, keyFile, false, 15*time.Second); err != nil {
		t.Fatalf("doorwatch did not clean up: %v\nfile:\n%s", err, dumpBytes(t, keyFile))
	}

	got, err := readLinesLocked(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range got {
		if IsOurs(l) {
			t.Fatalf("door line still in file after taskkill: %q", l)
		}
	}
	if len(got) != len(foreignBefore) {
		t.Fatalf("foreign lines count: want %d got %d\nfile:\n%s", len(foreignBefore), len(got), dumpBytes(t, keyFile))
	}
	for i, fb := range foreignBefore {
		if got[i] != fb {
			t.Errorf("foreign line %d altered: want %q got %q", i, fb, got[i])
		}
	}
}

// buildRealBinary builds the iamtunnel binary (cmd/iamtunnel) into
// a fresh temp dir and returns its absolute path. The binary is the
// real production binary the server role spawns — same argv layout,
// same RunWatchdog. CGO_ENABLED=1 is required for the race
// detector and for the file-locking primitives.
func buildRealBinary(t *testing.T) string {
	t.Helper()
	return buildIamtunnel(t, filepath.Join(t.TempDir(), "iamtunnel.exe"))
}

// buildParentHelper builds the helper_watchdog_parent test binary
// from this package's testdata into a fresh temp dir.
func buildParentHelper(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	parentExe := buildPackage(t, filepath.Join(dir, "parent.exe"), testdataPackage("helper_watchdog_parent"))
	return parentExe, dir
}

// ─── Claim 7 — file lock at the right path ───────────────────────────────

// TestAcceptance_FileLockPathIsCorrect verifies that the lock file
// is created at <keyFile>.lock (NOT <keyFile> itself) and is left
// in place after Release. A regression where the lock path drifts
// to the key file itself would either block sshd from reading the
// keys or, worse, replace the keys with the lock.
//
// Sensitive to: changes in the lock-path constant, file mode on
// lock creation, Release deleting the lock (the spike/WinKeys.cs
// behaviour is to leave it in place).
func TestAcceptance_FileLockPathIsCorrect(t *testing.T) {
	path := freshPath(t)
	lockPath := path + ".lock"

	if _, err := os.Stat(lockPath); !os.IsNotExist(err) {
		t.Fatalf("lock file unexpectedly exists before Install: %v", err)
	}

	d, err := NewDoor(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	id := makeID(t)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatalf("Install: %v", err)
	}

	if _, err := os.Stat(lockPath); err != nil {
		t.Errorf("lock file %s missing after Install: %v", lockPath, err)
	}

	lines, err := d.ReadLines()
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) == 0 {
		t.Errorf("key file %s unexpectedly empty — lock may have overwritten it", path)
	}

	info, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Errorf("lock file is not regular: mode=%v", info.Mode())
	}

	if err := d.Remove(id); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(lockPath); err != nil {
		t.Errorf("lock file vanished after Remove: %v", err)
	}
}

// ─── shared helpers used by the watchdog test ───────────────────────────

// winkeysDir and winkeysRepoRoot (this package's source directory and the
// module root above it) live in moduleroot_test.go, untagged: they derive both
// paths from this file's own path instead of os.Getwd(), which IAMT-305 round 3
// showed a chdir-ing test in this package can move out from under a build
// helper (the full package run built from "/" and failed with "go.mod file not
// found").
