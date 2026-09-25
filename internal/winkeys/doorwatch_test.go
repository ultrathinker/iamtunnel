//go:build windows

// Layer 3 test: spawn a real doorwatch child process, install a
// line as a "parent" (a separate helper binary), taskkill the
// parent with /f, and verify the watcher removes the line.
//
// The full sequence is the one the server role relies on at
// runtime:
//
//   1. Server spawns watchdog BEFORE writing the door line.
//   2. Server writes the door line under file lock; the watcher's
//      WaitForSingleObject is already in flight on the parent PID.
//   3. Server dies (any cause: Stop, crash, taskkill /f, power
//      loss).
//   4. Watcher's wait fires; it removes the door line; exits.
//
// Step 1 + step 2 + step 4 are exercised here.

package winkeys

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// dumpFile reads a file's contents for failure messages in Windows-only
// doorwatch tests.
func dumpFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("<read err %v>", err)
	}
	return string(b)
}

// TestDoorwatch_RemovesLineAfterTaskkillF is the headline test for
// layer 3. We split the "parent" into a separate helper binary so
// the test process itself is not the parent we kill — keeping the
// test running while the watchdog-cleanup happens elsewhere.
// It compiles the REAL iamtunnel program, launches it as the watchdog,
// kills the parent with taskkill /f, and verifies both that the door line
// disappeared and that foreign lines are untouched byte-for-byte.
func TestDoorwatch_RemovesLineAfterTaskkillF(t *testing.T) {
	parentExe, wdExe := buildWatchdogTestBinaries(t)

	keyFile := filepath.Join(t.TempDir(), "testkeys")

	// Pre-populate keyFile with foreign lines (SPEC §6.3, gate 4):
	// other people's lines must remain completely untouched byte-for-byte.
	foreignBefore := []string{
		"# System administrator key - must never be deleted",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdminKeyBobForTestingOnlyDoNotUse111 admin@company.org",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCbackupServiceKeyNightlyRunDoNotTouch backup@company.org",
	}
	initialContent := strings.Join(foreignBefore, "\r\n") + "\r\n"
	if err := os.WriteFile(keyFile, []byte(initialContent), 0o600); err != nil {
		t.Fatalf("setup foreign lines: %v", err)
	}

	cmd := exec.Command(parentExe, keyFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		// Best-effort cleanup if the test fails mid-run.
		_ = exec.Command("taskkill", "/f", "/pid", strconv.Itoa(cmd.Process.Pid)).Run()
	}()

	// Wait for the helper to publish its PID. The helper installs
	// the line FIRST and THEN writes the .parent.pid file; once
	// we see the file, the line is already in place.
	pidPath := keyFile + ".parent.pid"
	helperPID := waitForPID(t, pidPath, 5*time.Second)

	// Read-back proof: the line must be present BEFORE we
	// spawn the watcher. Use IsOursID with any door-id format
	// that the helper might have produced; the test only cares
	// that SOME iamtunnel line is present.
	if err := waitForOurs(t, keyFile, true, 5*time.Second); err != nil {
		t.Fatalf("setup: %v", err)
	}
	t.Logf("BEFORE:\n%s", dumpFile(t, keyFile))

	// Spawn the watchdog detached from any job object, no
	// console window. We pass the helper's PID and the REAL iamtunnel binary.
	doorID := findOurDoorID(t, keyFile)
	wd, err := SpawnWatchdog(wdExe, doorID, keyFile, helperPID, 10*time.Minute, "", "", 0, 0)
	if err != nil {
		t.Fatalf("SpawnWatchdog: %v", err)
	}
	defer wd.Stop()
	t.Logf("spawned watcher pid=%d for parent=%d file=%s", wd.PID(), helperPID, keyFile)

	// Give the watcher a moment to OpenProcess and settle.
	time.Sleep(500 * time.Millisecond)

	// taskkill /f /pid <helperPID> — the test does NOT exit.
	if err := exec.Command("taskkill", "/f", "/pid", strconv.Itoa(helperPID)).Run(); err != nil {
		t.Logf("taskkill warning: %v", err)
	}

	// Watcher must remove the line within 10 s. (Real production
	// expectation: under 1 s.)
	if err := waitForOurs(t, keyFile, false, 10*time.Second); err != nil {
		t.Fatalf("doorwatch did not clean up: %v\n%s", err, dumpFile(t, keyFile))
	}
	t.Logf("AFTER:\n%s", dumpFile(t, keyFile))

	// Verify foreign lines are untouched byte-for-byte (Gate 4)
	linesAfter, err := readLinesLocked(keyFile)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	for _, l := range linesAfter {
		if IsOurs(l) {
			t.Fatalf("door line still in %s: %s", keyFile, l)
		}
	}
	if len(linesAfter) != len(foreignBefore) {
		t.Fatalf("expected %d foreign lines after cleanup, got %d:\n%s", len(foreignBefore), len(linesAfter), dumpFile(t, keyFile))
	}
	for i, fb := range foreignBefore {
		if linesAfter[i] != fb {
			t.Fatalf("line %d altered: want %q, got %q", i, fb, linesAfter[i])
		}
	}
}

// TestDoorwatch_RunsWhenParentAlreadyDead covers the race between
// SpawnWatchdog and a very-fast parent crash: if the parent is
// already gone before the watcher opens a SYNCHRONIZE handle,
// the watcher still removes the line if one is there.
func TestDoorwatch_RunsWhenParentAlreadyDead(t *testing.T) {
	parentExe, wdExe := buildWatchdogTestBinaries(t)
	keyFile := filepath.Join(t.TempDir(), "testkeys")

	foreignBefore := []string{
		"# System administrator key - must never be deleted",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdminKeyBobForTestingOnlyDoNotUse111 admin@company.org",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCbackupServiceKeyNightlyRunDoNotTouch backup@company.org",
	}
	initialContent := strings.Join(foreignBefore, "\r\n") + "\r\n"
	if err := os.WriteFile(keyFile, []byte(initialContent), 0o600); err != nil {
		t.Fatalf("setup foreign lines: %v", err)
	}

	// Spawn helper, wait for it to publish its PID, then kill
	// it before spawning the watcher.
	cmd := exec.Command(parentExe, keyFile)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	helperPID := waitForPID(t, keyFile+".parent.pid", 5*time.Second)
	if err := exec.Command("taskkill", "/f", "/pid", strconv.Itoa(helperPID)).Run(); err != nil {
		t.Logf("taskkill warning: %v", err)
	}
	// Wait for the line to be present. The helper installs
	// before publishing its PID, so the line is already there.
	if err := waitForOurs(t, keyFile, true, 5*time.Second); err != nil {
		t.Fatalf("setup: helper died before publishing its line: %v", err)
	}

	// Spawn watcher against an already-dead parent. The
	// watchdog should still remove the line.
	doorID := findOurDoorID(t, keyFile)
	wd, err := SpawnWatchdog(wdExe, doorID, keyFile, helperPID, 10*time.Minute, "", "", 0, 0)
	if err != nil {
		t.Fatalf("SpawnWatchdog: %v", err)
	}
	defer wd.Stop()
	if err := waitForOurs(t, keyFile, false, 10*time.Second); err != nil {
		t.Fatalf("late watcher did not clean up: %v", err)
	}

	// Verify foreign lines are untouched byte-for-byte
	linesAfter, err := readLinesLocked(keyFile)
	if err != nil {
		t.Fatalf("read after: %v", err)
	}
	for _, l := range linesAfter {
		if IsOurs(l) {
			t.Fatalf("door line still in %s: %s", keyFile, l)
		}
	}
	if len(linesAfter) != len(foreignBefore) {
		t.Fatalf("expected %d foreign lines after cleanup, got %d:\n%s", len(foreignBefore), len(linesAfter), dumpFile(t, keyFile))
	}
	for i, fb := range foreignBefore {
		if linesAfter[i] != fb {
			t.Fatalf("line %d altered: want %q, got %q", i, fb, linesAfter[i])
		}
	}
}

// TestDoorwatch_StopReturnsNoErrorOnNil confirms the server role's
// "Stop after confirmed close" call against a possibly-already-
// dead watchdog does not panic and does not error.
func TestDoorwatch_StopOnNilReceiver(t *testing.T) {
	var wd *Watchdog
	if err := wd.Stop(); err != nil {
		t.Fatalf("Stop on nil must return nil, got %v", err)
	}
}

// TestDoorwatch_RunWatchdogHonoursMaxWait is the IAMT-130 proof that
// the watchdog's safety cap on the parent wait actually flows from
// the spawner's value, not from a hard-coded 5 minutes. We point
// RunWatchdog at the test process itself (which is alive and will
// stay alive for the duration of the test) with a deliberately
// tiny maxWait, and assert it returns the timeout error within a
// bound larger than maxWait but much smaller than the old 5 minutes.
//
// FAILURE MODES that should make this test red:
//   - the run site re-hardcodes 5*time.Minute — the call never
//     returns inside the test budget and we t.Fatal with a message
//     naming RunWatchdog's maxWait;
//   - the cmdline argv does not carry maxWait through, so the
//     child uses a default and the same thing happens.
//
// Setup failures (cannot install the file, the helper binary does
// not build, etc.) are surfaced via separate t.Fatalf calls so they
// do not look like the discovery we are after.
func TestDoorwatch_RunWatchdogHonoursMaxWait(t *testing.T) {
	const maxWait = 200 * time.Millisecond
	parentPID := os.Getpid()
	keyFile := filepath.Join(t.TempDir(), "testkeys")
	if err := os.WriteFile(keyFile, nil, 0o600); err != nil {
		t.Fatalf("setup: create empty keyfile: %v", err)
	}
	doorID := strings.Repeat("a", 32)

	start := time.Now()
	err := RunWatchdog(parentPID, doorID, keyFile, nil, maxWait, "", 0, 0)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("RunWatchdog must return a timeout error against a live parent with maxWait=%s", maxWait)
	}
	if !strings.Contains(err.Error(), "still alive") {
		t.Fatalf("RunWatchdog returned %v, want the \"still alive after %s\" timeout error", err, maxWait)
	}
	// We expect RunWatchdog to give up after approximately maxWait,
	// plus a small loop iteration (RunWatchdog waits up to 500 ms
	// inside WaitForSingleObject before re-checking the deadline).
	// 5 * maxWait is comfortably larger than the natural loop slack
	// (≈500 ms) yet vastly smaller than the old 5-minute hard-code.
	if elapsed > 5*maxWait {
		t.Fatalf("RunWatchdog waited %s, which is more than 5x the configured maxWait %s — the safety cap is not the one passed in", elapsed, maxWait)
	}
}

// TestDoorwatch_AuditEventWrittenOnParentDeath is the IAMT-130 proof
// that the watchdog's layer-3 cleanup lands a distinct audit event
// in the journal — the exact distinction the audit-sink plumbing
// was added for. We start a real parent helper, wait for it to write
// the door line, spawn the watchdog with a journal path under
// t.TempDir(), kill the parent, and assert the journal contains a
// close event for our door-id.
//
// FAILURE MODES that should make this test red:
//   - the run site still passes sink=nil — the journal stays empty
//     and we t.Fatalf naming the missing close event;
//   - the spawner drops the journal path from argv — same outcome.
//
// Setup failures are reported separately and do not constitute the
// discovery.
func TestDoorwatch_AuditEventWrittenOnParentDeath(t *testing.T) {
	parentExe, wdExe := buildWatchdogTestBinaries(t)

	keyFile := filepath.Join(t.TempDir(), "testkeys")
	if err := os.WriteFile(keyFile, nil, 0o600); err != nil {
		t.Fatalf("setup: create empty keyfile: %v", err)
	}
	journal := filepath.Join(t.TempDir(), "journal.jsonl")

	cmd := exec.Command(parentExe, keyFile)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	defer func() {
		_ = exec.Command("taskkill", "/f", "/pid", strconv.Itoa(cmd.Process.Pid)).Run()
	}()
	helperPID := waitForPID(t, keyFile+".parent.pid", 5*time.Second)
	if err := waitForOurs(t, keyFile, true, 5*time.Second); err != nil {
		t.Fatalf("setup: helper did not install the door line: %v", err)
	}
	doorID := findOurDoorID(t, keyFile)

	wd, err := SpawnWatchdog(wdExe, doorID, keyFile, helperPID, 10*time.Minute, journal, "", 0, 0)
	if err != nil {
		t.Fatalf("SpawnWatchdog: %v", err)
	}
	defer wd.Stop()
	time.Sleep(500 * time.Millisecond)

	if err := exec.Command("taskkill", "/f", "/pid", strconv.Itoa(helperPID)).Run(); err != nil {
		t.Logf("taskkill warning: %v", err)
	}

	// The journal must contain a close event for our door-id. We
	// do NOT wait for a specific elapsed time — only until the
	// file appears or the test budget is up.
	deadline := time.Now().Add(15 * time.Second)
	var contents []byte
	for time.Now().Before(deadline) {
		contents, err = os.ReadFile(journal)
		if err == nil && len(contents) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if len(contents) == 0 {
		t.Fatalf("journal at %s is empty after the parent was killed — the watchdog's layer-3 cleanup did NOT write a distinct audit event for door %s", journal, doorID)
	}
	if !strings.Contains(string(contents), `"Op":"close"`) {
		t.Fatalf("journal at %s has no close event:\n%s", journal, string(contents))
	}
	if !strings.Contains(string(contents), doorID) {
		t.Fatalf("journal at %s has no record for door %s:\n%s", journal, doorID, string(contents))
	}
}

func buildWatchdogTestBinaries(t *testing.T) (parentExe, wdExe string) {
	t.Helper()
	dir := t.TempDir()
	parentExe = filepath.Join(dir, "parent.exe")
	wdExe = filepath.Join(dir, "iamtunnel.exe")

	buildPackage(t, parentExe, testdataPackage("helper_watchdog_parent"))
	return parentExe, buildIamtunnel(t, wdExe)
}

func waitForPID(t *testing.T, path string, max time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			s := strings.TrimSpace(string(b))
			if n, err := strconv.Atoi(s); err == nil {
				return n
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("PID file %s did not appear within %s", path, max)
	return 0
}

func waitForOurs(t *testing.T, path string, present bool, max time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		lines, err := readLinesLocked(path)
		if err == nil {
			found := false
			for _, l := range lines {
				if IsOurs(l) {
					found = true
					break
				}
			}
			if found == present {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if present {
		return fmt.Errorf("no iamtunnel line appeared in %s within %s", path, max)
	}
	return fmt.Errorf("iamtunnel line still in %s after %s", path, max)
}

func findOurDoorID(t *testing.T, path string) string {
	t.Helper()
	lines, err := readLinesLocked(path)
	if err != nil {
		t.Fatalf("readLines: %v", err)
	}
	for _, l := range lines {
		if IsOurs(l) {
			idx := strings.Index(l, Marker)
			if idx < 0 {
				continue
			}
			tail := l[idx+len(Marker):]
			if len(tail) >= 32 {
				return tail[:32]
			}
		}
	}
	t.Fatalf("no iamtunnel line found in %s: %v", path, lines)
	return ""
}

// TestDoorwatch_StopCachesTheStatusItReaps is the Windows half of the round-4
// exit-status contract (the whole of it is stated in
// doorwatch_exitstatus_test.go; the Linux sibling lives in
// doorwatch_linux_test.go), driven through the real Stop the server role calls.
//
// Stop reaps the child — it has to, or a killed watcher stays a zombie — and on
// Windows it also closes the process handle. Both are one-way: after them
// GetExitCodeProcess can only answer ERROR_INVALID_HANDLE. So the code has to be
// read and cached inside Stop, and that is what makes the sequence
//
//	wd.Stop()
//	wd.ExitStatus()
//
// answer on Windows the way it answers on Unix instead of erroring where Unix
// used to invent a zero.
//
// Canary: drop the watchdogExitCode call from Stop (or move it after
// CloseHandle) and this test fails with "ExitStatus after Stop: <error> ..." —
// the handle is gone and the code with it.
func TestDoorwatch_StopCachesTheStatusItReaps(t *testing.T) {
	_, wdExe := buildWatchdogTestBinaries(t)
	keyFile := filepath.Join(t.TempDir(), "testkeys")
	if err := os.WriteFile(keyFile, nil, 0o600); err != nil {
		t.Fatalf("setup: create empty keyfile: %v", err)
	}

	// The parent is this test process, which stays alive, so the watcher keeps
	// waiting instead of cleaning anything up: the key file is not touched.
	wd, err := SpawnWatchdog(wdExe, strings.Repeat("a", 32), keyFile, os.Getpid(), 10*time.Minute, "", "", 0, 0)
	if err != nil {
		t.Fatalf("SpawnWatchdog: %v", err)
	}
	t.Cleanup(func() { _ = wd.Stop() })

	// No status exists yet, and that answer must stay distinguishable from the
	// "the status is gone" one below: still running is not an error.
	if exited, code, err := wd.ExitStatus(); exited || code != 0 || err != nil {
		t.Fatalf("a live watcher reported (exited=%v, code=%d, err=%v), want (false, 0, nil)", exited, code, err)
	}

	if err := wd.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	exited, code, err := wd.ExitStatus()
	if err != nil {
		t.Fatalf("ExitStatus after Stop: %v — Stop closes the process handle, so the status it read must be cached; without the cache nothing is left to probe (IAMT-305 round 4)", err)
	}
	if !exited {
		t.Fatal("ExitStatus after Stop reported the reaped watcher as still running")
	}
	if code != 1 {
		t.Fatalf("ExitStatus after Stop reported code %d, want 1 — the code Stop hands TerminateProcess and reads back before closing the handle; a 0 here would be a clean exit the watcher never had (IAMT-305 round 4)", code)
	}
}
