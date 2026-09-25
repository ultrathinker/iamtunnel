//go:build windows

// IAMT-70: the cross-process file lock must actually exclude a
// second process. A goroutine-only test cannot prove this — the
// Door's in-process mutex (doors.go) already serialises goroutines,
// so a broken AcquireFileLock (e.g. plain os.OpenFile, which asks
// Windows for FILE_SHARE_READ|FILE_SHARE_WRITE) would still pass a
// goroutine test. Every test below spawns a real second OS process,
// the same way doorwatch_test.go does for the watchdog.
//
// Gate table:
//
//  1. A holds, B denied            -> TestFileLock_SecondProcessDenied
//  2. A releases, B gets it        -> TestFileLock_ReleasedAfterGracefulRelease
//  3. A killed, lock frees, B gets -> TestFileLock_ReleasedWhenHolderKilled
//  4. stuck holder -> bounded error -> TestAcquireFileLock_TimesOutOnStuckHolder
//  5. no loss / no duplicate       -> TestCrossProcessInstallRemove_NoLossNoDuplicate
package winkeys

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// buildLockTestBinaries compiles the two helper programs used by
// every test in this file. Built once per test via t.TempDir(), the
// same pattern buildWatchdogTestBinaries uses in doorwatch_test.go.
func buildLockTestBinaries(t *testing.T) (holderExe, cyclerExe string) {
	t.Helper()
	dir := t.TempDir()
	holderExe = filepath.Join(dir, "holder.exe")
	cyclerExe = filepath.Join(dir, "cycler.exe")

	buildPackage(t, holderExe, testdataPackage("helper_filelock_holder"))
	buildPackage(t, cyclerExe, testdataPackage("helper_door_cycler"))
	return holderExe, cyclerExe
}

// startHolder spawns helper_filelock_holder against keyFile and
// blocks until it has published proof that it holds the lock
// (pidFile appears). releaseFile is optional: pass "" for a holder
// that never releases on its own (tests 1, 3, 4); pass a path for a
// holder that releases once that path exists (test 2).
func startHolder(t *testing.T, holderExe, keyFile, releaseFile string) (cmd *exec.Cmd, pidFile string) {
	t.Helper()
	pidFile = keyFile + ".holder.pid"
	args := []string{keyFile, pidFile}
	if releaseFile != "" {
		args = append(args, releaseFile)
	}
	cmd = exec.Command(holderExe, args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start holder: %v", err)
	}
	waitForFile(t, pidFile, 5*time.Second)
	return cmd, pidFile
}

func killHolder(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = exec.Command("taskkill", "/f", "/pid", strconv.Itoa(cmd.Process.Pid)).Run()
	_ = cmd.Wait()
}

// waitForFile polls until path exists or the deadline passes.
func waitForFile(t *testing.T, path string, max time.Duration) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s did not appear within %s", path, max)
}

// TestFileLock_SecondProcessDenied is gate table point 1: a real
// second process holding the lock must make AcquireFileLock in this
// (different) process fail, not succeed. Under the pre-fix
// os.OpenFile implementation this test is red: os.OpenFile asks for
// FILE_SHARE_READ|FILE_SHARE_WRITE, so the second open always
// succeeds and this test's AcquireFileLock call returns nil, nil.
func TestFileLock_SecondProcessDenied(t *testing.T) {
	holderExe, _ := buildLockTestBinaries(t)
	keyFile := filepath.Join(t.TempDir(), "testkeys")

	cmd, _ := startHolder(t, holderExe, keyFile, "")
	defer killHolder(cmd)

	lock, err := AcquireFileLock(keyFile + ".lock")
	if err == nil {
		lock.Release()
		t.Fatalf("AcquireFileLock succeeded while a separate process holds the lock — the lock does not exclude")
	}
	if !strings.Contains(err.Error(), "held by another writer") {
		t.Fatalf("unexpected error shape: %v", err)
	}
}

// TestFileLock_ReleasedAfterGracefulRelease is gate table point 2: once
// process A releases, process B (this test) must be able to acquire.
func TestFileLock_ReleasedAfterGracefulRelease(t *testing.T) {
	holderExe, _ := buildLockTestBinaries(t)
	keyFile := filepath.Join(t.TempDir(), "testkeys")
	releaseFile := keyFile + ".release-me"

	cmd, pidFile := startHolder(t, holderExe, keyFile, releaseFile)
	defer killHolder(cmd)

	// Confirm denial first — otherwise a "succeeds immediately" bug
	// would make the release step meaningless.
	if lock, err := AcquireFileLock(keyFile + ".lock"); err == nil {
		lock.Release()
		t.Fatalf("AcquireFileLock succeeded before the holder released")
	}

	if err := os.WriteFile(releaseFile, []byte("go"), 0o600); err != nil {
		t.Fatalf("signal release: %v", err)
	}
	waitForFile(t, pidFile+".released", 5*time.Second)

	lock, err := AcquireFileLock(keyFile + ".lock")
	if err != nil {
		t.Fatalf("AcquireFileLock failed after holder released: %v", err)
	}
	defer lock.Release()
}

// TestFileLock_ReleasedWhenHolderKilled is gate table point 3: process
// A is killed with taskkill /f (no graceful shutdown at all), and
// the lock must free itself — because Windows closes every handle a
// killed process owned. This is the failure mode this whole design is
// about: a design where the holder must run cleanup code to release
// would leave the door locked forever the moment the server crashes.
func TestFileLock_ReleasedWhenHolderKilled(t *testing.T) {
	holderExe, _ := buildLockTestBinaries(t)
	keyFile := filepath.Join(t.TempDir(), "testkeys")

	cmd, _ := startHolder(t, holderExe, keyFile, "")

	if lock, err := AcquireFileLock(keyFile + ".lock"); err == nil {
		lock.Release()
		t.Fatalf("AcquireFileLock succeeded before the holder was killed")
	}

	if err := exec.Command("taskkill", "/f", "/pid", strconv.Itoa(cmd.Process.Pid)).Run(); err != nil {
		t.Fatalf("taskkill: %v", err)
	}
	_ = cmd.Wait()

	// The lock must free itself promptly; poll well inside
	// AcquireFileLock's own ~2s budget times a small safety margin.
	deadline := time.Now().Add(5 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		lock, err := AcquireFileLock(keyFile + ".lock")
		if err == nil {
			lock.Release()
			return
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("lock never freed after holder was killed: %v", lastErr)
}

// TestAcquireFileLock_TimesOutOnStuckHolder is gate table point 4: a
// holder that never releases must turn AcquireFileLock into a
// bounded error, not a hang. The test itself must be able to fail
// via its own timeout — the outer select below is exactly that: if
// AcquireFileLock regresses to blocking forever, this test goes red
// on its own 10s bound instead of hanging the whole suite.
func TestAcquireFileLock_TimesOutOnStuckHolder(t *testing.T) {
	holderExe, _ := buildLockTestBinaries(t)
	keyFile := filepath.Join(t.TempDir(), "testkeys")

	cmd, _ := startHolder(t, holderExe, keyFile, "")
	defer killHolder(cmd)

	type result struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		_, err := AcquireFileLock(keyFile + ".lock")
		done <- result{err: err, elapsed: time.Since(start)}
	}()

	select {
	case r := <-done:
		if r.err == nil {
			t.Fatalf("AcquireFileLock succeeded against a permanently stuck holder")
		}
		// AcquireFileLock's documented budget is ~25*80ms = ~2s.
		// Give it generous slack for a loaded CI box, but a value
		// anywhere near the 10s outer bound means the retry loop is
		// not doing what the comment says.
		if r.elapsed > 5*time.Second {
			t.Fatalf("AcquireFileLock took %s to give up, budget is ~2s", r.elapsed)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("AcquireFileLock did not return within 10s — it hung instead of erroring on a stuck holder")
	}
}

// TestCrossProcessInstallRemove_NoLossNoDuplicate is gate table point
// 5, the load-bearing assertion: two independent OS processes
// hammering Install/Remove on the SAME key file, hundreds of times
// each (not once, not twice — a "ran it
// twice" proof is explicitly rejected), must never lose a foreign
// line and must never leave a door's line duplicated. This is the
// cross-process twin of
// TestConcurrentInstallAndRemove in doors_test.go: each process
// always ends its own cycle on Remove(myID), so a correctly
// serialised run always converges to zero iamtunnel lines — any
// stray line left behind, or any foreign line altered, means the
// lock let the two processes race on the file. Every Install/Remove
// call also carries its own read-back proof (doors.go), so a lock
// that lets the two processes interleave a read-modify-write can
// also surface as a non-zero helper exit.
func TestCrossProcessInstallRemove_NoLossNoDuplicate(t *testing.T) {
	_, cyclerExe := buildLockTestBinaries(t)
	keyFile := filepath.Join(t.TempDir(), "testkeys")

	foreign := []string{
		`# admin key - must never move or duplicate`,
		`ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAforeignKeyOneDoNotTouchThisLine admin@example.org`,
		`ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCforeignKeyTwoBackupServiceDoNotTouch backup@example.org`,
	}
	if err := os.WriteFile(keyFile, []byte(strings.Join(foreign, "\r\n")+"\r\n"), 0o600); err != nil {
		t.Fatalf("seed foreign lines: %v", err)
	}

	const iterations = 300 // hundreds of cross-process lock acquisitions, not two
	idA := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	idB := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	cmdA := exec.Command(cyclerExe, keyFile, idA, strconv.Itoa(iterations))
	cmdB := exec.Command(cyclerExe, keyFile, idB, strconv.Itoa(iterations))
	var bufA, bufB strings.Builder
	cmdA.Stdout, cmdA.Stderr = &bufA, &bufA
	cmdB.Stdout, cmdB.Stderr = &bufB, &bufB

	if err := cmdA.Start(); err != nil {
		t.Fatalf("start cycler A: %v", err)
	}
	if err := cmdB.Start(); err != nil {
		t.Fatalf("start cycler B: %v", err)
	}
	errA := cmdA.Wait()
	errB := cmdB.Wait()
	if errA != nil {
		t.Fatalf("cycler A failed after %d iterations: %v\n%s", iterations, errA, bufA.String())
	}
	if errB != nil {
		t.Fatalf("cycler B failed after %d iterations: %v\n%s", iterations, errB, bufB.String())
	}

	got, err := readLinesLocked(keyFile)
	if err != nil {
		t.Fatalf("read final file: %v", err)
	}

	// No loss: every foreign line present, byte-for-byte, in order.
	var gotForeign []string
	for _, l := range got {
		if !IsOurs(l) {
			gotForeign = append(gotForeign, l)
		}
	}
	if len(gotForeign) != len(foreign) {
		t.Fatalf("foreign line count changed: want %d got %d\nwant=%v\ngot=%v", len(foreign), len(gotForeign), foreign, gotForeign)
	}
	for i := range foreign {
		if gotForeign[i] != foreign[i] {
			t.Fatalf("foreign line %d corrupted: want %q got %q", i, foreign[i], gotForeign[i])
		}
	}

	// No duplication, no leftover: both cyclers end their own cycle
	// on Remove(myID), so a correctly serialised run leaves zero
	// iamtunnel lines. A stray line (of either ID) here means some
	// Install/Remove pair from one process was invisible to the
	// other — the file lock let them race.
	ourCount := 0
	for _, l := range got {
		if IsOurs(l) {
			ourCount++
			t.Logf("unexpected leftover line: %q", l)
		}
	}
	if ourCount != 0 {
		t.Errorf("expected 0 iamtunnel lines after both cyclers finished, got %d", ourCount)
	}
}
