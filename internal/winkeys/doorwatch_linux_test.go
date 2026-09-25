//go:build linux

// Layer 3 tests on Linux (IAMT-247): spawn a real doorwatch child
// process, install a line as a "parent" (a separate helper
// binary), kill the parent with SIGKILL, and verify the watcher
// removes the line.
//
// The full sequence is the one the server role relies on at
// runtime:
//
//   1. Server spawns watchdog BEFORE writing the door line
//      (PROTOCOL §5.2).
//   2. Server writes the door line under file lock; the watcher's
//      pidfd poll is already in flight on the parent PID.
//   3. Server dies (any cause: Stop, crash, SIGKILL, power loss).
//   4. Watcher's poll on pidfd becomes readable; it removes the
//      door line; exits.
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

	"golang.org/x/sys/unix"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// buildLinuxWatchdogTestBinaries compiles, into the test's own
// t.TempDir(), the linux-side parent helper and the watchdog binary.
// In root environments (e.g. Docker CI), the real iamtunnel CLI binary
// can be used directly because requireServerElevation accepts euid==0.
// On normal developer machines (non-root, uid 1000), requireServerElevation
// in the CLI handler legitimately refuses ("root privileges are required").
// In that case, we build the wd_linux helper
// (github.com/ultrathinker/iamtunnel/internal/winkeys/testdata/wd_linux), which runs the identical
// ParseWatchdogArgsUnix and RunWatchdog logic without requiring root elevation.
func buildLinuxWatchdogTestBinaries(t *testing.T) (parentExe, wdExe string) {
	t.Helper()
	dir := t.TempDir()
	parentExe = filepath.Join(dir, "helper_watchdog_parent_linux")
	wdExe = filepath.Join(dir, "watchdog")

	buildPackage(t, parentExe, testdataPackage("helper_watchdog_parent_linux"))
	// Root environments (Docker CI) can use the real CLI binary as the
	// watchdog: requireServerElevation accepts euid==0 there. Everywhere else
	// the CLI refuses that verb by design, and ./testdata/wd_linux runs the
	// identical ParseWatchdogArgsUnix / RunWatchdog path without the gate.
	//
	// The real binary is built through testsupport.BuildIamtunnel (IAMT-302),
	// which picks the build environment and reports "this host cannot build a
	// cgo package" as ErrNoCgo — a skip, not a failure.
	if unix.Geteuid() == 0 {
		return parentExe, buildIamtunnel(t, wdExe)
	}
	buildPackage(t, wdExe, testdataPackage("wd_linux"))
	return parentExe, wdExe
}

// dumpFile reads a file's contents for failure messages.
func dumpFileLinux(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("<read err %v>", err)
	}
	return string(b)
}

// waitForPIDLinux is the linux analogue of waitForPID in
// doorwatch_test.go (which has a Windows build tag).
func waitForPIDLinux(t *testing.T, path string, max time.Duration) int {
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

// waitForOursLinux polls the key file for the presence or
// absence of an iamtunnel line. Foreign lines do not count.
func waitForOursLinux(t *testing.T, path string, present bool, max time.Duration) error {
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

// findOurDoorIDLinux locates the iamtunnel door-id the helper
// parent installed. Mirrors findOurDoorID in doorwatch_test.go.
func findOurDoorIDLinux(t *testing.T, path string) string {
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

// startLinuxParent brings up the helper parent in a fake ~/.ssh tree
// (mode 0700) and waits for it to publish its PID + door line. The caller is
// responsible for killing the returned command's process at the
// end of the test (typically via exec.Command("kill", ...)).
func startLinuxParent(t *testing.T, parentExe string, optionalKeyFile ...string) (*exec.Cmd, string, int) {
	t.Helper()
	var keyFile, lockPath string
	if len(optionalKeyFile) > 0 && optionalKeyFile[0] != "" {
		keyFile = optionalKeyFile[0]
		lockPath = filepath.Join(filepath.Dir(filepath.Dir(keyFile)), "door.lock")
	} else {
		tree := testsupport.NewSSHTree(t)
		keyFile = tree.KeyPath("authorized_keys")
		lockPath = filepath.Join(tree.Home, "door.lock")
	}

	// The helper builds its DoorOptions straight from these two argv
	// values, so they have to be this process's uid AND gid — passing the
	// uid twice (as this did before IAMT-284) is only right where uid==gid,
	// i.e. in a Linux container.
	cmd := exec.Command(parentExe, keyFile, lockPath, strconv.Itoa(testOwnerUID()), strconv.Itoa(testOwnerGID()))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start parent helper: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort cleanup if the test fails mid-run. The
		// test usually kills the parent itself, so this is a
		// safety net.
		_ = exec.Command("kill", "-9", strconv.Itoa(cmd.Process.Pid)).Run()
	})
	helperPID := waitForPIDLinux(t, keyFile+".parent.pid", 5*time.Second)
	if err := waitForOursLinux(t, keyFile, true, 5*time.Second); err != nil {
		t.Fatalf("setup: helper did not install the door line: %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
	}
	return cmd, keyFile, helperPID
}

// captureWatchdogStderrForTest turns the test-only stderr capture on for one
// test (doorwatch.go's captureWatchdogStderr) and restores it afterwards.
//
// Production sends the child's stderr to /dev/null on purpose (IAMT-305 round
// 3: a capture that only Watchdog.Stop removes leaks one temp file per door
// when the server is killed -9, the very case the watcher exists for), so a
// test that wants to print why a watcher died has to ask for the capture. Stop
// still removes the file these tests produce.
func captureWatchdogStderrForTest(t *testing.T) {
	t.Helper()
	prev := captureWatchdogStderr
	captureWatchdogStderr = true
	t.Cleanup(func() { captureWatchdogStderr = prev })
}

// TestDoorwatch_RemovesLineAfterParentKilled is the headline test
// for layer 3 on Linux. We split the "parent" into a separate
// helper binary so the test process itself is not the parent we
// kill — keeping the test running while the watchdog-cleanup
// happens elsewhere. It compiles the real iamtunnel program,
// launches it as the watchdog, kills the parent with SIGKILL,
// and verifies both that the door line disappeared and that
// foreign lines are untouched byte-for-byte.
//
// The canary: a fork that loses pidfd-open (e.g. swaps to a
// signal-only watchdog) would NOT remove the line within the
// test budget — the line stays behind and waitForOursLinux
// returns "iamtunnel line still in %s after %s", which is
// exactly what IAMT-130-style regressions used to look like
// (pre-fix doorwatch left the line behind until the next
// SweepStale). The failure message names pidfd specifically.
func TestDoorwatch_RemovesLineAfterParentKilled(t *testing.T) {
	captureWatchdogStderrForTest(t)
	parentExe, wdExe := buildLinuxWatchdogTestBinaries(t)

	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("authorized_keys")

	// Pre-populate keyFile with foreign lines (SPEC §6.3,
	// gate 4): other people's lines must remain completely
	// untouched byte-for-byte.
	foreignBefore := []string{
		"# System administrator key - must never be deleted",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdminKeyBobForTestingOnlyDoNotUse111 admin@company.org",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCbackupServiceKeyNightlyRunDoNotTouch backup",
	}
	tree.WriteKeyFile(t, "authorized_keys", []byte(strings.Join(foreignBefore, "\n")+"\n"))

	cmd, _, helperPID := startLinuxParent(t, parentExe, keyFile)

	// Spawn the watchdog detached into its own session, no
	// controlling terminal.
	doorID := findOurDoorIDLinux(t, keyFile)
	wd, err := SpawnWatchdog(wdExe, doorID, keyFile, helperPID, 10*time.Minute, "", filepath.Join(tree.Home, "door.lock"), testOwnerUID(), testOwnerGID())
	if err != nil {
		t.Fatalf("SpawnWatchdog: %v", err)
	}
	defer wd.Stop()
	t.Logf("spawned watcher pid=%d for parent=%d file=%s", wd.PID(), helperPID, keyFile)

	// Give the watcher a moment to open the pidfd and settle.
	time.Sleep(500 * time.Millisecond)

	// SIGKILL the helper — the test does NOT exit.
	if err := exec.Command("kill", "-9", strconv.Itoa(helperPID)).Run(); err != nil {
		t.Logf("kill warning: %v", err)
	}

	// Watcher must remove the line within 10 s. (Real
	// production expectation: under 1 s.)
	if err := waitForOursLinux(t, keyFile, false, 10*time.Second); err != nil {
		exited, exitCode, _ := wd.ExitStatus()
		t.Fatalf("doorwatch did not clean up after pidfd fired (watcher exited=%v, exitCode=%d, stderr=%q) — pidfd_open/poll path appears broken: %v\n%s",
			exited, exitCode, wd.Stderr(), err, dumpFileLinux(t, keyFile))
	}
	t.Logf("AFTER:\n%s", dumpFileLinux(t, keyFile))

	// Verify foreign lines are untouched byte-for-byte
	// (gate 4).
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
		t.Fatalf("expected %d foreign lines after cleanup, got %d:\n%s", len(foreignBefore), len(linesAfter), dumpFileLinux(t, keyFile))
	}
	for i, fb := range foreignBefore {
		if linesAfter[i] != fb {
			t.Fatalf("line %d altered: want %q, got %q", i, fb, linesAfter[i])
		}
	}
	_ = cmd
}

// TestDoorwatch_RunsWhenParentAlreadyDead covers the race between
// SpawnWatchdog and a very-fast parent crash: if the parent is
// already gone before the watcher opens its pidfd, the watcher
// still removes the line. unix.PidfdOpen returns ESRCH for a
// gone PID and RunWatchdog falls through to removeOnceAndAudit,
// exactly mirroring Windows' OpenProcess-fails branch.
func TestDoorwatch_RunsWhenParentAlreadyDead(t *testing.T) {
	captureWatchdogStderrForTest(t)
	parentExe, wdExe := buildLinuxWatchdogTestBinaries(t)

	// Spawn helper, wait for it to publish its PID + line,
	// then SIGKILL it before spawning the watcher.
	cmd, keyFile, helperPID := startLinuxParent(t, parentExe)
	if err := exec.Command("kill", "-9", strconv.Itoa(helperPID)).Run(); err != nil {
		t.Logf("kill warning: %v", err)
	}
	// Reap the killed parent process so it does not linger as a zombie.
	// This ensures pidfd_open(helperPID) encounters ESRCH on a gone PID.
	_ = cmd.Wait()

	if err := waitForOursLinux(t, keyFile, true, 5*time.Second); err != nil {
		t.Fatalf("setup: helper died before publishing its line: %v", err)
	}

	home := filepath.Dir(filepath.Dir(keyFile))
	lockPath := filepath.Join(home, "door.lock")

	doorID := findOurDoorIDLinux(t, keyFile)
	wd, err := SpawnWatchdog(wdExe, doorID, keyFile, helperPID, 10*time.Minute, "", lockPath, testOwnerUID(), testOwnerGID())
	if err != nil {
		t.Fatalf("SpawnWatchdog: %v", err)
	}
	defer wd.Stop()
	if err := waitForOursLinux(t, keyFile, false, 10*time.Second); err != nil {
		exited, exitCode, _ := wd.ExitStatus()
		t.Fatalf("late watcher did not clean up (watcher exited=%v, exitCode=%d, stderr=%q) — pidfd_open(ESRCH) branch must still reach removeOnceAndAudit: %v",
			exited, exitCode, wd.Stderr(), err)
	}
}

// TestDoorwatch_StopOnNilReceiver confirms the server role's
// "Stop after confirmed close" call against a possibly-already-
// dead watchdog does not panic and does not error. Cross-platform
// invariant (Windows test covers the same property).
func TestDoorwatch_StopOnNilReceiver(t *testing.T) {
	var wd *Watchdog
	if err := wd.Stop(); err != nil {
		t.Fatalf("Stop on nil must return nil, got %v", err)
	}
}

// TestDoorwatch_RunWatchdogHonoursMaxWait is the IAMT-130 proof
// that the watchdog's safety cap on the parent wait actually
// flows from the spawner's value, not from a hard-coded
// duration. We point RunWatchdog at the test process itself
// (which is alive and will stay alive for the duration of the
// test) with a deliberately tiny maxWait, and assert it returns
// the timeout error within a bound larger than maxWait but much
// smaller than a would-be hard-coded default.
//
// FAILURE MODES that should make this test red:
//   - RunWatchdog re-hardcodes any default — the call never
//     returns inside the test budget and t.Fatal names the
//     discrepancy;
//   - the cmdline argv does not carry maxWait through, so the
//     child uses a default and the same outcome.
//
// The Linux variant also tests that the new lockPath/OwnerUID/
// OwnerGID parameters are accepted; if RunWatchdog's signature
// ever regresses to the Windows shape, this test fails to
// compile.
func TestDoorwatch_RunWatchdogHonoursMaxWait(t *testing.T) {
	const maxWait = 200 * time.Millisecond
	parentPID := os.Getpid()
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.WriteKeyFile(t, "authorized_keys", nil)
	lockPath := filepath.Join(tree.Home, "door.lock")
	doorID := strings.Repeat("a", 32)

	start := time.Now()
	err := RunWatchdog(parentPID, doorID, keyFile, nil, maxWait, lockPath, testOwnerUID(), testOwnerGID())
	elapsed := time.Since(start)

	if err == nil {
		t.Fatalf("RunWatchdog must return a timeout error against a live parent with maxWait=%s", maxWait)
	}
	if !strings.Contains(err.Error(), "still alive") {
		t.Fatalf("RunWatchdog returned %v, want the \"still alive after %s\" timeout error", err, maxWait)
	}
	if !strings.Contains(err.Error(), maxWait.String()) {
		t.Fatalf("RunWatchdog error %v does not name the configured maxWait %s — the cap that reached the loop is not the one this call passed in", err, maxWait)
	}
	// What a stopwatch can honestly say about a real poll loop (IAMT-305
	// round 3): the cap is a wait, so the call cannot return before it, and it
	// must not hang. The old upper bound here was 5x maxWait = 1s, which
	// measured the scheduler rather than the cap: the loop's granularity is one
	// watchdogPollWindow (500ms) of real polling, and a loaded machine
	// stretched it to 1.246s and 2.85s. The claim "the deadline really is the
	// configured maxWait" is proved deterministically, by poll count, in
	// TestRunWatchdogUnix_CapIsTheConfiguredMaxWait (doorwatch_maxwait_test.go);
	// what is left for the end-to-end path is the plumbing and a hung-test
	// guard.
	if elapsed < maxWait {
		t.Fatalf("RunWatchdog returned after %s, before the configured maxWait %s — the cap is not what bounds the wait", elapsed, maxWait)
	}
	if elapsed > maxWait+20*watchdogPollWindow {
		t.Fatalf("RunWatchdog waited %s for a %s cap — the loop is not applying the configured maxWait (IAMT-130 regression on Linux)", elapsed, maxWait)
	}
}

// TestDoorwatch_AuditEventWrittenOnParentDeath is the IAMT-130
// proof that the watchdog's layer-3 cleanup lands a distinct
// audit event in the journal — the exact distinction the
// audit-sink plumbing was added for. We start a real parent
// helper, wait for it to write the door line, spawn the watchdog
// with a journal path under t.TempDir(), kill the parent, and
// assert the journal contains a close event for our door-id.
//
// The Linux canary: if SpawnWatchdog dropped the journal path
// from argv (the helper uses the parsed argv to construct its
// file sink), the journal stays empty and t.Fatal names the
// missing close event.
func TestDoorwatch_AuditEventWrittenOnParentDeath(t *testing.T) {
	captureWatchdogStderrForTest(t)
	parentExe, wdExe := buildLinuxWatchdogTestBinaries(t)
	cmd, keyFile, helperPID := startLinuxParent(t, parentExe)
	doorID := findOurDoorIDLinux(t, keyFile)

	home := filepath.Dir(filepath.Dir(keyFile))
	lockPath := filepath.Join(home, "door.lock")
	journal := filepath.Join(t.TempDir(), "journal.jsonl")
	wd, err := SpawnWatchdog(wdExe, doorID, keyFile, helperPID, 10*time.Minute, journal, lockPath, testOwnerUID(), testOwnerGID())
	if err != nil {
		t.Fatalf("SpawnWatchdog: %v", err)
	}
	defer wd.Stop()
	time.Sleep(500 * time.Millisecond)

	if err := exec.Command("kill", "-9", strconv.Itoa(helperPID)).Run(); err != nil {
		t.Logf("kill warning: %v", err)
	}
	_ = cmd.Wait()

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
		exited, exitCode, _ := wd.ExitStatus()
		t.Fatalf("read journal (watcher exited=%v, exitCode=%d, stderr=%q): %v", exited, exitCode, wd.Stderr(), err)
	}
	if len(contents) == 0 {
		exited, exitCode, _ := wd.ExitStatus()
		t.Fatalf("journal at %s is empty after the parent was killed (watcher exited=%v, exitCode=%d, stderr=%q) — the watchdog's layer-3 cleanup did NOT write a distinct audit event for door %s",
			journal, exited, exitCode, wd.Stderr(), doorID)
	}
	if !strings.Contains(string(contents), `"Op":"close"`) {
		t.Fatalf("journal at %s has no close event:\n%s", journal, string(contents))
	}
	if !strings.Contains(string(contents), doorID) {
		t.Fatalf("journal at %s has no record for door %s:\n%s", journal, doorID, string(contents))
	}
}

// TestDoorwatch_RealBinaryRequiresRootUnderNonRoot asserts that the production
// iamtunnel binary legitimately enforces elevation and refuses to run
// `server doorwatch` when spawned as a non-root user.
func TestDoorwatch_RealBinaryRequiresRootUnderNonRoot(t *testing.T) {
	if unix.Geteuid() == 0 {
		t.Skip("running as root (euid=0); elevation refusal only fires under non-root")
	}
	captureWatchdogStderrForTest(t)
	realExe := buildIamtunnel(t, filepath.Join(t.TempDir(), "iamtunnel_real"))

	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("authorized_keys")
	lockPath := filepath.Join(tree.Home, "door.lock")

	wd, err := SpawnWatchdog(realExe, strings.Repeat("a", 32), keyFile, os.Getpid(), 10*time.Minute, "", lockPath, testOwnerUID(), testOwnerGID())
	if err != nil {
		t.Fatalf("SpawnWatchdog: %v", err)
	}
	defer wd.Stop()

	// The real iamtunnel binary must exit almost immediately because requireServerElevation fails.
	deadline := time.Now().Add(5 * time.Second)
	var exited bool
	var exitCode int
	for time.Now().Before(deadline) {
		exited, exitCode, _ = wd.ExitStatus()
		if exited {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if !exited {
		t.Fatalf("real iamtunnel did not exit within 5s; stderr: %q", wd.Stderr())
	}
	if exitCode == 0 {
		t.Fatalf("real iamtunnel exited with 0 under non-root, want non-zero")
	}
	stderr := wd.Stderr()
	if !strings.Contains(stderr, "root privileges are required") {
		t.Fatalf("stderr must contain 'root privileges are required', got: %q", stderr)
	}
}

// TestDoorwatch_StopCachesTheStatusItReaps is the end-to-end half of the
// round-4 exit-status contract (the whole of it is stated in
// doorwatch_exitstatus_test.go), driven through the real Stop the server role
// calls: spawn a real watchdog against a live parent, stop it, and ask for the
// exit status.
//
// Stop reaps the child — it has to, or a killed watcher stays a zombie — and
// reaping is what consumes the status. Before round 4 that left ExitStatus with
// ECHILD and it answered (exited=true, code=0, nil): "the watcher we just
// SIGKILLed exited cleanly". The status Stop saw is now cached, so the same
// sequence reports 137 (128+SIGKILL).
//
// Canary: drop the recordExit call from Stop (either closure) and this test
// fails with "ExitStatus after Stop reported code 0 for a watcher that was
// SIGKILLed..." — the fabrication round 4 removed, on the very path the server
// role uses.
func TestDoorwatch_StopCachesTheStatusItReaps(t *testing.T) {
	_, wdExe := buildLinuxWatchdogTestBinaries(t)
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.WriteKeyFile(t, "authorized_keys", nil)
	lockPath := filepath.Join(tree.Home, "door.lock")

	// The parent is this test process, which stays alive, so the watcher keeps
	// polling instead of cleaning anything up: the door line is not touched and
	// no stderr file exists (captureWatchdogStderr is off in tests unless a
	// test asks for it).
	wd, err := SpawnWatchdog(wdExe, strings.Repeat("a", 32), keyFile, os.Getpid(), 10*time.Minute, "", lockPath, testOwnerUID(), testOwnerGID())
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
		t.Fatalf("ExitStatus after Stop: %v — Stop reaps the child, so the status it observed must be cached; without the cache the reaped status is only ECHILD (IAMT-305 round 4)", err)
	}
	if !exited {
		t.Fatal("ExitStatus after Stop reported the reaped watcher as still running")
	}
	if code != 137 {
		t.Fatalf("ExitStatus after Stop reported code %d for a watcher that was SIGKILLed, want 137 (128+9): the watcher did not exit cleanly, and a 0 here is the fabricated clean exit round 4 removed (IAMT-305)", code)
	}
}
