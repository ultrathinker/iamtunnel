//go:build linux || darwin

// doorwatch_unix_test.go — the shared half of the Unix watchdog
// (doorwatch_unix.go): the argv parser both platforms use, and the wait
// loop whose policy is the same whether the parent's death arrives
// through a Linux pidfd or a macOS kqueue NOTE_EXIT.
//
// The loop is driven here with a fake parentWatcher, so these tests pin
// the three decisions that are easy to get wrong and expensive to get
// wrong — "the parent exited, clean the line up", "the parent never
// exited, give up with a named error", and "the wait itself failed,
// surface it instead of cleaning up" — on every platform this file
// builds for, including the Linux CI that cannot run the macOS kqueue
// half at all (doorwatch_darwin_test.go).
//
// The real removeOnceAndAudit path is exercised against a real key file
// and a real file lock through NewDoorWithOptions, which is the same
// constructor the production watcher uses, so a fake watcher cannot hide
// a broken cleanup.

package winkeys

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// fakeParentWatcher is a parentWatcher whose answers are written by the
// test: exits is a queue of already-exited verdicts, so a test can model
// "still alive twice, then gone".
type fakeParentWatcher struct {
	exits  []bool
	err    error
	calls  int
	closed bool
}

func (f *fakeParentWatcher) Wait(time.Duration) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	if len(f.exits) == 0 {
		return false, nil
	}
	next := f.exits[0]
	f.exits = f.exits[1:]
	return next, nil
}

func (f *fakeParentWatcher) Close() { f.closed = true }

// installTestDoorLine writes one foreign line and one of ours into a
// fresh key file and returns (keyFile, lockPath, doorID). The options
// are the unix ones NewDoorWithOptions requires (validateOptionsPlatform),
// with the same uid/gid the linux integration test uses so the fixture
// works whether the test binary runs as root or as an ordinary user.
func installTestDoorLine(t *testing.T) (keyFile, lockPath, doorID string) {
	t.Helper()
	tree := testsupport.NewSSHTree(t)
	keyFile = tree.KeyPath("authorized_keys")
	lockPath = filepath.Join(tree.Home, "door.lock")
	foreign := "# somebody else's key — must survive\n"
	tree.WriteKeyFile(t, "authorized_keys", []byte(foreign))
	opts := DoorOptions{LockPath: lockPath, OwnerUID: testUID, OwnerGID: testGID}
	d, err := NewDoorWithOptions(keyFile, nil, opts)
	if err != nil {
		t.Fatalf("NewDoorWithOptions: %v", err)
	}
	doorID = randomDoorID(t)
	if err := d.Install(doorID, TestKey); err != nil {
		t.Fatalf("install door line: %v", err)
	}
	if err := waitForOurLineUnix(t, keyFile, true, 2*time.Second); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return keyFile, lockPath, doorID
}

// waitForOurLineUnix polls the key file until a line of ours is present
// (or absent). It is the linux||darwin sibling of the linux-only
// waitForOursLinux in doorwatch_linux_test.go; the two exist because a
// linux-tagged helper is not visible to the darwin build, and this file
// must compile on both.
func waitForOurLineUnix(t *testing.T, path string, present bool, max time.Duration) error {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		if got, err := hasOurLineUnix(path); err == nil && got == present {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	if present {
		return errors.New("no iamtunnel line appeared in " + path)
	}
	return errors.New("the iamtunnel line is still in " + path)
}

func hasOurLineUnix(path string) (bool, error) {
	lines, err := readLinesLocked(path)
	if err != nil {
		return false, err
	}
	for _, l := range lines {
		if IsOurs(l) {
			return true, nil
		}
	}
	return false, nil
}

// TestParseWatchdogArgsUnix pins the argv layout both Unix platforms
// share — the one cmdServerDoorwatch's Unix half parses and
// spawnWatchdogUnix builds. A change to either side that shifts a field
// has to fail here first, because the fields are positional and a silent
// shift would make the child lock the wrong file with the wrong owner.
func TestParseWatchdogArgsUnix(t *testing.T) {
	args := []string{
		"/usr/local/bin/iamtunnel", "server", "doorwatch",
		"deadbeefcafebabe1234567890abcdef", // door-id
		"4242",                             // parent-pid
		"/home/alice/.ssh/authorized_keys", // keyfile
		"900000",                           // max-wait-ms
		"/var/lib/iamtunnel-machine/events.jsonl", // journal
		"/var/lib/iamtunnel-machine/door.lock",    // lock-path
		"1000",                                    // owner-uid
		"1001",                                    // owner-gid
	}
	pid, doorID, keyFile, journalPath, lockPath, uid, gid, maxWait, err := ParseWatchdogArgsUnix(args)
	if err != nil {
		t.Fatalf("ParseWatchdogArgsUnix: %v", err)
	}
	if pid != 4242 || doorID != args[3] || keyFile != args[5] || journalPath != args[7] ||
		lockPath != args[8] || uid != 1000 || gid != 1001 {
		t.Fatalf("fields landed wrong: pid=%d doorID=%q key=%q journal=%q lock=%q uid=%d gid=%d",
			pid, doorID, keyFile, journalPath, lockPath, uid, gid)
	}
	if maxWait != 900*time.Second {
		t.Fatalf("maxWait = %s, want 900s (max-wait-ms is milliseconds)", maxWait)
	}

	// Too few positional arguments: the usage line, not a field error.
	if _, _, _, _, _, _, _, _, err := ParseWatchdogArgsUnix(args[:10]); err == nil ||
		!strings.Contains(err.Error(), "usage:") {
		t.Fatalf("short argv must give the usage error, got %v", err)
	}
	// Not our invocation at all.
	notOurs := append([]string(nil), args...)
	notOurs[2] = "something-else"
	if _, _, _, _, _, _, _, _, err := ParseWatchdogArgsUnix(notOurs); err == nil ||
		!strings.Contains(err.Error(), "not a server doorwatch invocation") {
		t.Fatalf("wrong verb must be refused, got %v", err)
	}
	// Each numeric field names itself when it does not parse, so an
	// operator reading the watchdog's stderr knows which one to fix.
	for _, tc := range []struct {
		idx  int
		want string
	}{
		{4, "bad parent pid"},
		{6, "bad max-wait-ms"},
		{9, "bad owner-uid"},
		{10, "bad owner-gid"},
	} {
		bad := append([]string(nil), args...)
		bad[tc.idx] = "not-a-number"
		if _, _, _, _, _, _, _, _, err := ParseWatchdogArgsUnix(bad); err == nil ||
			!strings.Contains(err.Error(), tc.want) {
			t.Fatalf("args[%d] unparseable: want %q, got %v", tc.idx, tc.want, err)
		}
	}
}

// TestRunWatchdogUnix_CleansUpWhenParentExits is the headline of the
// shared loop: the watcher reports the parent's exit, and the door line
// is gone afterwards while the foreign line is untouched — the same
// guarantee the platform integration tests assert for a real killed
// parent, pinned here for both platforms through the loop that owns it.
func TestRunWatchdogUnix_CleansUpWhenParentExits(t *testing.T) {
	keyFile, lockPath, doorID := installTestDoorLine(t)
	w := &fakeParentWatcher{exits: []bool{false, true}}
	err := runWatchdogUnix(w, 4242, doorID, keyFile, nil, 5*time.Second, lockPath, testUID, testGID)
	if err != nil {
		t.Fatalf("runWatchdogUnix: %v", err)
	}
	if err := waitForOurLineUnix(t, keyFile, false, 2*time.Second); err != nil {
		t.Fatalf("the door line must be gone after the parent exited: %v", err)
	}
	data, rerr := os.ReadFile(keyFile)
	if rerr != nil {
		t.Fatalf("read key file: %v", rerr)
	}
	if !strings.Contains(string(data), "somebody else's key") {
		t.Fatalf("foreign lines must survive byte-for-byte, got:\n%s", data)
	}
}

// TestRunWatchdogUnix_TimeoutLeavesTheLineAlone pins the other half of
// the contract: a watcher that gives up because the parent outlived
// maxWait returns a named error and does NOT touch the file — the door is
// still legally open, and a watchdog that cleaned up early would be the
// very gap it exists to close (IAMT-130's shape).
func TestRunWatchdogUnix_TimeoutLeavesTheLineAlone(t *testing.T) {
	keyFile, lockPath, doorID := installTestDoorLine(t)
	w := &fakeParentWatcher{} // never exits
	err := runWatchdogUnix(w, 4242, doorID, keyFile, nil, time.Millisecond, lockPath, testUID, testGID)
	if err == nil || !strings.Contains(err.Error(), "still alive after") {
		t.Fatalf("a parent that outlives maxWait must be a named error, got %v", err)
	}
	if !strings.Contains(err.Error(), "4242") {
		t.Fatalf("the error must name the parent PID, got %v", err)
	}
	if err := waitForOurLineUnix(t, keyFile, true, 2*time.Second); err != nil {
		t.Fatalf("the door line must still be there: %v", err)
	}
}

// TestRunWatchdogUnix_WaitErrorIsNotAnExit: a failing wait must surface
// as an error and must NOT be mistaken for "the parent died" — cleaning
// up on a syscall failure would remove a live door line, which is the one
// mistake this loop cannot make.
func TestRunWatchdogUnix_WaitErrorIsNotAnExit(t *testing.T) {
	keyFile, lockPath, doorID := installTestDoorLine(t)
	w := &fakeParentWatcher{err: errors.New("kevent wait on parent proc: boom")}
	err := runWatchdogUnix(w, 4242, doorID, keyFile, nil, 5*time.Second, lockPath, testUID, testGID)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("the wait error must be surfaced, got %v", err)
	}
	if err := waitForOurLineUnix(t, keyFile, true, 2*time.Second); err != nil {
		t.Fatalf("a failed wait must not remove the line: %v", err)
	}
	if w.closed {
		t.Fatalf("the loop must not close a watcher it did not open")
	}
}

// TestWatchdog_ExitStatusDoesNotFabricateACodeWhenTheStatusIsGone is the unix
// half of the round-4 exit-status contract (the whole of it is stated in
// doorwatch_exitstatus_test.go): the platform probe knows two different things
// when a wait cannot answer — "still running" (WNOHANG returned 0) and "gone,
// and its status with it" (ECHILD, i.e. something already reaped it). Only the
// first is an absence of news. Reporting ECHILD as "exited with 0" turns a
// SIGKILLed watcher into a clean exit, and it is what made unix and Windows
// disagree about the very same sequence: Stop then ExitStatus.
//
// A pid that was never this process's child is the deterministic way to reach
// ECHILD without spawning anything: wait4 answers ECHILD for any pid that is
// not one of our children, whether or not a process with that pid exists. The
// number is far above the usable range so the test cannot accidentally name a
// real child.
//
// Canary: reinstate the pre-round-4 ECHILD branch (`w.hasExited = true; return
// true, w.exitCode, nil`) and this test fails with "ExitStatus reported the
// fabricated (exited=true, code=0) ...".
func TestWatchdog_ExitStatusDoesNotFabricateACodeWhenTheStatusIsGone(t *testing.T) {
	const notAChildPID = 1 << 30
	w := &Watchdog{pid: notAChildPID}

	exited, code, err := w.ExitStatus()
	if err == nil {
		t.Fatalf("ExitStatus reported the fabricated (exited=%v, code=%d, err=nil) for pid %d, which was never our child: ECHILD means the status is gone — already reaped — not that the watcher exited cleanly (IAMT-305 round 4)", exited, code, notAChildPID)
	}
	if exited || code != 0 {
		t.Fatalf("ExitStatus for a status that is gone = (exited=%v, code=%d, err=%v), want (false, 0, err): the error is the verdict, and no code may accompany it", exited, code, err)
	}
}
