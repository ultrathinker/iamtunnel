//go:build darwin

// doorwatch_darwin_test.go — the kqueue half of the Unix watchdog
// (doorwatch_darwin.go, IAMT-263).
//
// These tests drive the three syscall seams (darwinKqueueFn,
// darwinKeventFn) instead of a real kernel queue, for two reasons: a
// darwin test binary must never watch or kill a real process as part of
// proving the loop's decisions, and the decisions themselves are what a
// review has to be able to repeat — "the registration says the parent is
// already gone", "the registration failed for another reason", "the wait
// fired", "the wait timed out", "the wait errored" — with no timing
// dependence.
//
// They are darwin-tagged because the code they test only exists on
// darwin; this repository's CI is Linux, so they compile for darwin
// (`GOOS=darwin go test -c -o NUL ./internal/winkeys/`) and are expected
// to run on a macOS host. The shared loop they feed — cleanup on exit,
// named error on timeout, no cleanup on a wait failure — is pinned for
// every platform by doorwatch_unix_test.go, which is why the darwin file
// concentrates on the syscall translation.

package winkeys

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeQueue swaps both syscall seams for the duration of one test and
// returns the recorders. fd is a real, harmless descriptor (one end of a
// pipe) so the code under test may Close it without touching the test
// process's own streams.
type fakeQueue struct {
	kqueueErr error
	kevent    func(call int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error)
	calls     int
}

func withFakeQueue(t *testing.T, fq *fakeQueue) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })

	prevKqueue, prevKevent := darwinKqueueFn, darwinKeventFn
	t.Cleanup(func() { darwinKqueueFn, darwinKeventFn = prevKqueue, prevKevent })

	darwinKqueueFn = func() (int, error) {
		if fq.kqueueErr != nil {
			return 0, fq.kqueueErr
		}
		return int(r.Fd()), nil
	}
	darwinKeventFn = func(kq int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
		fq.calls++
		if fq.kevent == nil {
			return 0, nil
		}
		return fq.kevent(fq.calls, changes, events, timeout)
	}
}

// TestDarwinProcWatcher_RegistrationIsExitOnly — the registration the
// watcher makes must be EVFILT_PROC/NOTE_EXIT, one-shot: NOTE_EXIT is
// what makes a dead parent readable (kqueue(2)), and EV_ONESHOT is what
// keeps a recycled PID from firing a second event into a watcher that has
// already done its job.
func TestDarwinProcWatcher_RegistrationIsExitOnly(t *testing.T) {
	var got unix.Kevent_t
	fq := &fakeQueue{}
	fq.kevent = func(call int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
		if len(changes) != 1 {
			t.Fatalf("registration must send exactly one change, got %d", len(changes))
		}
		got = changes[0]
		return 0, nil
	}
	withFakeQueue(t, fq)

	w, alreadyGone, err := newProcWatcher(4242)
	if err != nil || alreadyGone {
		t.Fatalf("newProcWatcher = (%v, %v), want a live watcher", alreadyGone, err)
	}
	defer w.Close()
	if got.Ident != 4242 {
		t.Errorf("registered ident = %d, want the parent pid 4242", got.Ident)
	}
	if got.Filter != unix.EVFILT_PROC || got.Fflags != unix.NOTE_EXIT {
		t.Errorf("registered filter/fflags = %#x/%#x, want EVFILT_PROC/NOTE_EXIT", got.Filter, got.Fflags)
	}
	if got.Flags&unix.EV_ADD == 0 || got.Flags&unix.EV_ENABLE == 0 || got.Flags&unix.EV_ONESHOT == 0 {
		t.Errorf("registration flags = %#x, want EV_ADD|EV_ENABLE|EV_ONESHOT", got.Flags)
	}
}

// TestDarwinProcWatcher_AlreadyGoneMeansCleanUpNow — kevent answers
// ESRCH for a PID that is no longer there (and ENOENT on some versions).
// That is macOS's "the parent is already dead" and must not be reported
// as a failure, or the line would stay behind: the newProcWatcher
// contract hands it back as alreadyGone, which RunWatchdog turns into
// the immediate cleanup.
func TestDarwinProcWatcher_AlreadyGoneMeansCleanUpNow(t *testing.T) {
	for _, errno := range []error{unix.ESRCH, unix.ENOENT} {
		fq := &fakeQueue{}
		fq.kevent = func(call int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
			return 0, errno
		}
		withFakeQueue(t, fq)
		_, alreadyGone, err := newProcWatcher(4242)
		if err != nil {
			t.Fatalf("%v: expected the already-gone branch, got error %v", errno, err)
		}
		if !alreadyGone {
			t.Fatalf("%v: expected alreadyGone=true", errno)
		}
	}
}

// TestDarwinProcWatcher_RegistrationErrorIsAnError — any other failure
// (EPERM on a process we may not watch, EINVAL on a bad flag) is a real
// error and must be named with the PID: silently treating it as "parent
// gone" would remove a live door line, and silently ignoring it would
// leave a watcher that never wakes up.
func TestDarwinProcWatcher_RegistrationErrorIsAnError(t *testing.T) {
	fq := &fakeQueue{}
	fq.kevent = func(call int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
		return 0, unix.EPERM
	}
	withFakeQueue(t, fq)
	_, alreadyGone, err := newProcWatcher(4242)
	if err == nil {
		t.Fatal("a failed registration must be an error")
	}
	if alreadyGone {
		t.Fatal("a failed registration must not be reported as 'parent gone'")
	}
	if !strings.Contains(err.Error(), "EVFILT_PROC") || !strings.Contains(err.Error(), "4242") {
		t.Fatalf("the error must name the filter and the pid, got %v", err)
	}
}

// TestDarwinProcWatcher_KqueueFailureIsNamed — kqueue(2) itself can fail
// (descriptor exhaustion); that must be named as the kqueue call, not as
// an exit.
func TestDarwinProcWatcher_KqueueFailureIsNamed(t *testing.T) {
	fq := &fakeQueue{kqueueErr: errors.New("too many open files")}
	withFakeQueue(t, fq)
	_, alreadyGone, err := newProcWatcher(4242)
	if err == nil || alreadyGone {
		t.Fatalf("kqueue failure must be an error, got (%v, %v)", alreadyGone, err)
	}
	if !strings.Contains(err.Error(), "kqueue") {
		t.Fatalf("the error must name kqueue, got %v", err)
	}
}

// TestDarwinProcWatcher_WaitOutcomes pins the four answers Wait can give
// back to the shared loop: the event fired (parent exited), nothing
// arrived (a timeout — the loop re-checks its deadline), EINTR (treated
// as a timeout for the same reason), and EV_ERROR (the kernel reporting
// that our own registration failed — an error, never an exit).
func TestDarwinProcWatcher_WaitOutcomes(t *testing.T) {
	t.Run("event fired is an exit", func(t *testing.T) {
		fq := &fakeQueue{}
		fq.kevent = func(call int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
			events[0] = unix.Kevent_t{Filter: unix.EVFILT_PROC, Fflags: unix.NOTE_EXIT}
			return 1, nil
		}
		withFakeQueue(t, fq)
		w := &procWatcher{kq: 3}
		exited, err := w.Wait(watchdogPollWindow)
		if err != nil || !exited {
			t.Fatalf("Wait = (%v, %v), want (true, nil)", exited, err)
		}
	})

	t.Run("no event is a timeout", func(t *testing.T) {
		fq := &fakeQueue{}
		withFakeQueue(t, fq)
		w := &procWatcher{kq: 3}
		exited, err := w.Wait(watchdogPollWindow)
		if err != nil || exited {
			t.Fatalf("Wait = (%v, %v), want (false, nil)", exited, err)
		}
	})

	t.Run("EINTR is a timeout", func(t *testing.T) {
		fq := &fakeQueue{}
		fq.kevent = func(call int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
			return 0, unix.EINTR
		}
		withFakeQueue(t, fq)
		w := &procWatcher{kq: 3}
		exited, err := w.Wait(watchdogPollWindow)
		if err != nil || exited {
			t.Fatalf("EINTR must be (false, nil), got (%v, %v)", exited, err)
		}
	})

	t.Run("EV_ERROR is an error", func(t *testing.T) {
		fq := &fakeQueue{}
		fq.kevent = func(call int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
			events[0] = unix.Kevent_t{Flags: unix.EV_ERROR, Data: int64(unix.EBADF)}
			return 1, nil
		}
		withFakeQueue(t, fq)
		w := &procWatcher{kq: 3}
		exited, err := w.Wait(watchdogPollWindow)
		if err == nil || exited {
			t.Fatalf("EV_ERROR must surface as an error, got (%v, %v)", exited, err)
		}
		if !strings.Contains(err.Error(), "kevent wait") {
			t.Fatalf("the error must name the wait, got %v", err)
		}
	})
}

// TestRunWatchdogDarwin_CleansUpWhenParentAlreadyGone is the darwin
// end-to-end of the cleanup path that matters most on this platform: the
// watcher is spawned before the door line is written, so a parent that
// dies in the gap must still have its line removed. With the
// registration answering ESRCH, RunWatchdog must remove the line from a
// real key file (real flock, real owner through NewDoorWithOptions) with
// no process involved at all.
func TestRunWatchdogDarwin_CleansUpWhenParentAlreadyGone(t *testing.T) {
	keyFile, lockPath, doorID := installTestDoorLine(t)
	fq := &fakeQueue{}
	fq.kevent = func(call int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
		return 0, unix.ESRCH
	}
	withFakeQueue(t, fq)

	err := RunWatchdog(4242, doorID, keyFile, nil, 5*time.Second, lockPath, testUID, testGID)
	if err != nil {
		t.Fatalf("RunWatchdog on an already-dead parent: %v", err)
	}
	if err := waitForOurLineUnix(t, keyFile, false, 2*time.Second); err != nil {
		t.Fatalf("the door line must be gone: %v", err)
	}
}

// TestRunWatchdogDarwin_HonoursMaxWaitWithoutCleaningUp — the wait never
// fires and the cap expires: a named error, and the line left alone,
// because the door may still be legally open (IAMT-130).
func TestRunWatchdogDarwin_HonoursMaxWaitWithoutCleaningUp(t *testing.T) {
	keyFile, lockPath, doorID := installTestDoorLine(t)
	fq := &fakeQueue{} // kevent always answers "nothing yet"
	withFakeQueue(t, fq)

	err := RunWatchdog(4242, doorID, keyFile, nil, time.Millisecond, lockPath, testUID, testGID)
	if err == nil || !strings.Contains(err.Error(), "still alive after") {
		t.Fatalf("a parent that outlives maxWait must be a named error, got %v", err)
	}
	if err := waitForOurLineUnix(t, keyFile, true, 2*time.Second); err != nil {
		t.Fatalf("the line must not be removed on a timeout: %v", err)
	}
}

// TestSpawnWatchdogDarwin_ValidatesBeforeSpawning — the argument gate is
// shared with Linux (validateWatchdogUnixArgs is called by RunWatchdog;
// SpawnWatchdog has its own inline gate for the same values), and it must
// refuse before anything is executed: a watchdog spawned with an empty
// lock path or the 0,0 owner sentinel would fail at NewDoorWithOptions
// only after the door line is already on disk.
func TestSpawnWatchdogDarwin_ValidatesBeforeSpawning(t *testing.T) {
	cases := []struct {
		name    string
		exe     string
		doorID  string
		keyFile string
		lock    string
		uid     int
		gid     int
		maxWait time.Duration
		want    string
	}{
		{"empty exe", "", "door", "/k", "/l", 1000, 1000, time.Second, "exe must not be empty"},
		{"empty door id", "/bin/true", "", "/k", "/l", 1000, 1000, time.Second, "doorID and keyFile"},
		{"empty key file", "/bin/true", "door", "", "/l", 1000, 1000, time.Second, "doorID and keyFile"},
		{"empty lock path", "/bin/true", "door", "/k", "", 1000, 1000, time.Second, "lockPath must not be empty"},
		{"zero owner", "/bin/true", "door", "/k", "/l", 0, 0, time.Second, "must be positive"},
		{"zero max wait", "/bin/true", "door", "/k", "/l", 1000, 1000, 0, "maxWait must be positive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := SpawnWatchdog(tc.exe, tc.doorID, tc.keyFile, 1, tc.maxWait, "", tc.lock, tc.uid, tc.gid)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error naming %q, got %v", tc.want, err)
			}
		})
	}
}
