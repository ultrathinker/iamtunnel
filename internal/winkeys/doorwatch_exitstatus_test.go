//go:build linux || darwin || windows

package winkeys

// doorwatch_exitstatus_test.go — IAMT-305 round 4: the exit-status contract
// Watchdog.ExitStatus advertises, on every platform that has a watchdog.
//
// A process's status can be read exactly once: the read reaps the child, and
// every later read answers ECHILD (unix) or fails on the closed handle
// (Windows). Stop performs such a read — it has to, or the killed watcher
// stays a zombie — so without a cache the natural sequence
//
//	wd.Stop()
//	wd.ExitStatus()
//
// had no honest answer available. The Unix half used to answer (true, 0, nil),
// i.e. "the watcher we just SIGKILLed exited cleanly", while the Windows half
// answered an error for the same sequence: two different stories about one
// death. Round 4 caches the status Stop observed and makes both halves answer
// from it.
//
// The platform-specific halves of the contract (unix ECHILD, Windows closed
// handle) live next to their implementations: doorwatch_unix_test.go and
// doorwatch_exitstatus_windows_test.go. This file pins the part that must be
// identical everywhere.

import "testing"

// TestWatchdog_ExitStatusReturnsTheStatusStopCached pins the cache itself: a
// recorded status is the answer, whatever the platform can still probe — which,
// for a Watchdog in this state (no pid, no handle: the shape left behind by a
// Stop that has already closed what it used), is nothing at all.
//
// Canary: make recordExit a no-op, and the first ExitStatus call reports
// exited=false code=0 with no error on a watchdog whose watcher was killed —
// the fabrication round 4 removed.
func TestWatchdog_ExitStatusReturnsTheStatusStopCached(t *testing.T) {
	w := &Watchdog{}
	w.recordExit(137)

	exited, code, err := w.ExitStatus()
	if err != nil {
		t.Fatalf("ExitStatus after a recorded status: %v — a cached status must be answerable, not looked up again (IAMT-305 round 4)", err)
	}
	if !exited || code != 137 {
		t.Fatalf("ExitStatus after a recorded status = (exited=%v, code=%d), want (true, 137): the cached status is what ExitStatus reports", exited, code)
	}

	// The first status wins. A second recorder cannot be given a better
	// answer, and overwriting a real code with a later 0 would be exactly the
	// fabrication this contract refuses.
	w.recordExit(0)
	if exited, code, err := w.ExitStatus(); err != nil || !exited || code != 137 {
		t.Fatalf("ExitStatus after a second recorded status = (exited=%v, code=%d, err=%v), want (true, 137, nil): the status of a process is decided once, by the wait that reaped it", exited, code, err)
	}
}
