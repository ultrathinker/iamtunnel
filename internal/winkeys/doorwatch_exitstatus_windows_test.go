//go:build windows

package winkeys

// doorwatch_exitstatus_windows_test.go — the Windows half of the round-4
// exit-status contract (doorwatch_exitstatus_test.go states the whole of it).
//
// Windows has no ECHILD: the status probe is GetExitCodeProcess on the process
// handle, and the state that makes the code unknowable is a handle that is no
// longer valid — which is what Stop leaves behind, since it closes the handle
// after caching the status read.

import "testing"

// TestWatchdog_ExitStatusRefusesToInventACodeForAnUnprobeableHandle pins the
// Windows shape of "the status is gone": an error, never a zero that reads as a
// clean exit — the same verdict the Unix half returns for ECHILD.
//
// The handle below is deliberately not a valid one: Windows handles are
// pointer-aligned, and 0xDEADBEEF has its low bits set, so no process handle
// can have that value and GetExitCodeProcess must answer ERROR_INVALID_HANDLE.
//
// Canary: drop the error branch in exitStatusPlatform (return `false, 0, nil`
// for a failed GetExitCodeProcess) and this test fails with "ExitStatus for an
// unprobeable handle returned exited=false code=0 with no error".
func TestWatchdog_ExitStatusRefusesToInventACodeForAnUnprobeableHandle(t *testing.T) {
	w := &Watchdog{handle: 0xDEADBEEF}

	exited, code, err := w.ExitStatus()
	if err == nil {
		t.Fatalf("ExitStatus for an unprobeable handle returned exited=%v code=%d with no error: the code is unknowable there (IAMT-305 round 4), and a 0 would read as a clean exit", exited, code)
	}
	if exited || code != 0 {
		t.Fatalf("ExitStatus for an unprobeable handle = (exited=%v, code=%d, err=%v), want (false, 0, err): only a real status may be reported as an exit", exited, code, err)
	}

	// The cache is checked before the probe, so a status read by Stop still
	// answers on a handle that is already closed — the sequence Stop then
	// ExitStatus is the one the whole finding is about.
	w.recordExit(137)
	if exited, code, err := w.ExitStatus(); err != nil || !exited || code != 137 {
		t.Fatalf("ExitStatus after a recorded status on a closed handle = (exited=%v, code=%d, err=%v), want (true, 137, nil): a cached status must outlive the handle", exited, code, err)
	}
}
