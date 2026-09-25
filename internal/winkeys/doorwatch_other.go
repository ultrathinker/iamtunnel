//go:build !windows && !linux && !darwin

// Doorwatch stub for the platforms that have no implementation:
// every GOOS except windows, linux and darwin. Windows has its real
// implementation in doorwatch_windows.go (CreateProcess with
// CREATE_BREAKAWAY_FROM_JOB + WaitForSingleObject), Linux in
// doorwatch_linux.go (pidfd + setsid + PR_SET_PDEATHSIG, IAMT-247)
// and macOS in doorwatch_darwin.go (kqueue EVFILT_PROC/NOTE_EXIT,
// IAMT-263); the three share the spawn/argv/cleanup half in
// doorwatch_unix.go. A build that ends up on any other Unix
// (FreeBSD, the other BSDs, illumos) gets the same explicit refusal
// so a misconfigured production launch fails with the right
// next-step hint rather than a generic "supported only on Windows"
// that the operator would have to trace back to the watchdog.
package winkeys

import (
	"errors"
	"time"
)

// SpawnWatchdog returns an explicit "doorwatch is not implemented
// on this OS yet" error on every GOOS that has no watchdog. Servers
// that CAN run are named so an operator reading a production refusal
// knows whether they are on a supported machine or a future port.
func SpawnWatchdog(_, _, _ string, _ int, _ time.Duration, _, _ string, _, _ int) (*Watchdog, error) {
	return nil, errors.New("winkeys: doorwatch is not implemented on this OS yet (supported: Windows, Linux, macOS; SPEC §3.2, §3.2.1, §12) — server start can run, but door.open will refuse until the watchdog lands for this platform")
}

// RunWatchdog returns the same explicit refusal on the child
// side. RunWatchdog is invoked by the spawned subprocess (the
// watchdog itself) — a non-Linux server that somehow reached this
// code path is broken in a deeper way than SpawnWatchdog refusal
// could explain, but the error is the same so a CI failure on a
// darwin / freebsd build gives a uniform message.
func RunWatchdog(_ int, _, _ string, _ Sink, _ time.Duration, _ string, _, _ int) error {
	return errors.New("winkeys: RunWatchdog is not implemented on this OS yet (Linux: IAMT-247; Darwin: IAMT-263)")
}

// exitStatusPlatform on a platform with no watchdog: nothing was ever spawned,
// so there is never a status to probe — but the cache is still honoured first,
// so Watchdog.ExitStatus's contract (a recorded status is the answer, whatever
// the platform can probe) is the same on every build of this package.
func (w *Watchdog) exitStatusPlatform() (bool, int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if exited, code, ok := w.cachedExit(); ok {
		return exited, code, nil
	}
	return false, 0, nil
}
