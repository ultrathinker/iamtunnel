//go:build darwin

// macOS doorwatch (IAMT-263): the kqueue half of the Unix watchdog.
// Spawn, the argv layout, the "already gone" cleanup and the wait loop
// are shared with Linux and live in doorwatch_unix.go; what is left
// here is the mechanism macOS has instead of pidfd.
//
// macOS has no pidfd_open(2), so the watcher learns of the parent's
// death from kqueue(2): it registers the parent PID with
// EVFILT_PROC / NOTE_EXIT and blocks in kevent(2) with a short timeout.
// NOTE_EXIT is delivered when the watched process exits — for any
// reason, including SIGKILL — which is the same signal shape pidfd
// gives Linux: "the thing you are watching is gone", not "here is how
// it died". A process that exits while the watcher is still registering
// is reported by kevent as ESRCH on the registration itself, and that
// is macOS's form of Linux's pidfd_open ENOENT: the parent is already
// gone, so clean up now.
//
// Two honest differences from the Linux half, both deliberate:
//
//   - There is no PR_SET_PDEATHSIG equivalent on macOS — and Linux no
//     longer sets one behind its pidfd either (IAMT-279: an uncatchable
//     death signal can end the watcher before the line is removed).
//     Here the kqueue registration is the only mechanism, and the
//     maxWait cap plus the server's own layer-2 cleanup
//     (server.doorController.teardown) are what bound the failure mode
//     if it ever missed an exit.
//   - NOTE_EXIT requires the watcher to be allowed to see the process.
//     The machine role runs as root (SPEC §3.2.1) and the parent is the
//     process that spawned the watcher, so both the permission question
//     and the "same session" question are answered by construction.
//
// The syscalls are behind kqueueFn/keventFn seams for the same reason
// the Linux half keeps its pidfd calls in one constructor: a darwin test
// binary must be able to drive the loop's decision points (fired /
// already gone / timeout / syscall error) without a real kqueue, and
// without killing anything.

package winkeys

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// darwinKqueueFn / darwinKeventFn are the syscall seams. Production uses
// golang.org/x/sys/unix directly; tests install fakes. They are
// variables rather than direct calls so the darwin tests can exercise
// the four outcomes above deterministically — the Linux half has no
// such seam because its tests drive the real pidfd path end to end,
// which a darwin test binary in this repo's CI cannot do (no macOS
// runner).
var (
	darwinKqueueFn = func() (int, error) { return unix.Kqueue() }
	darwinKeventFn = func(kq int, changes, events []unix.Kevent_t, timeout *unix.Timespec) (int, error) {
		return unix.Kevent(kq, changes, events, timeout)
	}
)

// SpawnWatchdog starts the doorwatch subprocess in a fresh session
// (setsid) so it survives the parent's controlling terminal, with
// stdout/stderr routed to /dev/null. It is the macOS half of the same
// contract SpawnWatchdog has on Linux (doorwatch_linux.go): the argv
// layout, the DoorOptions tail and this platform's Stop behaviour —
// stopWatchdogUnix, kill by saved PID — are shared (doorwatch_unix.go;
// on Linux 5.3+ Stop goes through the child's pidfd instead, IAMT-281),
// and only the child's waiting mechanism differs.
//
// maxWait must come from the machine's door ceiling, never hard-coded
// (IAMT-130); journalPath may be empty ("no journal"); lockPath /
// ownerUID / ownerGID are the unix DoorOptions NewDoorWithOptions
// requires on macOS exactly as on Linux.
func SpawnWatchdog(exe, doorID, keyFile string, parentPID int, maxWait time.Duration, journalPath, lockPath string, ownerUID, ownerGID int) (*Watchdog, error) {
	if exe == "" {
		return nil, errors.New("winkeys: exe must not be empty")
	}
	if doorID == "" || keyFile == "" {
		return nil, errors.New("winkeys: doorID and keyFile must not be empty")
	}
	if lockPath == "" {
		return nil, errors.New("winkeys: lockPath must not be empty on linux and darwin (NewDoorWithOptions requires LockPath)")
	}
	if ownerUID <= 0 || ownerGID <= 0 {
		return nil, errors.New("winkeys: ownerUID and ownerGID must be positive on linux and darwin (NewDoorWithOptions refuses the unset 0,0 sentinel)")
	}
	if maxWait <= 0 {
		return nil, errors.New("winkeys: maxWait must be positive")
	}
	pid, stderrPath, err := spawnWatchdogUnix(exe, doorID, keyFile, parentPID, maxWait, journalPath, lockPath, ownerUID, ownerGID)
	if err != nil {
		return nil, err
	}
	proc, err := os.FindProcess(pid)
	if err != nil {
		_ = os.Remove(stderrPath)
		return nil, fmt.Errorf("find spawned process %d: %w", pid, err)
	}
	watchdog := &Watchdog{pid: pid, stderrPath: stderrPath}
	watchdog.stop = func() error {
		// The wait inside stopWatchdogUnix reaps the child, so its status is
		// cached here: afterwards a probe can only answer ECHILD, and a
		// killed watcher reported as "exited with 0" would be a fabrication
		// (IAMT-305 round 4).
		if code, ok := stopWatchdogUnix(proc); ok {
			watchdog.recordExit(code)
		}
		if watchdog.stderrPath != "" {
			_ = os.Remove(watchdog.stderrPath)
		}
		return nil
	}
	return watchdog, nil
}

// procWatcher is the macOS parentWatcher: a kqueue with
// EVFILT_PROC/NOTE_EXIT registered on the watched PID.
type procWatcher struct {
	kq int
}

// newProcWatcher opens a kqueue and registers NOTE_EXIT for parentPID.
//
// alreadyGone is true when the parent had already exited before the
// registration could be made: kevent answers ESRCH (and, on some
// versions, ENOENT) for a PID that is no longer there — macOS's
// equivalent of Linux's pidfd_open ENOENT/ESRCH, and the reason the
// watcher must remove the line instead of erroring out.
//
// EV_ADD|EV_ENABLE registers and arms the filter; EV_ONESHOT makes the
// kernel drop it after the event fires, which is all this watcher ever
// needs (it exits right afterwards) and keeps it from re-firing on a
// recycled PID — the same reason PROTOCOL §5.1 forbids image-name
// wildcards: a stale handle must not name a different process later.
func newProcWatcher(parentPID int) (w parentWatcher, alreadyGone bool, err error) {
	kq, err := darwinKqueueFn()
	if err != nil {
		return nil, false, fmt.Errorf("kqueue: %w", err)
	}
	change := unix.Kevent_t{
		Ident:  uint64(parentPID),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ENABLE | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}
	if _, err := darwinKeventFn(kq, []unix.Kevent_t{change}, nil, nil); err != nil {
		_ = unix.Close(kq)
		if errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("kevent register EVFILT_PROC/NOTE_EXIT for %d: %w", parentPID, err)
	}
	return &procWatcher{kq: kq}, false, nil
}

// Wait blocks in kevent for at most timeout and reports whether the
// NOTE_EXIT event fired. A timeout returns (false, nil) — still alive —
// and the shared loop re-checks its own deadline; EINTR is treated the
// same way for the same reason as on Linux.
func (p *procWatcher) Wait(timeout time.Duration) (bool, error) {
	events := make([]unix.Kevent_t, 1)
	ts := unix.NsecToTimespec(int64(timeout))
	n, err := darwinKeventFn(p.kq, nil, events, &ts)
	if err != nil {
		if errors.Is(err, unix.EINTR) {
			return false, nil
		}
		return false, fmt.Errorf("kevent wait on parent proc: %w", err)
	}
	if n > 0 {
		// The only filter registered is the parent's NOTE_EXIT, and the
		// registration is EV_ONESHOT, so any event that arrives here is
		// that exit. EV_ERROR would be a registration failure surfaced on
		// the wait instead; treat it as an error rather than as an exit,
		// so a broken registration cannot masquerade as a dead parent and
		// remove a live door line.
		if events[0].Flags&unix.EV_ERROR != 0 {
			return false, fmt.Errorf("kevent wait on parent proc: %w", unix.Errno(events[0].Data))
		}
		return true, nil
	}
	return false, nil
}

// Close releases the kqueue descriptor.
func (p *procWatcher) Close() {
	if p != nil && p.kq >= 0 {
		_ = unix.Close(p.kq)
		p.kq = -1
	}
}

// RunWatchdog registers the parent PID with kqueue and waits for its
// NOTE_EXIT. On the event it removes the door line via
// NewDoorWithOptions (DoorOptions{LockPath, OwnerUID, OwnerGID}) and
// exits — the same cleanup, under the same file lock, that the Linux
// half performs through pidfd. If the parent has already exited when the
// registration is attempted, the line is removed immediately (the
// already-gone branch), which is what keeps a crash between
// SpawnWatchdog returning and the child reaching kevent from leaving the
// line behind.
//
// maxWait bounds how long the watcher waits before giving up; production
// passes MaxDoorHard + WatchdogLifetimeSlack, tests a short value.
func RunWatchdog(parentPID int, doorID, keyFile string, sink Sink, maxWait time.Duration, lockPath string, ownerUID, ownerGID int) error {
	if err := validateWatchdogUnixArgs(doorID, keyFile, lockPath, ownerUID, ownerGID); err != nil {
		return err
	}
	if sink == nil {
		sink = noopSink{}
	}
	w, alreadyGone, err := newProcWatcher(parentPID)
	if err != nil {
		return err
	}
	if alreadyGone {
		return removeOnceAndAudit(keyFile, doorID, sink, lockPath, ownerUID, ownerGID)
	}
	defer w.Close()
	return runWatchdogUnix(w, parentPID, doorID, keyFile, sink, maxWait, lockPath, ownerUID, ownerGID)
}
