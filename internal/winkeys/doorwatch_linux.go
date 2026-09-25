//go:build linux

// Linux doorwatch (IAMT-247): the pidfd half of the Unix watchdog.
// Spawn, the argv layout, the "already gone" cleanup and the wait loop
// are shared with macOS and live in doorwatch_unix.go; what is left
// here is the mechanism that names this platform's task: poll(2) on a
// pidfd returned by pidfd_open(2) (kernel 5.3+).
//
// pidfd becomes readable when the watched PID terminates for any
// reason, without a race against signal-handler latency: the loop sits
// in poll(2) with a short timeout (the shared loop's 500 ms window,
// mirroring the Windows side's WaitForSingleObject cadence) and when
// the pidfd fires the watcher removes the line and exits.
//
// PR_SET_PDEATHSIG is deliberately NOT set on this path (IAMT-279).
// A PDEATHSIG is delivered by the kernel at the same instant the
// parent exits — exactly the moment the pidfd becomes readable — and
// SIGKILL is uncatchable, so the delivery could win that undefined
// race and end this process before the door line is removed, leaving
// the line behind in the very kill -9 scenario the watchdog exists
// for (the parent's own layer-2 cleanup only covers deaths the parent
// survives to clean up after, and a kill -9 is not one). pidfd
// polling is therefore the sole parent-death mechanism on the pidfd
// path. On a kernel without pidfd_open (Linux < 5.3, PidfdOpen
// answering ENOSYS) the watcher is getppidWatcher instead — the SPEC
// §3.2.1 fallback: PR_SET_PDEATHSIG with a catchable SIGTERM this
// process handles itself, plus a getppid() poll. The death signal
// lives only there, behind a handler, never as an uncatchable
// backstop.

package winkeys

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/unix"
)

// SpawnWatchdog starts the doorwatch subprocess in a fresh session
// (setsid) so it survives the parent's controlling terminal, with
// stdout/stderr routed to /dev/null. The child receives the parent PID,
// the safety-cap maxWait, the optional journalPath and the unix
// DoorOptions (LockPath/OwnerUID/OwnerGID) via argv, and waits on the
// parent (spawnWatchdogUnix in doorwatch_unix.go builds exactly the
// argv cmdServerDoorwatch's Unix half parses).
//
// maxWait is how long the watcher is willing to sit waiting for the
// parent before it gives up. It MUST be derived from the machine's own
// door ceiling, not hard-coded — IAMT-130 found a 5-minute hard-coded
// value that could expire while the door was still legally open under
// MaxDoorHard, and any crash that followed left the admin-key line
// behind until the next SweepStale.
//
// journalPath is the audit log the child writes its cleanup event to.
// Empty string means "no journal": the child uses noopSink and the
// cleanup event is dropped.
//
// lockPath / ownerUID / ownerGID are required on linux (and darwin):
// NewDoorWithOptions refuses a Door without them
// (validateOptionsPlatform gate). The same call sites on Windows pass
// them through but the platform implementation there ignores them; one
// signature across platforms keeps server.Config and cmdServerDoorwatch
// from branching on runtime.GOOS.
//
// Returns a Watchdog handle whose Stop method kills the child through
// the child's own pidfd (pidfd_send_signal), so a PID reused after the
// watchdog's own exit can never be signalled by mistake (IAMT-281).
// PROTOCOL §5.1 forbids image-name wildcards; on kernels without
// pidfd_open (Linux < 5.3) no such handle exists and Stop degrades to
// the shared by-PID stop (stopWatchdogUnix), the same shape macOS
// uses. Layer 2 in the parent has already removed the door line before
// Stop is called, so the watchdog's own exit does not need a
// graceful-cleanup phase.
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

	// IAMT-281: pin the child by its own pidfd immediately after the
	// start — a different pidfd from RunWatchdog's: this one names the
	// child, not the parent. The child is our direct child and has not
	// been waited on yet, so at worst it is an unreaped zombie; its PID
	// cannot be reused in this window, and the pidfd keeps naming that
	// exact process for the whole lifetime of the handle afterwards.
	childPidfd, perr := unix.PidfdOpen(pid, 0)
	if perr != nil && !errors.Is(perr, unix.ENOSYS) {
		// The child is already running — do not leak it. At this
		// instant it is our unreaped direct child, so its PID cannot
		// be reused yet and a by-number SIGKILL is race-free (the
		// pidfd path below is exactly what keeps later stops
		// race-free).
		_ = proc.Kill()
		_, _ = proc.Wait()
		_ = os.Remove(stderrPath)
		return nil, fmt.Errorf("pidfd_open(%d) for the spawned watchdog: %w", pid, perr)
	}
	watchdog := &Watchdog{pid: pid, stderrPath: stderrPath}
	if perr != nil {
		// ENOSYS: kernel < 5.3, no pidfd facility at all — the same
		// kernels RunWatchdog's fallback serves with the getppid
		// watcher. No safe handle exists on this kernel, so Stop
		// degrades to stopWatchdogUnix (kill(2) by number, with its
		// PID-reuse window), the same shape macOS uses.
		watchdog.stop = func() error {
			// The wait inside stopWatchdogUnix reaps the child, so its
			// status has to be cached here — afterwards a probe can only
			// answer ECHILD (IAMT-305 round 4).
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
	watchdog.stop = func() error {
		// SIGKILL mirrors Windows' TerminateProcess: layer 2 in the
		// parent has already removed the line before Stop is called,
		// so the watchdog's own exit does not need a graceful-cleanup
		// phase. The signal goes through the child's pidfd, not
		// kill(2): if the watchdog already exited on its own and its
		// PID was reused, a by-number kill would hit the wrong process
		// (IAMT-281); pidfd_send_signal on an exited but unreaped
		// child is a harmless no-op.
		_ = unix.PidfdSendSignal(childPidfd, unix.SIGKILL, nil, 0)
		ps, _ := proc.Wait()
		// proc.Wait is the reap, so this is the only moment the code of a
		// SIGKILLed watcher can still be read: 128+9, the same number the
		// wait4 probe would have produced (IAMT-305 round 4).
		if code, ok := exitCodeFromProcessState(ps); ok {
			watchdog.recordExit(code)
		}
		_ = unix.Close(childPidfd)
		if watchdog.stderrPath != "" {
			_ = os.Remove(watchdog.stderrPath)
		}
		return nil
	}
	return watchdog, nil
}

// pidfdWatcher is the Linux parentWatcher: a pidfd polled for
// readability. Constructing it is where the "parent is already gone"
// case is decided — pidfd_open answers ENOENT/ESRCH for a PID that no
// longer exists, which RunWatchdog turns into "clean up now" rather than
// an error (the Windows side's OpenProcess-failed branch).
type pidfdWatcher struct {
	fd int32
}

// newPidfdWatcher opens the pidfd. alreadyGone is true when the parent
// had already exited before the watcher could attach — the caller then
// removes the line immediately, exactly as it would after a normal
// NOTE_EXIT. ENOSYS is not one of those "the parent is not there"
// answers: it means this kernel has no pidfd_open at all, and it is
// returned wrapped so newLinuxParentWatcher can recognise it and fall
// back to getppidWatcher (IAMT-280).
func newPidfdWatcher(parentPID int) (w parentWatcher, alreadyGone bool, err error) {
	fd, err := unix.PidfdOpen(parentPID, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
			return nil, true, nil
		}
		if errors.Is(err, unix.ENOSYS) {
			return nil, false, fmt.Errorf("pidfd_open not supported by kernel (need Linux 5.3+): %w", err)
		}
		return nil, false, fmt.Errorf("pidfd_open(%d): %w", parentPID, err)
	}
	return &pidfdWatcher{fd: int32(fd)}, false, nil
}

// Wait polls the pidfd with the shared loop's window. POLLIN means the
// process behind the descriptor has terminated for any reason; POLLHUP
// is accepted alongside it because a pidfd that has already fired can
// report either across kernel versions, and treating a fired descriptor
// as "still alive" would leave the door line behind.
//
// EINTR is swallowed as "still alive" rather than surfaced: the shared
// loop re-checks its own deadline on the next iteration, which is
// exactly what the pre-IAMT-263 code did by hand in its EINTR branch.
func (p *pidfdWatcher) Wait(timeout time.Duration) (bool, error) {
	pollFds := []unix.PollFd{{Fd: p.fd, Events: unix.POLLIN}}
	n, err := unix.Poll(pollFds, int(timeout/time.Millisecond))
	if err != nil {
		if err == unix.EINTR {
			return false, nil
		}
		return false, fmt.Errorf("poll on parent pidfd: %w", err)
	}
	if n > 0 && pollFds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
		return true, nil
	}
	return false, nil
}

// Close releases the pidfd.
func (p *pidfdWatcher) Close() {
	if p != nil && p.fd >= 0 {
		_ = unix.Close(int(p.fd))
		p.fd = -1
	}
}

// getppidWatcher is the Linux parentWatcher for kernels without
// pidfd_open (PidfdOpen answering ENOSYS, i.e. Linux < 5.3): the SPEC
// §3.2.1 fallback. Its primitive is the parent-death signal this
// process arms for itself — PR_SET_PDEATHSIG with SIGTERM, which is
// catchable (IAMT-279 is about the uncatchable SIGKILL, never set
// here) — plus a getppid() poll as the authoritative answer.
//
// The signal is routed through signal.Notify into a buffered channel
// and never gets the default (terminating) action while the watcher is
// registered. It only wakes Wait early: the exit decision is always
// made from getppid(), because once the parent dies the child is
// re-parented (to init or the nearest subreaper) and getppid() stops
// naming the watched PID. A stray SIGTERM sent while the parent is
// alive is absorbed the same way — the channel fires, getppid() still
// matches, Wait answers "still alive".
type getppidWatcher struct {
	parentPID int
	sigCh     chan os.Signal
}

// newGetppidWatcher arms the death signal and immediately re-checks
// getppid(). That re-check is the fork→prctl race closer: if the
// parent died between our spawn and this prctl, no signal will ever
// be delivered (the setting came too late), and the re-parented
// getppid() is the only evidence — that is alreadyGone, the same
// answer ENOENT/ESRCH gives the pidfd path. Arming the signal itself
// is best-effort: if prctl is refused (seccomp, hardening profile)
// the getppid poll alone still detects the death within one
// watchdogPollWindow.
func newGetppidWatcher(parentPID int) (w parentWatcher, alreadyGone bool, err error) {
	sigCh := make(chan os.Signal, 1)
	// Notify BEFORE Prctl: a SIGTERM arriving in the instant after the
	// prctl must land in the buffer, not on the default handler.
	signal.Notify(sigCh, unix.SIGTERM)
	_ = unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGTERM), 0, 0, 0)
	g := &getppidWatcher{parentPID: parentPID, sigCh: sigCh}
	if unix.Getppid() != parentPID {
		g.Close()
		return nil, true, nil
	}
	return g, false, nil
}

// Wait sleeps up to timeout, woken early by the death signal, then
// answers from getppid(). It never returns an error: this watcher has
// no syscall whose failure should abort the cleanup — the poll is a
// plain process-attribute read, and the shared loop treats an error as
// "give up without cleaning", which is exactly what this fallback must
// never do.
func (g *getppidWatcher) Wait(timeout time.Duration) (bool, error) {
	tick := time.NewTimer(timeout)
	defer tick.Stop()
	select {
	case <-g.sigCh:
	case <-tick.C:
	}
	return unix.Getppid() != g.parentPID, nil
}

// Close unregisters the signal channel. The armed PDEATHSIG itself
// stays for the process's remaining lifetime, but the only code still
// running after Close is RunWatchdog's tail — the line is already
// removed or the alreadyGone branch is being returned from — so a
// terminating SIGTERM from that point on costs nothing.
func (g *getppidWatcher) Close() {
	if g != nil && g.sigCh != nil {
		signal.Stop(g.sigCh)
		g.sigCh = nil
	}
}

// newLinuxParentWatcher is the constructor RunWatchdog uses: the pidfd
// watcher when the kernel has pidfd_open, the getppid watcher when it
// answers ENOSYS (Linux < 5.3). Every other pidfd_open outcome is
// returned as-is — the already-dead parent came back as alreadyGone
// above, and a real failure has no fallback that could name the
// parent either.
func newLinuxParentWatcher(parentPID int) (w parentWatcher, alreadyGone bool, err error) {
	w, alreadyGone, err = newPidfdWatcher(parentPID)
	if err == nil || !errors.Is(err, unix.ENOSYS) {
		return w, alreadyGone, err
	}
	return newGetppidWatcher(parentPID)
}

// RunWatchdog attaches a parentWatcher to parentPID — the pidfd path on
// Linux 5.3+, the getppid path on older kernels (newLinuxParentWatcher)
// — and runs it through the shared loop. When the watcher reports the
// parent terminated, the door line is removed via
// NewDoorWithOptions(..., DoorOptions{LockPath, OwnerUID, OwnerGID})
// and the watcher exits. If the parent has already died before the
// watcher could attach (pidfd_open ENOENT/ESRCH, or the fallback's
// re-parented getppid), the watchdog still removes the line — the race
// between SpawnWatchdog returning and the child attaching its watcher
// is the same one the Windows side handles via OpenProcess returning
// ERROR_INVALID_HANDLE.
//
// maxWait bounds how long RunWatchdog is willing to sit waiting for the
// parent. Tests use a short value; production passes a safety cap
// (MaxDoorHard + WatchdogLifetimeSlack).
//
// RunWatchdog does NOT set an uncatchable PDEATHSIG (IAMT-279): the
// only death signal in play is the fallback's catchable SIGTERM,
// consumed inside getppidWatcher.Wait and never allowed the default
// terminating action.
func RunWatchdog(parentPID int, doorID, keyFile string, sink Sink, maxWait time.Duration, lockPath string, ownerUID, ownerGID int) error {
	if err := validateWatchdogUnixArgs(doorID, keyFile, lockPath, ownerUID, ownerGID); err != nil {
		return err
	}
	if sink == nil {
		sink = noopSink{}
	}
	w, alreadyGone, err := newLinuxParentWatcher(parentPID)
	if err != nil {
		return err
	}
	if alreadyGone {
		return removeOnceAndAudit(keyFile, doorID, sink, lockPath, ownerUID, ownerGID)
	}
	defer w.Close()
	return runWatchdogUnix(w, parentPID, doorID, keyFile, sink, maxWait, lockPath, ownerUID, ownerGID)
}
