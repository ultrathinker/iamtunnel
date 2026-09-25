//go:build linux || darwin

// doorwatch_unix.go — the half of the Unix doorwatch that Linux and
// macOS share (Linux: IAMT-247, pidfd; macOS: IAMT-263, kqueue).
//
// Per PROTOCOL §5.2 the doorwatch is spawned by the server role BEFORE
// the door line is written, and it is detached from the parent's
// process group / controlling terminal (a new session via setsid) so
// the child survives the parent. On the parent's death — including a
// SIGKILL or a panic — the child removes the door line and exits.
//
// What differs between the two Unixes is only how the child learns that
// the parent is gone: Linux opens a pidfd and polls it (pidfd_open(2),
// kernel 5.3+), macOS registers EVFILT_PROC / NOTE_EXIT on a kqueue
// (kqueue(2); macOS has no pidfd). Both are the same shape — a
// descriptor that becomes ready when the watched process exits — so the
// loop that owns the deadline, the "parent already gone" branch and the
// cleanup-and-audit call lives here, and each platform file supplies
// nothing but a parentWatcher.
//
// The argv layout is shared too, and it is the same one cmdServerDoorwatch's
// Unix half parses:
//
//	<exe> server doorwatch <door-id> <parent-pid> <keyfile> <max-wait-ms>
//	      <journal-path> <lock-path> <owner-uid> <owner-gid>
//
// The three tail fields carry the unix-only DoorOptions
// (LockPath/OwnerUID/OwnerGID) that NewDoorWithOptions requires on both
// platforms: the watchdog subprocess calls NewDoorWithOptions on its own
// end to remove the line, and the lock file must live in the server's
// data directory rather than beside the user's key file (SPEC §3.2.1).

package winkeys

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// watchdogPollWindow is how long one wait iteration blocks before the
// shared loop re-checks its own deadline. 500 ms mirrors the Windows
// side's WaitForSingleObject cadence (doorwatch_windows.go): short
// enough that a test with a short maxWait finishes promptly, long
// enough that the watcher is idle rather than spinning.
const watchdogPollWindow = 500 * time.Millisecond

// parentWatcher is the platform's "has this process exited?" primitive.
// Linux: a pidfd polled for readability (doorwatch_linux.go). macOS: a
// kqueue with EVFILT_PROC/NOTE_EXIT on the parent PID
// (doorwatch_darwin.go). The constructor for each platform handles the
// "the parent is already gone" case itself and reports it as
// parentAlreadyGone, so the loop below never has to know which syscall
// noticed.
type parentWatcher interface {
	// Wait blocks for at most timeout and reports whether the watched
	// process has exited. (false, nil) means "still alive" — a timeout,
	// not an error. An error means the wait itself failed.
	Wait(timeout time.Duration) (exited bool, err error)
	// Close releases the descriptor. Safe to call once, after Wait.
	Close()
}

// runWatchdogUnix is the shared wait loop: block on the platform
// watcher until the parent exits, then remove the door line under the
// file lock and exit. maxWait is the watcher's own safety cap — it MUST
// be derived from the machine's door ceiling (MaxDoorHard plus the
// lifetime slack), never hard-coded (IAMT-130). Exceeding it is an
// error, not a silent exit: a watcher that gave up while the door was
// still legally open would be the very gap the watchdog exists to
// close.
//
// Both clock reads go through watchdogNow (doorwatch.go) so a test can drive
// this loop with a virtual clock and assert the cap exactly: with a real clock
// the number of polls a cap produces is only bounded, never exact.
func runWatchdogUnix(w parentWatcher, parentPID int, doorID, keyFile string, sink Sink, maxWait time.Duration, lockPath string, ownerUID, ownerGID int) error {
	deadline := watchdogNow().Add(maxWait)
	for {
		exited, err := w.Wait(watchdogPollWindow)
		if err != nil {
			return err
		}
		if exited {
			return removeOnceAndAudit(keyFile, doorID, sink, lockPath, ownerUID, ownerGID)
		}
		if watchdogNow().After(deadline) {
			return fmt.Errorf("parent %d still alive after %s", parentPID, maxWait)
		}
	}
}

// validateWatchdogUnixArgs is the argument gate both Unix halves share
// before they touch the OS. The wording says "linux and darwin" rather
// than naming one platform, matching NewDoorWithOptions's own gate
// (doors_unix.go: "LockPath is required on linux and darwin").
func validateWatchdogUnixArgs(doorID, keyFile, lockPath string, ownerUID, ownerGID int) error {
	if doorID == "" {
		return errors.New("winkeys.RunWatchdog: doorID must not be empty")
	}
	if keyFile == "" {
		return errors.New("winkeys.RunWatchdog: keyFile must not be empty")
	}
	if lockPath == "" {
		return errors.New("winkeys.RunWatchdog: lockPath must not be empty on linux and darwin")
	}
	if ownerUID <= 0 || ownerGID <= 0 {
		return errors.New("winkeys.RunWatchdog: ownerUID and ownerGID must be positive on linux and darwin")
	}
	return nil
}

// spawnWatchdogUnix launches <exe> with the Unix argv layout in a fresh
// session (setsid), detached from the parent's controlling terminal and
// process group — the counterpart of the Windows side's
// CREATE_BREAKAWAY_FROM_JOB + STARTF_USESHOWWINDOW pair. The argv layout
// MUST stay in sync with cmdServerDoorwatch's Unix half in
// cmd/iamtunnel/server.go and with ParseWatchdogArgsUnix below: these
// are the three places the shape is documented.
//
// maxWaitMs is int64 rather than time.Duration for the same reason the
// Windows side does it: the argv-encoding step downgrades the type, and
// naming the parameter in milliseconds keeps the conversion explicit
// (staticcheck ST1011 — Duration misnamed).
func spawnWatchdogUnix(exe, doorID, keyFile string, parentPID int, maxWait time.Duration, journalPath, lockPath string, ownerUID, ownerGID int) (int, string, error) {
	maxWaitMs := int64(maxWait / time.Millisecond)
	if maxWaitMs <= 0 {
		maxWaitMs = 1
	}
	cmd := exec.Command(exe, "server", "doorwatch",
		doorID,
		strconv.Itoa(parentPID),
		keyFile,
		strconv.FormatInt(maxWaitMs, 10),
		journalPath,
		lockPath,
		strconv.Itoa(ownerUID),
		strconv.Itoa(ownerGID),
	)
	cmd.SysProcAttr = &unix.SysProcAttr{
		Setsid: true,
	}
	cmd.Stdin = nil
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return 0, "", fmt.Errorf("open /dev/null: %w", err)
	}
	cmd.Stdout = devNull

	// The child's stderr goes to /dev/null in production and into a temporary
	// file only for a test (captureWatchdogStderr, doorwatch.go). The capture
	// is what a red test needs to show why a watcher died, but as production
	// behaviour it leaked: the file was removed only by Watchdog.Stop, and the
	// one case the watcher exists for — the server killed -9 — is exactly the
	// case where Stop never runs, so every door left one
	// iamtunnel-doorwatch-*.stderr behind in the system temp dir (root-owned,
	// on the machine the server runs on). IAMT-305 round 3.
	var stderrFile *os.File
	stderrPath := ""
	if captureWatchdogStderr {
		stderrFile, err = os.CreateTemp("", "iamtunnel-doorwatch-*.stderr")
		if err != nil {
			_ = devNull.Close()
			return 0, "", fmt.Errorf("create doorwatch stderr: %w", err)
		}
		cmd.Stderr = stderrFile
		stderrPath = stderrFile.Name()
	} else {
		cmd.Stderr = devNull
	}

	if err := cmd.Start(); err != nil {
		_ = devNull.Close()
		if stderrFile != nil {
			_ = stderrFile.Close()
			_ = os.Remove(stderrPath)
		}
		return 0, "", fmt.Errorf("start doorwatch %s: %w", exe, err)
	}
	// os/exec dups the parent's fds into the child via the fork+exec
	// syscall; the parent's own copies can be closed right after Start()
	// returns. Leaving them open is a slow leak over a long-running server.
	_ = devNull.Close()
	if stderrFile != nil {
		_ = stderrFile.Close()
	}
	return cmd.Process.Pid, stderrPath, nil
}

func (w *Watchdog) exitStatusPlatform() (bool, int, error) {
	if w == nil {
		return false, 0, nil
	}
	// Held across the probe on purpose: wait4(WNOHANG) does not block, and the
	// lock is what keeps two concurrent calls from issuing two waits for one
	// child — the second would get ECHILD while the first consumed the status.
	w.mu.Lock()
	defer w.mu.Unlock()
	// The cached status is authoritative and is checked before the pid/handle
	// guard: after a Stop the status is cached while the handle may already be
	// gone, and the cache is exactly what makes that state answerable.
	if exited, code, ok := w.cachedExit(); ok {
		return exited, code, nil
	}
	if w.pid <= 0 {
		return false, 0, nil
	}
	var ws unix.WaitStatus
	pid, err := unix.Wait4(w.pid, &ws, unix.WNOHANG, nil)
	if err != nil {
		if errors.Is(err, unix.ECHILD) {
			// The child is gone and its status is gone with it: something
			// already reaped it (Stop's wait, or another waiter). The death is
			// a fact, the code is not knowable, and "0" would read as a clean
			// exit that never happened (IAMT-305 round 4).
			return false, 0, fmt.Errorf("watchdog process %d was already reaped: its exit code is no longer available", w.pid)
		}
		return false, 0, err
	}
	if pid == 0 {
		return false, 0, nil
	}
	w.hasExited = true
	w.exitCode = exitCodeFromWaitStatus(syscall.WaitStatus(ws))
	return true, w.exitCode, nil
}

// exitCodeFromWaitStatus is the one mapping from a wait status to the code
// ExitStatus reports: an ordinary exit keeps its own code, a signal death
// becomes 128+signal (SIGKILL -> 137, the code a killed watcher is expected to
// show). Both waits that can observe a status go through it — the live probe's
// wait4 and the wait Stop performs — so one death cannot be reported as two
// different codes depending on who looked first.
//
// The argument is the standard library's syscall.WaitStatus: that is the type
// os.ProcessState.Sys() carries on both Unix platforms. x/sys's unix.WaitStatus
// is a distinct defined type over the same uint32, so the wait4 caller converts
// (doorwatch_unix.go, exitStatusPlatform).
func exitCodeFromWaitStatus(ws syscall.WaitStatus) int {
	if ws.Exited() {
		return ws.ExitStatus()
	}
	if ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return 0
}

// exitCodeFromProcessState maps the state os.Process.Wait returns onto the same
// code space, for the Stop path that has already reaped the child.
func exitCodeFromProcessState(ps *os.ProcessState) (int, bool) {
	if ps == nil {
		return 0, false
	}
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok {
		return exitCodeFromWaitStatus(ws), true
	}
	if code := ps.ExitCode(); code >= 0 {
		return code, true
	}
	return 0, false
}

// removeOnceAndAudit is the single-path removal used by RunWatchdog and
// by the helper binary on both Unix platforms. The audit event records
// the watcher's cleanup distinctly from the server's layer-2 cleanup so
// a journal can tell them apart.
//
// NewDoorWithOptions is the constructor: validateOptionsPlatform
// (doors_unix.go) requires LockPath and refuses the 0,0 owner sentinel,
// and both platform halves validate those before calling here.
func removeOnceAndAudit(keyFile, doorID string, sink Sink, lockPath string, ownerUID, ownerGID int) error {
	opts := DoorOptions{LockPath: lockPath, OwnerUID: ownerUID, OwnerGID: ownerGID}
	d, err := NewDoorWithOptions(keyFile, sink, opts)
	if err != nil {
		return err
	}
	return d.Remove(doorID)
}

// stopWatchdogUnix is the by-PID Stop: SIGKILL the child by saved PID, wait for
// it, return. Layer 2 in the parent has already removed the door line before
// Stop is called, so the watchdog's own exit does not need a graceful-cleanup
// phase: kill it and rely on layer 2. Process.Kill sends SIGKILL on
// both Linux and macOS; image-name wildcards are forbidden (PROTOCOL §5.1), so
// the PID is the only handle. macOS installs it as-is (pidfd_send_signal is a
// Linux syscall); Linux installs it only as the fallback for kernels without
// pidfd_open — the same kernels the getppid watcher serves — while Linux 5.3+
// stops the child through the child's own pidfd instead (doorwatch_linux.go,
// IAMT-281).
//
// The wait this performs is what reaps the child, so it is also the last chance
// to learn the exit code: the status comes back here and nowhere else afterwards
// (a later wait4 answers ECHILD). ok=false means the wait could not name one —
// the caller then leaves the cache alone rather than caching a 0 that no process
// ever exited with (IAMT-305 round 4).
func stopWatchdogUnix(proc *os.Process) (code int, ok bool) {
	if proc == nil {
		return 0, false
	}
	_ = proc.Kill()
	ps, _ := proc.Wait()
	return exitCodeFromProcessState(ps)
}

// ParseWatchdogArgsUnix is the Unix-side sibling of ParseWatchdogArgs
// (the Windows argv parser). The two layouts differ — the Unix one
// carries three extra fields at the tail (lock-path, owner-uid,
// owner-gid) — so a single cross-platform parser would either grow
// conditional branches or split anyway; a separate function is the
// simpler shape. It is shared by Linux and macOS because the layout
// itself is: IAMT-263 gave macOS the same tail rather than inventing a
// second one, so the kqueue half of the argv parser is this function.
// cmdServerDoorwatch's Unix half in cmd/iamtunnel/server.go is the only
// production caller; tests reach for it through
// internal/winkeys/testdata/wd_linux (the linux-tagged integration test
// spawns that helper, so the shared parser is exercised by the same
// test that drives the real watchdog).
//
// The expected layout (mirror of that command's help string and of
// spawnWatchdogUnix's argv construction):
//
//	args[0]  = exe name
//	args[1]  = "server"
//	args[2]  = "doorwatch"
//	args[3]  = door-id
//	args[4]  = parent-pid
//	args[5]  = keyfile
//	args[6]  = max-wait-ms
//	args[7]  = journal-path
//	args[8]  = lock-path
//	args[9]  = owner-uid
//	args[10] = owner-gid
//
// So len(args) must be >= 11 (exe + 10 positional).
func ParseWatchdogArgsUnix(args []string) (parentPID int, doorID, keyFile, journalPath, lockPath string, ownerUID, ownerGID int, maxWait time.Duration, err error) {
	if len(args) < 11 {
		err = errors.New("usage: <exe> server doorwatch <door-id> <parent-pid> <keyfile> <max-wait-ms> <journal-path> <lock-path> <owner-uid> <owner-gid>")
		return
	}
	if args[1] != "server" || args[2] != "doorwatch" {
		err = errors.New("not a server doorwatch invocation")
		return
	}
	parentPID, err = parseIntArg(args[4])
	if err != nil {
		err = errors.New("bad parent pid: " + args[4])
		return
	}
	mw, merr := parseIntArg(args[6])
	if merr != nil {
		err = errors.New("bad max-wait-ms: " + args[6])
		return
	}
	uid, uerr := parseIntArg(args[9])
	if uerr != nil {
		err = errors.New("bad owner-uid: " + args[9])
		return
	}
	gid, gerr := parseIntArg(args[10])
	if gerr != nil {
		err = errors.New("bad owner-gid: " + args[10])
		return
	}
	return parentPID, args[3], args[5], args[7], args[8], uid, gid, time.Duration(mw) * time.Millisecond, nil
}
