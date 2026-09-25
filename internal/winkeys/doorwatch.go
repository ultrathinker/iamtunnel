// Cross-platform Watchdog type. The handle is created by
// SpawnWatchdog (Windows: doorwatch_windows.go; non-Windows:
// doorwatch_other.go). The actual block-on-parent-and-clean-up
// behaviour lives in the platform-specific files; this file only
// owns the handle type, its Stop method, and the argv parser
// shared by the helper binary.
//
// On non-Windows the doorwatch is a no-op — production targets
// are Windows machines in 1.0 (SPEC §12).
package winkeys

import (
	"errors"
	"os"
	"sync"
	"time"
)

// watchdogNow is the clock the watchdog's wait loops read: runWatchdogUnix's
// deadline (doorwatch_unix.go) and the Windows loop's (doorwatch_windows.go)
// both go through it, so the cap a spawned watcher applies is one function
// call away from being measured exactly.
//
// It is a test-only seam and its production value is time.Now. The reason it
// exists (IAMT-305 round 4): the cap test cannot assert the deadline with a
// real clock without either sleeping through it or tolerating a slack wide
// enough to swallow the regression it is meant to catch. With the clock
// swapped for one the fake watcher advances by a known amount per poll, the
// number of polls a cap produces is exact, so a deadline that is off by even
// one poll period is a red test rather than a rounding question. Only tests
// in this package set it, before they spawn anything.
var watchdogNow = time.Now

// captureWatchdogStderr is the test-only switch behind Watchdog.Stderr(): with
// it true, SpawnWatchdog redirects the child's stderr into a fresh
// iamtunnel-doorwatch-*.stderr file so a failing test can print why the
// watcher died, instead of the /dev/null production sends it to.
//
// It is false in production, and that is a correctness requirement rather than
// a preference (IAMT-305 round 3): the temporary file is removed by
// Watchdog.Stop, and the case the watchdog exists for — the server killed -9 —
// is precisely the case where Stop never runs, so the capture left one file
// per door in the system temp directory, owned by the server's user (root on a
// real machine). Nothing outside this package's tests reads Stderr(), so
// production gets the pre-IAMT-305 behaviour back and the diagnostics stay
// where they are needed.
var captureWatchdogStderr = false

// Watchdog is a handle to a spawned doorwatch subprocess. The
// server role obtains one by calling SpawnWatchdog BEFORE writing
// the door line (PROTOCOL §5.2 layer 3 ordering). The spawn
// detaches the child from any job object the parent is in so the
// child survives the parent.
//
// Watchdog must outlive the open door: the server calls Stop on a
// confirmed door.close, terminating the child by saved PID/handle.
// Image-name wildcards are forbidden (PROTOCOL §5.1).
type Watchdog struct {
	pid        int
	stop       func() error
	stderrPath string
	// mu guards hasExited/exitCode, the cached exit status. Two callers may
	// ask for the status at once (ExitStatus is advertised as non-blocking
	// diagnostics and nothing forbids a concurrent diagnostic call), and the
	// platform probes below consume the status from the OS: without the lock
	// two probes would race on the fields and could both issue a wait4 for
	// one child (IAMT-305 round 4).
	mu sync.Mutex
	// hasExited/exitCode cache the status once it is known — either from a
	// probe or from the wait Stop performs. Caching is not an optimisation:
	// reaping a child CONSUMES its status, so a later probe gets ECHILD and
	// could not name the code even though the death is a fact (see ExitStatus).
	hasExited bool
	exitCode  int
	// handle is the create-process handle Windows keeps between the spawn and
	// Stop/ExitStatus (TerminateProcess, GetExitCodeProcess). The Unix halves
	// address the child by pid instead — pidfd on Linux, kill(2) on macOS,
	// wait4(2) for the exit status — so nothing on those builds reads this
	// field, which is what staticcheck reports as U1000 (IAMT-305 round 3).
	// A platform-specific struct type does not help: it only moves the same
	// "unused field" report to the other side of the build. The directive
	// below names the one reader.
	//lint:ignore U1000 read by doorwatch_windows.go (Stop and exitStatusPlatform)
	handle uintptr
}

// PID returns the spawned child's PID. Diagnostic only.
func (w *Watchdog) PID() int {
	if w == nil {
		return 0
	}
	return w.pid
}

// Stderr returns any stderr output captured from the watchdog process.
func (w *Watchdog) Stderr() string {
	if w == nil || w.stderrPath == "" {
		return ""
	}
	b, err := os.ReadFile(w.stderrPath)
	if err != nil {
		return ""
	}
	return string(b)
}

// ExitStatus reports the watchdog subprocess's exit status without blocking.
//
// The status is known exactly once per process: a probe reads it from the OS,
// and reaping a child consumes it. So this method answers from a cache — the
// status an earlier probe found, or the one Stop's own wait observed — and the
// first answer wins.
//
// The contract is the same on every platform:
//
//	exited=true, err=nil       the code is real: exited with it, or 128+signal
//	                           when the process died from a signal (SIGKILL: 137);
//	exited=false, err=nil      the process is still running;
//	exited=false, err!=nil     the code could not be determined. Callers must
//	                           treat the error as the verdict and NOT read the
//	                           zero code as "exited cleanly": a status that was
//	                           already reaped (ECHILD on unix, a closed handle on
//	                           Windows) leaves the death a fact and the code
//	                           unknowable, and reporting 0 there would be a
//	                           fabrication (IAMT-305 round 4).
//
// Concurrent calls are safe; Stop is not safe to call concurrently with
// itself (see Stop).
func (w *Watchdog) ExitStatus() (bool, int, error) {
	if w == nil {
		return false, 0, nil
	}
	return w.exitStatusPlatform()
}

// cachedExit reports a status already observed, if any. The caller holds mu.
func (w *Watchdog) cachedExit() (bool, int, bool) {
	if w.hasExited {
		return true, w.exitCode, true
	}
	return false, 0, false
}

// recordExit caches the exit status a wait observed, so ExitStatus can still
// name the code after the status has been consumed. The first status wins:
// a second wait for the same child cannot succeed, and overwriting a real code
// with a later zero is exactly the fabrication ExitStatus refuses to make.
func (w *Watchdog) recordExit(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.hasExited {
		return
	}
	w.hasExited = true
	w.exitCode = code
}

// Stop terminates the doorwatch subprocess. Stop is safe to call
// on a nil receiver; returns nil in that case. It is NOT safe to
// call concurrently with itself — the server role is expected to
// call Stop at most once per Watchdog.
//
// Stop caches the exit status its wait observes, so a later ExitStatus can
// report the code instead of the ECHILD/closed-handle error that would
// otherwise be all that is left of a reaped child (IAMT-305 round 4).
func (w *Watchdog) Stop() error {
	if w == nil || w.stop == nil {
		return nil
	}
	return w.stop()
}

// WatchdogStartedAt is the moment SpawnWatchdog returned. Useful
// for tests that want to check the delay between spawn and the
// eventual handle teardown.
type WatchdogEvent struct {
	At time.Time
	Op string // "spawn" | "stop"
}

// ParseWatchdogArgs parses the argv of a doorwatch subprocess
// invocation. The expected layout is:
//
//	<exe> server doorwatch <door-id> <parent-pid> <keyfile> <max-wait-ms> <journal-path>
//
// <max-wait-ms> is the watchdog's own safety cap on how long it
// will sit waiting for the parent. The server supplies it on every
// spawn; it is derived from the machine's MaxDoorHard ceiling plus a
// slack so the watcher lives as long as the door can live (IAMT-130:
// the previous hard-coded 5 minutes could expire while the door was
// still open, and a crash that followed left the admin key line
// behind until SweepStale ran).
//
// <journal-path> is the optional audit log the watchdog writes its
// "the watcher cleaned up the door line" event into. Empty means
// "no journal" — RunWatchdog uses noopSink in that case, mirroring
// the same sink=nil convention internal/server keeps for its own
// layer-2 cleanup when no Sink is configured.
//
// ParseWatchdogArgs is platform-independent — used by the helper
// binary's main() as well as by tests that want to confirm the
// argv layout. The args slice follows os.Args convention: args[0]
// is the executable name.
func ParseWatchdogArgs(args []string) (parentPID int, doorID, keyFile, journalPath string, maxWait time.Duration, err error) {
	if len(args) < 8 {
		return 0, "", "", "", 0, errors.New("usage: <exe> server doorwatch <door-id> <parent-pid> <keyfile> <max-wait-ms> <journal-path>")
	}
	if args[1] != "server" || args[2] != "doorwatch" {
		return 0, "", "", "", 0, errors.New("not a server doorwatch invocation")
	}
	pid, perr := parseIntArg(args[4])
	if perr != nil {
		return 0, "", "", "", 0, errors.New("bad parent pid: " + args[4])
	}
	mw, merr := parseIntArg(args[6])
	if merr != nil {
		return 0, "", "", "", 0, errors.New("bad max-wait-ms: " + args[6])
	}
	return pid, args[3], args[5], args[7], time.Duration(mw) * time.Millisecond, nil
}

func parseIntArg(s string) (int, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, errors.New("not an integer: " + s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
