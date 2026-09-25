//go:build windows

// Windows doorwatch: spawn + block-on-parent + clean up.
//
// Per PROTOCOL §5.2 the doorwatch is spawned by the server role
// BEFORE the door line is written, and it is detached from any
// job object the parent is in (so the child survives the parent).
// On the parent's death — including a taskkill /f — the child
// removes the door line and exits.
//
// The actual blocking uses WaitForSingleObject on a SYNCHRONIZE
// handle to the parent PID, which is fired by Windows on every
// process death regardless of how the death came about.

package winkeys

import (
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SpawnWatchdog starts the doorwatch subprocess detached from any
// job object the parent is in, with no console window. The child
// receives the parent PID, the safety-cap maxWait and the optional
// journalPath via argv and waits on the parent.
//
// maxWait is how long the watcher is willing to sit waiting for the
// parent before it gives up. It MUST be derived from the machine's
// own door ceiling, not hard-coded — IAMT-130 found a 5-minute
// hard-coded value that could expire while the door was still
// legally open under MaxDoorHard, and any crash that followed left
// the admin-key line behind until the next SweepStale.
//
// journalPath is the audit log the child writes its cleanup event
// to. Empty string means "no journal": the child uses noopSink and
// the cleanup event is dropped. A non-empty path is opened with
// O_APPEND by the child at startup; the parent's own layer-2 audit
// can write to the same path concurrently because each write is
// atomic at POSIX rename / Windows MoveFileEx granularity, and the
// watchdog's audit record is short enough that a torn write is
// detected on the next open.
//
// lockPath, ownerUID and ownerGID are required on linux/darwin,
// where NewDoorWithOptions refuses a Door without them; Windows
// validateOptionsPlatform is a no-op, so the same call site on
// Windows passes them through but the platform implementation
// here ignores them. Keeping one signature across platforms
// (rather than a build-tagged split) means server.Config never
// has to branch on runtime.GOOS when calling SpawnWatchdog.
//
// Returns a Watchdog handle the server can use to terminate the
// child by saved PID, in line with PROTOCOL §5.1 (image-name is
// forbidden). On Windows the handle is the create-process handle;
// Stop uses TerminateProcess on it.
func SpawnWatchdog(exe, doorID, keyFile string, parentPID int, maxWait time.Duration, journalPath, lockPath string, ownerUID, ownerGID int) (*Watchdog, error) {
	if exe == "" {
		return nil, errors.New("winkeys: exe must not be empty")
	}
	if doorID == "" || keyFile == "" {
		return nil, errors.New("winkeys: doorID and keyFile must not be empty")
	}
	if maxWait <= 0 {
		return nil, errors.New("winkeys: maxWait must be positive")
	}
	// Same rule as the Unix half (doorwatch.go's captureWatchdogStderr): the
	// stderr file exists for a failing test to read, not for production. With
	// the switch off, spawnWatchdogInternal is handed "" and the child gets no
	// redirected stderr — byte for byte the behaviour before IAMT-305 added
	// the capture, and no temp file to leak when the server is killed.
	var stderrPath string
	if captureWatchdogStderr {
		tempFile, err := os.CreateTemp("", "iamtunnel-doorwatch-*.stderr")
		if err != nil {
			return nil, fmt.Errorf("create doorwatch stderr: %w", err)
		}
		stderrPath = tempFile.Name()
		_ = tempFile.Close()
	}
	pid, h, err := spawnWatchdogInternal(exe, doorID, keyFile, stderrPath, parentPID, maxWait, journalPath)
	if err != nil {
		if stderrPath != "" {
			_ = os.Remove(stderrPath)
		}
		return nil, err
	}
	watchdog := &Watchdog{pid: pid, handle: uintptr(h), stderrPath: stderrPath}
	watchdog.stop = func() error {
		// TerminateProcess is the polite-stop primitive on
		// Windows; the child may not get a chance to run its
		// cleanup, but layer 2 in the parent handles that. The
		// important thing here is the child is dead — the file
		// lock it could have held is released.
		var stopErr error
		if err := windows.TerminateProcess(h, 1); err != nil && !isAlreadyInvalid(err) {
			stopErr = fmt.Errorf("TerminateProcess watchdog: %w", err)
		}
		if stopErr == nil {
			// Read the exit code BEFORE the handle goes away: GetExitCodeProcess
			// is the only way to name a Windows child's code and a closed handle
			// cannot answer, so Stop is the last moment it can be cached for a
			// later ExitStatus (IAMT-305 round 4). The wait is bounded rather
			// than INFINITE because a diagnostic read must not be able to hang
			// the door-close path; a timeout simply leaves the code uncached,
			// which ExitStatus reports as an explicit error instead of a 0.
			if code, ok := watchdogExitCode(h); ok {
				watchdog.recordExit(code)
			}
		}
		windows.CloseHandle(h)
		if watchdog.stderrPath != "" {
			_ = os.Remove(watchdog.stderrPath)
		}
		return stopErr
	}
	return watchdog, nil
}

// watchdogExitCodeMs bounds how long Stop is willing to wait for the process
// object to signal after a successful TerminateProcess. Termination is forced
// and normally observable at once; the bound exists so a wedged kernel object
// cannot turn a door close into a hang.
const watchdogExitCodeMs = 5000

// watchdogExitCode waits for the terminated child and reads its exit code.
// ok=false means the code is not available (the wait failed or timed out, the
// handle is not a process handle, or the API answered STILL_ACTIVE), and the
// caller must then cache nothing.
func watchdogExitCode(h windows.Handle) (int, bool) {
	if r, _, _ := procWaitForSingleObject.Call(uintptr(h), uintptr(watchdogExitCodeMs)); r != 0 {
		// WAIT_OBJECT_0 (0) is the only answer that means "terminated".
		// WAIT_TIMEOUT (258) and WAIT_FAILED (0xFFFFFFFF) both leave the code
		// unknowable.
		return 0, false
	}
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return 0, false
	}
	if code == 259 { // STILL_ACTIVE
		return 0, false
	}
	return int(code), true
}

func (w *Watchdog) exitStatusPlatform() (bool, int, error) {
	if w == nil {
		return false, 0, nil
	}
	// Held across the probe for the same reason the Unix half holds it: two
	// concurrent calls must not both read (and race on) the fields, and a
	// cached status must win over a probe of a handle that Stop has already
	// closed (IAMT-305 round 4).
	w.mu.Lock()
	defer w.mu.Unlock()
	if exited, code, ok := w.cachedExit(); ok {
		return exited, code, nil
	}
	if w.handle == 0 {
		return false, 0, nil
	}
	var code uint32
	err := windows.GetExitCodeProcess(windows.Handle(w.handle), &code)
	if err != nil {
		// A closed or invalid handle lands here, which is the Windows shape of
		// "the status is gone": an explicit error, never a zero code
		// (IAMT-305 round 4).
		return false, 0, err
	}
	if code == 259 { // STILL_ACTIVE
		return false, 0, nil
	}
	w.hasExited = true
	w.exitCode = int(code)
	return true, w.exitCode, nil
}

func isAlreadyInvalid(err error) bool {
	if err == nil {
		return false
	}
	// ERROR_INVALID_HANDLE == 6
	var errno windows.Errno
	if errors.As(err, &errno) {
		return errno == 6
	}
	return false
}

// spawnWatchdogInternal is the shared spawn implementation with
// a logFile hook (used by tests for capturing the child's
// stderr) and the watchdog-specific argv elements (maxWait and
// journalPath).
//
// Per CreateProcess docs, when lpApplicationName is non-NULL the
// first whitespace-delimited token in lpCommandLine is taken as
// argv[0]. If we put "server ..." in lpCommandLine, Windows
// interprets "server" as the executable name — silently using
// lpApplicationName. We work around it by starting lpCommandLine
// with the quoted executable name, mirroring cmd.exe: "<exe>"
// server doorwatch <args>.
//
// CREATENO_WINDOW = 0x08000000, CREATE_BREAKAWAY_FROM_JOB =
// 0x01000000. The first means we never spawn a console window;
// the second detaches the child from any job object the parent
// is in, so the child survives the parent's death even on
// Windows server / CI-runner setups where the parent runs in a
// job. If the second flag is refused (some restricted jobs),
// we fall back to NO_WINDOW alone.
func spawnWatchdogInternal(exe, doorID, keyFile, logFile string, parentPID int, maxWait time.Duration, journalPath string) (int, windows.Handle, error) {
	// int64, not time.Duration: maxWait/time.Millisecond keeps the
	// Duration type, so the name promised milliseconds while the type
	// said nanoseconds-with-a-unit (staticcheck ST1011). The %d below
	// prints the same bytes either way.
	maxWaitMs := int64(maxWait / time.Millisecond)
	if maxWaitMs <= 0 {
		maxWaitMs = 1
	}
	cmdLine := fmt.Sprintf(`"%s" server doorwatch %s %d "%s" %d "%s"`, exe, doorID, parentPID, keyFile, maxWaitMs, journalPath)

	si := windows.StartupInfo{}
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = 0x00000001 // STARTF_USESHOWWINDOW
	si.ShowWindow = 0     // SW_HIDE

	var inheritHandles = false
	if logFile != "" {
		utf16Log, err := windows.UTF16PtrFromString(logFile)
		if err != nil {
			return 0, 0, err
		}
		hLog, err := windows.CreateFile(
			utf16Log,
			windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ,
			nil,
			windows.CREATE_ALWAYS,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if err != nil {
			return 0, 0, fmt.Errorf("CreateFile log: %w", err)
		}
		si.Flags = windows.STARTF_USESTDHANDLES | si.Flags
		si.StdErr = hLog
		si.StdOutput = hLog
		inheritHandles = true
		defer windows.CloseHandle(hLog)
	}

	var flags uint32 = 0x08000000 | 0x01000000

	exePtr, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, 0, err
	}
	cmdPtr, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return 0, 0, err
	}
	var pi windows.ProcessInformation
	if err := windows.CreateProcess(
		exePtr,
		cmdPtr,
		nil,
		nil,
		inheritHandles,
		flags,
		nil,
		nil,
		&si,
		&pi,
	); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			// Restricted job object — retry without
			// CREATE_BREAKAWAY_FROM_JOB. This only happens on
			// setups where the parent is in a non-breakaway
			// job; production iamtunnel is not, so the
			// fallback is for tests / sandbox.
			flags = 0x08000000
			if err := windows.CreateProcess(
				exePtr,
				cmdPtr,
				nil,
				nil,
				inheritHandles,
				flags,
				nil,
				nil,
				&si,
				&pi,
			); err != nil {
				return 0, 0, fmt.Errorf("CreateProcess(%s): %w", exe, err)
			}
		} else {
			return 0, 0, fmt.Errorf("CreateProcess(%s): %w", exe, err)
		}
	}
	windows.CloseHandle(pi.Thread)
	return int(pi.ProcessId), pi.Process, nil
}

// procWaitForSingleObject is the lazy-loaded Win32 entry so we can
// pass the handle and timeout directly via syscall semantics
// (Windows SDK does not export a Golang signature for it in
// golang.org/x/sys/windows).
var procWaitForSingleObject = windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitForSingleObject")

// RunWatchdog opens a SYNCHRONIZE handle to parentPID and waits
// for it. If the parent has already died before we got here (a
// race), we still remove our line and exit. When the parent dies
// the child removes the door line via the same path the parent
// uses (file-locked, atomic rewrite). The sink records the
// cleanup; passing nil is fine.
//
// maxWait bounds how long RunWatchdog is willing to sit waiting
// for the parent. Tests use a short value; production passes a
// safety cap (e.g. 5 minutes).
//
// lockPath, ownerUID and ownerGID mirror the same fields on
// SpawnWatchdog: required on linux/darwin so NewDoorWithOptions
// can satisfy the unix validateOptionsPlatform gate, ignored on
// Windows (where NewDoor is sufficient). The Linux-side
// removeOnceAndAudit (doorwatch_linux.go) is the one that actually
// threads them into NewDoorWithOptions.
func RunWatchdog(parentPID int, doorID, keyFile string, sink Sink, maxWait time.Duration, lockPath string, ownerUID, ownerGID int) error {
	if doorID == "" {
		return errors.New("winkeys.RunWatchdog: doorID must not be empty")
	}
	if keyFile == "" {
		return errors.New("winkeys.RunWatchdog: keyFile must not be empty")
	}
	if sink == nil {
		sink = noopSink{}
	}

	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(parentPID))
	if err != nil {
		// Parent is already gone — still clean up so we don't
		// leave an orphan line.
		return removeOnceAndAudit(keyFile, doorID, sink)
	}
	defer windows.CloseHandle(h)

	deadline := watchdogNow().Add(maxWait)
	for {
		// 500 ms timeouts so a stuck parent doesn't wedge us
		// forever and so the loop is responsive in tests.
		r, _, _ := procWaitForSingleObject.Call(uintptr(h), 500)
		switch r {
		case 0:
			// WAIT_OBJECT_0: parent died
			return removeOnceAndAudit(keyFile, doorID, sink)
		case 0xFFFFFFFF:
			return fmt.Errorf("WaitForSingleObject failed for parent %d", parentPID)
		}
		if watchdogNow().After(deadline) {
			return fmt.Errorf("parent %d still alive after %s", parentPID, maxWait)
		}
	}
}

// removeOnceAndAudit is the single-path removal used by
// RunWatchdog and by the helper binary. The audit event records
// the watcher's cleanup distinctly from the server's layer-2
// cleanup so a journal can tell them apart.
//
// On Windows the legacy NewDoor(keyFile, sink) is sufficient: the
// platform layer derives the lock path from keyFile and the file's
// owner is sshd's Match Group administrators identity. The
// Linux-side helper in doorwatch_linux.go takes the explicit
// lockPath/ownerUID/ownerGID so NewDoorWithOptions's
// validateOptionsPlatform (linux/darwin) is satisfied. The
// signature is identical on both platforms so server.Config
// and cmdServerDoorwatch do not branch.
func removeOnceAndAudit(keyFile, doorID string, sink Sink) error {
	d, err := NewDoor(keyFile, sink)
	if err != nil {
		return err
	}
	return d.Remove(doorID)
}
