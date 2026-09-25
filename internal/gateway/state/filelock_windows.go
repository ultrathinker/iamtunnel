//go:build windows

package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	modkernel32      = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx   = modkernel32.NewProc("LockFileEx")
	procUnlockFileEx = modkernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 1
	lockfileExclusiveLock   = 2

	// ERROR_LOCK_VIOLATION. Together with ERROR_SHARING_VIOLATION (declared next to
	// the file replace helper) these are the codes that genuinely mean contention.
	errorLockViolation = syscall.Errno(33)
)

// FileLock holds an exclusive OS-level file lock on Windows.
type FileLock struct {
	file *os.File
}

// AcquireFileLock acquires an exclusive non-blocking lock on lockPath.
// If another process already holds the lock, ErrLockHeld is returned.
// The adoption step is a no-op on Windows (see PreserveOwnership) —
// both platform files call it so the portable test of the seam is
// meaningful everywhere. The open itself never follows a symlink
// planted at the lock file's name (IAMT-332 round three).
func AcquireFileLock(lockPath string) (*FileLock, error) {
	f, err := OpenDataFile(lockPath, os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}

	if aerr := adoptOwnership(f, ""); aerr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to adopt the owner of lock file %s: %w", lockPath, aerr)
	}

	h := syscall.Handle(f.Fd())
	var ol syscall.Overlapped
	r1, _, errSys := procLockFileEx.Call(
		uintptr(h),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0, // reserved
		1, // numberOfBytesToLockLow
		0, // numberOfBytesToLockHigh
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		_ = f.Close()
		return nil, lockErrorFor(lockPath, errSys)
	}

	return &FileLock{file: f}, nil
}

// AcquireFileLockExisting acquires an exclusive non-blocking lock on
// an already-existing lock file (IAMT-98, round two). The Windows
// read-path twin of AcquireFileLock: it is the same call except the
// file is opened without O_CREATE, so the read path can never be the
// one that materialises state.lock. If the file does not exist,
// os.ErrNotExist is returned verbatim so the caller can collapse
// "missing state.json" and "missing state.lock" into one branch. If
// the file exists but another handle already owns the lock, the same
// lockErrorFor classifier used by AcquireFileLock turns the OS error
// into ErrLockHeld - the liveness signal is unchanged. A symlink at
// the lock file's name is refused, never followed (IAMT-332 round
// three).
func AcquireFileLockExisting(lockPath string) (*FileLock, error) {
	f, err := OpenExistingDataFile(lockPath, os.O_RDWR)
	if err != nil {
		return nil, err
	}

	h := syscall.Handle(f.Fd())
	var ol syscall.Overlapped
	r1, _, errSys := procLockFileEx.Call(
		uintptr(h),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0, // reserved
		1, // numberOfBytesToLockLow
		0, // numberOfBytesToLockHigh
		uintptr(unsafe.Pointer(&ol)),
	)
	if r1 == 0 {
		_ = f.Close()
		return nil, lockErrorFor(lockPath, errSys)
	}

	return &FileLock{file: f}, nil
}

// lockErrorFor tells "another gateway holds the lock" apart from "locking failed".
// LockFileEx returns zero for both, and answering "already running" to a broken disk
// sends the administrator looking in the wrong place. Only the two codes that really
// mean contention become ErrLockHeld; everything else is handed out with its own code.
func lockErrorFor(lockPath string, raw error) error {
	if errors.Is(raw, errorLockViolation) || errors.Is(raw, errorSharingViolation) {
		return fmt.Errorf("%w: %v", ErrLockHeld, raw)
	}
	return fmt.Errorf("failed to lock %s: %w", lockPath, raw)
}

// Unlock releases the OS-level lock and closes the file handle.
func (fl *FileLock) Unlock() error {
	if fl == nil || fl.file == nil {
		return nil
	}
	h := syscall.Handle(fl.file.Fd())
	var ol syscall.Overlapped
	r1, _, errSys := procUnlockFileEx.Call(
		uintptr(h),
		0, // reserved
		1, // numberOfBytesToUnlockLow
		0, // numberOfBytesToUnlockHigh
		uintptr(unsafe.Pointer(&ol)),
	)
	errClose := fl.file.Close()
	fl.file = nil
	if r1 == 0 {
		return fmt.Errorf("failed to unlock file: %v", errSys)
	}
	return errClose
}
