//go:build !windows

package state

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// FileLock holds an exclusive OS-level file lock on POSIX systems.
type FileLock struct {
	file *os.File
}

// AcquireFileLock acquires an exclusive non-blocking lock on lockPath using flock.
// If another process already holds the lock, ErrLockHeld is returned.
//
// A lock file this call CREATES carries the creating process's account,
// so a root-run maintenance command over a gateway whose state.lock was
// missing would leave the lock owned by root and the unprivileged
// service could never take its own lock again (IAMT-332). The owner of
// the data directory is adopted on the open descriptor; for the
// service's own runs the file is already owned by the right account and
// the step is skipped. The open itself never follows a symlink planted
// at the lock file's name — the file is long-lived and reused across
// restarts, so the open is two-legged (create-or-refuse), not
// unconditionally O_EXCL (IAMT-332 round three).
func AcquireFileLock(lockPath string) (*FileLock, error) {
	f, err := OpenDataFile(lockPath, os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open lock file %s: %w", lockPath, err)
	}

	if aerr := adoptOwnership(f, ""); aerr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to adopt the owner of lock file %s: %w", lockPath, aerr)
	}

	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err != nil {
		_ = f.Close()
		return nil, lockErrorFor(lockPath, err)
	}

	return &FileLock{file: f}, nil
}

// AcquireFileLockExisting acquires an exclusive non-blocking flock on an
// already-existing lock file (IAMT-98, round two). It is the read-path
// twin of AcquireFileLock: the difference is the missing O_CREATE, so
// a caller that has already decided "if this file does not exist, the
// gateway was never installed here" does not accidentally materialise
// it just by looking. If the file does not exist, os.ErrNotExist is
// returned verbatim - the same typed error the store uses for "no state
// file" - so callers can collapse the two cases into one branch. If
// the file exists but another process holds the lock, ErrLockHeld is
// returned (liveness signal). On success the returned *FileLock owns
// the open file description; the lock file on disk is not deleted by
// Unlock (flock only releases the OS-level lock and closes the handle).
// A symlink at the lock file's name is refused, never followed
// (IAMT-332 round three).
func AcquireFileLockExisting(lockPath string) (*FileLock, error) {
	f, err := OpenExistingDataFile(lockPath, os.O_RDWR)
	if err != nil {
		return nil, err
	}

	if lerr := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); lerr != nil {
		_ = f.Close()
		return nil, lockErrorFor(lockPath, lerr)
	}

	return &FileLock{file: f}, nil
}

// lockErrorFor tells "another gateway holds the lock" apart from "locking failed".
// flock reports both through the same return value, and answering "already running" to
// a broken disk sends the administrator looking in the wrong place.
func lockErrorFor(lockPath string, raw error) error {
	if errors.Is(raw, syscall.EWOULDBLOCK) || errors.Is(raw, syscall.EAGAIN) {
		return fmt.Errorf("%w: %v", ErrLockHeld, raw)
	}
	return fmt.Errorf("failed to lock %s: %w", lockPath, raw)
}

// Unlock releases the OS-level lock and closes the file handle.
func (fl *FileLock) Unlock() error {
	if fl == nil || fl.file == nil {
		return nil
	}
	_ = syscall.Flock(int(fl.file.Fd()), syscall.LOCK_UN)
	err := fl.file.Close()
	fl.file = nil
	return err
}
