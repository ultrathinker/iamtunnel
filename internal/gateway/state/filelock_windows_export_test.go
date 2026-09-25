//go:build windows

package state

import "syscall"

// Errno values the shared lock-classification test feeds to the classifier.
var (
	ErrnoLockHeldForTest     error = syscall.Errno(33)   // ERROR_LOCK_VIOLATION
	ErrnoIOFailureForTest    error = syscall.Errno(1117) // ERROR_IO_DEVICE
	ErrnoOtherFailureForTest error = syscall.Errno(5)    // ERROR_ACCESS_DENIED
)

// LockErrorForTest exposes the classifier to tests.
func LockErrorForTest(path string, raw error) error { return lockErrorFor(path, raw) }
