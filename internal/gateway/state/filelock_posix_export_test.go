//go:build !windows

package state

import "syscall"

// Errno values the shared lock-classification test feeds to the classifier.
var (
	ErrnoLockHeldForTest     error = syscall.EWOULDBLOCK
	ErrnoIOFailureForTest    error = syscall.EIO
	ErrnoOtherFailureForTest error = syscall.ENOLCK
)

// LockErrorForTest exposes the classifier to tests.
func LockErrorForTest(path string, raw error) error { return lockErrorFor(path, raw) }
