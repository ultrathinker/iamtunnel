//go:build !windows

package server

// isTransientSharingViolation is the non-Windows stub: on POSIX a
// rename over an existing file never makes a concurrent open-for-read
// fail, so there is no transient errno to retry (IAMT-219).
func isTransientSharingViolation(err error) bool {
	return false
}
