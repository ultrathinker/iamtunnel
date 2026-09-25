//go:build windows

package server

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// isTransientSharingViolation reports whether err is Windows'
// ERROR_SHARING_VIOLATION (32): the errno an open-for-read gets when
// it lands inside a file replace that is in flight (IAMT-219).
// os.ReadFile wraps the errno in *fs.PathError, hence errors.As; the
// x/sys constant is the same syscall.Errno the PathError carries.
func isTransientSharingViolation(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == windows.ERROR_SHARING_VIOLATION
}
