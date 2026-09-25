//go:build !windows

package datafile

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// Create creates the file at path for writing — new names only. The flag
// set is O_CREATE|O_EXCL|O_NOFOLLOW: only a creator wins the name, two
// concurrent first-time creators cannot truncate each other's file, and
// a planted entry at the path is never overwritten (IAMT-332 round 9:
// the session recorders and the enrol HMAC key create names like this).
//
// On os.ErrExist the name is Lstat'ed so the error says what actually
// stands there: a symlink or a non-regular entry gets the same typed
// refusal the opens report, and only a REGULAR file already in place
// comes back as plain os.ErrExist — that is the legitimate concurrent-
// creator case, which callers disambiguate with errors.Is.
func Create(path string, perm fs.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, perm)
	if err == nil {
		return f, nil
	}
	if errors.Is(err, os.ErrExist) {
		return nil, createRefuseExisting(path)
	}
	return nil, err
}
