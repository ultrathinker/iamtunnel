//go:build !windows

package client

import (
	"errors"
	"os"
	"syscall"
)

// tryLockStore takes the store's lock on f without waiting; busy means
// another open of the lock file holds it. flock belongs to the open file
// description, so a second open in the same process is excluded exactly
// like another process is.
func tryLockStore(f *os.File) (busy bool, err error) {
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, syscall.EWOULDBLOCK), errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EINTR):
		return true, nil
	}
	return false, err
}

// unlockStore: closing the descriptor lets the flock go.
func unlockStore(*os.File) {}
