//go:build windows

package client

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// tryLockStore takes the store's lock on f without waiting; busy means
// another handle holds it. LockFileEx belongs to the handle, so a second
// open in the same process is excluded exactly like another process is.
func tryLockStore(f *os.File) (busy bool, err error) {
	var ol windows.Overlapped
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return true, nil
	}
	return false, err
}

// unlockStore lets the lock go before the handle closes: Windows frees
// the locks of a closed handle too, but "when resources allow", and the
// next writer is waiting for exactly this.
func unlockStore(f *os.File) {
	var ol windows.Overlapped
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &ol)
}
