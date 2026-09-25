package client

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// storeLockFile sits next to connection.json and exists only to be
// locked (R1-CX F-17). The list itself cannot carry the lock: every
// write puts a new file in its place, and a lock taken on the old one
// would guard nothing the next reader opens.
const storeLockFile = "connection.lock"

// storeLockWait bounds how long a change waits for another one to
// finish. A change is a read, a few comparisons and a write -
// milliseconds; a holder still busy after this long is stuck, and
// saying so beats waiting on it without end.
const storeLockWait = 5 * time.Second

// storeLockPause is the pause between two tries of a lock in use.
const storeLockPause = 20 * time.Millisecond

// changeStore runs change - a read of the saved connections, the change
// itself and the write - holding the store's lock across all three
// (R1-CX F-17). The write was always atomic, so the file was never
// half-written; but two writers that had read the same list each wrote
// back their own version of it, and the one that wrote second wiped out
// the other's change without a word: the Client tab saving one gateway
// while "client forget" dropped another, or a "client use" whose choice
// silently vanished. The lock is the operating system's (flock,
// LockFileEx), so it holds between processes and not only goroutines,
// and the system lets it go if its holder dies.
//
// create says the change may bring the directory into being (a first
// save). A change that may not reads a missing directory as "nothing is
// saved" and runs without the lock: there is nothing a second writer
// could lose, and forgetting on a machine that never saved anything
// must not create anything there.
func changeStore(dir string, create bool, change func() error) error {
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return classifyPathErr(err, dir)
		}
	}
	unlock, err := lockStore(dir)
	if err != nil {
		if !create && errors.Is(err, os.ErrNotExist) {
			return change()
		}
		return err
	}
	defer unlock()
	return change()
}

// lockStore takes the store's lock, waiting out a change in flight for
// up to storeLockWait. A missing directory comes back as os.ErrNotExist.
func lockStore(dir string) (unlock func(), err error) {
	path := filepath.Join(dir, storeLockFile)
	// datafile.Open, like every long-lived file of the client directory:
	// a symlink, a FIFO or a hard link planted at the lock's name is
	// refused, never followed - a lock taken on a planted target would
	// exclude nobody.
	f, err := datafile.Open(path, os.O_RDWR, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return nil, classifyPathErr(err, path)
	}
	deadline := time.Now().Add(storeLockWait)
	for {
		busy, err := tryLockStore(f)
		switch {
		case err != nil:
			_ = f.Close()
			return nil, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf(
				"the saved connections cannot be locked for a change (%s): %v", path, err)}
		case !busy:
			return func() {
				unlockStore(f)
				_ = f.Close()
			}, nil
		case !time.Now().Before(deadline):
			_ = f.Close()
			return nil, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf(
				"another iamtunnel has been changing the saved connections for %s and has not finished (%s is locked) — try again in a moment",
				storeLockWait, path)}
		}
		time.Sleep(storeLockPause)
	}
}
