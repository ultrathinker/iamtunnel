package state

import "os"

// This file is compiled only into the test binary of package state. Everything it
// exposes is therefore reachable from this package's own tests (including the external
// state_test package in this directory) and from nowhere else: an importer of
// github.com/ultrathinker/iamtunnel/internal/gateway/state gets none of it.
//
// That is the whole point. A hook that can interrupt an atomic write, or anything else
// that can weaken an invariant from the outside, does not belong in the product API.

// SetBeforeRenameHook installs an interceptor invoked immediately before the atomic
// rename in saveAtomicLocked. Tests use it to model a power cut at the one moment when
// the temporary file is complete and the target has not been replaced yet.
//
// It is deliberately a function and not a method: a method would still show up on
// *state.Store under reflection inside the test binary, and "there are no interceptors
// on Store" is a property worth being able to check that way.
func SetBeforeRenameHook(s *Store, hook func(tmpPath string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.beforeRenameHook = hook
}

// ReconcileGrantsForTest exposes the unexported reconciliation to tests that need to
// examine revocations without going through a Store.
func ReconcileGrantsForTest(prev, draft *State) []Revocation {
	return reconcileGrants(prev, draft)
}

// SyncDirForTest calls the product syncDir - the exact function the §3.5 save path
// (saveAtomicLocked -> syncDir) runs after every replace - so a test can hold the
// DurableReplace declaration to what the save path actually does.
func SyncDirForTest(dir string) error {
	return syncDir(dir)
}

// FlushDirForTest performs the fourth step of the §3.5 formula by hand - open the
// directory, fsync it - without going through this platform's syncDir. A test uses it
// to learn whether the platform itself accepts an fsync of a directory handle, which
// is the fact the DurableReplace declaration stands on.
func FlushDirForTest(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
