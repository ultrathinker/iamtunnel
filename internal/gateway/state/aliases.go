package state

import (
	"io/fs"
	"os"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// aliases.go — thin shims kept so the ~50 existing call sites in this
// package and its siblings compile unchanged while the implementation
// lives in internal/datafile (IAMT-332 round 9, §5.1 of the audit). The
// safe-file-I/O primitives moved to a leaf package because a subsystem
// that did not already import the gateway's state store — internal/client
// is the example that cost round 8 — had no obvious place to get them
// from, and rolled its own writer; now every package imports datafile
// directly. New code should call datafile.<name>, not these aliases;
// they exist only to keep the existing call sites and the existing
// IAMT-332 tests untouched during the move, and scripts/check_rawfileio's
// allowlist carries the entry that keeps this file honest about being
// shims, not a second implementation.

// OpenDataFile opens one of the data directory's LONG-LIVED files at its
// final name, create-or-refuse, never following a planted name. See
// datafile.Open.
func OpenDataFile(path string, flags int, perm fs.FileMode) (*os.File, error) {
	return datafile.Open(path, flags, perm)
}

// OpenExistingDataFile reopens an existing name the no-follow way:
// O_NOFOLLOW (or the Windows Lstat checks), prompt, fstat, REGULAR only.
// See datafile.OpenExisting.
func OpenExistingDataFile(path string, flags int) (*os.File, error) {
	return datafile.OpenExisting(path, flags)
}

// ReadDataFile returns the bytes of an existing data file, refusing a
// planted entry outright; a missing name is os.ErrNotExist verbatim. See
// datafile.ReadFile.
func ReadDataFile(path string) ([]byte, error) {
	return datafile.ReadFile(path)
}

// OpenAppendDataFile opens — or creates, only if the name is genuinely
// missing — a long-lived append-mode journal file. See
// datafile.OpenAppend.
func OpenAppendDataFile(path string) (*os.File, error) {
	return datafile.OpenAppend(path)
}

// PreserveOwnership gives an open file the owner account the gateway
// service expects — the chown-on-the-descriptor step, a no-op on
// Windows. See datafile.PreserveOwnership. (A function shim, not a var:
// the exported-invariant guard, hardening_test.go, forbids exported
// writable package variables.)
func PreserveOwnership(f *os.File, replacedPath string) error {
	return datafile.PreserveOwnership(f, replacedPath)
}

// adoptOwnership is the ownership seam for every file this package puts
// into the gateway data directory (IAMT-332): atomic replaces
// (saveAtomicLocked) and creators that stand where nothing did
// (enrol-hmac.key, state.lock). The real step is PreserveOwnership
// above; tests swap this variable for a recorder, so nothing is chowned
// for real and root is never needed; the tests in this package run
// sequentially, so the swap is not observed by anyone else.
var adoptOwnership = PreserveOwnership
