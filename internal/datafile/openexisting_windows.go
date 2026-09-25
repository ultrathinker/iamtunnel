//go:build windows

package datafile

import (
	"io/fs"
	"os"
)

// OpenExisting is Open's second leg on Windows. The os.OpenFile flag set
// has no O_NOFOLLOW, so the checks are an explicit Lstat before the
// open: the name must not be a symlink, must not be a name-surrogate
// reparse point, and must be a REGULAR file (IAMT-332 rounds four and
// nine) — the same predicate the POSIX leg fstats out of its descriptor,
// so the contract reads word-for-word the same on both platforms.
//
// The symlink check is not a privilege argument. Creating a symlink on
// Windows does need admin or Developer Mode, but a HARD LINK needs no
// special right at all — any user can link a name to a file they cannot
// write, and an elevated process that opens through it writes into the
// shared inode. A junction (a mount-point reparse point) needs no
// privilege either, and Go never reports one as ModeSymlink: a
// name-surrogate reparse point carries ModeIrregular and no ModeDir
// ($GOROOT/src/os/types_windows.go). Both are therefore refused
// explicitly, each with its own branch — the junction is not to be
// refused "by accident" through !IsRegular. PreserveOwnership is a
// no-op here, so nothing can be chowned through a followed link
// regardless. Windows behaviour outside the planted-entry case is
// unchanged.
//
// The Lstat is a classification, not the guarantee, and round ten is
// where that distinction is paid for. The hard link — the plant that
// needs no privilege on this platform — IS a regular file, so it passes
// every branch above; and an entry can be swapped between the Lstat and
// the open, so even a correct classification describes a name rather
// than the file finally opened. The guarantee is therefore taken AFTER
// the open, on the descriptor itself: checkOpenedEntry re-establishes
// the regular-file predicate through the handle and refuses a file that
// carries more than one name (GetFileInformationByHandle on that very
// handle, never a second open by path). The POSIX leg ends in the same
// function, so the contract reads word-for-word the same on both
// platforms.
func OpenExisting(path string, flags int) (*os.File, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode()&fs.ModeSymlink != 0 {
		return nil, SymlinkRefusal(path)
	}
	if st.Mode()&fs.ModeIrregular != 0 {
		// A junction or another name-surrogate reparse point: creatable
		// by any user, never a regular file, and Go's Lstat does not
		// report it as a symlink — refuse it by name (IAMT-332 round 9,
		// §5.7.1 of the audit).
		return nil, NonRegularRefusal(path, st.Mode())
	}
	if !st.Mode().IsRegular() {
		return nil, NonRegularRefusal(path, st.Mode())
	}
	f, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	if cerr := checkOpenedEntry(path, f); cerr != nil {
		_ = f.Close()
		return nil, cerr
	}
	return f, nil
}
