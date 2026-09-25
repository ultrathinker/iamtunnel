package datafile

import (
	"fmt"
	"os"
)

// createRefuseExisting classifies the already-exists error of Create.
//
// Only a plain, singly-linked regular file comes back as os.ErrExist:
// that is the legitimate "this name is taken by a file of ours" case the
// callers disambiguate with errors.Is — the journal archives advance to
// the next name on it (internal/winkeys/file_sink.go's nextArchivePath)
// and so do the session recorders (internal/gateway/record's
// claimSessionName), because a name derived from a clock repeats
// whenever the clock stands still, and a repeated name must not refuse
// the operation.
//
// Everything else is refused in words, because nothing else can be a
// file this program created at that name:
//
//   - a symlink is a plant (SymlinkRefusal);
//   - a FIFO, socket, device, directory or Windows reparse point is a
//     plant (NonRegularRefusal);
//   - a regular file with MORE THAN ONE link is a plant too, and the one
//     an unprivileged attacker on Windows can arrange for free. This
//     program never creates a link to a data file — every writer here
//     creates its own file and renames over names — so a linked entry at
//     a data file's name is somebody else's file reachable under our
//     name, which is exactly what writing through it would destroy. The
//     door layer refuses the same shape on POSIX (nlink != 1) and this
//     is the cross-platform form of that guard; see links_posix.go /
//     links_windows.go for how the count is read.
func createRefuseExisting(path string) error {
	st, lerr := os.Lstat(path)
	if lerr != nil {
		// The entry vanished between the failed create and the Lstat:
		// the create error is the honest answer.
		return fmt.Errorf("%s: %w", path, os.ErrExist)
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return SymlinkRefusal(path)
	}
	if !st.Mode().IsRegular() {
		return NonRegularRefusal(path, st.Mode())
	}
	if n, known := linkCount(path, st); known && n > 1 {
		return LinkedRefusal(path, n)
	}
	return fmt.Errorf("%s: %w", path, os.ErrExist)
}
