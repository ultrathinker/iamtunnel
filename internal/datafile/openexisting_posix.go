//go:build !windows

package datafile

import (
	"errors"
	"os"
	"syscall"
)

// OpenExisting is Open's second leg on POSIX: the name already exists,
// so reopen it for reading or writing with O_NOFOLLOW. The kernel-level
// refusal closes the check-then-open gap by construction: if the name is
// — or is swapped to — a symlink at open time, the open fails with ELOOP
// and the command refuses, instead of opening through the link.
//
// O_NOFOLLOW refuses only symlinks, so the opened descriptor is then
// handed to checkOpenedEntry, which fstats it (fstat(2) — the open file
// itself, no path to follow) and refuses anything that is not a REGULAR
// file carrying exactly one name: a FIFO planted at the name passes
// O_NOFOLLOW and would otherwise wedge the privileged recovery path
// (IAMT-332 round four), and a HARD LINK passes every one of these
// checks except the link count, which is why round ten added it here as
// well as on the create path. The prompt part of the non-regular refusal
// is O_NONBLOCK — a plain open of a FIFO BLOCKS inside open(2) itself
// (read-only: until a writer appears; write-only: until a reader), so
// the fstat could never run; POSIX makes an O_NONBLOCK open of a FIFO
// return without delay (write-only with no reader: ENXIO, mapped to the
// same refusal below). On the regular files that survive the check the
// flag has no effect, so it is left set.
func OpenExisting(path string, flags int) (*os.File, error) {
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, SymlinkRefusal(path)
	}
	if errors.Is(err, syscall.ENXIO) {
		// ENXIO here is an O_WRONLY open of a FIFO with no reader (or a
		// device with no backing unit): prompt, and the entry is by
		// definition not a regular file — refuse it in the same words
		// instead of leaking the raw errno.
		if st, lerr := os.Lstat(path); lerr == nil && !st.Mode().IsRegular() {
			return nil, NonRegularRefusal(path, st.Mode())
		}
		return nil, err
	}
	if err != nil {
		// A write-mode open of a name that holds a non-regular entry
		// fails before the fstat above can run (O_WRONLY on a
		// directory: EISDIR), but the situation is the same planted
		// entry the ENXIO branch refuses — refuse it in the same words
		// instead of leaking the raw errno (IAMT-332 round seven). A
		// symlink at the name stays with the branches above (ELOOP
		// when it resolves, the raw error when it dangles, so
		// ReadFile's missing-name-is-ErrNotExist contract keeps
		// holding), and a genuinely missing name keeps the raw error
		// too — that is the "first run" case, not a plant.
		if st, lerr := os.Lstat(path); lerr == nil && !st.Mode().IsRegular() && st.Mode()&os.ModeSymlink == 0 {
			return nil, NonRegularRefusal(path, st.Mode())
		}
		return nil, err
	}
	if cerr := checkOpenedEntry(path, f); cerr != nil {
		_ = f.Close()
		return nil, cerr
	}
	return f, nil
}
