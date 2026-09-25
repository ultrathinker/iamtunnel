package datafile

import (
	"fmt"
	"os"
)

// checkOpenedEntry is the half of OpenExisting's contract that runs on
// the DESCRIPTOR rather than on the name, and it is the half that cannot
// be raced (IAMT-332 round 10). Both platform legs end here, so the
// predicate reads word-for-word the same on each: the thing we are
// holding open must be a plain regular file that carries exactly one
// name.
//
// Why the descriptor and not the path. Every check performed on a
// pathname — Lstat, os.Stat, a second open to measure something — leaves
// a window in which the entry at that name can be swapped for another
// one before the descriptor that will actually be written is obtained.
// Once the file is open the window is shut: the descriptor refers to a
// file, not to a name, so fstat (POSIX) and GetFileInformationByHandle
// (Windows) describe exactly the object the caller is about to read or
// write. The name-based Lstat the Windows leg still performs before the
// open stays useful — it is what refuses a symlink or a junction without
// traversing it — but it is a classification, never the guarantee.
//
// The link count is the guard round 9 put only on Create, and that
// asymmetry was the round-9 REJECT: Create refused a linked name while
// OpenExisting handed one back, so every path that REUSES an existing
// data file inherited the hole — ReadFile, Open's second leg, and
// OpenAppend, which is how the machine audit journal opens events.jsonl
// (internal/winkeys/file_sink.go's NewJournalSink). An unprivileged user
// who owns a data directory could plant a hard link there and have the
// elevated "server start" append audit records into the linked-to file.
// On Windows that plant costs nothing at all: a hard link needs no
// privilege, unlike a symlink.
//
// This program never creates a link to a data file — every writer here
// creates its own file and renames over names (WriteFileAtomic) — so
// more than one name on a data file means somebody else's file is
// reachable under ours, with no legitimate case to weigh against it.
//
// A count that cannot be read is REFUSED here, and that is deliberately
// the opposite of the direction createRefuseExisting takes. The two are
// not the same situation. There, the count only decides the WORDING of
// an error the failed O_EXCL create already settled, and no write can
// follow, so an unmeasurable entry is better described loosely than
// refused. Here the count gates a descriptor that is about to be read or
// written by a privileged process: "I could not tell whether this file
// is somebody else's" is not a state in which to write, and a refusal
// says so in words the operator can act on.
func checkOpenedEntry(path string, f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return NonRegularRefusal(path, fi.Mode())
	}
	n, lerr := linkCountOfOpen(f, fi)
	if lerr != nil {
		return fmt.Errorf("%s: refusing to use a data file whose link count could not be read — an unmeasured name may be a hard link to somebody else's file: %w", path, lerr)
	}
	if n > 1 {
		return LinkedRefusal(path, n)
	}
	return nil
}
