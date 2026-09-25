package datafile

import (
	"errors"
	"fmt"
	"io/fs"
)

// RefusalError is the typed error every open in this package reports for
// a name that turned out to hold a planted — or just broken — entry
// instead of the regular data file that belongs there (IAMT-332 round
// nine). Callers and tests branch on it with errors.As / IsRefusal
// instead of string-matching the message; the message itself is pinned
// word for word, because the refusal text IS the contract (SPEC §3.5)
// and older tests match it.
type RefusalError struct {
	// Path is the name the entry was found at.
	Path string
	// Kind names what was planted: one of the Kind* constants below.
	Kind string
	// Mode is the Lstat/fstat mode of the refused entry. It is what the
	// non-symlink wording renders ("a FIFO", "a directory", ...); it is
	// zero for symlinks, whose wording names the link itself.
	Mode fs.FileMode
	// Links is how many names the refused entry carries, for KindLinked.
	Links uint64
}

// The kinds a RefusalError can carry.
const (
	KindSymlink    = "symlink"
	KindFIFO       = "fifo"
	KindDirectory  = "directory"
	KindSocket     = "socket"
	KindCharDevice = "chardevice"
	KindBlockDev   = "blockdevice"
	KindIrregular  = "irregular"
	// KindLinked is a REGULAR file that carries more than one name: a
	// hard link, which is the one plant in this class an unprivileged
	// attacker on Windows can create for free. It is its own kind
	// because it is the only refusal here whose entry is a perfectly
	// ordinary regular file — the caller must not confuse it with the
	// "this name is taken by our own earlier file" case that
	// createRefuseExisting reports as plain os.ErrExist.
	KindLinked = "hardlink"
)

func (e *RefusalError) Error() string {
	if e.Kind == KindSymlink {
		return fmt.Sprintf("%s is a symlink — refusing to open it: the gateway never follows a link planted at a data file's name; remove the link and restore the real file (or reinstall) before running the command again", e.Path)
	}
	if e.Kind == KindLinked {
		return fmt.Sprintf("%s is a regular file with %d links — refusing to use it: the gateway never replaces a name that is a hard link to another file, because the write would land on the file the link points at; remove the link and restore the real file (or reinstall) before running the command again", e.Path, e.Links)
	}
	return fmt.Sprintf("%s is %s, not a regular file — refusing to open it: the gateway's data files are plain files, and a FIFO (or device, or socket) at such a name would hang or misdirect the command; remove it and restore the real file (or reinstall) before running the command again", e.Path, describeMode(e.Mode))
}

// IsRefusal reports whether err is (or wraps) a refusal this package
// raised for a planted or non-regular entry.
func IsRefusal(err error) bool {
	var re *RefusalError
	return errors.As(err, &re)
}

// SymlinkRefusal is the error every no-follow open reports for a name
// that turned out to be (or just became) a symlink.
func SymlinkRefusal(path string) error {
	return &RefusalError{Path: path, Kind: KindSymlink}
}

// NonRegularRefusal is the error every no-follow open reports for a name
// that holds something other than a regular file. O_NOFOLLOW alone
// cannot refuse these: a FIFO is not a symlink, opens successfully, and
// a read-only open of it then blocks forever waiting for a writer that
// will never come — wedging the privileged recovery path that called us
// (IAMT-332 round four). A device or socket at the name is equally not
// this data file. The check is the one predicate "regular file" —
// S_ISREG excludes every one of these kinds at once, so the refusal
// needs no per-kind cases; only the wording below does.
func NonRegularRefusal(path string, mode fs.FileMode) error {
	return &RefusalError{Path: path, Kind: kindOfMode(mode), Mode: mode}
}

// LinkedRefusal is the error Create reports for a name held by a regular
// file that carries more than one link. It is the one entry in this
// package's refusal family that is a plain regular file, which is why it
// exists as its own constructor: a symlink or a FIFO cannot be mistaken
// for anything this program wrote, while a hard link looks exactly like
// a file of ours to every check except the link count. The count is what
// separates "a previous recording of ours is at this name, take the next
// one" (plain os.ErrExist) from "somebody else's file is reachable under
// our name, refuse it loudly" (this).
func LinkedRefusal(path string, links uint64) error {
	return &RefusalError{Path: path, Kind: KindLinked, Links: links}
}

// kindOfMode maps a file mode to the RefusalError kind it represents.
// A name-surrogate reparse point on Windows (a junction) lands in
// ModeIrregular — Go never reports it as ModeSymlink or ModeDir — so it
// gets its own kind instead of vanishing into "other".
func kindOfMode(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return KindDirectory
	case m&fs.ModeNamedPipe != 0:
		return KindFIFO
	case m&fs.ModeSocket != 0:
		return KindSocket
	case m&fs.ModeDevice != 0 && m&fs.ModeCharDevice != 0:
		return KindCharDevice
	case m&fs.ModeDevice != 0:
		return KindBlockDev
	case m&fs.ModeIrregular != 0:
		return KindIrregular
	default:
		return KindIrregular
	}
}

// describeMode names the kind of non-regular entry for the refusal, so
// the error says what was actually planted rather than a raw mode string.
func describeMode(m fs.FileMode) string {
	switch {
	case m.IsDir():
		return "a directory"
	case m&fs.ModeNamedPipe != 0:
		return "a FIFO"
	case m&fs.ModeSocket != 0:
		return "a socket"
	case m&fs.ModeDevice != 0 && m&fs.ModeCharDevice != 0:
		return "a character device"
	case m&fs.ModeDevice != 0:
		return "a block device"
	case m&fs.ModeIrregular != 0:
		return "a reparse point (junction or similar)"
	default:
		return fmt.Sprintf("mode %s", m)
	}
}
