//go:build windows

package datafile

import (
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// linkCount reports how many names the entry has — Windows has no POSIX
// stat, and Go's FileInfo does not carry the count, so the answer comes
// from the handle (GetFileInformationByHandle) opened with
// FILE_READ_ATTRIBUTES. The handle is opened with
// FILE_FLAG_OPEN_REPARSE_POINT so a link swapped in during the race is
// measured as itself and never traversed.
//
// The hard link is the Windows-native member of the planted-name class:
// unlike a symlink it needs no privilege at all, so "somebody else's
// file is reachable under our name" is the one case here that an
// unprivileged attacker can arrange. This is the same guard the door
// layer applies to its key file on POSIX (internal/winkeys/doors_unix.go:
// "existing key file has nlink=%d, refusing (hard-link attack surface)")
// and IAMT-291 applies to its chown walk — Windows simply has to ask the
// handle for the number.
//
// known=false on any failure (the file vanished, the handle was refused):
// the caller then treats the entry as an ordinary file and moves on. That
// direction is deliberate — the caller's other option here is to REFUSE
// the name, and refusing a name it could not measure is worse than
// leaving a loud warning unmade, because in no case does this function
// gate a write: the create that got here was O_EXCL and already failed.
// The guard that DOES gate a write is linkCountOfOpen below, and it
// takes the opposite direction for exactly that reason.
func linkCount(path string, _ fs.FileInfo) (n uint64, known bool) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, false
	}
	h, err := windows.CreateFile(p,
		windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0)
	if err != nil {
		return 0, false
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return 0, false
	}
	return uint64(info.NumberOfLinks), true
}

// linkCountOfOpen reports how many names the OPEN file carries — the
// race-free twin of linkCount, used by the guard that gates a descriptor
// about to be read or written (IAMT-332 round 10).
//
// The measurement is GetFileInformationByHandle on the caller's OWN
// handle, never a second CreateFile by the same path. That distinction
// is the whole point of this function existing next to linkCount: a
// second open by name can land on a different file than the one the
// descriptor holds — the attacker only has to swap the entry between the
// two calls — and a link count measured on a file nobody is going to
// write is no guard at all. A handle, once obtained, refers to the file
// itself, so the number this returns describes exactly the object the
// caller is about to use.
//
// Every access mask Go's os.OpenFile produces carries the right to read
// attributes, including the FILE_APPEND_DATA-only mask it builds for
// O_WRONLY|O_APPEND (the journal's open), so no special open is needed
// here; this was measured on the platform rather than assumed. A failure
// is returned as an error, not swallowed as "unknown", because on this
// path the count gates a privileged write.
func linkCountOfOpen(f *os.File, _ fs.FileInfo) (uint64, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		return 0, err
	}
	return uint64(info.NumberOfLinks), nil
}
