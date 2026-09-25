//go:build windows

package datafile

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Create creates the file at path for writing — new names only — the
// Windows leg of create_posix.go. os.OpenFile's O_CREATE|O_EXCL gives
// the only-the-creator-wins guarantee; there is no O_NOFOLLOW, and the
// platform's best equivalent is the Lstat classification on the
// already-exists error: a symlink or a junction planted at the name gets
// the same typed refusal the opens report (a junction is never
// ModeSymlink in Go — it lands in ModeIrregular), and only a REGULAR
// file already in place comes back as plain os.ErrExist. A hard link at
// the name IS a regular file, so it surfaces as os.ErrExist — refused
// either way; the link is never written through.
//
// EISDIR joins ErrExist in the "an entry is in the way" set (IAMT-332
// round nine): Windows reports an existing DIRECTORY at the name as
// EISDIR rather than ERROR_FILE_EXISTS — a directory can never be the
// successful outcome of a create, so EISDIR here means exactly "some
// entry holds the name", and it must get the same Lstat classification
// (NonRegularRefusal in words) instead of a raw OS error leaking out.
func Create(path string, perm fs.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err == nil {
		return f, nil
	}
	if errors.Is(err, os.ErrExist) || errors.Is(err, syscall.EISDIR) {
		return nil, createRefuseExisting(path)
	}
	return nil, err
}

// CreateWithDACL is Create for a file that must never exist, even for an
// instant, with the access list its folder would hand down (R1-CX F-14):
// dacl is part of the create itself - the protected, own access list of
// the file from the moment the name is claimed - so no other account can
// open the name in between. Create followed by a later access-list call
// left that moment open, and a handle opened in it outlives any list set
// afterwards: the client's key was written into a file another account
// could already be holding open.
//
// The name rules are Create's: new names only (CREATE_NEW), a link or a
// junction is not followed (FILE_FLAG_OPEN_REPARSE_POINT), and an entry
// already there is classified the same way. The handle can write and read
// its own access list back, and is shared for reading, as Create's is.
func CreateWithDACL(path string, dacl *windows.ACL) (*os.File, error) {
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := sd.SetDACL(dacl, true, false); err != nil {
		return nil, err
	}
	if err := sd.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &sa, windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		if _, lerr := os.Lstat(path); lerr == nil {
			return nil, createRefuseExisting(path)
		}
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
