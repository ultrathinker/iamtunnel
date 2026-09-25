//go:build windows

package winkeys

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
)

// TreeACL is what LockTree gives a data directory and everything in it:
// the protected DACLs of its directories and of its files, and whom
// besides OwnerTrusted's own list an object may belong to before it is
// handed to Administrators.
type TreeACL struct {
	DirDACL  *windows.ACL
	FileDACL *windows.ACL
	// TrustedOwners - see OwnerTrusted's extra.
	TrustedOwners []*windows.SID
	// BeforeApply, when set, runs after an object below the root has
	// been opened and classified and before its DACL is set: the window
	// R2-CX F-12 is about. Tests only; nil in the product.
	BeforeApply func(path string)
	// RefuseLinkedPath refuses, besides a root that is itself a link, a
	// root its path reaches through one: set it when the caller goes on
	// writing into root by name while the lock is held. The pin holds
	// root and every real folder above it - a folder with something open
	// below it cannot be renamed, and one that is not empty cannot be
	// made a link - but not a link on the way, which whoever may change
	// it can repoint.
	RefuseLinkedPath bool
}

// LockTree locks root and everything in it down to acl (R2-CX F-12),
// each object through the one handle it was classified by.
//
// The walks it replaces classified a child by what the directory listing
// said and then set its DACL by NAME, and the name could mean something
// else by then: a hard link to a file outside the directory (no privilege
// needed), or a directory link the walk then went on into - and the
// lockdown, owner and all, fell on the other object. Here every object is
// opened without following a reparse point, classified from its handle,
// checked (its owner - R2-CX F-07/F-13 - and its explicit DENY entries -
// IAMT-315) and locked through the same handle: SetSecurityInfo acts on
// the object the handle holds, whatever its name means meanwhile. The
// root and every directory below it stay open, without FILE_SHARE_DELETE,
// while their contents are walked, so none of them can be renamed or
// removed under the walk, and top-down order means each directory is
// already Administrators' by the time its entries are listed.
//
// A name surrogate (symlink, junction) below the root and a file with
// more than one name are left alone and reported: neither is an object
// of this directory alone. A root that is itself a surrogate is refused,
// and so, under RefuseLinkedPath, is one reached through a surrogate.
//
// The returned release keeps the root pinned until it is called - a
// caller that goes on writing into root by name (gateway install) keeps
// it until the last write, so nothing on the path can be renamed away and
// replaced meanwhile.
func LockTree(root string, acl TreeACL, replaceACL bool, report io.Writer) (release func(), err error) {
	err = withLockPrivileges(func() error {
		release, err = lockTree(root, acl, replaceACL, report)
		return err
	})
	return release, err
}

func lockTree(root string, acl TreeACL, replaceACL bool, report io.Writer) (release func(), err error) {
	h, info, err := openForLock(root)
	if err != nil {
		return nil, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(h)
		return nil, &LinkedPathRefusalError{Path: root}
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	if acl.RefuseLinkedPath {
		if err := refuseLinkedPath(h, root); err != nil {
			windows.CloseHandle(h)
			return nil, err
		}
	}
	if err := lockObject(h, root, acl.DirDACL, acl, replaceACL, report); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if err := lockEntries(root, acl, replaceACL, report); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	return func() { windows.CloseHandle(h) }, nil
}

// withLockPrivileges runs fn on one OS thread whose token has the backup
// and restore privileges enabled, when the process holds them - an
// elevated administrator does - so that opening an object to lock it does
// not depend on what the object's DACL grants. openForLock asks for the
// data right that pins a directory and for WRITE_OWNER, which no DACL
// gives an owner by default; and an explicit DENY an operator placed
// (IAMT-315), or a DACL that grants administrators nothing, is what the
// lock is there to read and refuse or replace, not a reason it cannot
// open the object. With FILE_FLAG_BACKUP_SEMANTICS the two privileges let
// the open by. They live on this thread's impersonation token and go with
// RevertToSelf: nothing else in the process runs with them.
//
// Found by the gates (R2-CX F-12): a console starts an administrator's
// processes with both privileges held and disabled, and the lock could
// not open such an object there - "Access is denied". Git Bash starts its
// children with both enabled, which is why the tests run from it had
// passed.
func withLockPrivileges(fn func() error) error {
	runtime.LockOSThread()
	if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
		runtime.UnlockOSThread()
		return fn()
	}
	defer func() {
		// A thread that could not stop impersonating is not handed back
		// to the scheduler: the runtime ends it with this goroutine.
		if windows.RevertToSelf() == nil {
			runtime.UnlockOSThread()
		}
	}()
	var token windows.Token
	if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, false, &token); err == nil {
		enableHeldPrivileges(token, "SeBackupPrivilege", "SeRestorePrivilege")
		token.Close()
	}
	return fn()
}

// enableHeldPrivileges enables each named privilege the token holds; one
// it does not hold stays absent (AdjustTokenPrivileges enables what it can
// and leaves the rest), and the open then gets exactly what the DACL
// grants, as before.
func enableHeldPrivileges(token windows.Token, names ...string) {
	for _, name := range names {
		n, err := windows.UTF16PtrFromString(name)
		if err != nil {
			continue
		}
		var luid windows.LUID
		if windows.LookupPrivilegeValue(nil, n, &luid) != nil {
			continue
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		_ = windows.AdjustTokenPrivileges(token, false, &tp, 0, nil, nil)
	}
}

// lockEntries locks every entry of dir, which the caller holds open.
func lockEntries(dir string, acl TreeACL, replaceACL bool, report io.Writer) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := lockEntry(filepath.Join(dir, e.Name()), acl, replaceACL, report); err != nil {
			return err
		}
	}
	return nil
}

func lockEntry(p string, acl TreeACL, replaceACL bool, report io.Writer) error {
	h, info, err := openForLock(p)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		if report != nil {
			fmt.Fprintf(report, "skipping %s: it is a name surrogate (symlink or junction), not an object of this data directory\n", p)
		}
		return nil
	case !isDir && info.NumberOfLinks > 1:
		if report != nil {
			fmt.Fprintf(report, "skipping %s: the file it names has %d names, so it is not an object of this data directory alone\n", p, info.NumberOfLinks)
		}
		return nil
	}
	if acl.BeforeApply != nil {
		acl.BeforeApply(p)
	}
	dacl := acl.FileDACL
	if isDir {
		dacl = acl.DirDACL
	}
	if err := lockObject(h, p, dacl, acl, replaceACL, report); err != nil {
		return err
	}
	if isDir {
		return lockEntries(p, acl, replaceACL, report)
	}
	return nil
}

// refuseLinkedPath refuses root unless the path it was opened by is the
// directory's own: the one Windows reports for the handle, compared with
// the 8.3 short names in the given path expanded.
func refuseLinkedPath(h windows.Handle, root string) error {
	given, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	real, err := finalPathByHandle(h)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", root, err)
	}
	if !strings.EqualFold(filepath.Clean(real), filepath.Clean(longPathName(given))) {
		return &LinkedPathRefusalError{Path: root, Resolved: real}
	}
	return nil
}

// finalPathByHandle is the path Windows reports for the object h holds,
// every link on the way resolved.
func finalPathByHandle(h windows.Handle) (string, error) {
	buf := make([]uint16, windows.MAX_PATH)
	for {
		// flags 0: VOLUME_NAME_DOS | FILE_NAME_NORMALIZED.
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			return withoutExtendedPrefix(windows.UTF16ToString(buf[:n])), nil
		}
		buf = make([]uint16, n)
	}
}

// longPathName is path with its 8.3 short names expanded - links on the
// way are left as they are - or path itself when Windows cannot say.
func longPathName(path string) string {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return path
	}
	buf := make([]uint16, windows.MAX_PATH)
	for {
		n, err := windows.GetLongPathName(name, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			return path
		}
		if n < uint32(len(buf)) {
			return withoutExtendedPrefix(windows.UTF16ToString(buf[:n]))
		}
		buf = make([]uint16, n)
	}
}

// withoutExtendedPrefix turns \\?\C:\x into C:\x and \\?\UNC\host\share
// into \\host\share.
func withoutExtendedPrefix(p string) string {
	switch {
	case strings.HasPrefix(p, `\\?\UNC\`):
		return `\\` + p[len(`\\?\UNC\`):]
	case strings.HasPrefix(p, `\\?\`):
		return p[len(`\\?\`):]
	}
	return p
}

// openForLock opens path without following a reparse point, for reading
// and replacing its security descriptor, and shared for everything but
// deletion: while the handle is open, the object cannot be removed or
// renamed, nor can a directory above it.
//
// FILE_READ_DATA (FILE_LIST_DIRECTORY on a directory) is what makes the
// share mode count: NTFS checks sharing only against handles that hold a
// data right, and a handle with nothing but READ_CONTROL, WRITE_DAC and
// WRITE_OWNER - the rights the lock itself needs - left the directory
// free to be removed and replaced by a link under the walk (found by the
// R2-CX F-12 test, which swaps a directory in exactly that window).
func openForLock(path string) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, info, err
	}
	h, err := windows.CreateFile(name,
		windows.FILE_READ_DATA|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, info, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return 0, info, &fs.PathError{Op: "stat", Path: path, Err: err}
	}
	return h, info, nil
}

// lockObject checks and locks the object h holds: its owner must be
// trusted, an explicit DENY entry is refused (or, under replaceACL,
// reported and dropped), and it is handed to Administrators with dacl,
// protected.
func lockObject(h windows.Handle, path string, dacl *windows.ACL, acl TreeACL, replaceACL bool, report io.Writer) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read the security descriptor of %s: %w", path, err)
	}
	if err := refuseForeignOwnerIn(path, sd, acl.TrustedOwners); err != nil {
		return err
	}
	denies, err := collectForeignDenies(sd)
	if err != nil {
		return fmt.Errorf("read security descriptor of %s: %w", path, err)
	}
	if len(denies) > 0 {
		if !replaceACL {
			return &ForeignDenyRefusalError{Path: path, Denies: denies}
		}
		reportForeignDeny(path, denies, report)
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		AdministratorsSID(), nil, dacl, nil); err != nil {
		return fmt.Errorf("SetSecurityInfo(%s): %w", path, err)
	}
	return nil
}

// LockObject is LockTree for one object and nothing below it: opened
// without following a reparse point, checked and locked through the one
// handle (R2-CX F-12). A path that is itself a link is refused - the
// lockdown is for the object, and a link names another one.
func LockObject(path string, dacl *windows.ACL, trusted []*windows.SID, replaceACL bool, report io.Writer) error {
	return withLockPrivileges(func() error {
		h, info, err := openForLock(path)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(h)
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return &LinkedPathRefusalError{Path: path}
		}
		return lockObject(h, path, dacl, TreeACL{TrustedOwners: trusted}, replaceACL, report)
	})
}

// ProtectedDACL is a DACL granting each trustee access, with inheritance
// (for a directory: SUB_CONTAINERS_AND_OBJECTS_INHERIT; for a file: 0).
func ProtectedDACL(access windows.ACCESS_MASK, inheritance uint32, trustees ...*windows.SID) (*windows.ACL, error) {
	eas := make([]windows.EXPLICIT_ACCESS, 0, len(trustees))
	for _, sid := range trustees {
		eas = append(eas, windows.EXPLICIT_ACCESS{
			AccessPermissions: access,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				MultipleTrusteeOperation: windows.NO_MULTIPLE_TRUSTEE,
				TrusteeForm:              windows.TRUSTEE_IS_SID,
				TrusteeType:              windows.TRUSTEE_IS_USER,
				TrusteeValue:             windows.TrusteeValueFromSID(sid),
			},
		})
	}
	// TrusteeValueFromSID hides each SID behind a uintptr the call
	// dereferences: pin them for its lifetime, as the other builders do.
	rp := &runtime.Pinner{}
	defer rp.Unpin()
	for _, sid := range trustees {
		rp.Pin(sid)
	}
	acl, err := windows.ACLFromEntries(eas, nil)
	if err != nil {
		return nil, fmt.Errorf("build the DACL: %w", err)
	}
	return acl, nil
}

// MachineTreeACL is the machine data directory's lockdown (IAMT-213):
// SYSTEM and Administrators, directories inherited by everything below.
func MachineTreeACL() (TreeACL, error) {
	dirDACL, err := ProtectedDACL(fileAllAccess, inheritContainerObject, AdministratorsSID(), mustSID("S-1-5-18"))
	if err != nil {
		return TreeACL{}, err
	}
	fileDACL, err := ProtectedDACL(genericAll, inheritNone, AdministratorsSID(), mustSID("S-1-5-18"))
	if err != nil {
		return TreeACL{}, err
	}
	return TreeACL{DirDACL: dirDACL, FileDACL: fileDACL}, nil
}
