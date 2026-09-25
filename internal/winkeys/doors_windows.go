//go:build windows

// Windows-specific primitives for the winkeys package:
//
//   - renameForReplace — MoveFileEx with REPLACE_EXISTING so the
//                         tmp-to-final rename in writeAtomic is
//                         atomic from sshd's point of view.
//   - FileLock          — <keyFile>.lock opened via windows.CreateFile
//                         with dwShareMode=0 so two writers in the
//                         same or different sessions collide on the
//                         lock file. os.OpenFile cannot express this:
//                         it always asks CreateFile for
//                         FILE_SHARE_READ|FILE_SHARE_WRITE, so a
//                         second opener always succeeds. CreateFile
//                         with an explicit share mode of 0 is the one
//                         call that can ask Windows for exclusivity.
//   - applyProtectedDACL — narrow a file's (or directory's) DACL to
//                         {Administrators FullControl, SYSTEM
//                         FullControl} with SE_DACL_PROTECTED set;
//                         read back via ReadDACL and DACLProtected.
//                         Exposed as LockDownFileACL / LockDownDirACL
//                         (IAMT-213, the machine role's own data
//                         directory) and reached by the key-file write
//                         path through protectTmpBeforeReplace
//                         (IAMT-214) — one DACL implementation for
//                         both.

package winkeys

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// moveFileEx and syncTmpFile are seams for the R4 F-08 test, which pins
// that the replace is flushed and written through.
var (
	moveFileEx  = windows.MoveFileEx
	syncTmpFile = (*os.File).Sync
)

// renameForReplace atomically replaces an existing file at newpath
// by moving oldpath over it. os.Rename on Windows refuses to
// overwrite an existing target; MoveFileEx REPLACE_EXISTING is the
// idiom that lets the whole writeAtomic round-trip work the same
// way it does on Unix. The retry is for the case where sshd (or
// any other reader) is holding the destination file briefly —
// ERROR_ACCESS_DENIED is what MoveFileEx returns in that state,
// and the right thing to do is back off briefly and try again. A
// hard error is anything else.
func renameForReplace(oldpath, newpath string) error {
	from, err := windows.UTF16PtrFromString(oldpath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(newpath)
	if err != nil {
		return err
	}
	// WRITE_THROUGH: the call returns only after the move is on disk
	// (R4 F-08) — the file is shared by every administrator, and a power
	// cut right after an unflushed replace can leave it empty.
	const MOVEFILE_REPLACE_EXISTING = 0x1
	const MOVEFILE_WRITE_THROUGH = 0x8
	const maxAttempts = 20
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		err := moveFileEx(from, to, MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableRenameErr(err) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
	return lastErr
}

// isRetryableRenameErr reports whether a MoveFileEx error is one
// we expect to clear on retry: ERROR_ACCESS_DENIED (5) and
// ERROR_SHARING_VIOLATION (32). Other errors are hard.
func isRetryableRenameErr(err error) bool {
	if err == nil {
		return false
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == 5 || errno == 32
	}
	return false
}

// FileLock is the cross-process lock on the key file. Each Door
// opens the file at opts.LockPath (Windows legacy: <keyFile>.lock)
// through windows.CreateFile with dwShareMode=0 (no sharing at all,
// not even for another handle opened by the same process) — two
// callers in the same or different sessions collide on this open,
// with ERROR_SHARING_VIOLATION returned to the loser. A bounded
// retry turns a stuck holder into an error rather than a silent
// hang.
//
// Holder death: Windows closes every open handle a process owns
// when the process terminates, including a hard kill (TerminateProcess,
// "taskkill /f", a crash) — there is no graceful-shutdown
// requirement for the release to happen. The moment the handle is
// gone, dwShareMode=0 no longer excludes anyone, and the next
// AcquireFileLock succeeds. This is verified by
// TestFileLock_ReleasedWhenHolderKilled (doors_windows_test.go),
// which taskkills a real holder process.
//
// On Windows the handle itself is what serialises; the lock file
// is not deleted on Release.
type FileLock struct {
	f *os.File
}

// AcquireFileLock opens lockPath with dwShareMode=0 (exclusive:
// no other handle, of any kind, may exist on the file while this
// one is open) and returns the held lock. The lock path is now an
// explicit parameter — on Linux and Darwin the path lives in the
// server's data directory rather than alongside the authorised
// keys file, and Door.lockPath() takes care of deriving it on each
// platform. On Windows the historical "keyFile.lock" path still
// works when the caller passes it through Door.lockPath(). Polls
// every 20 ms for up to lockContentionWait before declaring
// contention and returning an error — a holder that never releases
// must surface as a failure, not a hang. This bound is verified by
// TestAcquireFileLock_TimesOutOnStuckHolder.
// lockContentionWait bounds how long AcquireFileLock waits for a busy
// lock. The handle is not queued, so under sustained contention a
// waiter can miss every gap for a while: two writers cycling hundreds
// of flushed install/remove pairs on a slow CI disk missed them for
// more than 2 s. Ten seconds is still a bounded failure for a holder
// that never lets go.
const lockContentionWait = 10 * time.Second

func AcquireFileLock(lockPath string) (*FileLock, error) {
	namePtr, err := windows.UTF16PtrFromString(lockPath)
	if err != nil {
		return nil, fmt.Errorf("lock path %s: %w", lockPath, err)
	}
	const fileShareNone = 0
	// Short, frequent tries rather than a few long ones: the handle is
	// not queued, so a writer that asks rarely can miss every gap between
	// another writer's release and its next acquire. Since R4 F-08 the
	// held section also flushes to disk, which widens it and made an
	// 80 ms poll lose whole seconds of gaps under load.
	deadline := time.Now().Add(lockContentionWait)
	for {
		h, err := windows.CreateFile(
			namePtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			fileShareNone,
			nil,
			windows.OPEN_ALWAYS,
			windows.FILE_ATTRIBUTE_NORMAL,
			0,
		)
		if err == nil {
			return &FileLock{f: os.NewFile(uintptr(h), lockPath)}, nil
		}
		if !isLockContention(err) {
			return nil, fmt.Errorf("open lock %s: %w", lockPath, err)
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("lock %s held by another writer", lockPath)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Release closes the lock handle. The on-disk lock file is left
// in place — WinKeys.cs behaves the same way.
func (l *FileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// isLockContention reports whether err is the CreateFile failure
// that means "someone else already holds this file exclusively":
// ERROR_SHARING_VIOLATION (32), ERROR_LOCK_VIOLATION (33) or
// ERROR_ACCESS_DENIED (5, seen when a deleting/renaming holder
// leaves the name in a transient state). windows.CreateFile returns
// the raw syscall.Errno directly — no *os.PathError wrapping, unlike
// the os package.
func isLockContention(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == windows.ERROR_SHARING_VIOLATION ||
			errno == windows.ERROR_LOCK_VIOLATION ||
			errno == windows.ERROR_ACCESS_DENIED
	}
	return false
}

// ACL primitives. The numbers are the documented Win32 flags we
// use; comments keep them tied to their names so the layouts
// below stay auditable.
const (
	genericAll       windows.ACCESS_MASK                 = 0x10000000
	daclSecurityInfo                                     = windows.DACL_SECURITY_INFORMATION
	protectedDaclSec                                     = 0x80000000
	seDaclProtected  windows.SECURITY_DESCRIPTOR_CONTROL = 0x1000
	aceInheritedFlag uint8                               = 0x10
	// accessDeniedACEType is the ACE-type byte for ACCESS_DENIED_ACE_TYPE
	// (the only deny variant in the DACL of an object we may read via
	// GetNamedSecurityInfo). ACCESS_ALLOWED_ACE_TYPE is 0; we never set a
	// deny ACE ourselves, so the check looks for ACE type 0x01.
	accessDeniedACEType uint8 = 0x01
)

// ACE inheritance flags for EXPLICIT_ACCESS.Inheritance (the Win32
// OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE pair): an ACE carrying
// both propagates to every file and subdirectory created below the
// object. Kept as local constants so the audit of the ACL layout does
// not depend on how x/sys names them.
const (
	inheritNone            uint32 = 0
	inheritContainerObject uint32 = 0x1 | 0x2
)

// fileAllAccess is FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | the
// file generic mapping) — the fully specific "Full control" mask. It
// matters for DIRECTORIES: an inheritable ACE whose mask carries
// GENERIC bits gets canonicalized by the security system into TWO
// stored ACEs per trustee — the generic mask mapped down to
// FILE_ALL_ACCESS applying to the object itself, plus the generic ACE
// kept for propagation — so two trustees with GENERIC_ALL+(OI)(CI)
// land as FOUR ACEs (the IAMT-213 round-2 finding). A specific mask
// needs no mapping and is stored as written: one (OI)(CI) ACE per
// trustee, which icacls shows as (OI)(CI)(F).
const fileAllAccess windows.ACCESS_MASK = 0x1F01FF

// applyProtectedDACL is the single ACL primitive of this package. It
// narrows the object's DACL to exactly two ACEs (Administrators and
// SYSTEM, both full control, set by SID — never by localized name) and
// sets SE_DACL_PROTECTED so nothing is inherited from the parent.
// inheritance carries the ACE inheritance flags (inheritNone for a
// file, inheritContainerObject for a directory); access carries the
// ACE mask — genericAll for files, fileAllAccess for directories (see
// the comment above for why a directory must not use the generic mask)
// (IAMT-213).
//
// Before overwriting, applyProtectedDACL reads the existing security
// descriptor (GetNamedSecurityInfo with DACL_SECURITY_INFORMATION) and
// looks for explicit, non-inherited ACCESS_DENIED ACEs (IAMT-315).
// Those are an operator's deliberate decision about THIS object; we
// never erase them silently. When any are present and replaceACL is
// false the function refuses with a *ForeignDenyRefusalError naming
// each principal and access mask. When replaceACL is true, the
// function prints the same list to the caller-supplied report writer
// (one line per ACE) and proceeds — the new protected DACL is written
// as if nothing was there. A nil report skips the printout (callers
// without a CLI writer to thread through — the machine role's own
// data directory routine, for example — pass nil). Inherited ACEs are
// not the operator's local decision about this object and are
// ignored. A failure to read the existing descriptor fails closed
// (never assume "there was nothing there").
//
// Every caller shares this one implementation: the key-file write path
// reaches it through protectTmpBeforeReplace (IAMT-214), and the
// machine role's own data directory reaches it through the exported
// LockDownFileACL / LockDownDirACL wrappers (IAMT-213). On any
// non-Windows platform the doors_other.go stubs return nil so test
// runs on Linux can still exercise the line code without the ACL
// piece.
func applyProtectedDACL(path string, inheritance uint32, access windows.ACCESS_MASK, replaceACL bool, report io.Writer) error {
	// R2-CX F-12: checked and set through one handle (LockObject), not by
	// name twice - GetNamedSecurityInfo then SetNamedSecurityInfo resolved
	// the name afresh each time, and what it named could change between.
	// LockObject refuses an owner nobody here can vouch for and hands the
	// object to Administrators (R2-CX F-13), and refuses or reports an
	// explicit DENY entry exactly as before (IAMT-315).
	dacl, err := ProtectedDACL(access, inheritance, mustSID("S-1-5-32-544"), mustSID("S-1-5-18"))
	if err != nil {
		return err
	}
	return LockObject(path, dacl, nil, replaceACL, report)
}

// LockDownFileACL applies the protected two-trustee DACL (SYSTEM and
// Administrators, full control, no inheritance) to an existing file.
// Exported for the machine role's own data directory (IAMT-213); the
// key-file path uses protectTmpBeforeReplace, which is this same
// primitive on the tmp file before the rename. replaceACL is the
// IAMT-315 opt-in flag — pass true when the caller already obtained
// explicit consent to drop any foreign explicit ACCESS_DENIED ACEs on
// the file (install on Windows threads it through --replace-acl).
// report is the caller-supplied destination for the dropped-ACE
// printout (one line per ACE) and may be nil for call sites that have
// no CLI stream to thread through (the machine-data writers — pass
// nil; their callers do not own the operator-facing narrative).
func LockDownFileACL(path string, replaceACL bool, report io.Writer) error {
	return applyProtectedDACL(path, inheritNone, genericAll, replaceACL, report)
}

// LockDownDirACL applies the protected two-trustee DACL to a directory
// with (OI)(CI) inheritance, so every file and subdirectory created
// below it starts from SYSTEM/Administrators only and nothing leaks in
// from the parent (IAMT-213). The ACE mask is the specific
// FILE_ALL_ACCESS, not GENERIC_ALL: the generic mask would be
// canonicalized into two stored ACEs per trustee (see fileAllAccess),
// and the directory must carry exactly two (OI)(CI)(F) entries.
// Existing children are NOT rewritten by this call — the caller heals
// them one by one with LockDownFileACL / LockDownDirACL. replaceACL is
// the IAMT-315 opt-in (--replace-acl threads it through install).
// report is the caller-supplied destination for the dropped-ACE
// printout; see LockDownFileACL for the nil contract.
func LockDownDirACL(path string, replaceACL bool, report io.Writer) error {
	return applyProtectedDACL(path, inheritContainerObject, fileAllAccess, replaceACL, report)
}

// protectTmpBeforeReplace narrows the tmp file's DACL before
// writeAtomicBytes renames it over the real key file (IAMT-214). The
// tmp file is a sibling of the key file and inherits the containing
// directory's DACL — on a stock machine that includes
// Authenticated Users read — so the lockdown MUST happen before the
// rename: after it, the file is already visible under its real name
// with the inherited entries. MoveFileEx moves the security descriptor
// together with the file (same-volume move), and MOVEFILE_REPLACE_
// EXISTING discards the previous target together with its DACL instead
// of merging it in, so what ends up under the real name is exactly
// this tmp file's protected DACL.
//
// replaceACL is false here on purpose: protectTmpBeforeReplace runs on
// a freshly-created tmp file (just-written via os.WriteFile), and the
// IAMT-315 check looks for explicit (non-inherited) DENY ACEs, which
// a brand-new file does not carry. The inherited entries that DO land
// on the tmp file come from the parent directory's DACL and are
// discarded by SE_DACL_PROTECTED on write anyway. report is passed
// through so the signature matches LockDownFileACL (callers without
// a writer pass nil; no report fires here regardless).
func protectTmpBeforeReplace(tmp string, report io.Writer) error {
	return applyProtectedDACL(tmp, inheritNone, genericAll, false, report)
}

// extractACLFromSD walks a self-relative SECURITY_DESCRIPTOR
// (returned by BuildSecurityDescriptor) and pulls out the DACL
// pointer.
func extractACLFromSD(sd *windows.SECURITY_DESCRIPTOR) (
	owner, group *windows.SID, dacl *windows.ACL, sacl *windows.ACL, err error,
) {
	sdPtr := unsafe.Pointer(sd)
	hd := unsafe.Slice((*byte)(sdPtr), 20)
	daclOff := *(*uint32)(unsafe.Pointer(&hd[16]))
	if daclOff != 0 {
		dacl = (*windows.ACL)(unsafe.Add(sdPtr, daclOff))
	}
	return
}

// ReadDACL returns the names of the trustees in the file's DACL,
// sorted alphabetically, ignoring inherited entries. Used by the
// ACL tests to verify the post-install state.
func ReadDACL(path string) ([]string, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		daclSecurityInfo,
	)
	if err != nil {
		return nil, fmt.Errorf("GetNamedSecurityInfo: %w", err)
	}
	return daclTrusteeNames(sd)
}

// ReadDACLOf is ReadDACL for a file already open: the list of the object
// the handle holds, whatever its name means by now (R1-CX F-14). The
// handle needs READ_CONTROL - any handle opened for reading has it.
func ReadDACLOf(h windows.Handle) ([]string, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, daclSecurityInfo)
	if err != nil {
		return nil, fmt.Errorf("GetSecurityInfo: %w", err)
	}
	return daclTrusteeNames(sd)
}

// daclTrusteeNames is the parse ReadDACL and ReadDACLOf share.
func daclTrusteeNames(sd *windows.SECURITY_DESCRIPTOR) ([]string, error) {
	sdBytes := unsafe.Slice((*byte)(unsafe.Pointer(sd)), 20)
	sdCopy := make([]byte, 20)
	copy(sdCopy, sdBytes)
	daclOff := *(*uint32)(unsafe.Pointer(&sdCopy[16]))
	if daclOff == 0 {
		return []string{}, nil
	}

	sdPtr := unsafe.Pointer(sd)
	daclPtr := unsafe.Add(sdPtr, daclOff)
	daclSize := int(*(*uint16)(unsafe.Add(daclPtr, 2)))
	if daclSize < 8 || daclSize > 64*1024 {
		return nil, fmt.Errorf("implausible DACL size %d", daclSize)
	}
	daclBuf := unsafe.Slice((*byte)(daclPtr), daclSize)
	daclCopy := make([]byte, daclSize)
	copy(daclCopy, daclBuf)

	aceCount := int(*(*uint16)(unsafe.Pointer(&daclCopy[4])))
	off := 8
	names := make([]string, 0, aceCount)
	for i := 0; i < aceCount; i++ {
		if off+4 > daclSize {
			return nil, fmt.Errorf("ACE index %d past DACL end (off=%d size=%d)", i, off, daclSize)
		}
		aceFlags := daclCopy[off+1]
		aceSize := int(*(*uint16)(unsafe.Pointer(&daclCopy[off+2])))
		if aceFlags&aceInheritedFlag != 0 {
			off += aceSize
			continue
		}
		sidPtr := (*windows.SID)(unsafe.Pointer(&daclCopy[off+8]))
		sidLen := windows.GetLengthSid(sidPtr)
		if sidLen == 0 || off+8+int(sidLen) > daclSize {
			off += aceSize
			continue
		}
		sidCopy, err := sidPtr.Copy()
		if err != nil {
			off += aceSize
			continue
		}
		name := sidCopy.String()
		name = friendlySIDName(name)
		names = append(names, name)
		off += aceSize
	}
	sort.Strings(names)
	return names, nil
}

func friendlySIDName(s string) string {
	switch s {
	case "S-1-5-18":
		return `NT AUTHORITY\SYSTEM`
	case "S-1-5-32-544":
		return `BUILTIN\Administrators`
	case "S-1-1-0":
		return `Everyone`
	case "S-1-5-32-545":
		return `BUILTIN\Users`
	}
	return s
}

// DACLProtected reports whether the file's security descriptor
// has SE_DACL_PROTECTED set.
func DACLProtected(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		daclSecurityInfo,
	)
	if err != nil {
		return false, fmt.Errorf("GetNamedSecurityInfo(sd): %w", err)
	}
	return daclProtectedIn(sd), nil
}

// DACLProtectedOf is DACLProtected for a file already open (R1-CX F-14).
func DACLProtectedOf(h windows.Handle) (bool, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, daclSecurityInfo)
	if err != nil {
		return false, fmt.Errorf("GetSecurityInfo(sd): %w", err)
	}
	return daclProtectedIn(sd), nil
}

func daclProtectedIn(sd *windows.SECURITY_DESCRIPTOR) bool {
	hd := unsafe.Slice((*byte)(unsafe.Pointer(sd)), 4)
	ctrl := *(*uint16)(unsafe.Pointer(&hd[2]))
	return windows.SECURITY_DESCRIPTOR_CONTROL(ctrl)&seDaclProtected != 0
}

// ForeignDenyACE, ForeignDenyRefusalError, DescribeAccessMask and the
// accessMaskKnownNames table live in foreign_deny.go so platform-neutral
// callers (cmd/iamtunnel/gateway_service.go, in its errors.As branch)
// can reference the refusal type without dragging the win32 DACL walk
// into the unix build. The Windows-only CheckForeignExplicitDeny /
// collectForeignDenies / resolveSIDName / reportForeignDeny that PRODUCE
// ForeignDenyACE values stay in this file below.

// CheckForeignExplicitDeny reads the DACL of path and returns every
// non-inherited ACCESS_DENIED ACE. Inherited ACEs are not the
// operator's local decision about THIS object (they came from a
// parent) and are ignored; the same rule the install-time audit
// applies — SE_DACL_PROTECTED will discard inherited entries on
// write anyway, so auditing them here would not change the
// outcome. A failure to read the security descriptor returns the
// error so the caller can fail closed (never assume "there was
// nothing there").
//
// Exported so the gateway-install path in cmd/iamtunnel can apply
// the same read-before-overwrite discipline to its three-trustee
// DACL.
func CheckForeignExplicitDeny(path string) ([]ForeignDenyACE, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		daclSecurityInfo,
	)
	if err != nil {
		return nil, fmt.Errorf("GetNamedSecurityInfo(%s): %w", path, err)
	}
	return collectForeignDenies(sd)
}

// collectForeignDenies walks the DACL inside an already-fetched
// self-relative SECURITY_DESCRIPTOR (the same walk
// iamt213's readDACLFull performs, scoped to the deny ACEs we care
// about). Copied out of iamt213 so production code does not depend
// on a test file's helper; the test in iamt315 calls this through
// the public CheckForeignExplicitDeny on a t.TempDir() file.
func collectForeignDenies(sd *windows.SECURITY_DESCRIPTOR) ([]ForeignDenyACE, error) {
	if sd == nil {
		return nil, fmt.Errorf("nil security descriptor")
	}
	sdBytes := unsafe.Slice((*byte)(unsafe.Pointer(sd)), 20)
	sdCopy := make([]byte, 20)
	copy(sdCopy, sdBytes)
	daclOff := *(*uint32)(unsafe.Pointer(&sdCopy[16]))
	if daclOff == 0 {
		// No DACL = everything is allowed. There is no explicit
		// DENY ACE to refuse on; report the empty list so the caller
		// proceeds (and SetNamedSecurityInfo will install a real
		// protected DACL).
		return nil, nil
	}
	daclPtr := unsafe.Add(unsafe.Pointer(sd), daclOff)
	daclSize := int(*(*uint16)(unsafe.Add(daclPtr, 2)))
	if daclSize < 8 || daclSize > 64*1024 {
		return nil, fmt.Errorf("implausible DACL size %d", daclSize)
	}
	daclBuf := unsafe.Slice((*byte)(daclPtr), daclSize)
	daclCopy := make([]byte, daclSize)
	copy(daclCopy, daclBuf)

	aceCount := int(*(*uint16)(unsafe.Pointer(&daclCopy[4])))
	off := 8
	var out []ForeignDenyACE
	for i := 0; i < aceCount; i++ {
		if off+4 > daclSize {
			return nil, fmt.Errorf("ACE index %d past DACL end (off=%d size=%d)", i, off, daclSize)
		}
		aceType := daclCopy[off]
		aceFlags := daclCopy[off+1]
		aceSize := int(*(*uint16)(unsafe.Pointer(&daclCopy[off+2])))
		if aceType != accessDeniedACEType || aceFlags&aceInheritedFlag != 0 {
			off += aceSize
			continue
		}
		sidPtr := (*windows.SID)(unsafe.Pointer(&daclCopy[off+8]))
		sidLen := windows.GetLengthSid(sidPtr)
		if sidLen == 0 || off+8+int(sidLen) > daclSize {
			off += aceSize
			continue
		}
		sidCopy, err := sidPtr.Copy()
		if err != nil {
			off += aceSize
			continue
		}
		out = append(out, ForeignDenyACE{
			SID:  sidCopy.String(),
			Name: resolveSIDName(sidCopy),
			Mask: *(*uint32)(unsafe.Pointer(&daclCopy[off+4])),
		})
		off += aceSize
	}
	return out, nil
}

// resolveSIDName looks up the friendly account name for sid. Returns
// the empty string if LookupAccountSid fails (a deleted user, a
// domain the machine no longer trusts, etc.) — the SID string
// remains in the printed message and is enough to identify the
// principal without the friendly form.
//
// LookupAccountSid's last parameter is a *uint32 in this binding of
// golang.org/x/sys/windows — the SID-name-use enum on the Win32 side,
// but the binding exposes it as the raw uint32 since the enum values
// are not exported. We do not use the value; passing a local uint32
// satisfies the Syscall.
func resolveSIDName(sid *windows.SID) string {
	sidPtr, err := sid.Copy()
	if err != nil {
		return ""
	}
	var (
		nameBuf   [256]uint16
		domainBuf [256]uint16
		nameLen   uint32 = uint32(len(nameBuf))
		domainLen uint32 = uint32(len(domainBuf))
		nameUse   uint32
	)
	if err := windows.LookupAccountSid(
		nil,
		sidPtr,
		&nameBuf[0],
		&nameLen,
		&domainBuf[0],
		&domainLen,
		&nameUse,
	); err != nil {
		return ""
	}
	name := windows.UTF16ToString(nameBuf[:nameLen])
	domain := windows.UTF16ToString(domainBuf[:domainLen])
	if domain == "" {
		return name
	}
	return domain + `\` + name
}

// reportForeignDeny prints one line per dropped ACE to the
// caller-supplied report writer. There is no package-level reporter
// variable: the "no kill switch" rule forbids an exported
// mutable writer a future maintainer could flip to silence the report
// — and the report is the operator's only signal that an explicit
// DENY was overwritten. The writer is thread-through, not state:
// every call to a primitive that may drop a foreign ACE receives its
// own writer from its caller (cmd/iamtunnel threads the CLI's
// captured s.out through install; nil is treated as "no report
// destination" — non-CLI call sites pass nil).
func reportForeignDeny(path string, denies []ForeignDenyACE, report io.Writer) {
	if report == nil {
		return
	}
	for _, d := range denies {
		principal := d.Name
		if principal == "" {
			principal = d.SID
		}
		fmt.Fprintf(report,
			"iamtunnel gateway install --replace-acl: dropping foreign ACCESS_DENIED ACE on %s: %s mask %#x (%s)\n",
			path, principal, d.Mask, DescribeAccessMask(d.Mask))
	}
}

func mustSID(s string) *windows.SID {
	sid, err := windows.StringToSid(s)
	if err != nil {
		panic(err)
	}
	return sid
}

// Supported reports whether winkeys can run on this platform.
// The Windows implementation covers lock, atomic rename, the file
// ACL lockdown and the doorwatch subprocess. Production targets
// are Windows machines in 1.0 (SPEC §12).
func Supported() bool { return true }

// validateOptionsPlatform is the Windows half of
// NewDoorWithOptions's gate. Windows has no LockPath
// requirement (the platform layer derives it from keyFile);
// OwnerUID/OwnerGID are ignored (sshd's Match Group
// administrators identity owns the file, not iamtunnel).
func validateOptionsPlatform(_ DoorOptions) error { return nil }

// pinTesting keeps the testing import live on every Windows
// build where the symbol is otherwise unreferenced; Go trips
// an "imported and not used" error otherwise. The DACL helpers
// already use testing.Testing() for their panic guard, but a
// future refactor could drop those references — this
// placeholder prevents an untracked drop from breaking the
// build.
var _ = testing.Testing

// writeAtomicBytesPlatform is the Windows half of writeAtomicBytes.
// The flow is identical to the original writeAtomicBytes: write
// the tmp file in the same directory, narrow the DACL to the
// protected {SYSTEM, Administrators} pair via protectTmpBeforeReplace,
// then MoveFileEx(REPLACE_EXISTING) so the rename carries the
// narrow DACL onto the final file. chownTmpBeforeReplace is a
// no-op here; the ACL is the Windows equivalent of ownership.
//
// The function is defined here rather than in doors.go so the
// Unix implementation in doors_unix.go can take a completely
// different shape (strict-mode preflight + openat-based write)
// without forcing a giant cross-platform function.
func writeAtomicBytesPlatform(path string, content []byte, _ DoorOptions) error {
	// The temporary is a random O_EXCL creation, not the flat
	// path+"."+pid+".tmp" this function used before IAMT-332 round 8:
	// the pid-name was computable — the door user knows their own
	// authorized_keys path and the service's PID is enumerable — so a
	// pre-planted symlink at it aimed both the write and the DACL
	// lockdown below at the attacker's target. The random name is safe
	// by construction, and the lockdown still lands on the tmp file
	// BEFORE the rename (IAMT-214) — now on a name nobody outside this
	// process ever saw.
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("create tmp in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write tmp %s: %w", tmpPath, err)
	}
	// FlushFileBuffers before the rename (R4 F-08), as the Unix half
	// fsyncs: NTFS journals the rename, not the data behind it.
	if err := syncTmpFile(tmp); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("flush tmp %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close tmp %s: %w", tmpPath, err)
	}
	if err := protectTmpBeforeReplace(tmpPath, nil); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("protect tmp %s before replace: %w", tmpPath, err)
	}
	if err := renameForReplace(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename %s -> %s: %w", tmpPath, path, err)
	}
	return nil
}

// modifyKeyFilePlatform is the Windows half of modifyKeyFile
// (a major finding from review). On Windows the openat-based
// strict-mode discipline from SPEC §3.2.1 is out of scope: the read
// and the write stay path-based. The Unix half of modifyKeyFile
// closes the TOCTOU window between path-read and openat-write by
// running everything on one sshFD; Windows cannot do that without
// a complete redesign of the ACL primitives, and path-based code is
// explicitly permitted on the Windows layer
// ("leave the path-based code (as it stands) only for the Windows layer").
//
// The read-back after the write follows the Unix-side
// verifyWriteBack discipline: read the file back as raw bytes and
// compare with `next` (what we asked the writeAtomicBytesPlatform
// to write). The earlier shape — "no iamtunnel line must remain" —
// was a semantic check that was only correct for Remove; Install
// and SweepStale-preserve legitimately leave iamtunnel lines on
// disk (Install writes one, SweepStale preserves currentDoorID).
// A byte-for-byte comparison catches both cases: the on-disk bytes
// either match the transform's result (success) or they do not
// (failure with a precise message naming path / lengths / first
// divergent byte for diagnostics).
func modifyKeyFilePlatform(path string, transform func(raw []byte) ([]byte, error), opts DoorOptions) error {
	// datafile.ReadFile, not os.ReadFile (IAMT-332 round nine): a hard
	// link or junction planted at the authorized_keys name — no privilege
	// needed on Windows — is refused instead of being read through, and a
	// missing file keeps os.ErrNotExist verbatim, as the create branch
	// below expects.
	raw, err := datafile.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			raw = nil
		} else {
			return fmt.Errorf("read %s: %w", path, err)
		}
	}
	next, err := transform(raw)
	if err != nil {
		return err
	}
	// No-op path (IAMT-282): the transform returned the on-disk
	// bytes unchanged — Remove of an absent id, SweepStale with
	// nothing to sweep, and the empty-on-empty idempotent case
	// (SweepStale on an empty file would call transform("") and
	// get "" back). writeAtomicBytesPlatform always replaces the
	// file (tmp + MoveFileEx), so before this check even a
	// byte-for-byte no-op rewrote it; now such a call returns
	// without touching the file at all. The read-back below only
	// runs when a real write happened and stays as is.
	if bytesEqualWindows(raw, next) {
		return nil
	}
	if err := writeAtomicBytesPlatform(path, next, opts); err != nil {
		return err
	}
	// Read-back: byte-for-byte compare against `next`, the same
	// invariant verifyWriteBack enforces on Unix. Mirrors
	// doors_unix.go:502-507 (length check, then bytes.Equal-style
	// compare) so a future maintainer reading either platform sees
	// the same shape.
	got, err := datafile.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read-back %s: %w", path, err)
	}
	if len(got) != len(next) {
		return fmt.Errorf("modifyKeyFile: read-back length %d, want %d for %s", len(got), len(next), path)
	}
	if !bytesEqualWindows(got, next) {
		return fmt.Errorf("modifyKeyFile: read-back bytes do not match what was written for %s", path)
	}
	return nil
}

// bytesEqualWindows is the Windows half of the constant-time byte
// compare — a tiny for-loop instead of pulling in bytes.Equal from
// the standard library (the Unix side uses string(bytes) ==
// string(want), which works because both sides come from the same
// Go process; on Windows we want the same shape as the Unix
// verifyWriteBack loop and avoid the string conversion). The helper
// is unexported and used only by modifyKeyFilePlatform.
func bytesEqualWindows(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
