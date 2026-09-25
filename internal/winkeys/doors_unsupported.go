//go:build !linux && !darwin && !windows

// Unix platforms that are not Linux or Darwin (FreeBSD, OpenBSD,
// NetBSD, illumos, …). Linux and Darwin ship their own real
// implementation in doors_unix.go; Windows ships its own in
// doors_windows.go. The line code (FormatLine, IsOurs, ReadLines)
// is cross-platform and runs everywhere, but the file-system
// primitives this package relies on — flock, fchown, O_NOFOLLOW,
// openat — differ from one Unix to another and SPEC §3.2.1
// targets those two specifically. A build that
// ends up on any other platform gets an explicit refusal rather
// than a silent no-op, so an accidental freebsd build cannot
// run with no lock and no ACL without a human noticing.
//
// The file defines only the primitives that doors.go still
// calls from the cross-platform surface — every primitive that
// doors.go routes through the dispatcher stays defined here so
// the build is complete. The Windows half of each primitive
// lives in doors_windows.go.
package winkeys

import (
	"errors"
	"io"
	"testing"
)

// errUnsupportedUnix is the single shape of error every primitive
// in this file reports. tests inspect errUnsupportedUnix to confirm
// the platform layer refused.
var errUnsupportedUnix = errors.New("winkeys: supported only on linux, darwin and windows")

// FileLock is the platform-layer lock handle. The stub here is
// never returned successfully; the constructor below refuses.
type FileLock struct{ held bool }

// AcquireFileLock refuses. Construction-time validation in
// NewDoorWithOptions refuses an empty LockPath on these platforms
// too, so a Door that reaches here is the result of a bad caller
// (one that bypassed NewDoorWithOptions and called the platform
// layer directly), not a normal-config situation.
func AcquireFileLock(_ string) (*FileLock, error) {
	if testing.Testing() {
		panic("winkeys: AcquireFileLock invoked on unsupported Unix in test binary")
	}
	return nil, errUnsupportedUnix
}

// Release is a no-op so a struct built via &FileLock{} for tests
// does not panic when Release is called; the function returning the
// lock has already refused.
func (l *FileLock) Release() error {
	if l == nil {
		return nil
	}
	l.held = false
	return nil
}

// validateOptionsPlatform refuses. LockPath is required on linux
// and darwin; on this build there is no production caller that
// satisfies it.
func validateOptionsPlatform(_ DoorOptions) error {
	if testing.Testing() {
		panic("winkeys: validateOptionsPlatform invoked on unsupported Unix in test binary")
	}
	return errUnsupportedUnix
}

// writeAtomicBytesPlatform is the unsupported-Unix half of
// writeAtomicBytes. NewDoorWithOptions refused an empty LockPath
// at construction time, so the only way to reach here is a
// caller that bypassed the constructor. Refuse rather than
// silently write without the layer-0 protection.
func writeAtomicBytesPlatform(_ string, _ []byte, _ DoorOptions) error {
	if testing.Testing() {
		panic("winkeys: writeAtomicBytesPlatform invoked on unsupported Unix in test binary")
	}
	return errUnsupportedUnix
}

// LockDownFileACL refuses. replaceACL is the IAMT-315 opt-in; it is
// accepted for cross-platform signature symmetry and ignored here.
// report is the Windows-only printout destination; the parameter
// exists so the cross-platform callers can thread it through.
func LockDownFileACL(_ string, _ bool, _ io.Writer) error {
	if testing.Testing() {
		panic("winkeys: LockDownFileACL invoked on unsupported Unix in test binary")
	}
	return errUnsupportedUnix
}

// LockDownDirACL refuses. See LockDownFileACL for the replaceACL and
// report parameter rationales.
func LockDownDirACL(_ string, _ bool, _ io.Writer) error {
	if testing.Testing() {
		panic("winkeys: LockDownDirACL invoked on unsupported Unix in test binary")
	}
	return errUnsupportedUnix
}

// ReadDACL returns an empty list. The Windows implementation
// walks the SECURITY_DESCRIPTOR; Unix systems that are not Linux
// or Darwin do not have an ACL concept here.
func ReadDACL(_ string) ([]string, error) {
	return nil, nil
}

// DACLProtected returns false. See ReadDACL.
func DACLProtected(_ string) (bool, error) {
	return false, nil
}

// Supported reports whether winkeys can run on this platform.
// Linux is not in 1.0 (SPEC §12); the same is true of every
// other Unix not called out by name.
func Supported() bool { return false }
