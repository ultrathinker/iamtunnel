//go:build windows

package state

import (
	"errors"
	"syscall"
	"time"
	"unsafe"
)

// The gateway is a Linux service (§3.5). The Windows build exists so that the data
// model can be developed and tested on a workstation, and it is honest about being
// weaker there:
//
//   - DurableReplace is false. Of the four steps of §3.5 (tmp -> fsync -> rename ->
//     fsync(dir)) Windows performs three. There is no fsync on a directory handle, so
//     the ordering of the directory entry against the file content is not enforced by
//     anything. replaceFile asks MoveFileEx for MOVEFILE_WRITE_THROUGH, which makes the
//     rename itself write through the cache - that is as close as this platform gets,
//     and it is still not the POSIX guarantee.
//   - POSIXPermissionsEnforced is false. 0700/0600 are passed to the runtime, but NTFS
//     ACLs are not derived from them; the directory is protected by whatever inherited
//     ACL it has. A test must not check for 0600 here, and must not silently skip
//     either - it checks this constant instead.
const (
	DurableReplace           = false
	POSIXPermissionsEnforced = false
)

// syncDir is a no-op on Windows: directory handles cannot be flushed. See the note
// above - this is the step of §3.5 that this platform does not perform.
func syncDir(dir string) error {
	return nil
}

var procMoveFileExW = modkernel32.NewProc("MoveFileExW")

const (
	moveFileReplaceExisting = 0x1
	moveFileWriteThrough    = 0x8

	// Error codes returned when another process (an indexer, an antivirus, a reader)
	// holds the target file open.
	errorAccessDenied     = syscall.Errno(5)
	errorSharingViolation = syscall.Errno(32)

	replaceRetries = 10
	replaceBackoff = 20 * time.Millisecond
)

// replaceFile replaces dst with src.
//
// MoveFileEx with MOVEFILE_REPLACE_EXISTING is the Windows counterpart of rename(2);
// MOVEFILE_WRITE_THROUGH additionally makes it complete before returning. Unlike
// rename(2) it fails while any other process has the target open, which on a desktop
// happens routinely and for reasons that pass in milliseconds - hence the bounded
// retry. Losing a state write because an indexer glanced at state.json would be worse
// than waiting a fifth of a second for it to let go.
func replaceFile(src, dst string) error {
	from, err := syscall.UTF16PtrFromString(src)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		return err
	}
	flags := uintptr(moveFileReplaceExisting | moveFileWriteThrough)

	var lastErr error
	for attempt := 0; attempt < replaceRetries; attempt++ {
		r1, _, errSys := procMoveFileExW.Call(
			uintptr(unsafe.Pointer(from)),
			uintptr(unsafe.Pointer(to)),
			flags,
		)
		if r1 != 0 {
			return nil
		}
		lastErr = errSys
		if !errors.Is(lastErr, errorAccessDenied) && !errors.Is(lastErr, errorSharingViolation) {
			return lastErr
		}
		time.Sleep(replaceBackoff)
	}
	return lastErr
}
