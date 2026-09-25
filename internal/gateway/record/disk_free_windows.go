//go:build windows

package record

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// platformDiskStats is the Windows side of diskStats. We hand
// GetDiskFreeSpaceEx the path's volume root (the kernel resolves the
// directory to its volume internally; passing the directory itself works
// for UNC paths and drive-relative paths alike per MSDN).
//
// The three out-params from the Win32 call distinguish "free to caller"
// from "free to admin" (the latter is what we want for recordings: the
// gateway process runs as a service account, so caller-visible bytes is
// the realistic ceiling). TotalNumberOfBytes is the volume size; we do not
// trust FreeBytesAvailableToCaller as a substitute for total - free.
func platformDiskStats(path string) (DiskStats, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return DiskStats{}, err
	}
	var freeToCaller, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &freeToCaller, &total, &totalFree); err != nil {
		return DiskStats{}, err
	}
	_ = totalFree // kernel reports it; we deliberately do not act on it
	return DiskStats{TotalBytes: int64(total), FreeBytes: int64(freeToCaller)}, nil
}
