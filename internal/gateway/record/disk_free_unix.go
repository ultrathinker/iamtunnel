//go:build !windows

package record

import "golang.org/x/sys/unix"

// platformDiskStats is the POSIX side of diskStats. Statfs is the right
// call on Linux and macOS; the field names are identical between the two
// thanks to x/sys/unix exposing a single Statfs_t.
//
// Bsize is the "optimal transfer block size" per statfs(2): not the
// physical sector size. Multiplying it by Bavail / Bfree gives the bytes
// available to an unprivileged caller (Bavail) and the bytes free to a
// superuser (Bfree). We use Bavail for FreeBytes so the rotation is
// pessimistic about free space — a service account cannot actually use
// Bfree - Bavail reserved blocks.
func platformDiskStats(path string) (DiskStats, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return DiskStats{}, err
	}
	total := int64(st.Bsize) * int64(st.Blocks)
	free := int64(st.Bsize) * int64(st.Bavail)
	return DiskStats{TotalBytes: total, FreeBytes: free}, nil
}
