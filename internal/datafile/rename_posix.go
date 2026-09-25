//go:build !windows

package datafile

import "os"

// replaceEntry is the rename at the end of WriteFileAtomic. rename(2)
// replaces an entry whatever other descriptors hold the old file, so
// POSIX needs none of the waiting the Windows half does (IAMT-503).
func replaceEntry(tmpPath, path string) error {
	return os.Rename(tmpPath, path)
}
