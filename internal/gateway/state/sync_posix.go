//go:build !windows

package state

import "os"

// DurableReplace reports whether this platform gives the full §3.5 write formula
// (tmp -> fsync -> rename -> fsync(dir)) with all four steps. On POSIX it does.
// The constant exists so that the strength of the guarantee is stated in the code and
// can be asserted by a test, instead of a platform quietly skipping the check.
const DurableReplace = true

// POSIXPermissionsEnforced reports whether the 0700/0600 modes this package asks for
// are actually enforced by the file system.
const POSIXPermissionsEnforced = true

// syncDir opens the directory and issues an fsync to flush directory entries.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// replaceFile atomically replaces dst with src. On POSIX this is rename(2), which is
// atomic within a file system; durability of the directory entry is then covered by
// syncDir.
func replaceFile(src, dst string) error {
	return os.Rename(src, dst)
}
