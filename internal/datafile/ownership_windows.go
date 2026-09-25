//go:build windows

package datafile

import "os"

// PreserveOwnership is a no-op on Windows (IAMT-332). The problem it
// answers is POSIX-only: rename(2) hands the replacement file the
// creating process's uid, so a root-run maintenance command could lock
// the unprivileged service account out of its own state file. Windows
// has no uid/gid to hand over — the service there is secured by ACLs
// (SPEC §3.5.1), and MoveFileEx moves the temporary file's security
// descriptor, which already inherits the data directory's entries, with
// the file (atomicWriteMachineBytes spells out the same mechanics for
// the machine's own files). Windows behaviour is unchanged.
func PreserveOwnership(f *os.File, replacedPath string) error {
	return nil
}
