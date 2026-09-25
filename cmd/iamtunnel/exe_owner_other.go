//go:build !linux && !darwin

package main

import "errors"

// statExeOwner has no Unix owner to report here: server install asks it only
// on Linux and macOS (IAMT-445b); Windows answers the same question with its
// ACLs (exe_acl_windows.go).
func statExeOwner(p string) (exeOwnerStat, error) {
	return exeOwnerStat{}, errors.New("unix file ownership is not available on this platform")
}
