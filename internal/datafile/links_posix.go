//go:build !windows

package datafile

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// linkCount reports how many names the entry has, when the platform can
// answer without opening it. POSIX carries it in the Lstat result, so
// this is free. The `known` flag is false when the platform gave no
// POSIX stat — the caller then treats the entry as an ordinary file.
func linkCount(_ string, fi fs.FileInfo) (n uint64, known bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}

// linkCountOfOpen reports how many names the OPEN file carries — the
// race-free twin of linkCount, used by the guard that gates a descriptor
// about to be read or written (IAMT-332 round 10).
//
// fi comes from the caller's f.Stat(), which on POSIX is fstat(2) on the
// descriptor itself: no pathname is resolved, so nothing can be swapped
// in between the measurement and the use. The count lives in the same
// Stat_t the name-based leg reads, so the two legs cannot drift apart.
//
// Unlike linkCount this returns an error rather than a `known` flag: on
// this path an unmeasurable count is a refusal, not a shrug, and the
// caller has to be able to say why in words.
func linkCountOfOpen(_ *os.File, fi fs.FileInfo) (uint64, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("fstat returned no POSIX stat for this file (%T)", fi.Sys())
	}
	return uint64(st.Nlink), nil
}
