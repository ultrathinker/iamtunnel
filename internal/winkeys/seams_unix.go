//go:build linux || darwin

// Seams for the Linux/Darwin platform layer of winkeys.
//
// Every production syscall in doors_unix.go goes through one of
// these seams so a test binary never reaches the real filesystem
// without consent. The default of every seam is the real syscall
// AND a `testing.Testing()` panic guard — the same pattern
// defaultCheckSSHDService uses (internal/server/run_windows.go /
// run_other.go). The pattern is:
//
//   - production binary: seam runs the real syscall, no panic
//     because testing.Testing() is false;
//   - test binary that did not install a seam: seam runs, panics
//     on the first call;
//   - test binary that installed a recording seam: seam runs the
//     recording, no panic;
//   - test binary that installed a "real-impl" seam (for
//     integration testing): seam runs the real syscall, no panic.
//
// This keeps the gate 11 invariant ("a test binary does not make
// real chown/chown/... syscalls") without forcing every
// test to know the syscall names; integration tests that want
// the real syscall install seams that just do the syscall and
// return the error.
//
// The door-write path uses the fd-based pair because every
// operation goes through an openat fd; the path-based pair serves
// the cross-platform LockDownFileACL / LockDownDirACL stubs.
// LockDownFileACL is reached from Unix production — but only for
// the machine data directory (cmd/iamtunnel's atomicWriteMachineBytes
// / generateMachineSigner), never inside the user's home, where the
// door's fd-only rule (SPEC §3.2.1) applies. LockDownDirACL has no
// Unix production caller since hardenServerDir switched to a plain
// os.Chmod (IAMT-248 fix2).

package winkeys

import (
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// chmodFn chmods path to mode. Path-based; used by the
// cross-platform LockDownFileACL / LockDownDirACL stubs. The real
// path on Unix is Fchmodat with AT_SYMLINK_NOFOLLOW so a symlink
// cannot be chmod'd under the file's real target.
var chmodFn = func(path string, mode uint32) error {
	if testing.Testing() {
		panic("winkeys: chmodFn invoked in test binary; tests must replace the seam or call chmodFnFD directly via the fd-based helper")
	}
	if err := unix.Fchmodat(0, path, mode, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	return nil
}

// chmodFnFD fchmods fd to mode via Fchmod (no path involvement).
// The door-write-path seam: every chmod in the openat sequence
// goes through here, never via a path.
var chmodFnFD = func(fd int, mode uint32) error {
	if testing.Testing() {
		panic("winkeys: chmodFnFD invoked in test binary on a real path; integration tests must replace the seam in init() with a real-impl version that does NOT panic")
	}
	if err := unix.Fchmod(fd, mode); err != nil {
		return err
	}
	return nil
}

// chownFn fchowns path to uid/gid (path-based). Same shape as
// chmodFn; the door write path uses the fd variant below.
var chownFn = func(path string, uid, gid int) error {
	if testing.Testing() {
		panic("winkeys: chownFn invoked in test binary on a real path; integration tests must replace the seam in init()")
	}
	if err := unix.Fchownat(0, path, uid, gid, 0); err != nil {
		return err
	}
	return nil
}

// chownFnFD fchowns fd to uid/gid via Fchown (no path). Used by
// the door-write path after openat.
var chownFnFD = func(fd int, uid, gid int) error {
	if testing.Testing() {
		panic("winkeys: chownFnFD invoked in test binary on a real path; integration tests must replace the seam in init()")
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	return nil
}

// realChmodFnFD is the production syscall without the test-binary
// panic guard. Tests that want real syscalls (the IAMT-269
// integration tests) install this via swapSeams; the seam is
// never the default so a test that does not opt in cannot
// accidentally reach the real syscall.
func realChmodFnFD(fd int, mode uint32) error {
	if err := unix.Fchmod(fd, mode); err != nil {
		return err
	}
	return nil
}

// realChownFnFD is the production syscall without the test-binary
// panic guard.
func realChownFnFD(fd int, uid, gid int) error {
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	return nil
}

// seamsMu serialises swaps of the package-level seams in tests.
// Tests that want to substitute one of the above at init() do not
// need the lock (init is single-threaded); tests that swap
// mid-run take the mutex so a parallel goroutine never sees a
// half-installed seam.
var seamsMu sync.Mutex

// swapSeams atomically swaps every seam at once. Used by tests
// that want to drive the door with a complete fake layer (or
// with a complete real-impl layer, for integration testing). The
// returned func restores the production seams; defer it.
//
// A nil field in s leaves the existing seam in place. The
// restore function only restores what was non-nil at swap time.
type Seams struct {
	Chmod   func(path string, mode uint32) error
	ChmodFD func(fd int, mode uint32) error
	Chown   func(path string, uid, gid int) error
	ChownFD func(fd int, uid, gid int) error
}

func swapSeams(s Seams) func() {
	seamsMu.Lock()
	defer seamsMu.Unlock()
	saved := Seams{
		Chmod:   chmodFn,
		ChmodFD: chmodFnFD,
		Chown:   chownFn,
		ChownFD: chownFnFD,
	}
	if s.Chmod != nil {
		chmodFn = s.Chmod
	}
	if s.ChmodFD != nil {
		chmodFnFD = s.ChmodFD
	}
	if s.Chown != nil {
		chownFn = s.Chown
	}
	if s.ChownFD != nil {
		chownFnFD = s.ChownFD
	}
	return func() {
		chmodFn = saved.Chmod
		chmodFnFD = saved.ChmodFD
		chownFn = saved.Chown
		chownFnFD = saved.ChownFD
	}
}
