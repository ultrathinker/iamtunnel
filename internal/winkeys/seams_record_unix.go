//go:build linux || darwin

// Recording seam stubs for the Unix door layer, plus the one
// exported hook other packages' test binaries use to install them.
//
// Every production syscall in doors_unix.go goes through a seam
// (chmodFn / chownFn / chmodFnFD / chownFnFD) whose DEFAULT is the
// real syscall AND a testing.Testing() panic guard — a test binary
// that does not install a stub panics on the first call (gate 11:
// a test binary never issues a real chmod/chown). This file holds
// the recording stubs: same signatures, but instead of a syscall
// they append a (fd, mode)/(fd, uid, gid) entry to an in-memory
// slice. FD == -1 marks a path-based call (chmodFn / chownFn); a
// real fd marks an fd-based one — the convention the door's own
// tests assert on ("every Install chmods by fd, never by path").
//
// The stubs live in a non-test file for one reason: a _test.go
// file cannot be imported. internal/server's tests drive the real
// doorController end to end (door.open must leave a line in the
// key file), so THEIR test binary has to install the same stubs —
// SetRecordingSeamsForTest is the entry point for that. It is not
// an off-switch for production code: outside a test binary it
// panics (the exact inverse of the seam defaults' own guard), and
// the only caller is a _test.go init() that never compiles into
// the iamtunnel binary. The Windows platform layer has no
// chmod/chown seams, so the hook does not exist there.

package winkeys

import (
	"sync"
	"testing"
)

// chownFDCalls / chmodFDCalls are the recording slices
// installRecordingSeams wires into the seams. chownFDCall.FD /
// chmodFDCall.FD carry the fd the door layer used, or -1 for a
// path-based call.
type chownFDCall struct {
	FD  int
	UID int
	GID int
}

type chmodFDCall struct {
	FD   int
	Mode uint32
}

var chownFDCalls []chownFDCall
var chmodFDCalls []chmodFDCall
var seamMu sync.Mutex

// installRecordingSeams replaces all four Unix seams with the
// recording stubs. Called from this package's test init() and from
// SetRecordingSeamsForTest.
func installRecordingSeams() {
	chmodFn = func(path string, mode uint32) error {
		seamMu.Lock()
		chmodFDCalls = append(chmodFDCalls, chmodFDCall{FD: -1, Mode: mode})
		seamMu.Unlock()
		return nil
	}
	chmodFnFD = func(fd int, mode uint32) error {
		seamMu.Lock()
		chmodFDCalls = append(chmodFDCalls, chmodFDCall{FD: fd, Mode: mode})
		seamMu.Unlock()
		return nil
	}
	chownFn = func(path string, uid, gid int) error {
		seamMu.Lock()
		chownFDCalls = append(chownFDCalls, chownFDCall{FD: -1, UID: uid, GID: gid})
		seamMu.Unlock()
		return nil
	}
	chownFnFD = func(fd int, uid, gid int) error {
		seamMu.Lock()
		chownFDCalls = append(chownFDCalls, chownFDCall{FD: fd, UID: uid, GID: gid})
		seamMu.Unlock()
		return nil
	}
}

// SetRecordingSeamsForTest installs the recording seam stubs in the
// calling package's test binary. It exists for internal/server,
// whose tests run the real door write sequence and therefore must
// never reach the seam defaults (they panic in a test binary by
// design); the call belongs in a _test.go init(). Outside a test
// binary it panics — production code must always run the real
// syscalls, and the seam defaults' own testing.Testing() guard is
// what enforces that. The stubs record instead of erroring, so a
// test that asserts on the recorded calls can still verify the
// door layer's behaviour (fd-based, correct mode/owner) without
// any real chmod/chown taking place.
func SetRecordingSeamsForTest() {
	if !testing.Testing() {
		panic("winkeys: SetRecordingSeamsForTest is a test-only hook — it must only be called from a test binary")
	}
	installRecordingSeams()
}
