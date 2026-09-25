//go:build linux || darwin

// Cross-package integration-test hook for the Unix door layer.
//
// The seam defaults (chmodFnFD / chownFnFD in seams_unix.go) refuse to
// run in a test binary by panicking — gate 11 ("a test binary does not
// make real chown/chown/... syscalls"). Tests that drive a real winkeys.
// Door end to end against a real key file inside t.TempDir() need the
// seams replaced with their non-panicking, real-syscall siblings
// (realChmodFnFD / realChownFnFD) for the duration of that test.
//
// Inside this package the swap goes through the package-private
// swapSeams / Seams / realChmodFnFD / realChownFnFD — see seams_unix.go
// and the recording-stub companion in seams_record_unix.go. From
// OUTSIDE this package those symbols are not visible (lower-case), and
// until this file existed the only exported cross-package test hook
// was SetRecordingSeamsForTest (seams_record_unix.go:95), which
// installs recording stubs — appropriate for unit tests that want to
// observe chmod/chown calls without paying for the syscall, but
// useless for the integration tests in test/e2e that genuinely drive a
// Door through SweepStale against a real key file on disk.
//
// EnableRealFilesystemSeamsForIntegrationTest is the narrow exported
// entry point for those cross-package integration tests. It panics
// outside a test binary (testing.Testing() guard, the inverse of the
// seam defaults' own guard) so the production binary can never
// accidentally link a weakened-seam code path; in a test binary it
// swaps both fd-based seams to their real-syscall implementations and
// returns a restore func. The caller is responsible for deferring it
// (or wiring it to t.Cleanup) so a later unit test in the same binary
// does not see a recording-default-vs-real-default mismatch.
//
// The file exists only under //go:build linux || darwin because the
// seams it touches (and the package-private swapSeams / Seams /
// real*FnFD symbols) exist only on those platforms; the Windows
// platform layer has no chmod/chown seams (doors_windows.go writes
// the door file via Windows ACL primitives, not fchmod/fchown), and
// the cross-package integration tests in test/e2e reach for this
// hook from a sibling linux/darwin-tagged file, never on Windows.

package winkeys

import "testing"

// EnableRealFilesystemSeamsForIntegrationTest installs the real,
// non-panicking chmod/chown seams for integration tests OUTSIDE this
// package that legitimately drive a real winkeys.Door end-to-end
// against a real key file inside t.TempDir() (e.g. test/e2e's
// TestScenario20_CorruptedMarkerSanitizedThenStatusClean). It panics
// if called outside testing.Testing() — this only ever weakens gate
// 11's protection inside a test binary, never in production; the
// caller is responsible for restoring the seams (defer the returned
// func, or t.Cleanup it).
//
// The path-based seams (chmodFn / chownFn, used by LockDownFileACL /
// LockDownDirACL) are not touched here: the cross-package integration
// tests in test/e2e only reach the door-write path, which uses the
// fd-based pair. Swapping only what the caller actually exercises
// keeps the surface narrow and avoids weakening gates no test asked
// to weaken.
func EnableRealFilesystemSeamsForIntegrationTest() func() {
	if !testing.Testing() {
		panic("winkeys: EnableRealFilesystemSeamsForIntegrationTest called outside a test binary")
	}
	return swapSeams(Seams{ChmodFD: realChmodFnFD, ChownFD: realChownFnFD})
}
