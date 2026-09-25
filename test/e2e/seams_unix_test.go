//go:build linux || darwin

// Cross-package integration-test seam: the entire test/e2e suite is
// driven against a real gateway + real iamtunnel-like fixtures on
// loopback, and one scenario (TestScenario20_CorruptedMarkerSanitized
// ThenStatusClean) drives a real winkeys.Door end-to-end through
// SweepStale against a real key file inside t.TempDir(). That path
// reaches the Unix door-write seam (chmodFnFD at
// internal/winkeys/doors_unix.go:299) — which by default panics in a
// test binary, by design (gate 11: a test binary never issues a real
// chmod/chown).
//
// The fix for that cross-package panic is the exported hook
// winkeys.EnableRealFilesystemSeamsForIntegrationTest (see
// internal/winkeys/integration.go). This file installs it ONCE for
// the whole test/e2e binary via init(), the same pattern the winkeys
// unit tests already use internally
// (internal/winkeys/doors_unix_test.go:60-64 installs recording
// seams in init()):
//
//   - The package test/e2e has no unit tests with their own recording
//     or custom seams (every scenario is an end-to-end test that
//     either exercises the gateway's fake-machine path or this real
//     Door sweep); one package-wide install at init time is enough
//     and avoids threading the restore func through every fixture /
//     every sanitize request.
//   - init() runs single-threaded before any test starts, so there
//     is no race against a parallel goroutine swapping seams mid-run.
//   - The hook itself has a testing.Testing() guard; production code
//     (cmd/iamtunnel) never calls it, so the gate 11 protection is
//     not weakened outside the test binary.
//
// The file is linux/darwin-tagged (not all-platform) because the hook
// it calls exists only under //go:build linux || darwin in the
// winkeys package; the Windows platform layer has no chmod/chown
// seams (its door-write path uses Windows ACL primitives, see
// internal/winkeys/doors_windows.go), so the test/e2e binary on
// Windows never has to install anything.

package e2e

import (
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func init() {
	winkeys.EnableRealFilesystemSeamsForIntegrationTest()
}
