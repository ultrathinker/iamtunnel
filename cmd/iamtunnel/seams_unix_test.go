//go:build linux || darwin

// Unix-only test-binary wiring for winkeys's chmod/chown seams (IAMT-248
// fix3). This package's tests drive the real enrol write path end to end:
// cmdEnrol -> enrolMachine -> loadOrGenerateMachineSigner / generateMachineSigner
// / atomicWriteMachineBytes / atomicWriteMachineJSON, each of which calls
// winkeys.LockDownFileACL — on Unix that routes to the path-based chmodFn
// seam (the real production path for the machine data directory, outside
// the user's home). The seam defaults run the real syscall AND panic in a
// test binary (gate 11: a test binary never issues a real chmod/chown), so
// without this file every Linux enrol-shaped test died with
// "winkeys: chmodFn invoked in test binary" — killing the whole package,
// not just the one test. The binary installs the same recording stubs
// internal/winkeys and internal/server use, through the exported hook.
//
// This file is a _test.go file: it never compiles into the iamtunnel
// binary, and SetRecordingSeamsForTest itself panics outside a test
// binary, so the hook is not a production off-switch. The stubs record
// and return nil — the temp file keeps its 0o600 from os.WriteFile, so
// every on-disk assertion in this package sees the same bytes and modes
// as before. Windows is untouched — its platform layer has no chmod/chown
// seams, and LockDownFileACL there does the real DACL work the Windows
// tests assert on (iamt213_server_dir_acl_windows_test.go).

package main

import (
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func init() {
	winkeys.SetRecordingSeamsForTest()
}
