//go:build linux || darwin

// Unix-only test-binary wiring for the door layer's seams (IAMT-248
// fix2). This package's tests drive the real doorController end to
// end — door.open must leave a line in the key file — so on
// linux/darwin the write sequence reaches winkeys's chmod/chown
// seams. The seam defaults run the real syscall AND panic in a test
// binary (gate 11: a test binary never issues a real chmod/chown),
// so the binary installs the same recording stubs internal/winkeys's
// own unit tests use, through the exported hook.
//
// This file is a _test.go file: it never compiles into the iamtunnel
// binary, and SetRecordingSeamsForTest itself panics outside a test
// binary, so the hook is not a production off-switch. Windows is
// untouched — its platform layer has no chmod/chown seams.

package server

import (
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func init() {
	winkeys.SetRecordingSeamsForTest()
}
