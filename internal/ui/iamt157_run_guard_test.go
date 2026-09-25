//go:build windows

package ui

// iamt157_run_guard_test.go is IAMT-157's belt-and-braces canary, mirrored
// from internal/server/iamt138_sshd_check_test.go
// (TestCheckSSHD_CannotTouchHostSCMInTests): Run opens a real OS window
// and, on success, never returns — app.Main() blocks forever on Windows
// (see gui.go) — so an un-mocked call reached from inside a test
// binary would hang the whole test run rather than fail it. Run refuses
// on its own, in testing.Testing(), before it ever creates an
// *app.Window.

import (
	"fmt"
	"strings"
	"testing"
)

func TestRunPanicsInTestBinary(t *testing.T) {
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				msg := fmt.Sprint(r)
				if !strings.Contains(msg, "tests must never open a real window") {
					t.Fatalf("unexpected panic message: %s", msg)
				}
			}
		}()
		_ = Run(FrameConfig{}, nil)
	}()

	if !panicked {
		t.Fatalf("calling Run in a test binary must panic, but it returned")
	}
}
