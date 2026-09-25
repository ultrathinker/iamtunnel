package server

// iamt138_sshd_check_test.go — IAMT-138:
//
//   "Before connecting, nobody checks whether sshd is alive on the machine".
//
// docs/SPEC.md:91–92:
//   "Before Start: checks that the sshd service is running and listening on
//    127.0.0.1:22 (QueryServiceStatusEx + dial). If not — a clear error, the
//    door does not open."

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
)

// TestCheckSSHD_NotListeningRefusesStart tests that CheckSSHD performs a pre-start
// dial check on TargetAddr and immediately fails when sshd is not listening.
//
// Canary 1:
//
//	In internal/server/run.go CheckSSHD, remove the net.DialTimeout call.
//	The test will fail on line:
//	  t.Fatalf("CheckSSHD with unreachable TargetAddr = %q did not fail: %v", targetAddr, err)
func TestCheckSSHD_NotListeningRefusesStart(t *testing.T) {
	// Pick an unused port on 127.0.0.1
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	targetAddr := ln.Addr().String()
	_ = ln.Close() // closed immediately so nothing is listening

	err = CheckSSHD(targetAddr, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), targetAddr) {
		t.Fatalf("CheckSSHD with unreachable TargetAddr = %q did not fail: %v", targetAddr, err)
	}
}

// TestCheckSSHD_ServiceStoppedRefusesStart tests that CheckSSHD checks the service
// status (QueryServiceStatusEx) independently of whether the TCP port is listening.
//
// Canary 2:
//
//	In internal/server/run.go CheckSSHD, remove the checkService invocation.
//	The test will fail on line:
//	  t.Fatalf("CheckSSHD with stopped sshd service did not fail: %v", err)
func TestCheckSSHD_ServiceStoppedRefusesStart(t *testing.T) {
	// Start a dummy TCP listener so the port IS open
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	targetAddr := ln.Addr().String()

	err = CheckSSHD(targetAddr, func() error {
		return errors.New("sshd service is stopped")
	})
	if err == nil || !strings.Contains(err.Error(), "sshd service check failed") {
		t.Fatalf("CheckSSHD with stopped sshd service did not fail: %v", err)
	}
}

// TestCheckSSHD_CannotTouchHostSCMInTests proves that defaultCheckSSHDService
// cannot touch the host service manager in test binaries: an un-mocked call
// panics instead of reaching the real SCM/systemd.
//
// Canary 4:
//
//	In internal/server/run_windows.go, remove `if testing.Testing() { panic(...) }` —
//	or the guard inside the default systemctlFn seam on Linux (internal/server/run_linux.go).
//	The test will fail on line:
//	  t.Fatalf("calling defaultCheckSSHDService in test binary must panic, but returned: %v", err)
func TestCheckSSHD_CannotTouchHostSCMInTests(t *testing.T) {
	// The refusal text is platform-specific: Windows has no seam to
	// hide a guard in, so the guard sits at the top of the function
	// (run_windows.go); Linux guards the seam default itself
	// (run_linux.go), the same pattern as the winkeys seams, so the
	// refusal names systemctlFn; other Unixes refuse via the
	// run_other.go stub guard.
	var wantMsg string
	switch runtime.GOOS {
	case "linux":
		wantMsg = "systemctlFn invoked in test binary"
	case "windows":
		wantMsg = "tests must never access real Windows SCM"
	default:
		wantMsg = "invoked in test binary"
	}
	var err error
	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
				msg := fmt.Sprint(r)
				if !strings.Contains(msg, wantMsg) {
					t.Fatalf("unexpected panic message: %s", msg)
				}
			}
		}()
		err = defaultCheckSSHDService()
	}()

	if !panicked {
		t.Fatalf("calling defaultCheckSSHDService in test binary must panic, but returned: %v", err)
	}
}
