//go:build !windows

package main

import (
	"strings"
	"testing"
)

// TestShotRefusesOnNonWindows: offscreen rendering is Windows-only
// (SPEC §9), so on other platforms the command answers with the
// environment class, naming the platform — and never with the shared
// "not implemented yet" stub.
func TestShotRefusesOnNonWindows(t *testing.T) {
	_, errs, code := drive(t, "shot", "client")
	if code != 3 {
		t.Errorf("shot on non-windows: exit code = %d, want 3 (stderr: %s)", code, errs)
	}
	if !strings.Contains(errs, "Windows-only") {
		t.Errorf("shot on non-windows: stderr lacks the Windows-only wording, got:\n%s", errs)
	}
	if strings.Contains(errs, "not implemented yet") {
		t.Errorf("shot on non-windows must answer for itself, got the shared stub:\n%s", errs)
	}
}
