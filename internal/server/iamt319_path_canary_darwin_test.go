//go:build darwin

// iamt319_path_canary_darwin_test.go — IAMT-319: the launchctl seam
// (run_darwin.go) used for the Remote Login preflight.
// requireServerElevation (cmd/iamtunnel/server.go) already gates
// "iamtunnel server start" on root before checkSSHD ever runs, so a
// bare exec.Command("launchctl", ...) resolved through PATH would let
// anyone who can influence that root process's PATH plant their own
// helper and get arbitrary code execution as root.
//
// Canary: revert exec.Command("launchctl", ...) back to
// exec.Command(serverDarwinLaunchctlPath, ...) in runServerLaunchctl —
// a planted launchctl earlier in PATH runs (the marker appears).
package server

import (
	"os"
	"path/filepath"
	"testing"
)

func planFakeLaunchctl(t *testing.T) (marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "executed")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "launchctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return marker
}

func TestIAMT319_RunServerLaunchctl_DoesNotUsePATH(t *testing.T) {
	marker := planFakeLaunchctl(t)

	_, _, _ = runServerLaunchctl([]string{"print", "system/iamt319-canary-does-not-exist"})

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("runServerLaunchctl must never resolve launchctl through PATH — a fake planted earlier in PATH must not run")
	}
}
