//go:build linux

// iamt319_path_canary_linux_test.go — IAMT-319: the same PATH-injection
// class IAMT-318 fixed inside the macOS gateway install path, here on
// the Linux server-start path. requireServerElevation
// (cmd/iamtunnel/server.go) already gates "iamtunnel server start" on
// root before checkSSHD/checkSSHDConfig ever run, so a bare
// exec.Command("systemctl", ...) resolved through PATH would let anyone
// who can influence that root process's PATH plant their own helper and
// get arbitrary code execution as root.
//
// Canary: revert exec.Command("systemctl", ...) back to
// exec.Command(serverSystemctlPath, ...) in runServerSystemctl —
// a planted systemctl earlier in PATH runs (the marker appears).
package server

import (
	"os"
	"path/filepath"
	"testing"
)

// planFakeSystemctl writes an executable shell script named systemctl
// into a fresh directory, prepends that directory to PATH, and returns
// the path to a marker file the script touches — proving whether it
// ever ran.
func planFakeSystemctl(t *testing.T) (marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "executed")
	script := "#!/bin/sh\ntouch " + marker + "\necho active\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return marker
}

func TestIAMT319_RunServerSystemctl_DoesNotUsePATH(t *testing.T) {
	marker := planFakeSystemctl(t)

	// serverSystemctlPath is /usr/bin/systemctl; a test machine's own
	// systemctl (if any) is expected to fail against a nonsense unit
	// name, which is fine — the assertion only cares that the PATH-planted
	// fake never ran.
	_, _ = runServerSystemctl([]string{"is-active", "iamt319-canary-does-not-exist"})

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("runServerSystemctl must never resolve systemctl through PATH — a fake planted earlier in PATH must not run")
	}
}
