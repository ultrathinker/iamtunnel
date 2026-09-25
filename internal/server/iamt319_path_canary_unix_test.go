//go:build linux || darwin

// iamt319_path_canary_unix_test.go — IAMT-319: the sshd -T seam
// (sshd_config_unix.go) is shared between Linux and macOS, so its
// PATH-pinning canary lives here rather than in either platform's own
// test file. requireServerElevation (cmd/iamtunnel/server.go) already
// gates "iamtunnel server start" on root before checkSSHDConfig ever
// runs, so a bare exec.Command("sshd", ...) resolved through PATH would
// let anyone who can influence that root process's PATH plant their own
// helper and get arbitrary code execution as root.
//
// Canary: revert exec.Command("sshd", ...) back to
// exec.Command(serverSshdPath, ...) in runServerSshdT — a planted sshd
// earlier in PATH runs (the marker appears).
package server

import (
	"os"
	"path/filepath"
	"testing"
)

func planFakeSshd(t *testing.T) (marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "executed")
	script := "#!/bin/sh\ntouch " + marker + "\necho \"pubkeyauthentication yes\"\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "sshd"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return marker
}

func TestIAMT319_RunServerSshdT_DoesNotUsePATH(t *testing.T) {
	marker := planFakeSshd(t)

	_, _, _ = runServerSshdT([]string{"-T", "-C", "user=iamt319-canary,host=localhost,addr=127.0.0.1"})

	if _, err := os.Stat(marker); err == nil {
		t.Fatal("runServerSshdT must never resolve sshd through PATH — a fake planted earlier in PATH must not run")
	}
}
