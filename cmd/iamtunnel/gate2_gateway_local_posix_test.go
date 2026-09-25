//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// backupDeniedByOS runs the real binary against an output directory that the OS
// refuses to write into, asserting exitDenied (4).
//
// This is the POSIX shape, and it serves linux AND darwin (MAC,
// 24.09.2026): the refusal must be a directory the OS refuses a create
// in. The fallback that used to cover darwin seeded a read-only FILE
// instead — which stops an in-place rewrite on Windows, but not a backup
// that publishes through a temp file and a rename, and POSIX rename(2)
// answers to the DIRECTORY's permissions, not the replaced file's. On
// macOS the backup succeeded (code=0), gates_r2main_d8d71da.log:28.
//
// The definition lives in a file without a GOOS suffix, with the choice
// spelled out in the build tag: the same code in
// gate2_gateway_local_linux_test.go is dead on arrival for darwin,
// because a "_linux" in the file's NAME is itself a build constraint,
// one no //go:build line can override (MAC, 24.09.2026, round 2).
//
// When running as root in a container (os.Geteuid() == 0), chmod alone does not
// cause EACCES because root bypasses DAC write permission checks; root therefore
// drops to unprivileged uid 65534 (nobody) to observe the refusal.
//
// When running as a normal user (os.Geteuid() != 0), dropping uid is impossible
// (fork/exec returns EPERM). Instead, writing into an unwritable directory with
// mode 0500 created by the test produces EACCES directly as the current user.
func backupDeniedByOS(t *testing.T, srcDir string) (string, int) {
	t.Helper()
	root := t.TempDir()
	isRoot := os.Geteuid() == 0
	if isRoot {
		if err := os.Chmod(filepath.Dir(root), 0o755); err != nil {
			t.Fatalf("chmod test parent: %v", err)
		}
		if err := os.Chmod(root, 0o755); err != nil {
			t.Fatalf("chmod test root: %v", err)
		}
		if err := os.Chmod(srcDir, 0o755); err != nil {
			t.Fatalf("chmod source dir: %v", err)
		}
		if err := os.Chmod(filepath.Join(srcDir, state.StateFileName), 0o644); err != nil {
			t.Fatalf("chmod state file: %v", err)
		}
	}

	outDir := filepath.Join(root, "unwritable")
	mode := os.FileMode(0o500)
	if isRoot {
		mode = 0o555
	}
	if err := os.Mkdir(outDir, mode); err != nil {
		t.Fatalf("make unwritable output directory: %v", err)
	}
	if err := os.Chmod(outDir, mode); err != nil {
		t.Fatalf("chmod unwritable output directory: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(outDir, 0o700) })

	exe := filepath.Join(root, "iamtunnel")
	if err := testsupport.BuildIamtunnel(exe); err != nil {
		if errors.Is(err, testsupport.ErrNoCgo) {
			t.Skip("building iamtunnel binary requires cgo on Linux/macOS (no C toolchain or CGO_ENABLED=0)")
		}
		t.Fatalf("build unprivileged test binary: %v", err)
	}
	if err := os.Chmod(exe, 0o755); err != nil {
		t.Fatalf("chmod test binary: %v", err)
	}

	outPath := filepath.Join(outDir, "backup.tar.gz")
	cmd := exec.Command(exe, "gateway", "backup", "--data-dir", srcDir, "--out", outPath)
	cmd.Env = append(os.Environ(),
		"LOCALAPPDATA="+root,
		"ProgramData="+root,
		"HOME="+root,
		"XDG_DATA_HOME="+root,
		"IAMTUNNEL_DATA_DIR="+root,
	)
	if isRoot {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	}
	output, err := cmd.CombinedOutput()
	if err == nil {
		return string(output), exitOK
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		if errors.Is(err, syscall.EPERM) || strings.Contains(err.Error(), "operation not permitted") {
			t.Skip("needs root to drop to uid 65534")
		}
		t.Fatalf("run unprivileged backup: %v\n%s", err, output)
	}
	return string(output), exitErr.ExitCode()
}
