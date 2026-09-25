//go:build !windows

package testsupport_test

import (
	"os"
	"syscall"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// TestSSHTree_UmaskCanary verifies that NewSSHTree and WriteKeyFile produce
// exact modes 0700 for directories and 0600 for key files even under desktop
// umask 0002 (or restrictive umask 0077).
//
// CANARY: If NewSSHTree creates directories via os.Mkdir/t.TempDir without an
// explicit os.Chmod, under umask 0002 the directory mode is 0775.
// Expected red text:
//
//	home directory mode = 0775, want 0700
//	.ssh directory mode = 0775, want 0700
//
// Note: umask is process-wide, so this test MUST NOT call t.Parallel().
func TestSSHTree_UmaskCanary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		umask int
	}{
		{name: "desktop_umask_0002", umask: 0o002},
		{name: "restrictive_umask_0077", umask: 0o077},
	} {
		t.Run(tc.name, func(t *testing.T) {
			old := syscall.Umask(tc.umask)
			t.Cleanup(func() {
				syscall.Umask(old)
			})

			tree := testsupport.NewSSHTree(t)
			keyPath := tree.WriteKeyFile(t, "authorized_keys", []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICanaryKey test@example\n"))

			homeStat, err := os.Stat(tree.Home)
			if err != nil {
				t.Fatalf("stat home: %v", err)
			}
			if mode := homeStat.Mode().Perm(); mode != 0o700 {
				t.Errorf("home directory mode = %#04o, want 0700", mode)
			}

			sshStat, err := os.Stat(tree.SSHDir)
			if err != nil {
				t.Fatalf("stat .ssh: %v", err)
			}
			if mode := sshStat.Mode().Perm(); mode != 0o700 {
				t.Errorf(".ssh directory mode = %#04o, want 0700", mode)
			}

			keyStat, err := os.Stat(keyPath)
			if err != nil {
				t.Fatalf("stat key file: %v", err)
			}
			if mode := keyStat.Mode().Perm(); mode != 0o600 {
				t.Errorf("key file mode = %#04o, want 0600", mode)
			}
		})
	}
}
