package testsupport

import (
	"os"
	"path/filepath"
	"testing"
)

// SSHTree represents a fake ~/.ssh directory tree created for tests.
// On Unix, Home and SSHDir are explicitly chmod'd to 0700 so that
// process umask (such as desktop 0002) can never leave group/world
// write bits set.
type SSHTree struct {
	Home     string
	SSHDir   string
	AuthKeys string
}

// NewFakeHome creates a fake home directory under t.TempDir() with mode 0700,
// explicitly chmod'd so umask cannot alter it.
func NewFakeHome(t testing.TB) string {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatalf("NewFakeHome: mkdir: %v", err)
	}
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("NewFakeHome: chmod: %v", err)
	}
	return home
}

// NewSSHTree creates a fake home and .ssh directory under t.TempDir().
// Both directories are created and explicitly chmod'd to 0700 so that
// no umask can widen or narrow their mode. The path to authorized_keys
// inside .ssh is returned as AuthKeys.
func NewSSHTree(t testing.TB) SSHTree {
	t.Helper()
	home := NewFakeHome(t)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("NewSSHTree: mkdir .ssh: %v", err)
	}
	if err := os.Chmod(sshDir, 0o700); err != nil {
		t.Fatalf("NewSSHTree: chmod .ssh: %v", err)
	}
	authKeys := filepath.Join(sshDir, "authorized_keys")
	return SSHTree{
		Home:     home,
		SSHDir:   sshDir,
		AuthKeys: authKeys,
	}
}

// FakeHomeSSH creates a fake home and .ssh directory under t.TempDir()
// with explicit mode 0700. It returns the home path, .ssh directory path,
// and authorized_keys path.
func FakeHomeSSH(t testing.TB) (home, sshDir, authKeys string) {
	t.Helper()
	tree := NewSSHTree(t)
	return tree.Home, tree.SSHDir, tree.AuthKeys
}

// KeyPath returns the full path to a named key file inside SSHDir.
func (s SSHTree) KeyPath(name string) string {
	return filepath.Join(s.SSHDir, name)
}

// WriteKeyFile writes data to a named key file inside SSHDir and explicitly
// chmods it to 0600 so that umask cannot alter the file mode.
func (s SSHTree) WriteKeyFile(t testing.TB, name string, data []byte) string {
	t.Helper()
	p := s.KeyPath(name)
	WriteKeyFile(t, p, data)
	return p
}

// WriteAuthKeys writes data to AuthKeys (authorized_keys) and explicitly
// chmods it to 0600.
func (s SSHTree) WriteAuthKeys(t testing.TB, data []byte) string {
	t.Helper()
	return s.WriteKeyFile(t, "authorized_keys", data)
}

// WriteKeyFile writes data to path and explicitly chmods it to 0600,
// ensuring umask does not affect the file mode.
func WriteKeyFile(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write key file %s: %v", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod key file %s: %v", path, err)
	}
}
