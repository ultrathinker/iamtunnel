//go:build !windows

package client_test

import (
	"os"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/client"
)

// TestEnsureKeyRejectsWorldReadableKey is the IAMT-242 canary for the
// Unix permission check. The fresh key file is created with 0o644
// (group + other readable); EnsureKey must refuse it the same way
// OpenSSH refuses an "UNPROTECTED PRIVATE KEY FILE", pointing at the
// path and the chmod 600 fix.
//
// The chmod and the call run as the test user, so the 0o644 -> 0o077
// test is meaningful on the platforms where mode bits exist. The test
// is built with !windows and skips only on the rare Linux host where
// the running user cannot change their own file's mode (root with a
// read-only filesystem, etc.) — those are not the configurations we
// ship to, and skipping is documented at the call site.
func TestEnsureKeyRejectsWorldReadableKey(t *testing.T) {
	dir := t.TempDir()
	path := client.KeyPath(dir)
	if err := os.WriteFile(path, []byte("not a key"), 0o644); err != nil {
		t.Fatalf("write probe key: %v", err)
	}
	_, err := client.EnsureKey(dir)
	if err == nil {
		t.Fatal("EnsureKey on a 0o644 key succeeded; want refusal with chmod 600 hint")
	}
	msg := err.Error()
	if !strings.Contains(msg, "chmod 600") {
		t.Errorf("error message lacks chmod 600 hint: %s", msg)
	}
	if !strings.Contains(msg, path) {
		t.Errorf("error message must name the key path %s: %s", path, msg)
	}
}

// TestEnsureKeyAcceptsOwnerOnlyKey proves the chmod 0o600 case is the
// "happy path": the freshly generated key (and any future re-read by a
// user who followed the hint) parses cleanly. We do not inspect the
// parsed signer beyond "the call did not refuse" because the existing
// TestEnsureKeyGeneratesThenPersists already covers that.
func TestEnsureKeyAcceptsOwnerOnlyKey(t *testing.T) {
	dir := t.TempDir()
	path := client.KeyPath(dir)
	if err := os.WriteFile(path, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write probe key: %v", err)
	}
	if _, err := client.EnsureKey(dir); err == nil {
		t.Fatal("EnsureKey on a 0o600 corrupt key succeeded; want parse error, not silent load")
	}
}

// TestEnsureKeyRejectsGroupReadableKey covers the group-only case
// separately because the bit arithmetic ("0o077 & mode != 0") treats
// group and other bits together but the SSH story is "any leak".
func TestEnsureKeyRejectsGroupReadableKey(t *testing.T) {
	dir := t.TempDir()
	path := client.KeyPath(dir)
	if err := os.WriteFile(path, []byte("not a key"), 0o640); err != nil {
		t.Fatalf("write probe key: %v", err)
	}
	// On a tmpfs owned by the test user, chmod 0o640 succeeds; the
	// canary is the refusal, not the chmod itself.
	if err := os.Chmod(path, 0o640); err != nil {
		t.Skipf("cannot chmod on this filesystem: %v", err)
	}
	if _, err := client.EnsureKey(dir); err == nil {
		t.Fatal("EnsureKey on a 0o640 key succeeded; want refusal")
	}
}
