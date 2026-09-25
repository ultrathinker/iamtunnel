package main

// iamt332_ownership_test.go — IAMT-332: the CLI's own atomic writers put
// files into the gateway data dir that the unprivileged service account
// must go on reading — the bootstrap token ("gateway install
// --rebootstrap", "gateway install") and the gateway host key ("gateway
// pair", "gateway run" on a dir that has none yet). Run under sudo on the
// real Linux gateway, their renames used to carry the running account's
// ownership onto those files. Both primitives must therefore ask for the
// replacement's ownership to be adopted — on the open descriptor, from a
// temporary whose name nothing could have pre-planted (round two). The
// real step is a POSIX chown — nothing a test may do for real — so the
// adoption tests record the request through the adoptOwnership seam (no
// root, no real ownership changes, on any platform). The planted-symlink
// test runs the real path instead: observing a followed link needs no
// chown.

import (
	"os"
	"path/filepath"
	"testing"
)

func withAdoptionRecorder(t *testing.T) func() []string {
	t.Helper()
	orig := adoptOwnership
	var requested []string
	adoptOwnership = func(f *os.File, replacedPath string) error {
		requested = append(requested, replacedPath)
		return nil
	}
	t.Cleanup(func() { adoptOwnership = orig })
	return func() []string { return requested }
}

func TestAtomicWriteBytesAdoptsTheReplacedFileOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-token")

	requested := withAdoptionRecorder(t)

	if err := atomicWriteBytes(path, []byte("token")); err != nil {
		t.Fatalf("atomicWriteBytes: %v", err)
	}

	got := requested()
	if len(got) != 1 || got[0] != path {
		t.Errorf("atomicWriteBytes asked to adopt the ownership of %v, want exactly one request for %q — a root-run \"gateway install --rebootstrap\" would otherwise leave the token file owned by root (IAMT-332)", got, path)
	}
}

func TestGenerateSignerAdoptsTheReplacedFileOwnership(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hostkey")

	requested := withAdoptionRecorder(t)

	if _, err := generateSigner(path); err != nil {
		t.Fatalf("generateSigner: %v", err)
	}

	got := requested()
	if len(got) != 1 || got[0] != path {
		t.Errorf("generateSigner asked to adopt the ownership of %v, want exactly one request for %q — a root-run \"gateway pair\" on a dir without a host key would otherwise leave the fresh key owned by root and the service unable to load it (IAMT-332)", got, path)
	}
}

// Round two, finding 1: a symlink planted at the old predictable
// temporary name (path+".tmp") must not be followed — the pre-round-two
// writer opened that name with O_CREATE|O_TRUNC, straight through the
// link, so the directory's owner could aim the write at any file on the
// system. The temporary must be a random O_EXCL creation instead.
func TestAtomicWriteBytesDoesNotFollowASymlinkPlantedAtTheOldTempName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bootstrap-token")

	target := filepath.Join(t.TempDir(), "victim")
	const canary = "the file a planted symlink points at"
	if err := os.WriteFile(target, []byte(canary), 0o600); err != nil {
		t.Fatalf("write the symlink target: %v", err)
	}
	planted := path + ".tmp"
	if err := os.Symlink(target, planted); err != nil {
		t.Skipf("this platform refuses the symlink the scenario needs (usually an unprivileged Windows): %v", err)
	}

	if err := atomicWriteBytes(path, []byte("token")); err != nil {
		t.Fatalf("atomicWriteBytes: %v", err)
	}

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("re-read the symlink target: %v", err)
	}
	if string(got) != canary {
		t.Errorf("the planted symlink at %q was followed: its target now holds %q — a hostile directory owner must not be able to aim the write at an arbitrary file; the temporary must be a random O_EXCL creation (IAMT-332 round 2)", planted, got)
	}
}
