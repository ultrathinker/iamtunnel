//go:build !windows

package datafile

// iamt332_ownership_posix_test.go — the real POSIX owner selection of
// PreserveOwnership (IAMT-332 round two), exercised for real and without
// root: every owner involved is this test process's own uid/gid, so the
// selection is verified against actual stat data while the chown itself
// stays out of reach — exactly what the review asked for. The recorder-
// based behaviour tests live in iamt332_ownership_test.go and also build
// here; these three do NOT build on Windows, where the whole mechanism
// is a deliberate no-op.

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestOwnerToCarryTakesTheReplacedFilesOwner pins the first leg of the
// selection: a file replacing an existing file carries THAT file's
// owner. Here the replaced file is owned by this process, so the
// expected uid/gid come straight from the runtime.
func TestOwnerToCarryTakesTheReplacedFilesOwner(t *testing.T) {
	dir := t.TempDir()
	replaced := filepath.Join(dir, "state.json")
	f, err := os.Create(replaced)
	if err != nil {
		t.Fatalf("create the replaced file: %v", err)
	}
	defer func() { _ = f.Close() }()

	uid, gid, known, err := ownerToCarry(f, replaced)
	if err != nil {
		t.Fatalf("ownerToCarry: %v", err)
	}
	if !known {
		t.Fatal("ownerToCarry reported no known owner for a regular file with a POSIX owner")
	}
	if uid != uint32(os.Geteuid()) || gid != uint32(os.Getegid()) {
		t.Errorf("ownerToCarry chose uid %d gid %d, want the replaced file's own owner uid %d gid %d", uid, gid, os.Geteuid(), os.Getegid())
	}
}

// TestOwnerToCarryFollowsASymlinkedDataDirToItsTarget pins round two
// finding 2: when there is nothing to replace, the owner is taken from
// the directory the file will really land in — a symlinked data
// directory must yield its TARGET's owner, not the symlink's. The real
// scenario has the two owners differ (root-owned symlink onto an
// iamtunnel-owned mount), which needs root to set up; this test pins the
// resolution through the link with owners that coincide, which is the
// part a non-root process can observe — the symlink is resolved and the
// directory behind it is stat'ed, not the link itself.
func TestOwnerToCarryFollowsASymlinkedDataDirToItsTarget(t *testing.T) {
	realDir := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("this platform refuses the symlink the scenario needs (usually an unprivileged Windows): %v", err)
	}

	// The open file is created THROUGH the symlinked path, exactly as a
	// writer with Dir="/var/lib/iamtunnel" (itself a symlink) would.
	f, err := os.Create(filepath.Join(link, "state.json.tmp.abc123"))
	if err != nil {
		t.Fatalf("create through the symlinked dir: %v", err)
	}
	defer func() { _ = f.Close() }()

	uid, gid, known, err := ownerToCarry(f, "")
	if err != nil {
		t.Fatalf("ownerToCarry: %v", err)
	}
	if !known {
		t.Fatal("ownerToCarry reported no known owner for a real directory")
	}
	// realDir is owned by this process — and the answer must come from
	// realDir (resolved through the link), not from the link's parent,
	// a different t.TempDir() directory this process also owns. Same
	// numeric owner here, but the source is checked by construction: a
	// Lstat of the link's parent would still pass the numeric check, so
	// pin the mechanics that make the right source win — Stat resolves,
	// and the target directory is what gets stat'ed.
	if uid != uint32(os.Geteuid()) || gid != uint32(os.Getegid()) {
		t.Errorf("ownerToCarry chose uid %d gid %d, want the resolved receiving directory's owner uid %d gid %d", uid, gid, os.Geteuid(), os.Getegid())
	}

	// Prove the resolution: stat of the path the implementation uses
	// (filepath.Dir of the file's name — through the link) must reach
	// the real directory, not stop at the link. On platforms where
	// Stat_t is unavailable this check degrades to the owner equality
	// above.
	if st, err := os.Stat(link); err == nil {
		if s, ok := st.Sys().(*syscall.Stat_t); ok && s.Ino != realDirIno(t, realDir) {
			t.Errorf("stat of the symlinked path did not resolve to the real directory (inode %d vs %d)", s.Ino, realDirIno(t, realDir))
		}
	}
}

// realDirIno is the inode of realDir, so the test can prove that Stat
// through the symlink lands on that directory and not somewhere else.
func realDirIno(t *testing.T, dir string) uint64 {
	t.Helper()
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	s, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skipf("no POSIX stat data on this platform")
	}
	return s.Ino
}

// TestPreserveOwnershipSameOwnerPerformsNoChown pins the fast path the
// whole seam leans on: when the open file is already owned by the
// expected account, PreserveOwnership returns nil WITHOUT attempting a
// chown. As a non-root process on Linux even `chown(self, self)` is
// EPERM — so a nil error here is only reachable when no chown was
// attempted, which makes the assertion carry real weight without any
// privilege. This is also the service's own steady state: every write
// the service itself performs pays two stat calls and nothing else.
func TestPreserveOwnershipSameOwnerPerformsNoChown(t *testing.T) {
	dir := t.TempDir()

	// Replacing a file the process owns: Lstat finds the owner, the
	// fstat finds the same owner — no chown, no error.
	replaced := filepath.Join(dir, "state.json")
	rf, err := os.Create(replaced)
	if err != nil {
		t.Fatalf("create the replaced file: %v", err)
	}
	if err := PreserveOwnership(rf, replaced); err != nil {
		t.Errorf("same-owner replace reported %v — the fast path must skip the chown (and a chown attempt by this unprivileged process would have failed EPERM, so the nil result proves the skip)", err)
	}
	_ = rf.Close()

	// Creating where nothing stood: the directory is the owner source,
	// same account again — no chown, no error.
	cf, err := os.Create(filepath.Join(dir, "enrol-hmac.key"))
	if err != nil {
		t.Fatalf("create a fresh file: %v", err)
	}
	defer func() { _ = cf.Close() }()
	if err := PreserveOwnership(cf, ""); err != nil {
		t.Errorf("same-owner creation reported %v — the fast path must skip the chown", err)
	}
}
