//go:build darwin

// iamt308_ancestors_safe_darwin_test.go — IAMT-308 round 10, review
// finding F-308-8: round 9's re-check (verifyGatewayReachable,
// immediately before the first secret write) only ever shrank the
// window between checking a custom --data-dir's reachability and using
// the path again — a successful "test -x" and the next path-based
// syscall are still two different actions, so whoever controls one of
// its ancestors could still rename or replace a component (or swap it
// for a symlink) in between, and root's writes of the host key, the
// bootstrap token and state.json would resolve into wherever that party
// pointed.
//
// darwinCustomDataDirAncestorsAreSafe removes the THREAT the window
// exists for, rather than shrinking the window further: every ancestor
// of a custom --data-dir, all the way to the filesystem root, must be
// exclusively controlled by root (owned by root, not writable by group
// or other, not a symlink) before install ever proceeds. A party who
// owns none of them cannot swap, rename or symlink one out from under
// install no matter how long any later window is.
//
// Canaries:
//  1. check only filepath.Dir(dataDir) (round 6/7's old mistake,
//     reintroduced here) — turns red
//     TestIAMT308_CustomDataDirAncestorsAreSafe_GrandparentControlledByThirdPartyRefused
//     (an otherwise perfectly root-owned PARENT would hide a bad
//     grandparent);
//  2. stop as soon as one ancestor "looks" safe instead of checking
//     EVERY one — the same check turns red for the same reason;
//  3. do not refuse on a non-root owner or on a group/other entry —
//     turns red
//     TestIAMT308_CustomDataDirAncestorsAreSafe_NonRootParentRefused;
//  4. do not refuse on a symbolic link — turns red
//     TestIAMT308_CustomDataDirAncestorsAreSafe_SymlinkedParentRefused.

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIAMT308_CustomDataDirAncestorsAreSafe_NonRootParentRefused needs
// no root: t.TempDir() is owned by whatever user is running the test,
// and — off root — that is never uid 0, so the immediate parent alone
// already fails the check without needing to look any further up.
func TestIAMT308_CustomDataDirAncestorsAreSafe_NonRootParentRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("IAMT-308: this test needs the parent to NOT be root-owned, which only holds when the test itself is not running as root")
	}
	root := t.TempDir()
	dataDir := filepath.Join(root, "gw")

	err := darwinAncestorsAreSafeUpTo(filepath.Dir(dataDir), string(filepath.Separator))
	if err == nil {
		t.Fatal("darwinAncestorsAreSafeUpTo must refuse when the immediate parent is not owned by root")
	}
}

// TestIAMT308_CustomDataDirAncestorsAreSafe_SymlinkedParentRefused needs
// no root: creating a symlink needs no special privilege, and a
// symlinked ancestor is refused independent of its target's ownership.
func TestIAMT308_CustomDataDirAncestorsAreSafe_SymlinkedParentRefused(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(link, "gw")

	err := darwinAncestorsAreSafeUpTo(filepath.Dir(dataDir), string(filepath.Separator))
	if err == nil {
		t.Fatal("darwinAncestorsAreSafeUpTo must refuse a symlinked ancestor regardless of what it points to")
	}
}

// TestIAMT308_CustomDataDirAncestorsAreSafe_GrandparentControlledByThirdPartyRefused
// is F-308-8's central canary, matching the review's own example exactly: the
// PARENT looks perfectly safe (root-owned, 0700) — round 6/7's mistake
// would have stopped there and accepted — but the GRANDPARENT is owned
// by someone else, who could rename the parent out from under install.
// Requires root to construct (only root can chown to an arbitrary uid).
func TestIAMT308_CustomDataDirAncestorsAreSafe_GrandparentControlledByThirdPartyRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("IAMT-308: constructing a root-owned parent under a THIRD-PARTY-owned grandparent needs root (chown to an arbitrary uid is a privileged operation) — this test only runs meaningfully as root")
	}
	root := t.TempDir()
	grandparent := filepath.Join(root, "gp")
	parent := filepath.Join(grandparent, "parent")
	dataDir := filepath.Join(parent, "gw")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	// Simulate a grandparent a THIRD PARTY controls: not root, and not
	// this test's own uid either — a nobody-ish uid picked well above
	// any real account range is enough; the exact identity does not
	// matter, only that it is not 0.
	if err := os.Chown(grandparent, 65534, 65534); err != nil {
		t.Skipf("could not chown %s to a non-root uid on this box: %v", grandparent, err)
	}

	err := darwinAncestorsAreSafeUpTo(filepath.Dir(dataDir), string(filepath.Separator))
	if err == nil {
		t.Fatal("darwinAncestorsAreSafeUpTo must refuse when the GRANDparent is not root-owned, even though the immediate parent looks perfectly safe on its own (IAMT-308 F-308-8)")
	}
}

// TestIAMT308_CustomDataDirAncestorsAreSafe_FullyTrustedChainSucceeds
// proves the accept path, bounded to a tree this test builds and owns
// itself (darwinAncestorsAreSafeUpTo's stopAt parameter) rather than
// depending on whatever the real system directories above t.TempDir()
// happen to be on this particular Mac. Requires root: only root can make
// something genuinely root-owned.
func TestIAMT308_CustomDataDirAncestorsAreSafe_FullyTrustedChainSucceeds(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("IAMT-308: a genuinely root-owned chain needs root to construct — this test only runs meaningfully as root")
	}
	root := t.TempDir()
	grandparent := filepath.Join(root, "gp")
	parent := filepath.Join(grandparent, "parent")
	dataDir := filepath.Join(parent, "gw")
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(grandparent, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := darwinAncestorsAreSafeUpTo(filepath.Dir(dataDir), grandparent); err != nil {
		t.Fatalf("darwinAncestorsAreSafeUpTo must accept a fully root-owned, non-writable, non-symlinked chain: %v", err)
	}
}

// TestIAMT308_CustomDataDirAncestorsAreSafe_GroupWritableParentRefused
// proves the mode half of the check independent of ownership: a
// root-owned but group-writable parent is exactly what a shared-admin
// directory (like macOS's own /Library/Application Support, 0775
// root:admin) looks like — legitimate for Apple's own system tree, but
// exactly the shape that would let a non-root member of that group swap
// something. Requires root: only root can create something root-owned
// with a deliberately loose mode to test this in isolation.
func TestIAMT308_CustomDataDirAncestorsAreSafe_GroupWritableParentRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("IAMT-308: a root-owned-but-group-writable parent needs root to construct — this test only runs meaningfully as root")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "parent")
	dataDir := filepath.Join(parent, "gw")
	if err := os.MkdirAll(parent, 0o775); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o775); err != nil {
		t.Fatal(err)
	}

	err := darwinAncestorsAreSafeUpTo(filepath.Dir(dataDir), string(filepath.Separator))
	if err == nil {
		t.Fatal("darwinAncestorsAreSafeUpTo must refuse a root-owned parent that is still group-writable (0775) — root ownership alone is not enough")
	}
}
