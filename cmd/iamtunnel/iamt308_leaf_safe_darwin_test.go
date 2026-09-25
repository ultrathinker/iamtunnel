//go:build darwin

// iamt308_leaf_safe_darwin_test.go — IAMT-308 round 11, review finding
// F-308-9: round 10's ancestor walk (darwinAncestorsAreSafeUpTo) starts
// at dataDir's PARENT and climbs upward — it never once looks at dataDir
// itself, and it never asked the kernel about macOS ACLs at all, only
// POSIX owner/mode bits. Either gap on its own lets a party who cannot
// touch a single ancestor's owner or mode bits still swap what install
// writes into: an ACL grant on an otherwise perfectly root-owned,
// non-writable ancestor (the review's own /opt example), or a symlink planted
// at the leaf itself, before install ever ran.
//
// Canaries:
//  1. check only the ancestor's owner/mode bits, not ACLs — turns red
//     TestIAMT308_CustomDataDirAncestorsAreSafe_ACLGrantRefused (the review's
//     own /opt scenario: root:wheel, 0755, but an ACL hands "nobody"
//     delete_child/add_file);
//  2. skip dataDir itself, checking only its ancestors — turns red
//     TestIAMT308_CustomDataDirLeafIsSafe_SymlinkedLeafRefused;
//  3. require an EXCLUSIVELY root owner for the leaf too (allowing no
//     exception for the repeat install's account) — turns red
//     TestIAMT308_CustomDataDirLeafIsSafe_OwnedByServiceAccountAccepted;
//  4. not create the missing leaf right here, leaving it to a later
//     os.MkdirAll — turns red
//     TestIAMT308_CustomDataDirLeafIsSafe_MissingLeafIsCreatedAsRoot.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestIAMT308_CustomDataDirAncestorsAreSafe_ACLGrantRefused is the review's
// own example: an ancestor that is root:wheel, 0755 (no group/other
// write bit at all) passes every POSIX check round 10 already ran, yet
// an ACL entry can still hand a concrete non-root identity the right to
// delete or replace what root just verified. Requires root (chmod +a
// against an arbitrary directory needs privilege on most setups, and
// constructing a root-owned parent needs it too); skips if the
// filesystem under t.TempDir() does not support ACLs at all rather than
// failing for an unrelated reason.
func TestIAMT308_CustomDataDirAncestorsAreSafe_ACLGrantRefused(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("IAMT-308: constructing a root-owned parent and granting it an ACL both need root — this test only runs meaningfully as root")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "opt")
	dataDir := filepath.Join(parent, "gw")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(parent, 0, 0); err != nil {
		t.Skipf("could not chown %s to root:root on this box: %v", parent, err)
	}

	out, err := exec.Command(darwinLsPath, "-lde", parent).CombinedOutput()
	if err != nil {
		t.Fatalf("ls -lde %s: %v: %s", parent, err, out)
	}
	if err := exec.Command("/bin/chmod", "+a", "user:nobody allow delete_child,add_file", parent).Run(); err != nil {
		t.Skipf("this filesystem does not appear to support ACLs (chmod +a failed): %v", err)
	}

	err = darwinAncestorsAreSafeUpTo(filepath.Dir(dataDir), string(filepath.Separator))
	if err == nil {
		t.Fatal("darwinAncestorsAreSafeUpTo must refuse a root-owned, 0755 ancestor that carries an ACL granting a non-root identity delete_child/add_file (IAMT-308 F-308-9) — owner and mode bits alone are not enough")
	}
}

// TestIAMT308_CustomDataDirLeafIsSafe_SymlinkedLeafRefused needs no
// root: dataDir ITSELF, not one of its ancestors, is a symlink — round
// 10's walk (which only ever looks at filepath.Dir(dataDir) and above)
// would never have noticed this.
func TestIAMT308_CustomDataDirLeafIsSafe_SymlinkedLeafRefused(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Join(root, "gw")
	if err := os.Symlink(real, dataDir); err != nil {
		t.Fatal(err)
	}

	err := darwinEnsureCustomDataDirLeafIsSafe(dataDir, os.Geteuid())
	if err == nil {
		t.Fatal("darwinEnsureCustomDataDirLeafIsSafe must refuse when dataDir itself is a symlink, regardless of what it points to (IAMT-308 F-308-9)")
	}
}

// TestIAMT308_CustomDataDirLeafIsSafe_OwnedByServiceAccountAccepted
// proves the one exception the leaf check must make that the ancestor
// walk must not: a REPEAT install's own dataDir was already chowned to
// the gateway's service account by a previous run's setupLaunchdDaemon,
// not root — that must still be accepted, or every second "gateway
// install" against the same custom --data-dir would refuse itself.
// Requires root (chowning to an arbitrary uid needs it).
func TestIAMT308_CustomDataDirLeafIsSafe_OwnedByServiceAccountAccepted(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("IAMT-308: chowning dataDir to an arbitrary uid needs root — this test only runs meaningfully as root")
	}
	root := t.TempDir()
	dataDir := filepath.Join(root, "gw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const serviceUID = 65533 // an arbitrary uid distinct from root, standing in for _iamtunnel's real uid
	if err := os.Chown(dataDir, serviceUID, serviceUID); err != nil {
		t.Skipf("could not chown %s to uid %d on this box: %v", dataDir, serviceUID, err)
	}

	if err := darwinEnsureCustomDataDirLeafIsSafe(dataDir, serviceUID); err != nil {
		t.Fatalf("darwinEnsureCustomDataDirLeafIsSafe must accept a dataDir already owned by the resolved service account (a repeat install), got: %v", err)
	}
}

// TestIAMT308_CustomDataDirLeafIsSafe_MissingLeafIsCreatedAsRoot needs
// no root: a fresh install's dataDir does not exist yet at the time this
// check runs (it runs before runGatewayInstall's own os.MkdirAll) — this
// must create it right here rather than leaving a gap for anything else
// to put something else there first.
func TestIAMT308_CustomDataDirLeafIsSafe_MissingLeafIsCreatedAsRoot(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "gw")

	if err := darwinEnsureCustomDataDirLeafIsSafe(dataDir, os.Geteuid()); err != nil {
		t.Fatalf("darwinEnsureCustomDataDirLeafIsSafe must create a missing dataDir itself: %v", err)
	}
	fi, err := os.Lstat(dataDir)
	if err != nil {
		t.Fatalf("dataDir must exist after darwinEnsureCustomDataDirLeafIsSafe returned nil: %v", err)
	}
	if !fi.IsDir() {
		t.Fatalf("dataDir must be a directory, got mode %v", fi.Mode())
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dataDir must be created 0700, got %#o", fi.Mode().Perm())
	}
}
