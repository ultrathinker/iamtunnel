//go:build windows

package main

// iamt332_round9_walk_test.go — the §5.7.3 half of IAMT-332 round nine:
// the ACL-hardening walk must not act on a child that is not what its
// name looks like. winkeys.LockDownFileACL goes through
// SetNamedSecurityInfo, which resolves the name — a planted symlink is
// followed — so the old walk handed the protected {SYSTEM,
// Administrators} DACL to whatever the plant aims at: a file the
// running account does not own, locked down by the very command that
// was supposed to heal this directory.
//
// The sentinel lives OUTSIDE the walked tree: the walk's job is to heal
// everything inside dir, so a sentinel left inside would be locked as
// its own legitimate regular-file child and the row could never tell
// "followed the plant" from "did its job".
//
// There is no hard-link row: a hard link is a regular file to every
// observer (DirEntry.Type() is 0), so no walk can tell it from our own
// children — the §5.7.3 contract is the symlink/reparse-point skip, and
// a hard link planted at a child name is the datafile readers'
// refuse-existing problem, not the walk's. There is no ModeIrregular
// row either: a junction (the reparse point Windows data dirs actually
// meet) has no os-level constructor, and nothing else in this tree
// produces a ModeIrregular entry on Windows.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

func TestIAMT332R9HardenServerDirChildrenSkipsPlantedChild(t *testing.T) {
	dir := t.TempDir()
	// A legitimate child first: it must still be healed, so the skip
	// cannot quietly pass for a broken walk.
	legit := filepath.Join(dir, "legit.dat")
	if err := os.WriteFile(legit, []byte("legit child"), 0o600); err != nil {
		t.Fatalf("write the legitimate child: %v", err)
	}
	// The plant, with its target outside the walked tree.
	outside := t.TempDir()
	sentinelPath := filepath.Join(outside, "sentinel.dat")
	testsupport.WriteSentinelFile(t, sentinelPath)
	linkAt := filepath.Join(dir, "planted.link")
	if err := os.Symlink(sentinelPath, linkAt); err != nil {
		t.Skipf("this host does not grant symlink creation, so the following the fix removes cannot be planted here (%v)", err)
	}

	if err := hardenServerDirChildren(dir, false); err != nil {
		if detectAccessDenied(err) {
			t.Skipf("the child-heal walk needs an elevated console on Windows: %v", err)
		}
		t.Fatalf("hardenServerDirChildren: %v", err)
	}

	prot, perr := winkeys.DACLProtected(legit)
	if perr != nil {
		t.Fatalf("DACLProtected on the legitimate child: %v", perr)
	}
	if !prot {
		t.Fatal("the legitimate child did not get the protected DACL — the walk stopped walking when it learned to skip plants")
	}

	targetProt, terr := winkeys.DACLProtected(sentinelPath)
	if terr != nil {
		t.Fatalf("DACLProtected on the plant's target: %v", terr)
	}
	if targetProt {
		t.Fatalf("the heal walk locked %s (the planted symlink's target) with the protected machine DACL — a child that is not what its name looks like must be skipped, not followed", sentinelPath)
	}

	// The decisive half, and the one the old tree goes red on: measured
	// on 1b92fad, SetNamedSecurityInfo on a file-symlink path lands the
	// DACL on the reparse point ITSELF (the target stays untouched — the
	// report's "through the plant" wording does not reproduce for file
	// symlinks on this host). Either way the walk acted on an entry that
	// is not one of this directory's objects; the plant must come out of
	// the walk with its security descriptor exactly as it was created.
	plantProt, lerr := winkeys.DACLProtected(linkAt)
	if lerr != nil {
		t.Fatalf("DACLProtected on the plant itself: %v", lerr)
	}
	if plantProt {
		t.Fatalf("the heal walk applied the protected machine DACL to the planted symlink at %s itself — a child that is not what its name looks like must be skipped, not locked", linkAt)
	}
}
