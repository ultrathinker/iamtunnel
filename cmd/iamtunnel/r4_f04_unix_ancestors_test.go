//go:build !windows

package main

// R4 F-04, the Unix side (REVIEW-R4, "the adjacent Linux/macOS matter"): the
// machine commands run elevated (SPEC §3.2.1 demands root for every one
// of them), and the record they act on resolves through $XDG_DATA_HOME /
// $HOME. An elevation that keeps the invoking user's HOME — sudo -E,
// older sudo configurations, osascript "with administrator privileges" —
// has root read a chain that non-root account owns outright, and that
// account needs no elevation to plant an enrolment.json there: their
// gateway, their fingerprint, any local account as the door's osUser.
// The elevated start then dials for it and writes its key into that
// account's authorized_keys.
//
// The fix under test: hardenServerDir (called by enrol and server start)
// refuses, for a root process, a data directory whose ancestor chain is
// not root's — anyone who can rename an ancestor can move the whole
// chain below away and put their own in its place. Plain `sudo` (root's
// HOME) and the service install's /var/lib/iamtunnel-machine pass; the
// per-user catalogue a non-root process reads stays untouched (there is
// no privilege transition to guard).
//
// Canary: drop the Geteuid()==0 gate or the serverDirAncestorCheck call
// from hardenServerDir's Unix branch, and TestF04Unix_RootHardenRefuses*
// go red under a root process; drop the gate alone and
// TestF04Unix_NonRootHardenIgnoresAncestors goes red everywhere.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func f04UID(t *testing.T) int {
	t.Helper()
	return os.Geteuid()
}

// TestF04Unix_AncestorCheckRefusesWritableAncestor pins the mode half of
// the rule with the one directory the test controls outright: a
// group-writable ancestor is refused no matter whose it is — /tmp itself
// (mode 1777) is the shape this refuses on every root-run fixture.
func TestF04Unix_AncestorCheckRefusesWritableAncestor(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o077); err != nil {
		t.Fatalf("chmod the fixture: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) }) //nolint:errcheck — restoring the fixture's own mode

	err := refuseServerDirForeignAncestors(filepath.Join(dir, "server"))
	if err == nil {
		t.Fatalf("a chain with a group/world-writable ancestor must be refused for the elevated reader")
	}
	if !strings.Contains(err.Error(), "writable") {
		t.Fatalf("the refusal must name the writable ancestor, got %v", err)
	}
}

// TestF04Unix_AncestorCheckRefusesForeignOwner pins the ownership half:
// an ancestor owned by someone other than root is refused — that account
// can rename it whatever its mode says, and the rename moves everything
// below it.
func TestF04Unix_AncestorCheckRefusesForeignOwner(t *testing.T) {
	dir := t.TempDir()
	err := refuseServerDirForeignAncestors(filepath.Join(dir, "server"))
	if f04UID(t) == 0 {
		// Under root the whole TempDir chain is root's and /tmp's mode is
		// the only thing that can be wrong here — this refusal shape is
		// covered by the writable test above; the ownership rule under
		// root is pinned by TestF04Unix_RootHardenAcceptsRootOwnedChain.
		if err != nil && !strings.Contains(err.Error(), "writable") {
			t.Fatalf("under root the TempDir chain must be refused only on /tmp's mode, got %v", err)
		}
		return
	}
	if err == nil {
		t.Fatalf("an ancestor owned by uid %d must be refused for the elevated reader", f04UID(t))
	}
	if !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("the refusal must name the foreign owner, got %v", err)
	}
}

// TestF04Unix_MoverPredicateJudgesEachFolder pins the per-folder rule the
// chain walk applies: root's own, mode-0700 folder passes (the shape of
// plain `sudo` and of /var/lib/iamtunnel-machine — a root process sees
// its TempDir exactly so), while the same folder under its non-root
// owner is a mover, and a writable folder is a mover whoever owns it.
// The walk-to-root itself cannot be shown accepting a fixture anywhere:
// every test chain ends in /tmp, which is world-writable by design and
// IS refused — that refusal is the chain-level tests above.
func TestF04Unix_MoverPredicateJudgesEachFolder(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat the fixture: %v", err)
	}
	if f04UID(t) == 0 {
		if mover := serverDirMover(dir, info); mover != "" {
			t.Fatalf("root's own mode-0700 folder must not be a mover, got %q", mover)
		}
	} else {
		mover := serverDirMover(dir, info)
		if mover == "" || !strings.Contains(mover, "owned by uid") {
			t.Fatalf("a non-root account's own folder must be named a mover for the root gate, got %q", mover)
		}
	}
}

// TestF04Unix_NonRootHardenIgnoresAncestors pins the gate that keeps the
// per-user design alive: an unelevated process reading its OWN catalogue
// is the per-user shape (SPEC §3.2.2), not a privilege transition — the
// ancestor check must not run for it, even though the chain above the
// fixture belongs to exactly the account whose ancestors the check
// refuses.
func TestF04Unix_NonRootHardenIgnoresAncestors(t *testing.T) {
	if f04UID(t) == 0 {
		t.Skip("the unelevated pass-through is only observable from a non-root process")
	}
	dir := t.TempDir()
	if err := hardenServerDir(filepath.Join(dir, "server"), false); err != nil {
		t.Fatalf("hardenServerDir unelevated must not run the ancestor check: %v", err)
	}
}

// TestF04Unix_RootHardenRefusesTempAncestors is the red test on the
// finding's own line ("there are no owner checks on the directory or
// its ancestors for the machine role on the Unixes"): under a root process,
// hardenServerDir on a fixture whose ancestors include a non-root-
// closable folder must refuse, and with the environment seam set aside
// must succeed — the refusal is the boundary, not the fixture.
func TestF04Unix_RootHardenRefusesTempAncestors(t *testing.T) {
	if f04UID(t) != 0 {
		t.Skip("the ancestor gate runs only for a root process (sudo -E / osascript is its scenario)")
	}
	dir := t.TempDir()
	err := hardenServerDir(filepath.Join(dir, "server"), false)
	if err == nil {
		t.Fatalf("root harden on a chain with a world-writable ancestor (/tmp) must refuse — the elevated reader acts on whatever that chain can be made to hold")
	}
	if !strings.Contains(err.Error(), "moved by") {
		t.Fatalf("the refusal must name who can move the chain, got %v", err)
	}

	// The same directory with the environment's own /tmp out of the way:
	// the check must be the only thing standing between root and the
	// fixture — a refused fixture with the check off proves the refusal
	// came from the check and not from something else in the harden.
	saved := serverDirAncestorCheck
	serverDirAncestorCheck = func(string) error { return nil }
	t.Cleanup(func() { serverDirAncestorCheck = saved })
	if err := hardenServerDir(filepath.Join(dir, "server"), false); err != nil {
		t.Fatalf("hardenServerDir with the ancestor seam aside must succeed: %v", err)
	}
}

// TestF04Unix_RootHardenAcceptsRootOwnedChain pins the supported root
// invocation: a root process hardening the root-owned, mode-0700 chain
// it just made — the /var/lib/iamtunnel-machine shape — is hardened to
// 0700 once the environment's own world-writable /tmp is out of the way
// (the seam; the refusal it stands in for is the boundary, not this
// fixture).
func TestF04Unix_RootHardenAcceptsRootOwnedChain(t *testing.T) {
	if f04UID(t) != 0 {
		t.Skip("the ancestor gate runs only for a root process")
	}
	dir := t.TempDir()
	saved := serverDirAncestorCheck
	serverDirAncestorCheck = func(string) error { return nil }
	t.Cleanup(func() { serverDirAncestorCheck = saved })
	target := filepath.Join(dir, "var", "lib", "iamtunnel-machine")
	if err := hardenServerDir(target, false); err != nil {
		t.Fatalf("root harden of a root-owned chain must pass: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat the hardened directory: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("hardened mode = %o, want 700", info.Mode().Perm())
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		t.Fatalf("hardened directory owner uid = %d, want 0", st.Uid)
	}
}
