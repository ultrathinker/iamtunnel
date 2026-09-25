//go:build darwin

// iamt308_probe_account_darwin_test.go — IAMT-308 round 7, review finding
// F-308-3: parentTraversableByAccount used to check only
// filepath.Dir(dataDir)'s own permission bits against uid/gid from THIS
// (root) process — a non-traversable GRANDparent (or any higher
// ancestor) was invisible, only one gid was ever considered, and POSIX
// ACLs were never consulted at all. probeAccountCanReach replaces that
// with a real "test -x path" subprocess, so the KERNEL performs the
// walk — every ancestor component, ACLs, symlinks — exactly as it will
// for the real LaunchDaemon.
//
// Round 8 (a real, unprivileged Mac test run found this): applying a
// Credential to a child process at all is privileged on Darwin — Go
// always issues setgroups() as part of it, and setgroups() needs root
// regardless of the target list, even a no-op one. probeAccountCanReach
// therefore only sets a Credential when uid/gid actually differ from
// the CALLING process's own — most of the tests below pass their own
// uid/gid (Credential skipped entirely, no privilege needed at all) and
// so exercise the exact same kernel-enforced WALK without ever touching
// the privileged path; TestIAMT308_ProbeAccountCanReach_RealImpersonation
// is the one test that genuinely impersonates a different account and
// is gated on root (self-explaining skip otherwise, gate 10); TestIAMT308_
// ProbeAccountCanReach_ImpersonationWithoutPrivilegeIsReportedAsCouldNotRun
// covers the opposite: impersonation attempted WITHOUT root, proving
// that failure is reported as "could not check", never as "fine" or
// "not reachable".
//
// The permission-stripping tests skip cleanly under root, the same
// convention iamt259_chown_darwin_test.go already uses: root bypasses
// the DAC checks they strip, so there would be nothing to observe.
//
// Canaries:
//  1. take the check back to filepath.Dir(dataDir) alone (a comparison
//     of bits instead of a real probe) — turns red
//     TestIAMT308_ProbeAccountCanReach_GrandparentBlocksEvenWhenImmediateParentIsFine;
//  2. swap "test -x" for "stat" (checking only that the parent is
//     reachable, not entering it) — turns red
//     TestIAMT308_ProbeAccountCanReach_TargetItselfNotSearchableFails;
//  3. not test symbolic links explicitly — these turn red:
//     TestIAMT308_ProbeAccountCanReach_SymlinkToAccessibleTargetSucceeds
//     and .../SymlinkToInaccessibleTargetFails;
//  4. always set a Credential (even when uid/gid match the current
//     process) — every check below turns red under an ordinary user
//     (EPERM instead of a meaningful result) — exactly how round 7
//     broke on a live Mac;
//  5. treat "could not run the probe" as "reachable" or as "not
//     reachable" — turns red
//     TestIAMT308_ProbeAccountCanReach_ImpersonationWithoutPrivilegeIsReportedAsCouldNotRun.
//
// Round 9, review finding F-308-5 (CRITICAL): install runs as root, and
// both accountGroupIDs ("id -G") and probeAccountCanReach ("test -x")
// used to resolve their helper through PATH — a planted "id" or "test"
// earlier in PATH is arbitrary code execution as root, and a planted
// "test" could separately forge a successful reachability check. Fixed
// by removing the "id" subprocess entirely (accountGroupIDs now uses
// os/user) and pinning probeAccountCanReach to the absolute
// darwinTestPath. Canary: take either helper back to resolving through
// PATH — TestIAMT308_ProbeAccountCanReach_DoesNotUsePATH and
// TestIAMT308_AccountGroupIDs_DoesNotUsePATH (a planted helper's marker
// file appears, or its forged gid 99999 leaks into the result).
//
// IAMT-318 (CRITICAL, follow-up board item): the SAME gap remained in
// the rest of the privileged launchd path — dscl(1) (looking up/creating
// _iamtunnel, reached even before any reachability check) and
// launchctl(1) (installing/restarting the LaunchDaemon), both still
// resolved through PATH. Fixed the same way: pinned to darwinDsclPath /
// darwinLaunchctlPath, called only through runDscl/runLaunchctl.
// Canary: take any of them back to resolving through PATH —
// TestIAMT318_RunDscl_DoesNotUsePATH and
// TestIAMT318_RunLaunchctl_DoesNotUsePATH.

package main

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// TestIAMT308_AccountGroupIDsIncludesPrimaryGID sanity-checks
// accountGroupIDs against the CURRENT test user (not _iamtunnel, which
// may not exist on this box): the real group list must at least contain
// the account's own primary gid, proving the parsed list is the
// account's actual membership rather than an empty/default set that
// would silently degrade probeAccountCanReach to "no supplementary
// groups at all" for every account (IAMT-308 F-308-3: the account's
// actual groups, not just the single gid dscl recorded).
func TestIAMT308_AccountGroupIDsIncludesPrimaryGID(t *testing.T) {
	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current: %v", err)
	}
	groups, err := accountGroupIDs(u.Username)
	if err != nil {
		t.Fatalf("accountGroupIDs(%s): %v", u.Username, err)
	}
	want := os.Getgid()
	for _, g := range groups {
		if int(g) == want {
			return
		}
	}
	t.Fatalf("accountGroupIDs(%s) = %v, must contain the primary gid %d", u.Username, groups, want)
}

func TestIAMT308_ProbeAccountCanReach_AllComponentsTraversableSucceeds(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "gp", "parent")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if err := probeAccountCanReach(parent, uid, gid, nil); err != nil {
		t.Fatalf("probeAccountCanReach must succeed when every ancestor and the target itself are traversable: %v", err)
	}
}

// TestIAMT308_ProbeAccountCanReach_GrandparentBlocksEvenWhenImmediateParentIsFine
// is F-308-3's central canary: round 6 only ever looked at
// filepath.Dir(dataDir) — here that immediate parent IS traversable
// (0755) — so round 6's check would have answered "reachable" while the
// real walk, blocked by a 0000 grandparent, cannot actually get there.
func TestIAMT308_ProbeAccountCanReach_GrandparentBlocksEvenWhenImmediateParentIsFine(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the DAC checks this test strips — run as a normal user (macOS acceptance runs unprivileged)")
	}
	root := t.TempDir()
	grandparent := filepath.Join(root, "gp")
	parent := filepath.Join(grandparent, "parent")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(grandparent, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(grandparent, 0o755) }) // let t.TempDir() clean up after itself

	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if err := probeAccountCanReach(parent, uid, gid, nil); err == nil {
		t.Fatalf("probeAccountCanReach must refuse: %s's own bits are fine (0755) but its parent %s is 0000 — the LAST component being traversable must not be mistaken for the whole path being reachable (IAMT-308 F-308-3)", parent, grandparent)
	}
}

// TestIAMT308_ProbeAccountCanReach_TargetItselfNotSearchableFails proves
// the check is about ENTERING the target, not merely reaching it: every
// ancestor here is fine, but the target directory's own execute bit is
// off — the shape a bare "stat" (reaching the inode) would have missed
// entirely, since stat on a name only needs search on the PARENT, never
// on the named entry itself.
func TestIAMT308_ProbeAccountCanReach_TargetItselfNotSearchableFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the DAC checks this test strips — run as a normal user (macOS acceptance runs unprivileged)")
	}
	root := t.TempDir()
	target := filepath.Join(root, "parent")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil { // readable, NOT searchable
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(target, 0o755) })

	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if err := probeAccountCanReach(target, uid, gid, nil); err == nil {
		t.Fatalf("probeAccountCanReach must refuse: %s itself has no execute bit (0644) — reachable is not the same as enterable", target)
	}
}

func TestIAMT308_ProbeAccountCanReach_SymlinkToAccessibleTargetSucceeds(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real", "inner")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(filepath.Join(root, "real"), link); err != nil {
		t.Fatal(err)
	}

	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if err := probeAccountCanReach(filepath.Join(link, "inner"), uid, gid, nil); err != nil {
		t.Fatalf("probeAccountCanReach must follow a symlinked ancestor to an accessible target exactly as the real daemon's own file access would: %v", err)
	}
}

func TestIAMT308_ProbeAccountCanReach_SymlinkToInaccessibleTargetFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the DAC checks this test strips — run as a normal user (macOS acceptance runs unprivileged)")
	}
	root := t.TempDir()
	blocked := filepath.Join(root, "blocked")
	if err := os.MkdirAll(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(blocked, 0o755) })
	link := filepath.Join(root, "link")
	if err := os.Symlink(blocked, link); err != nil {
		t.Fatal(err)
	}

	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	if err := probeAccountCanReach(link, uid, gid, nil); err == nil {
		t.Fatalf("probeAccountCanReach must refuse when a symlinked component resolves to a target that is not itself searchable (IAMT-308 F-308-3: symlinked components must be handled explicitly, not silently trusted)")
	}
}

// TestIAMT308_ProbeAccountCanReach_RealImpersonation is the ONE test in
// this file that genuinely impersonates a different account — uid/gid 1
// ("daemon", always present on macOS) — proving the Credential-switching
// path itself works end to end, not just the self-uid walking logic
// every other test here exercises. Root is required to set a Credential
// at all (see probeAccountCanReach's own doc comment), so this test
// skips with a self-explaining reason otherwise (gate 10) rather than
// silently passing for the wrong reason.
func TestIAMT308_ProbeAccountCanReach_RealImpersonation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("IAMT-308: genuinely impersonating a different account needs root (setgroups() is privileged regardless of the target list) — this test only runs meaningfully as root; the self-uid walking logic it would otherwise duplicate is already covered unprivileged by the other tests in this file")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "gp", "parent")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := probeAccountCanReach(parent, 1, 1, nil); err != nil {
		t.Fatalf("probeAccountCanReach must succeed when genuinely impersonating uid/gid 1 (daemon) against a traversable path: %v", err)
	}
}

// TestIAMT308_ProbeAccountCanReach_ImpersonationWithoutPrivilegeIsReportedAsCouldNotRun
// is the round-8 canary for the review's third requirement: when the probe
// itself cannot even run (here: this test process is not root, so
// setting a Credential for a genuinely different uid fails with EPERM),
// probeAccountCanReach must say so distinctly — wrapped in
// errProbeCouldNotRun — rather than reporting either "reachable" (which
// would reopen F-308-3) or "not reachable" (which would misdirect the
// operator toward a chmod that fixes nothing).
func TestIAMT308_ProbeAccountCanReach_ImpersonationWithoutPrivilegeIsReportedAsCouldNotRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("IAMT-308: this test proves the UNPRIVILEGED failure shape — root can always set any Credential, so there is nothing to observe as root")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "gp", "parent")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	// A uid genuinely different from this process's own forces
	// probeAccountCanReach onto the Credential-setting path, which EPERMs
	// without root.
	foreignUID := uint32(os.Getuid()) + 1
	err := probeAccountCanReach(parent, foreignUID, uint32(os.Getgid()), nil)
	if err == nil {
		t.Fatal("probeAccountCanReach must not silently succeed when it could not even start the check (no privilege to impersonate)")
	}
	if !errors.Is(err, errProbeCouldNotRun) {
		t.Fatalf("an unprivileged impersonation failure must be reported as errProbeCouldNotRun (\"could not check\"), not as an ordinary not-reachable error: %v", err)
	}
}

// planFakeHelper writes an executable shell script named name into a
// fresh directory, prepends that directory to PATH (t.Setenv, restored
// automatically), and returns the marker file the script touches when
// run — used by the two F-308-5 tests below to prove a privileged
// helper is never resolved through PATH.
func planFakeHelper(t *testing.T, name string) (marker string) {
	t.Helper()
	dir := t.TempDir()
	marker = filepath.Join(dir, "executed")
	script := "#!/bin/sh\ntouch " + marker + "\necho 99999\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	return marker
}

// TestIAMT308_ProbeAccountCanReach_DoesNotUsePATH is the round-9 canary
// for review finding F-308-5 (CRITICAL): a "test" planted earlier in PATH
// must never run — install runs as root, so a PATH-resolved privileged
// helper is arbitrary code execution as root, and a planted "test" could
// separately forge a successful reachability check (exit 0) while the
// real LaunchDaemon can never reach the tree. probeAccountCanReach must
// use the pinned darwinTestPath, never a PATH lookup.
//
// Canary: go back to exec.Command("test", ...) instead of
// exec.Command(darwinTestPath, ...) — the marker appears (the planted
// helper ran) and/or the refusal is faked into a success.
func TestIAMT308_ProbeAccountCanReach_DoesNotUsePATH(t *testing.T) {
	marker := planFakeHelper(t, "test")

	root := t.TempDir()
	grandparent := filepath.Join(root, "gp")
	parent := filepath.Join(grandparent, "parent")
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	notRoot := os.Geteuid() != 0
	if notRoot {
		if err := os.Chmod(grandparent, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(grandparent, 0o755) })
	}

	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	err := probeAccountCanReach(parent, uid, gid, nil)

	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("probeAccountCanReach executed a PATH-resolved helper instead of the pinned darwinTestPath (IAMT-308 F-308-5, CRITICAL: this is arbitrary code execution as root during a real install)")
	}
	if notRoot && err == nil {
		t.Fatal("probeAccountCanReach must still refuse using the REAL /bin/test, not report a forged success from the planted PATH helper (which would have printed 99999 and exited 0)")
	}
}

// TestIAMT308_AccountGroupIDs_DoesNotUsePATH is the round-9 canary for
// the other half of review finding F-308-5: accountGroupIDs no longer
// spawns any subprocess at all (os/user.Lookup resolves the account
// through the system's own APIs), so a planted "id" earlier in PATH
// must have zero effect — not merely "not exploited", genuinely never
// consulted.
//
// Canary: take accountGroupIDs back to exec.Command("id", "-G", name) —
// the marker appears and/or the planted gid 99999 leaks into the
// result.
func TestIAMT308_AccountGroupIDs_DoesNotUsePATH(t *testing.T) {
	marker := planFakeHelper(t, "id")

	u, err := user.Current()
	if err != nil {
		t.Skipf("user.Current: %v", err)
	}
	groups, err := accountGroupIDs(u.Username)
	if err != nil {
		t.Fatalf("accountGroupIDs must work regardless of PATH (it uses no subprocess at all): %v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("accountGroupIDs executed a PATH-resolved \"id\" helper (IAMT-308 F-308-5, CRITICAL: this is arbitrary code execution as root during a real install) — accountGroupIDs must use os/user, never a subprocess")
	}
	want := os.Getgid()
	for _, g := range groups {
		if int(g) == want {
			return
		}
	}
	t.Fatalf("accountGroupIDs(%s) = %v, must contain the real primary gid %d — not the forged 99999 a poisoned PATH helper would have produced", u.Username, groups, want)
}

// TestIAMT318_RunDscl_DoesNotUsePATH is the IAMT-318 canary for the rest
// of the privileged launchd path: dscl(1) is called from the moment
// install first looks up the _iamtunnel account — well before any
// reachability check — so a planted "dscl" earlier in PATH would be
// arbitrary code execution as root reached even earlier than F-308-5's
// "id"/"test" gap. runDscl is the one place every darwinLaunchd closure
// that shells out to dscl actually calls (lookupUser, systemUIDsTaken,
// createUser); pulled out on its own, exactly like probeAccountCanReach
// (round 9), so this is testable without tripping guardProductionLaunchd
// or needing a real _iamtunnel account.
//
// Canary: take runDscl back to exec.Command("dscl", ...) — the marker
// appears.
func TestIAMT318_RunDscl_DoesNotUsePATH(t *testing.T) {
	marker := planFakeHelper(t, "dscl")

	_, _ = runDscl([]string{".", "-read", "/Users/iamt318-probe-nonexistent", "UniqueID"})

	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("runDscl executed a PATH-resolved \"dscl\" helper instead of the pinned darwinDsclPath (IAMT-318, CRITICAL: arbitrary code execution as root — reached even before any reachability check runs)")
	}
}

// TestIAMT318_RunLaunchctl_DoesNotUsePATH is IAMT-318's other half:
// launchctl(1) is called while installing and restarting the
// LaunchDaemon (serviceLoaded, bootout, bootstrap, serviceRunning), all
// through runLaunchctl.
//
// Canary: take runLaunchctl back to exec.Command("launchctl", ...) —
// the marker appears.
func TestIAMT318_RunLaunchctl_DoesNotUsePATH(t *testing.T) {
	marker := planFakeHelper(t, "launchctl")

	_, _ = runLaunchctl([]string{"print", "system/com.iamtunnel.gateway-iamt318-probe"})

	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("runLaunchctl executed a PATH-resolved \"launchctl\" helper instead of the pinned darwinLaunchctlPath (IAMT-318, CRITICAL: arbitrary code execution as root)")
	}
}
