package main

// iamt308_gateway_parent_traversable_test.go — IAMT-308: on a real Mac,
// `sudo iamtunnel gateway install` reported success (exit 0) and then the
// LaunchDaemon crash-looped forever (launchctl: "last exit code = 4"),
// because the data dir's PARENT — the one this command itself creates via
// MkdirAll — came out 0700, root-only. The unprivileged _iamtunnel service
// account could not even traverse it, so probing the OPTIONAL sibling
// config file (gateway.json) failed with EACCES instead of ENOENT, and
// gateway run treated that as a fatal environment error on every respawn.
//
// Round 5 (review finding 2): the original fix chmod'd the parent of ANY
// dir to 0755, including a custom --data-dir — e.g. --data-dir
// /private/company-secrets/iamtunnel-gateway would give every other user
// traverse+listing rights over /private/company-secrets, a directory this
// command has no business touching. prepareGatewayParentDir (gateway.go)
// scopes the fix-up to the exact standard macOS gateway path, taking that
// standard path as a parameter rather than resolving it internally —
// production passes config.DirsFor("darwin", env).Gateway, a fixed
// absolute /Library/Application Support path a hermetic test must never
// create or chmod; tests below pass a t.TempDir()-rooted stand-in
// instead, so the "standard path" branch is exercised without touching
// real system state.
//
// Round 6: round 5 ALSO made prepareGatewayParentDir refuse a custom
// --data-dir outright when its parent was not traversable, checked by
// permission bits alone. That refusal fired for any private parent
// whether or not a real daemon would ever run as _iamtunnel — including
// every test in this package that installs into a --data-dir under
// t.TempDir(), which on a real Mac sits under /var/folders/.../T, a
// per-user tree that genuinely is not world-traversable. Fifteen tests
// that never touch a real launchd broke. The traversability check now
// lives in setupLaunchdDaemon's parentTraversable seam step
// (iamt259_launchd_test.go), which only ever fires against the real
// service account; prepareGatewayParentDir itself only ever creates or
// chmods, never refuses.
//
// Custom --data-dir scenarios ARE safe to drive through the full CLI
// (drive()): they are always rooted in the test's own TempDir.
//
// Canaries:
//  1. bring back prepareGatewayParentDir's lone MkdirAll(parent,
//     0o700) without the standardGatewayDir branch —
//     TestIAMT308_PrepareGatewayParentDir/standard_path_healed_to_0755_traversable
//     turns red;
//  2. bring back the unconditional parent chmod (without the
//     standard/custom branch) — TestIAMT308_CustomDataDirParentModeUntouched
//     turns red (the parent's 0711 becomes 0755) and so does
//     .../custom_path_with_existing_parent_is_left_untouched;
//  3. bring back prepareGatewayParentDir's refusal on an untraversable
//     custom parent (round 5's mistake) —
//     TestIAMT308_CustomDataDirWithUntraversableParentSucceedsUnderFakeSeam
//     turns red, and any of the fifteen tests round 6 listed as a
//     requirement (TestIAMT177_HostTouchesOnlyItsOwnSeam and others);
//  4. the real refusal on an untraversable parent against a real
//     account — TestIAMT259_SetupLaunchdDaemonRefusesWhenParentNotTraversable
//     in iamt259_launchd_test.go.
//
// Round 7 (review findings F-308-3, F-308-4):
//  5. bring back the bits-only check of filepath.Dir(dataDir) alone —
//     the darwin-only probeAccountCanReach tests turn red, in
//     iamt312_gateway_exe_dir_acl_windows... no, in
//     iamt308_probe_account_darwin_test.go (the full ancestor chain,
//     symbolic links);
//  6. bring back the reachability check AFTER hostkey/token/state.json/
//     printing the link (as it was in round 6) —
//     TestIAMT308_RefusalOnUnreachableParentLeavesNothingBehind below
//     turns red.
//
// Round 9 (review finding F-308-6 — TOCTOU race between the early preflight and
// the first secret write):
//  7. drop the re-check immediately before
//     os.MkdirAll/loadOrGenerateSigner —
//     TestIAMT308_RaceGrandparentChangesBetweenPreflightAndFirstWrite
//     turns red;
//  8. clean up dataDir on a re-check refusal unconditionally (not only
//     for a freshly created one) —
//     TestIAMT308_RaceRefusalNeverRemovesAPreexistingDataDir turns red.
//
// Round 10 (review finding F-308-8 — the re-check shrinks the TOCTOU window but
// does not close it):
//  9. drop the checkCustomDataDirAncestorsAreSafe call from
//     runGatewayInstall (or call it for the standard path too) —
//     TestIAMT308_CustomDataDirWithUnsafeAncestorLeavesNothingBehind
//     below turns red (and, for the standard path,
//     TestIAMT308_GatewayParentDirStaysTraversableOnDarwin — the
//     standard path must never reach this check at all).

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestIAMT308_PrepareGatewayParentDir unit-tests prepareGatewayParentDir
// directly — hermetic, no CLI, no real /Library path — covering both
// halves of review finding 2.
func TestIAMT308_PrepareGatewayParentDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("IAMT-308: prepareGatewayParentDir only ever runs on the darwin branch of runGatewayInstall, and asserts POSIX permission bits Windows does not have")
	}
	t.Run("standard path healed to 0755 traversable", func(t *testing.T) {
		root := t.TempDir()
		standard := filepath.Join(root, "iamtunnel", "gateway")
		parent := filepath.Dir(standard)
		// Simulate an earlier, broken install that left the parent at
		// 0700 — the exact real-Mac symptom IAMT-308 first fixed.
		if err := os.MkdirAll(parent, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := prepareGatewayParentDir(standard, standard); err != nil {
			t.Fatalf("prepareGatewayParentDir: %v", err)
		}
		st, err := os.Stat(parent)
		if err != nil {
			t.Fatal(err)
		}
		if perm := st.Mode().Perm(); perm != 0o755 {
			t.Fatalf("standard gateway parent %s has mode %#o, want 0755 (healed unconditionally)", parent, perm)
		}
	})

	t.Run("custom path with existing parent is left untouched", func(t *testing.T) {
		root := t.TempDir()
		standard := filepath.Join(root, "standard-root", "iamtunnel", "gateway")
		parent := filepath.Join(root, "company-secrets")
		if err := os.MkdirAll(parent, 0o711); err != nil {
			t.Fatal(err)
		}
		custom := filepath.Join(parent, "iamtunnel-gateway")

		if err := prepareGatewayParentDir(custom, standard); err != nil {
			t.Fatalf("prepareGatewayParentDir: %v", err)
		}
		st, err := os.Stat(parent)
		if err != nil {
			t.Fatal(err)
		}
		if perm := st.Mode().Perm(); perm != 0o711 {
			t.Fatalf("IAMT-308: custom --data-dir's parent %s has mode %#o, want unchanged 0711 — install must not chmod a parent it does not own (review finding 2)", parent, perm)
		}
	})

	t.Run("custom path with untraversable new parent succeeds without a refusal here", func(t *testing.T) {
		// Round 6: prepareGatewayParentDir itself must NEVER refuse on
		// permission bits alone — that check belongs to
		// setupLaunchdDaemon's parentTraversable seam step, which only
		// fires against the real service account (see
		// TestIAMT259_SetupLaunchdDaemonRefusesWhenParentNotTraversable).
		// A restrictive-but-freshly-created parent here is simply left
		// as is.
		root := t.TempDir()
		standard := filepath.Join(root, "standard-root", "iamtunnel", "gateway")
		custom := filepath.Join(root, "company-secrets", "iamtunnel-gateway")

		if err := prepareGatewayParentDir(custom, standard); err != nil {
			t.Fatalf("prepareGatewayParentDir must not refuse on permission bits alone (IAMT-308 round 6): %v", err)
		}
	})
}

// TestIAMT308_GatewayParentDirStaysTraversableOnDarwin proves the CLI
// actually wires prepareGatewayParentDir into `gateway install` end to
// end, using a custom --data-dir whose parent is already traversable
// (0755) — the ordinary "operator's own directory is already fine" case.
// The "healed from a broken 0700" and "standard path" scenarios that the
// original IAMT-308 regression covered now live in
// TestIAMT308_PrepareGatewayParentDir, which can safely use dir ==
// standardGatewayDir without ever touching the real /Library/Application
// Support tree that drive() cannot avoid resolving through the real
// config.DirsFor.
func TestIAMT308_GatewayParentDirStaysTraversableOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("IAMT-308: the darwin branch is selected by runtime.GOOS and only exercised on a darwin host; here %s", runtime.GOOS)
	}
	withFakeSystemd(t)
	withFakeLaunchd(t)

	root := t.TempDir()
	dir := filepath.Join(root, "iamtunnel", "gateway")
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		t.Fatal(err)
	}

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	if code != exitOK {
		t.Fatalf("gateway install: code=%d out=%q errs=%q", code, out, errs)
	}

	pst, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if perm := pst.Mode().Perm(); perm != 0o755 {
		t.Fatalf("IAMT-308: parent directory %s has mode %#o, want 0755 unchanged", parent, perm)
	}

	dst, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("install must have created the data directory %s: %v", dir, err)
	}
	if perm := dst.Mode().Perm(); perm != 0o700 {
		t.Fatalf("the leaf data directory %s must stay 0700 (SPEC §3.5.1) — got %#o", dir, perm)
	}
}

// TestIAMT308_CustomDataDirParentModeUntouched is the CLI-level canary
// for review finding 2: a custom --data-dir sitting under a pre-existing
// parent the operator already prepared (0711 — traversable but
// deliberately NOT install's own default of 0755) must come out of
// install with that exact mode, proving install never chmods a parent it
// does not own.
func TestIAMT308_CustomDataDirParentModeUntouched(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("IAMT-308: the darwin branch is selected by runtime.GOOS and only exercised on a darwin host; here %s", runtime.GOOS)
	}
	withFakeSystemd(t)
	withFakeLaunchd(t)

	root := t.TempDir()
	parent := filepath.Join(root, "company-secrets")
	if err := os.MkdirAll(parent, 0o711); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "iamtunnel-gateway")

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	if code != exitOK {
		t.Fatalf("gateway install: code=%d out=%q errs=%q", code, out, errs)
	}

	pst, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("stat parent: %v", err)
	}
	if perm := pst.Mode().Perm(); perm != 0o711 {
		t.Fatalf("IAMT-308: custom --data-dir's parent %s has mode %#o, want unchanged 0711 — install must not chmod a parent it does not own (review finding 2)", parent, perm)
	}

	dst, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("install must have created the data directory %s: %v", dir, err)
	}
	if perm := dst.Mode().Perm(); perm != 0o700 {
		t.Fatalf("the leaf data directory %s must stay 0700 (SPEC §3.5.1) — got %#o", dir, perm)
	}
}

// TestIAMT308_CustomDataDirWithUntraversableParentSucceedsUnderFakeSeam
// is the round-6 regression canary: a custom --data-dir whose freshly
// created parent is NOT traversable (0700, the same shape t.TempDir()'s
// own parent has on a real Mac) must still let install succeed when no
// real LaunchDaemon is being wired — exactly what all fifteen tests
// round 6 named exercise via the fake OS seam. The real-account refusal
// lives in setupLaunchdDaemon's parentTraversable seam step and is
// covered separately, against the real seam, by
// TestIAMT259_SetupLaunchdDaemonRefusesWhenParentNotTraversable.
func TestIAMT308_CustomDataDirWithUntraversableParentSucceedsUnderFakeSeam(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("IAMT-308: the darwin branch is selected by runtime.GOOS and only exercised on a darwin host; here %s", runtime.GOOS)
	}
	withFakeSystemd(t)
	withFakeLaunchd(t)

	root := t.TempDir()
	dir := filepath.Join(root, "company-secrets", "iamtunnel-gateway")

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	if code != exitOK {
		t.Fatalf("IAMT-308 round 6: install into a custom --data-dir with an untraversable (but freshly created, private) parent must succeed under a fake OS seam — no real daemon is being wired to need that traversal: code=%d out=%q errs=%q", code, out, errs)
	}
}

// TestIAMT308_RefusalOnUnreachableParentLeavesNothingBehind is the
// round-7 canary for review finding F-308-4: exactly what was seen live
// on the Mac — for an unreachable parent, install had already created
// the leaf, the host key, the bootstrap token and state.json, and had
// already printed the bootstrap reference, before the reachability
// check ever refused. preflightGatewayReachability now runs before any
// of that, so a refusal must leave dataDir itself entirely absent (every
// secret lives inside it) and must never have printed the reference.
//
// Canary: move the preflightGatewayReachability call back to its old
// place (after hostkey/token/state.json and printing the link) — either
// os.Stat(dir) turns red (the directory got created) or the "bootstrap
// reference" check in the output does.
func TestIAMT308_RefusalOnUnreachableParentLeavesNothingBehind(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("IAMT-308: the darwin branch is selected by runtime.GOOS and only exercised on a darwin host; here %s", runtime.GOOS)
	}
	withFakeSystemd(t)
	rec := withFakeLaunchd(t)
	rec.traversableErr = fmt.Errorf("stat /company-secrets: permission denied")

	root := t.TempDir()
	dir := filepath.Join(root, "company-secrets", "iamtunnel-gateway")

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	if code == exitOK {
		t.Fatalf("gateway install must refuse when the real account cannot reach the parent, got exit 0: out=%q errs=%q", out, errs)
	}
	if !strings.Contains(errs, "cannot reach") {
		t.Fatalf("refusal does not name the unreachable-parent problem: %s", errs)
	}
	if strings.Contains(out, "bootstrap reference") {
		t.Fatalf("IAMT-308 round 7: the bootstrap reference must never be printed when the reachability preflight refuses: %q", out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("IAMT-308 round 7: dataDir %s must not exist after a preflight refusal (nothing — host key, token, state.json — may be created): stat err=%v", dir, err)
	}
}

// TestIAMT308_RaceGrandparentChangesBetweenPreflightAndFirstWrite is the
// round-9 canary for review finding F-308-6: the early preflight and the
// first secret write are not the same instant — whoever controls a
// custom --data-dir's ancestor could swap its mode, ACL or replace it
// with a symlink in between. This simulates exactly that: the fake
// seam's parentTraversable answers "reachable" on the FIRST call (the
// early preflight, before dataDir even exists) and "not reachable" on
// the SECOND (the round-9 re-check immediately before the host key is
// written) — proving install still refuses, still leaves dataDir
// absent, and still prints nothing, even though the early preflight
// alone would have let it through.
//
// Canary: delete the re-check from runGatewayInstall (go back to the
// single check before everything, round 7/8's shape) — this test turns
// red: calls stays 1, and install reaches the bootstrap-link printing
// because the adversarial second check is never called.
func TestIAMT308_RaceGrandparentChangesBetweenPreflightAndFirstWrite(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("IAMT-308: the darwin branch is selected by runtime.GOOS and only exercised on a darwin host; here %s", runtime.GOOS)
	}
	withFakeSystemd(t)
	withFakeLaunchd(t)

	calls := 0
	darwinLaunchd.parentTraversable = func(dataDir string, uid, gid int) error {
		calls++
		if calls == 1 {
			return nil // the early preflight sees a fine ancestor chain
		}
		return fmt.Errorf("stat /company-secrets: permission denied") // an ancestor changed before the re-check
	}

	root := t.TempDir()
	dir := filepath.Join(root, "company-secrets", "iamtunnel-gateway")

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	if code == exitOK {
		t.Fatalf("gateway install must refuse when an ancestor changes between the preflight and the first write, got exit 0: out=%q errs=%q", out, errs)
	}
	if calls < 2 {
		t.Fatalf("IAMT-308 round 9: the re-check must actually run a second parentTraversable call before the first secret write: got %d call(s)", calls)
	}
	if !strings.Contains(errs, "cannot reach") {
		t.Fatalf("refusal does not name the unreachable-parent problem: %s", errs)
	}
	if strings.Contains(out, "bootstrap reference") {
		t.Fatalf("IAMT-308 round 9: the bootstrap reference must never be printed when the re-check refuses: %q", out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("IAMT-308 round 9: dataDir %s must not exist after the re-check refuses (host key, token, state.json all live inside it and none may exist): stat err=%v", dir, err)
	}
}

// TestIAMT308_RaceRefusalNeverRemovesAPreexistingDataDir proves the
// round-9 re-check's cleanup is scoped correctly: on a REPEAT install
// whose dataDir already existed — with its own, earlier-installed data
// inside it — before this attempt ever ran, a race-triggered refusal
// must leave that directory and its contents untouched. The cleanup
// only ever removes a leaf THIS attempt created fresh.
//
// Canary: drop the dirExistedBefore check before os.Remove in
// runGatewayInstall — this test turns red: the pre-existing hostkey
// disappears.
func TestIAMT308_RaceRefusalNeverRemovesAPreexistingDataDir(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("IAMT-308: the darwin branch is selected by runtime.GOOS and only exercised on a darwin host; here %s", runtime.GOOS)
	}
	withFakeSystemd(t)
	withFakeLaunchd(t)

	root := t.TempDir()
	dir := filepath.Join(root, "company-secrets", "iamtunnel-gateway")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "hostkey")
	if err := os.WriteFile(marker, []byte("pre-existing-from-an-earlier-install"), 0o600); err != nil {
		t.Fatal(err)
	}

	calls := 0
	darwinLaunchd.parentTraversable = func(dataDir string, uid, gid int) error {
		calls++
		if calls == 1 {
			return nil
		}
		return fmt.Errorf("stat /company-secrets: permission denied")
	}

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	if code == exitOK {
		t.Fatalf("expected the race-triggered refusal, got exit 0: out=%q errs=%q", out, errs)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("IAMT-308 round 9: a repeat install's pre-existing dataDir %s must never be removed by the re-check's cleanup: stat err=%v", dir, err)
	}
	got, err := os.ReadFile(marker)
	if err != nil || string(got) != "pre-existing-from-an-earlier-install" {
		t.Fatalf("IAMT-308 round 9: pre-existing data inside %s must survive a race-triggered refusal untouched: content=%q err=%v", dir, got, err)
	}
}

// TestIAMT308_CustomDataDirWithUnsafeAncestorLeavesNothingBehind is the
// round-10 CLI-level canary for review finding F-308-8: a custom
// --data-dir whose ancestors are not exclusively root-controlled must be
// refused — by name — before a single secret exists on disk or a single
// byte reaches stdout, exactly like F-308-4's original guarantee for the
// account-reachability refusal.
//
// Canary: drop the checkCustomDataDirAncestorsAreSafe check in
// runGatewayInstall — install reaches the bootstrap-link printing and
// creates dataDir although rec.ancestorsUnsafeErr was set.
func TestIAMT308_CustomDataDirWithUnsafeAncestorLeavesNothingBehind(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skipf("IAMT-308: the darwin branch is selected by runtime.GOOS and only exercised on a darwin host; here %s", runtime.GOOS)
	}
	withFakeSystemd(t)
	rec := withFakeLaunchd(t)
	rec.ancestorsUnsafeErr = fmt.Errorf("/company-secrets is not exclusively controlled by root (owner uid 501, mode 0755)")

	root := t.TempDir()
	dir := filepath.Join(root, "company-secrets", "iamtunnel-gateway")

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	if code == exitOK {
		t.Fatalf("gateway install must refuse when a custom --data-dir's ancestors are not exclusively root-controlled, got exit 0: out=%q errs=%q", out, errs)
	}
	if !strings.Contains(errs, "not exclusively controlled by root") {
		t.Fatalf("refusal does not name the unsafe-ancestor problem: %s", errs)
	}
	if strings.Contains(out, "bootstrap reference") {
		t.Fatalf("IAMT-308 round 10: the bootstrap reference must never be printed when the ancestor-safety check refuses: %q", out)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("IAMT-308 round 10: dataDir %s must not exist after an ancestor-safety refusal (nothing — host key, token, state.json — may be created): stat err=%v", dir, err)
	}
	if len(rec.traversableCalls) != 0 {
		t.Fatalf("IAMT-308 round 10: the ancestor-safety refusal must stop BEFORE the account-reachability probe ever runs: %v", rec.traversableCalls)
	}
}
