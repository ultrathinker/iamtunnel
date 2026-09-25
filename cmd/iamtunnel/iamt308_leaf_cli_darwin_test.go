//go:build darwin

// iamt308_leaf_cli_darwin_test.go — IAMT-308 round 12: the review found
// TestConfigPlumbingPrecedenceEndToEnd (an ordinary CLI install, no
// exotic setup at all) panicking with a nil pointer dereference inside
// checkCustomDataDirLeafIsSafe on a real Mac. Round 11 added the
// leafIsSafe field to darwinLaunchdSetup and wired it into
// runGatewayInstall, but never updated launchdRecorder.setup() (the one
// fake OS seam every CLI-level darwin test in this package installs
// through) to supply it — every test driving "gateway install" with a
// custom --data-dir on darwin called a nil func the instant it reached
// the leaf check. This drives the exact same route
// TestConfigPlumbingPrecedenceEndToEnd does — the CLI (drive), not the
// seam directly — and proves the leaf check actually runs and reaches
// a verdict there, so a future regression of the same shape (a new
// darwinLaunchdSetup field wired into product code but left unset in
// launchdRecorder.setup()) reddens here instead of panicking on a live
// Mac.
//
// Canary: leave leafIsSafe nil in launchdRecorder.setup() (or in any
// other darwinLaunchdSetup literal in the tests) — a panic instead of
// the test failure below; weakening checkCustomDataDirLeafIsSafe to "if
// setup.leafIsSafe == nil, return nil" also paints the canary below
// red, because rec.leafIsSafeCalls then stays empty (the "actually
// runs and reaches a verdict" check requires a recorded call, not just
// success).
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestIAMT308_CLI_LeafIsSafeRunsOnCustomDataDir drives "gateway install
// --data-dir <custom>" through the real CLI (drive, exactly like
// TestConfigPlumbingPrecedenceEndToEnd) and requires the leaf check to
// have actually run against that exact directory before install can
// succeed — the fake seam's default (nil error) lets the rest of
// install proceed, so a successful exit code alone would not prove the
// check ran at all; the call log is the only thing that does.
func TestIAMT308_CLI_LeafIsSafeRunsOnCustomDataDir(t *testing.T) {
	_ = withFakeSystemd(t)
	rec := withFakeLaunchd(t)
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	if code != exitOK {
		t.Fatalf("gateway install with a custom --data-dir on macOS: code=%d out=%q errs=%q — the leaf check's default (safe) must not itself refuse", code, out, errs)
	}
	if len(rec.leafIsSafeCalls) != 1 || !strings.HasPrefix(rec.leafIsSafeCalls[0], dir+":") {
		t.Fatalf("checkCustomDataDirLeafIsSafe must have run against %s through the real CLI route: leafIsSafeCalls=%v", dir, rec.leafIsSafeCalls)
	}
}

// TestIAMT308_CLI_LeafIsSafeRefusalLeavesNothingBehind drives the same
// CLI route with the fake seam wired to refuse the leaf check
// (review round21, F-308-9's own acceptance line: "on refusal — no host
// key, no bootstrap token, no state.json, nothing on stdout"). This is
// the CLI-level half of that requirement; iamt308_leaf_safe_darwin_test.go
// covers the real darwin implementation reaching the same refusal
// against a real filesystem tree.
func TestIAMT308_CLI_LeafIsSafeRefusalLeavesNothingBehind(t *testing.T) {
	_ = withFakeSystemd(t)
	rec := withFakeLaunchd(t)
	rec.leafUnsafeErr = errors.New("/company-secrets/gw is a symbolic link — a custom --data-dir and its ancestors must not be symlinks")
	dir := t.TempDir()

	out, errs, code := drive(t, "gateway", "install", "--data-dir", dir, "--public-host", "gw.example.test")
	if code == exitOK {
		t.Fatalf("gateway install must refuse when leafIsSafe answers a non-nil error, got exitOK: out=%q", out)
	}
	if !strings.Contains(errs, "symbolic link") {
		t.Fatalf("refusal must carry the seam's own text: errs=%q", errs)
	}
	if out != "" {
		t.Fatalf("a refused install must print nothing to stdout (no bootstrap reference), got: %q", out)
	}
	for _, name := range []string{hostkeyFileName, bootstrapFileName, state.StateFileName} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			t.Fatalf("a refused install must leave no %s behind in %s", name, dir)
		}
	}
}
