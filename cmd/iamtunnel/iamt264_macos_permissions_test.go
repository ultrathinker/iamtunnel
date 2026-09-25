package main

// iamt264_macos_permissions_test.go — IAMT-264: the macOS-permissions
// hint that `enrol` and `server start` print before the first OS call.
//
// macOS is the only platform where both the daemon the preflight check
// needs (Remote Login / the com.openssh.sshd launchd job) and the
// directory the door writes into are locked down by permissions that
// only the operator can grant by hand — and neither of the two failures
// names itself: a disabled daemon gives "connection refused", while a
// TCC refusal is EPERM, which reads as an ordinary filesystem error.
// The hint is printed where the operator will actually see it — in the
// command's output and in the LaunchDaemon's journal.
//
// The text and its gating live in permissionHint(goos) — the function
// takes GOOS as an argument instead of reading runtime.GOOS — so both
// are checked on any host OS, including this repository's Linux CI.
// The CLI wiring (that the commands really print it) is checked on
// darwin only: on other OSes there is no hint by construction.

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// TestIAMT264_PermissionHintIsDarwinOnly — the gating canary: there is
// exactly one text and it exists on darwin only. Printing it on Linux
// or Windows would send the operator to System Settings they do not
// have.
//
// Canary: drop the goos check (or return the text for every OS) — the
// linux/windows/freebsd assertion turns red.
func TestIAMT264_PermissionHintIsDarwinOnly(t *testing.T) {
	hint := permissionHint("darwin")
	if hint == "" {
		t.Fatal("on darwin the hint must exist")
	}
	for _, goos := range []string{"linux", "windows", "freebsd"} {
		if got := permissionHint(goos); got != "" {
			t.Fatalf("on %s there must be no hint, got %q", goos, got)
		}
	}
}

// TestIAMT264_PermissionHintNamesBothGrants — the content canary: both
// things the operator needs to enable are named, together with the
// System Settings path, because "enable Remote Login" without the path
// is not a hint for someone seeing macOS for the first time.
//
// Canary: drop either half (Remote Login or Full Disk Access) or the
// System Settings path — the corresponding assertion turns red.
func TestIAMT264_PermissionHintNamesBothGrants(t *testing.T) {
	hint := permissionHint("darwin")
	for _, want := range []string{
		// 1. The daemon: the same thing the pre-flight needs
		// (run_darwin.go, the com.openssh.sshd launchd job).
		"Remote Login",
		"Sharing",
		"System Settings",
		"setremotelogin",
		"127.0.0.1:22",
		// 2. The directory: a TCC permission needed only when the door
		// file sits in a protected folder.
		"Full Disk Access",
		"Privacy",
		"Desktop",
		"Documents",
		"Downloads",
	} {
		if !strings.Contains(hint, want) {
			t.Errorf("IAMT-264: the hint does not name %q:\n%s", want, hint)
		}
	}
	// The hint must be truthful about who needs Full Disk Access: the
	// watchdog is a re-launch of THE SAME binary (winkeys.SpawnWatchdog),
	// so one permission covers both the server and its child process.
	if !strings.Contains(hint, "doorwatch") {
		t.Errorf("IAMT-264: the hint must say the permission is needed by the watchdog too (the same binary):\n%s", hint)
	}
	// And it must not promise that Full Disk Access is always needed:
	// ~/.ssh is not under TCC, an ordinary install does without it.
	if !strings.Contains(hint, "protected folder") {
		t.Errorf("IAMT-264: Full Disk Access must be conditional (a protected folder), not an obligatory step:\n%s", hint)
	}
}

// TestIAMT264_PermissionHintIsPrintedByEnrolAndStart — the CLI wiring:
// both commands the operator runs on the machine print the hint, and
// they print it BEFORE the refusal — otherwise on an unenrolled machine
// (the most common first run) the operator would see only "not
// registered" and never learn about Remote Login.
//
// darwin only: on other OSes the branch is not taken by construction,
// and the assertion would be checking itself.
//
// Canary: drop the printout from cmdEnrol or cmdServerStart — the
// corresponding out assertion turns red. Putting a six-character
// secret back into the enrol code (as before IAMT-297) turns
// assertElevationRefusal red: the command would stop at code parsing,
// not at the root gate.
func TestIAMT264_PermissionHintIsPrintedByEnrolAndStart(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("the hint is printed on darwin only (permissionHint(runtime.GOOS))")
	}
	hintFirstLine := strings.SplitN(permissionHint("darwin"), "\n", 2)[0]

	// IAMT-297: before this fix the enrol code carried a six-character
	// secret, ParseEnrolCode failed EARLIER than the hint could print,
	// and on a live Mac the run looked like this: out="" and "enrol
	// secret has a wrong shape". The test stayed green on every
	// non-darwin machine precisely because it never reached the darwin
	// branch, and on darwin itself it checked code parsing instead of
	// hint wiring. Now the code is well-formed (enrolCode from
	// main_test.go — the same one the other CLI tests use), and the
	// refusal must be the root gate's refusal: that is the reason the
	// command does not go through, and assertElevationRefusal names it
	// by name.
	t.Run("enrol", func(t *testing.T) {
		out, errs, code := driveUnelevated(t, "enrol", enrolCode, "--data-dir", t.TempDir())
		if !strings.Contains(out, hintFirstLine) {
			t.Fatalf("enrol must print the macOS permissions hint; out=%q errs=%q", out, errs)
		}
		assertElevationRefusal(t, "enrol", errs, code)
	})

	t.Run("server start", func(t *testing.T) {
		out, errs, code := driveUnelevated(t, "server", "start", "--data-dir", t.TempDir())
		if !strings.Contains(out, hintFirstLine) {
			t.Fatalf("server start must print the macOS permissions hint; out=%q errs=%q", out, errs)
		}
		assertElevationRefusal(t, "server start", errs, code)
	})
}

// driveUnelevated uses the same streams as drive(), but the elevation
// check seam answers "not elevated". This is not a concession but an
// observability condition: driveFull substitutes isElevated=true ("the
// console is already elevated"), so through drive the root gate NEVER
// refuses, on any OS — the command proceeds to loadConfig and to
// 127.0.0.1:1, and stderr ends up holding a connection refusal. A
// subtest that wants to see the gate's refusal must set the seam
// itself (iamt190 and iamt248 do the same).
func driveUnelevated(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errs bytes.Buffer
	code := run(args, &streams{
		out:  &out,
		errs: &errs,
		env:  testsupport.PlatformDataEnv(t),
		isElevated: func() (bool, error) {
			return false, nil
		},
	})
	return out.String(), errs.String(), code
}

// assertElevationRefusal requires that the command failed AND stopped
// precisely at the root gate (requireServerElevation), not at argument
// parsing and not at a later step.
//
// Why a separate assertion: the IAMT-264 hint is printed before the
// gate, so "the hint was printed" does not by itself prove the command
// reached the gate — only the refusal text proves that. A code-parsing
// refusal ("enrol secret has a wrong shape"), a "not registered"
// refusal and the gate's own refusal all leave out carrying the hint
// alike, and a test checking only out takes the first two for success.
// That is exactly what happened on a live Mac (IAMT-297), so the
// expected text is named here: the gate speaks for itself through
// deniedErrf — "root privileges are required — run it with sudo:
// sudo iamtunnel %s" — and returns exitDenied.
func assertElevationRefusal(t *testing.T, path, errs string, code int) {
	t.Helper()
	if !strings.Contains(errs, "root privileges are required") {
		t.Fatalf("%s must stop at the root gate (\"root privileges are required\"), not at code parsing and not at a later step; errs=%q (code %d)", path, errs, code)
	}
	if code != exitDenied {
		t.Fatalf("%s: the gate's refusal must return exitDenied=%d, got %d; errs=%q", path, exitDenied, code, errs)
	}
}
