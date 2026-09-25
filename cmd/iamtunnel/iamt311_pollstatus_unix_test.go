//go:build (linux || darwin) && !nogui

package main

// iamt311_pollstatus_unix_test.go — IAMT-311's end-to-end reproduction:
// a live run found the machine's own data directory root-owned 0700
// (/var/lib/iamtunnel-machine, exactly docs/RUNBOOK.md's own layout),
// which makes control.json unreadable to an unprivileged window. Before
// this fix, pollServerStatus discarded sendControl's error entirely
// (`reply, contacted, _ := sendControl(dir, "status")`), so the denied
// read came back indistinguishable from "no server running at all":
// sshd drawn as not running, the tunnel drawn as offline, while
// systemctl/ss/admin machines list on the same machine all agreed it was
// reachable. This reproduces the denial with a chmod, no root needed.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIAMT311_PollServerStatusUnknownOnPermissionDenied pins the fix at
// the seam the bug actually lived in.
//
// Canary: restore `reply, contacted, _ := sendControl(dir, "status")`
// (discarding the error) in pollServerStatus. This test goes red on:
//
//	pollServerStatus on a permission-denied control.json returned
//	Unknown=false — the old bug reads an unreadable status as a
//	confident "not running" (IAMT-311)
func TestIAMT311_PollServerStatusUnknownOnPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions — cannot reproduce the denial")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, controlFileName), []byte(`{"port":1,"token":"x"}`), 0o644); err != nil {
		t.Fatalf("seeding control.json: %v", err)
	}
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	got := pollServerStatus(dir)

	if !got.Unknown {
		t.Fatalf("pollServerStatus on a permission-denied control.json returned Unknown=%v, want true — the old bug reads an unreadable status as a confident \"not running\" (IAMT-311)", got.Unknown)
	}
	if got.SshdRunning || got.Waiting || len(got.Sessions) != 0 {
		t.Fatalf("pollServerStatus on a permission-denied status carried a positive fact (SshdRunning=%v Waiting=%v Sessions=%v) — Unknown must be the whole story, not an addition to a guessed one", got.SshdRunning, got.Waiting, got.Sessions)
	}
	if got.UnknownReason == "" {
		t.Fatal("Unknown was true but UnknownReason was empty — the fact would draw with no explanation at all")
	}
	if !strings.Contains(got.UnknownReason, "root privileges are required") {
		t.Fatalf("UnknownReason = %q, want the same missing-rights wording the CLI's own \"server status\" refusal already uses", got.UnknownReason)
	}
}
