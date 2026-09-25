package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// regression_findings_test.go — finding tests from an independent acceptance
// review (second round, IAMT-62). Each test is pinned under
// t.Skip("FINDING S-X: ...") per the acceptance rules (gate 10).
// With t.Skip removed, each test is guaranteed to fail (go red) on the
// current mainline, proving a real implementation defect or a
// divergence from the spec.
//
// WARNING: all tests are isolated inside t.TempDir() and never touch
// the real C:\ProgramData\ssh folder or the OpenSSH service.

// FINDING S-1: PROTOCOL §5.1 (line 237/245) and §5.2 (lines 266–268)
// require that the initial and check door.status report the actual
// state of the admin key file: {installed, doorId?, publicKeyFingerprint?}.
// If a line from a past crash/BSOD/failure remains on disk, or was
// added from outside, the gateway must see it via door.status and run
// cleanup (reconnect/sanitize).
//
// In reality doorController.status (door.go:175-182) checks ONLY the
// in-memory dc.installed flag. The administrators_authorized_keys file
// on disk is never read at all! On a fresh start/reconnect,
// door.status unconditionally reports installed:false, hiding the
// presence of an active admin key in the file. The gateway marks the
// machine online:true and never triggers cleanup, leaving foreign/stale
// admin access active.
func TestFinding_StatusMustReflectDiskFileNotJustMemory(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)

	// On disk, administrators_authorized_keys holds an active door line
	// (for example, left over from a sudden process crash/BSOD before
	// SweepStale, or after a teardown error).
	staleDoorID := "22222222-2222-2222-2222-222222222222"
	staleHexID := winkeysID(staleDoorID)
	line := winkeys.FormatLine(staleHexID, winkeys.TestKey)
	if err := os.WriteFile(keyFile, []byte(line+"\r\n"), 0o600); err != nil {
		t.Fatalf("seed key file: %v", err)
	}

	// The gateway requests an initial door.status right after connecting:
	resp := dc.status(controlRequest{ID: "status-disk-check", Op: "door.status"})
	if !resp.OK {
		t.Fatalf("door.status failed: %+v", resp.Error)
	}
	var res doorStatusResult
	if err := json.Unmarshal(resp.Result, &res); err != nil {
		t.Fatalf("unmarshal doorStatusResult: %v", err)
	}

	// Spec expectation (PROTOCOL §5.1 / §5.2): the status must detect the line on disk!
	if !res.Installed {
		t.Fatalf("door.status reported installed=false, but key file on disk contains a valid active door line %s", line)
	}
	if res.DoorID != staleDoorID && res.DoorID != staleHexID {
		t.Fatalf("door.status reported DoorID=%q, want %q", res.DoorID, staleDoorID)
	}
}

// FINDING S-2: PROTOCOL §5.2 / SPEC §6.3 define 4 layers of protection
// (Layer 0–3). The watchdog (Layer 3) is an autonomous external
// process, required to remove the key line if the parent dies and the
// parent itself (Layer 2) failed to remove it.
//
// In reality doorController.teardown (door.go:218-229), on a
// dc.door.Remove error (for example, a temporary file lock from
// antivirus/backup, ERROR_SHARING_VIOLATION), only logs it and
// UNCONDITIONALLY calls dc.stopSelfLocked(reason), which kills the
// watchdog (dc.watchdog.Stop()), disarms the timers, and clears
// dc.installed = false!
// The result: the admin access line stays in the file on disk, while
// the emergency watchdog is forcibly killed by the server. The Layer 3
// guarantee is completely broken.
func TestFinding_TeardownMustNotKillWatchdogWhenRemoveFails(t *testing.T) {
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("administrators_authorized_keys")
	cfg := &Config{
		KeyFile:       keyFile,
		DoorLockPath:  filepath.Join(tree.Home, "door.lock"),
		OwnerUID:      testUIDForDoor(),
		OwnerGID:      testGIDForDoor(),
		DoorwatchExe:  "test-doorwatch",
		MaxDoorIdle:   DefaultMaxDoorIdle,
		MaxDoorHard:   DefaultMaxDoorHard,
		SpawnWatchdog: noopSpawnWatchdog,
	}
	dc, err := newDoorController(cfg)
	if err != nil {
		t.Fatalf("newDoorController: %v", err)
	}

	now := time.Now()
	openReq := doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)
	if resp := dc.open(openReq); !resp.OK {
		t.Fatalf("open failed: %+v", resp.Error)
	}

	if !fileContains(t, keyFile, winkeysID(testDoorID)) {
		t.Fatal("door line missing after open")
	}

	// Simulate an external file lock (antivirus, a backup service,
	// etc.) that keeps dc.door.Remove from modifying the file. The
	// path locked must be exactly the one production holds during a
	// write — cfg.DoorLockPath (door.go passes it into
	// NewDoorWithOptions, SPEC §3.2.1: the lock lives in the server's
	// data directory, not next to the key). Emulating it on the wrong
	// path (the legacy <keyFile>.lock) does not block the door write,
	// Remove goes through — and the test would catch the wrong behavior.
	lock, err := winkeys.AcquireFileLock(cfg.DoorLockPath)
	if err != nil {
		t.Fatalf("acquire external file lock: %v", err)
	}
	defer lock.Release()

	// Call teardown on transport loss
	dc.teardown("transport-closed")

	// The line must have remained in the file (because of the lock)
	if !fileContains(t, keyFile, winkeysID(testDoorID)) {
		t.Fatal("expected door line to remain in file because of lock")
	}

	// dc.installed must not have been cleared to false, pretending everything is clean!
	dc.mu.Lock()
	installed := dc.installed
	dc.mu.Unlock()
	if !installed {
		t.Fatal("teardown cleared dc.installed to false despite failing to remove the door line from disk")
	}
}

// FINDING S-3: PROTOCOL §5.1 (line 244) requires:
// "Remove only the line with the exact marker for this doorId; a
// missing line yields {removed:true}; a marker/key mismatch →
// E_CONTROL_DOOR_MISMATCH".
//
// In reality doorController.close (door.go:154-166), on a doorId
// mismatch (door A is installed but a close arrives for door B), does
// not remove door A, does not stop its watchdog and timers, but
// returns okResponse with {DoorID: B, Removed: true}!
// The gateway considers the door closed, while door A stays open in
// the key file forever.
func TestFinding_DoorCloseMismatchedIDReturnsDoorMismatch(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)
	now := time.Now()
	doorIDA := "11111111-1111-1111-1111-111111111111"
	doorIDB := "22222222-2222-2222-2222-222222222222"

	// Install door A
	if r := dc.open(doorOpenRequest(t, doorIDA, now, time.Minute, time.Hour)); !r.OK {
		t.Fatalf("open door A failed: %+v", r.Error)
	}

	// Send a close request for door B
	closeResp := dc.close(controlRequest{
		ID:     "c-mismatch",
		Op:     "door.close",
		DoorID: doorIDB,
		Reason: "stop",
	})

	// Per the PROTOCOL §5.1 spec: a marker mismatch -> refusal E_CONTROL_DOOR_MISMATCH!
	if closeResp.OK {
		t.Fatalf("door.close(mismatched ID) returned OK: true; want error E_CONTROL_DOOR_MISMATCH per PROTOCOL §5.1")
	}
	if closeResp.Error == nil || closeResp.Error.Code != "E_CONTROL_DOOR_MISMATCH" {
		t.Fatalf("got error %+v, want code E_CONTROL_DOOR_MISMATCH", closeResp.Error)
	}

	// Door A must remain in the file
	if !fileContains(t, keyFile, winkeysID(doorIDA)) {
		t.Fatal("door A line was unexpectedly removed")
	}
}

// FINDING S-5: PROTOCOL §5.1 (line 244) defines the exhaustive list of
// valid door-close reasons in controlRequest:
// "reason only idle, hard, stop, tunnel-lost, reconnect, late-reply".
// Any other reason, or its absence, is a protocol format violation
// (E_CONTROL_PROTOCOL).
//
// In reality doorController.close (door.go:154) completely ignores the
// reason field, accepting arbitrary garbage or an empty string, unlike
// door.sanitize, where the reason check is strictly encoded (door.go:198).
func TestFinding_DoorCloseMustValidateReason(t *testing.T) {
	dc, _ := newTestDoorController(t, nil)
	now := time.Now()
	if r := dc.open(doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)); !r.OK {
		t.Fatalf("open failed: %+v", r.Error)
	}

	// A request with an invalid reason
	invalidClose := controlRequest{
		ID:     "c-invalid-reason",
		Op:     "door.close",
		DoorID: testDoorID,
		Reason: "unauthorized-custom-reason",
	}
	resp := dc.close(invalidClose)
	if resp.OK {
		t.Fatalf("door.close with invalid reason %q was accepted, want E_CONTROL_PROTOCOL", invalidClose.Reason)
	}
	if resp.Error == nil || resp.Error.Code != "E_CONTROL_PROTOCOL" {
		t.Fatalf("got error %+v, want E_CONTROL_PROTOCOL", resp.Error)
	}
}
