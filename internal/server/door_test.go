package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// door_test.go covers the doorController level: a well-formed request
// is executed, a malformed or over-ceiling one is refused with the
// file untouched, and a confirmed close removes exactly the line it
// named.

func newTestDoorController(t *testing.T, spawn func(string, string, string, int, time.Duration, string, string, int, int) (*winkeys.Watchdog, error)) (*doorController, string) {
	return newTestDoorControllerWithSink(t, spawn, nil)
}

func newTestDoorControllerWithSink(t *testing.T, spawn func(string, string, string, int, time.Duration, string, string, int, int) (*winkeys.Watchdog, error), sink winkeys.Sink) (*doorController, string) {
	t.Helper()
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("administrators_authorized_keys")
	cfg := &Config{
		KeyFile:      keyFile,
		DoorLockPath: filepath.Join(tree.Home, "door.lock"),
		DoorwatchExe: "unused-in-unit-tests",
		MaxDoorIdle:  DefaultMaxDoorIdle,
		MaxDoorHard:  DefaultMaxDoorHard,
		Sink:         sink,
		OwnerUID:     testUIDForDoor(),
		OwnerGID:     testGIDForDoor(),
	}
	if spawn == nil {
		cfg.SpawnWatchdog = noopSpawnWatchdog
	} else {
		cfg.SpawnWatchdog = spawn
	}
	dc, err := newDoorController(cfg)
	if err != nil {
		t.Fatalf("newDoorController: %v", err)
	}
	return dc, keyFile
}

type doorActionSink chan winkeys.Action

func (s doorActionSink) OnDoor(action winkeys.Action) {
	select {
	case s <- action:
	default:
	}
}

func doorOpenRequest(t *testing.T, id string, opened time.Time, idleDur, hardDur time.Duration) controlRequest {
	t.Helper()
	pub := validPubKeyLine(t)
	return controlRequest{
		Proto: 1, Caps: []string{}, ID: "req-" + id, Op: "door.open",
		Door: &controlDoor{
			ID:           id,
			PubKey:       pub,
			Opened:       opened.Format(time.RFC3339Nano),
			IdleDeadline: opened.Add(idleDur).Format(time.RFC3339Nano),
			HardDeadline: opened.Add(hardDur).Format(time.RFC3339Nano),
		},
	}
}

const testDoorID = "11111111-1111-1111-1111-111111111111"

// fileContains reports whether path contains needle. A door rewrite
// (open, close, sweep) replaces the key file through tmp + rename,
// and a read landing inside that replace window fails transiently
// with ERROR_SHARING_VIOLATION (IAMT-219: since the POSIX-semantics
// rename this needs a fallback filesystem or a filter driver to
// occur, but a poll must not turn a transient sharing violation into
// a hard failure). Exactly that errno is retried briefly — the same
// 20×50 ms bound renameForReplace itself uses; any other read error
// still fails the test on the spot.
func fileContains(t *testing.T, path, needle string) bool {
	t.Helper()
	for i := 0; ; i++ {
		b, err := os.ReadFile(path)
		if err == nil {
			return strings.Contains(string(b), needle)
		}
		if os.IsNotExist(err) {
			return false
		}
		if !isTransientSharingViolation(err) || i >= 20 {
			t.Fatalf("read %s: %v", path, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// ---- item 3: well-formed door.open installs the line, ordered so the
// watchdog exists before the write -----------------------------------------

func TestDoorOpen_InstallsLineAndSpawnsWatchdogBeforeWrite(t *testing.T) {
	var spawnCalls []string
	dc, keyFile := newTestDoorController(t, func(exe, doorID, kf string, pid int, _ time.Duration, _, _ string, _, _ int) (*winkeys.Watchdog, error) {
		// At the moment SpawnWatchdog is called, the line must not be
		// in the file yet (PROTOCOL §5.2: "the watchdog starts BEFORE
		// the line is written").
		if fileContains(t, kf, "iamtunnel-door="+doorID) {
			t.Fatalf("watchdog spawned AFTER the door line was already written")
		}
		spawnCalls = append(spawnCalls, doorID)
		return nil, nil
	})

	now := time.Now()
	req := doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)
	resp := dc.open(req)
	if !resp.OK {
		t.Fatalf("door.open refused: %+v", resp.Error)
	}
	if len(spawnCalls) != 1 || spawnCalls[0] != winkeysID(testDoorID) {
		t.Fatalf("expected exactly one watchdog spawn for %s, got %v", winkeysID(testDoorID), spawnCalls)
	}
	if !fileContains(t, keyFile, "iamtunnel-door="+winkeysID(testDoorID)) {
		t.Fatal("door line not present in key file after a successful open")
	}
	if !fileContains(t, keyFile, winkeys.Options) {
		t.Fatal("door line missing the required restrict,pty,from=\"127.0.0.1\" options prefix")
	}

	// Permissions are narrowed: winkeys.Door.Install narrows the file's
	// DACL as part of a successful install (winkeys/doors_
	// windows.go: lockDownACL); on the platform where that applies, a
	// door.open through this code must actually have triggered it.
	// DACL is a Windows-only concept, so branch on runtime.GOOS rather
	// than winkeys.Supported(): the latter is also true on linux/darwin
	// (doors_unix.go), where winkeys.DACLProtected is a stub that can
	// only return false — the same Supported()-vs-GOOS anti-pattern
	// hardenServerDir shed in IAMT-248 fix2.
	if runtime.GOOS == "windows" {
		protected, err := winkeys.DACLProtected(keyFile)
		if err != nil {
			t.Fatalf("DACLProtected: %v", err)
		}
		if !protected {
			t.Fatal("key file DACL was not narrowed after a successful door.open")
		}
	}
}

func TestDoorOpen_IdempotentSameIDSameKey(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)
	now := time.Now()
	req := doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)

	r1 := dc.open(req)
	if !r1.OK {
		t.Fatalf("first open refused: %+v", r1.Error)
	}
	r2 := dc.open(req)
	if !r2.OK {
		t.Fatalf("idempotent repeat refused: %+v", r2.Error)
	}
	_, wantFingerprint, err := decodeDoorPubKey(req.Door.PubKey)
	if err != nil {
		t.Fatalf("decode test key: %v", err)
	}
	for n, response := range []controlResponse{r1, r2} {
		var result doorOpenResult
		if err := json.Unmarshal(response.Result, &result); err != nil {
			t.Fatalf("response %d has no door.open result: %v", n+1, err)
		}
		if result.DoorID != testDoorID || !result.Installed || result.PublicKeyFingerprint != wantFingerprint {
			t.Fatalf("response %d lied about idempotent door: %+v", n+1, result)
		}
	}
	b, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("read installed key file: %v", err)
	}
	if count := strings.Count(string(b), "iamtunnel-door="+winkeysID(testDoorID)); count != 1 {
		t.Fatalf("idempotent repeat left %d matching door lines, want exactly one: %q", count, b)
	}
}

func TestDoorOpen_SameIDDifferentKeyIsMismatch(t *testing.T) {
	dc, _ := newTestDoorController(t, nil)
	now := time.Now()
	req1 := doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)
	if r := dc.open(req1); !r.OK {
		t.Fatalf("first open refused: %+v", r.Error)
	}

	req2 := doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)
	// Swap in a different, but still valid, key for the same door id.
	req2.Door.PubKey = strings.TrimRight(string(ssh.MarshalAuthorizedKey(mustSigner(t).PublicKey())), "\r\n")
	r2 := dc.open(req2)
	if r2.OK || r2.Error == nil || r2.Error.Code != "E_CONTROL_DOOR_MISMATCH" {
		t.Fatalf("expected E_CONTROL_DOOR_MISMATCH, got %+v", r2)
	}
}

func TestDoorOpen_DifferentIDWhileOneInstalledIsConflict(t *testing.T) {
	dc, _ := newTestDoorController(t, nil)
	now := time.Now()
	if r := dc.open(doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)); !r.OK {
		t.Fatalf("first open refused: %+v", r.Error)
	}
	other := "22222222-2222-2222-2222-222222222222"
	r2 := dc.open(doorOpenRequest(t, other, now, time.Minute, time.Hour))
	if r2.OK || r2.Error == nil || r2.Error.Code != "E_CONTROL_DOOR_CONFLICT" {
		t.Fatalf("expected E_CONTROL_DOOR_CONFLICT, got %+v", r2)
	}
}

// ---- item 4: a bad key or bad deadline order is refused, file untouched --

func TestDoorOpen_MalformedKeyRefusedFileUntouched(t *testing.T) {
	dc, keyFile := newTestDoorController(t, func(string, string, string, int, time.Duration, string, string, int, int) (*winkeys.Watchdog, error) {
		t.Fatal("watchdog must not be spawned for a request that fails validation")
		return nil, nil
	})
	now := time.Now()
	req := doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)
	req.Door.PubKey = "ssh-ed25519 not-valid-base64!!!"

	resp := dc.open(req)
	if resp.OK {
		t.Fatal("malformed key was accepted")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatalf("key file must not have been created at all, stat err=%v", err)
	}
}

func TestDoorOpen_BadDeadlineOrderRefusedFileUntouched(t *testing.T) {
	dc, keyFile := newTestDoorController(t, func(string, string, string, int, time.Duration, string, string, int, int) (*winkeys.Watchdog, error) {
		t.Fatal("watchdog must not be spawned for a request that fails validation")
		return nil, nil
	})
	now := time.Now()
	req := doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)
	// hard before idle: PROTOCOL §5.1 order violated.
	req.Door.HardDeadline = now.Add(30 * time.Second).Format(time.RFC3339Nano)

	resp := dc.open(req)
	if resp.OK {
		t.Fatal("out-of-order deadlines were accepted")
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatalf("key file must not have been created at all, stat err=%v", err)
	}
}

// ---- item 5: a request above the machine's own ceiling is refused -------

func TestDoorOpen_AboveOwnIdleCeilingRefused(t *testing.T) {
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("keys")
	cfg := &Config{
		KeyFile:      keyFile,
		DoorLockPath: filepath.Join(tree.Home, "door.lock"),
		OwnerUID:     testUIDForDoor(),
		OwnerGID:     testGIDForDoor(),
		DoorwatchExe: "unused",
		MaxDoorIdle:  5 * time.Minute, MaxDoorHard: DefaultMaxDoorHard,
		SpawnWatchdog: noopSpawnWatchdog,
	}
	dc, err := newDoorController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	req := doorOpenRequest(t, testDoorID, now, 6*time.Minute, time.Hour) // above the 5-minute ceiling
	resp := dc.open(req)
	if resp.OK || resp.Error == nil || resp.Error.Code != "E_CONTROL_DOOR_LIMIT" {
		t.Fatalf("expected E_CONTROL_DOOR_LIMIT, got %+v", resp)
	}
	if _, err := os.Stat(keyFile); !os.IsNotExist(err) {
		t.Fatal("key file must not have been created for a request above the machine's own ceiling")
	}
}

func TestDoorOpen_AboveOwnHardCeilingRefused(t *testing.T) {
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("keys")
	cfg := &Config{
		KeyFile:      keyFile,
		DoorLockPath: filepath.Join(tree.Home, "door.lock"),
		OwnerUID:     testUIDForDoor(),
		OwnerGID:     testGIDForDoor(),
		DoorwatchExe: "unused",
		MaxDoorIdle:  DefaultMaxDoorIdle, MaxDoorHard: 10 * time.Minute,
		SpawnWatchdog: noopSpawnWatchdog,
	}
	dc, err := newDoorController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	req := doorOpenRequest(t, testDoorID, now, time.Minute, 20*time.Minute) // above the 10-minute ceiling
	resp := dc.open(req)
	if resp.OK || resp.Error == nil || resp.Error.Code != "E_CONTROL_DOOR_LIMIT" {
		t.Fatalf("expected E_CONTROL_DOOR_LIMIT, got %+v", resp)
	}
}

func TestDoorOpen_AtExactlyOwnCeilingAccepted(t *testing.T) {
	tree := testsupport.NewSSHTree(t)
	keyFile := tree.KeyPath("keys")
	cfg := &Config{
		KeyFile:      keyFile,
		DoorLockPath: filepath.Join(tree.Home, "door.lock"),
		OwnerUID:     testUIDForDoor(),
		OwnerGID:     testGIDForDoor(),
		DoorwatchExe: "unused",
		MaxDoorIdle:  5 * time.Minute, MaxDoorHard: time.Hour,
		SpawnWatchdog: noopSpawnWatchdog,
	}
	dc, err := newDoorController(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	req := doorOpenRequest(t, testDoorID, now, 5*time.Minute, time.Hour) // exactly at both ceilings
	resp := dc.open(req)
	if !resp.OK {
		t.Fatalf("a request exactly at the machine's ceiling must be accepted, got %+v", resp.Error)
	}
	_, wantFingerprint, err := decodeDoorPubKey(req.Door.PubKey)
	if err != nil {
		t.Fatalf("decode test key: %v", err)
	}
	var result doorOpenResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		t.Fatalf("accepted request has no door.open result: %v", err)
	}
	if result.DoorID != testDoorID || !result.Installed || result.PublicKeyFingerprint != wantFingerprint {
		t.Fatalf("accepted-at-ceiling response lied: %+v", result)
	}
	if !fileContains(t, keyFile, "iamtunnel-door="+winkeysID(testDoorID)) {
		t.Fatal("accepted-at-ceiling request did not install its door line")
	}
}

// ---- item 6: confirmed close removes exactly the named line -------------

func TestDoorClose_RemovesExactLineAndIsIdempotent(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)
	now := time.Now()
	if r := dc.open(doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)); !r.OK {
		t.Fatalf("open failed: %+v", r.Error)
	}
	if !fileContains(t, keyFile, winkeysID(testDoorID)) {
		t.Fatal("setup: line missing after open")
	}

	resp := dc.close(controlRequest{ID: "c1", Op: "door.close", DoorID: testDoorID, Reason: "stop"})
	if !resp.OK {
		t.Fatalf("close refused: %+v", resp.Error)
	}
	if fileContains(t, keyFile, winkeysID(testDoorID)) {
		t.Fatal("line still present after confirmed close")
	}

	// PROTOCOL §5.1: closing an already-absent door id is idempotent.
	resp2 := dc.close(controlRequest{ID: "c2", Op: "door.close", DoorID: testDoorID, Reason: "stop"})
	if !resp2.OK {
		t.Fatalf("idempotent close on an absent line must still succeed, got %+v", resp2)
	}
}

func TestDoorClose_ForeignLinesUntouched(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)
	foreign := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAdminKeyDoNotTouch111111111 admin@example"
	if err := os.WriteFile(keyFile, []byte(foreign+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if r := dc.open(doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)); !r.OK {
		t.Fatalf("open failed: %+v", r.Error)
	}
	if r := dc.close(controlRequest{ID: "c1", Op: "door.close", DoorID: testDoorID, Reason: "stop"}); !r.OK {
		t.Fatalf("close failed: %+v", r.Error)
	}
	b, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), foreign) {
		t.Fatalf("foreign line was altered or removed; file now: %q", string(b))
	}
}

// ---- door.status reports only marker/id/fingerprint ----------------------

func TestDoorStatus_ReflectsInstalledState(t *testing.T) {
	dc, _ := newTestDoorController(t, nil)
	s0 := dc.status(controlRequest{ID: "s0", Op: "door.status"})
	if !s0.OK {
		t.Fatalf("status failed: %+v", s0.Error)
	}
	var got0 doorStatusResult
	if err := json.Unmarshal(s0.Result, &got0); err != nil {
		t.Fatalf("decode status before open: %v", err)
	}
	if got0.Installed || got0.DoorID != "" || got0.PublicKeyFingerprint != "" {
		t.Fatalf("status before open must be exactly installed:false without door identity, got %+v", got0)
	}

	now := time.Now()
	openReq := doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour)
	if resp := dc.open(openReq); !resp.OK {
		t.Fatalf("open before status: %+v", resp.Error)
	}
	_, wantFP, err := decodeDoorPubKey(openReq.Door.PubKey)
	if err != nil {
		t.Fatalf("decode test door key: %v", err)
	}
	s1 := dc.status(controlRequest{ID: "s1", Op: "door.status"})
	if !s1.OK {
		t.Fatalf("status failed: %+v", s1.Error)
	}
	var got1 doorStatusResult
	if err := json.Unmarshal(s1.Result, &got1); err != nil {
		t.Fatalf("decode status after open: %v", err)
	}
	if !got1.Installed || got1.DoorID != testDoorID || got1.PublicKeyFingerprint != wantFP {
		t.Fatalf("status after open mismatch: got %+v, want installed=true doorId=%q fingerprint=%q", got1, testDoorID, wantFP)
	}
}

// ---- door.sanitize sweeps unconditionally ---------------------------------

func TestDoorSanitize_RemovesOrphanedDoorLineRegardlessOfID(t *testing.T) {
	// winkeys.IsOurs only recognises a marker followed by exactly 32 hex
	// characters (winkeys/doors.go); a marker this controller never
	// installed itself — left behind by, say, a crash before this
	// process started — is exactly what PROTOCOL §5.1's door.sanitize
	// exists to remove regardless of whether the id means anything to
	// this connection.
	dc, keyFile := newTestDoorController(t, nil)
	orphan := winkeys.FormatLine("deadbeefdeadbeefdeadbeefdeadbeef", winkeys.TestKey)
	if err := os.WriteFile(keyFile, []byte(orphan+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := dc.sanitize(controlRequest{ID: "z1", Op: "door.sanitize", Reason: "corrupted"})
	if !resp.OK {
		t.Fatalf("sanitize refused: %+v", resp.Error)
	}
	if fileContains(t, keyFile, "iamtunnel-door=") {
		t.Fatal("orphaned door line survived sanitize")
	}
}

// TestDoorSanitize_RemovesCorruptedMarker proves the control operation uses
// the same corruption-aware sweep as startup, rather than only recognising
// a known valid id.
func TestDoorSanitize_RemovesCorruptedMarker(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)
	corrupt := winkeys.Options + ` ssh-ed25519 ` + winkeys.TestKey + ` iamtunnel-door=not-a-valid-id`
	foreign := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRealForeignKey user@home iamtunnel-door=bad`
	want := []byte(foreign)
	if err := os.WriteFile(keyFile, []byte(corrupt+"\r\n"+foreign), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := dc.sanitize(controlRequest{ID: "z-corrupt", Op: "door.sanitize", Reason: "corrupted"})
	if !resp.OK {
		t.Fatalf("sanitize refused: %+v", resp.Error)
	}
	got, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("sanitize did not preserve foreign bytes:\n got: %q\nwant: %q", got, want)
	}
}

func TestDoorSanitize_RejectsWrongReason(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)
	orphan := winkeys.FormatLine("deadbeefdeadbeefdeadbeefdeadbeef", winkeys.TestKey)
	if err := os.WriteFile(keyFile, []byte(orphan+"\r\n"), 0o600); err != nil {
		t.Fatalf("prepare orphan line: %v", err)
	}
	resp := dc.sanitize(controlRequest{ID: "z1", Op: "door.sanitize", Reason: "because-i-said-so"})
	if resp.OK || resp.Error == nil || resp.Error.Code != "E_CONTROL_PROTOCOL" {
		t.Fatalf("sanitize wrong reason response = %+v, want E_CONTROL_PROTOCOL", resp)
	}
	if !fileContains(t, keyFile, "iamtunnel-door=deadbeefdeadbeefdeadbeefdeadbeef") {
		t.Fatal("rejected sanitize had a side effect and removed the orphan line")
	}
}

// ---- teardown removes the door the machine currently owns -----------------

func TestTeardown_RemovesOwnDoor(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)
	now := time.Now()
	dc.open(doorOpenRequest(t, testDoorID, now, time.Minute, time.Hour))
	dc.teardown("transport-closed")
	if fileContains(t, keyFile, winkeysID(testDoorID)) {
		t.Fatal("door line survived teardown")
	}
	status := dc.status(controlRequest{ID: "status-after-teardown", Op: "door.status"})
	if !status.OK || status.Result == nil {
		t.Fatalf("door.status after teardown failed: %+v", status)
	}
	var result doorStatusResult
	if err := json.Unmarshal(status.Result, &result); err != nil || result.Installed {
		t.Fatalf("controller still reports an installed door after teardown: result=%s err=%v", status.Result, err)
	}
}

func TestTeardown_NoOpWhenNothingInstalled(t *testing.T) {
	dc, _ := newTestDoorController(t, nil)
	dc.teardown("transport-closed") // must not panic or error when there is nothing to remove
}

func waitForDoorRemoval(t *testing.T, keyFile, doorID, why string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !fileContains(t, keyFile, winkeysID(doorID)) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("door line was not removed by %s", why)
}

func TestSelfClose_IdleTimerRemovesOwnDoor(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)
	if resp := dc.open(doorOpenRequest(t, testDoorID, time.Now(), 40*time.Millisecond, time.Second)); !resp.OK {
		t.Fatalf("open failed: %+v", resp.Error)
	}
	waitForDoorRemoval(t, keyFile, testDoorID, "the idle timer")
}

func TestSelfClose_HardTimerRemovesOwnDoorDespiteActivity(t *testing.T) {
	actions := make(doorActionSink, 4)
	dc, _ := newTestDoorControllerWithSink(t, nil, actions)
	const idle = 100 * time.Millisecond
	if resp := dc.open(doorOpenRequest(t, testDoorID, time.Now(), idle, 300*time.Millisecond)); !resp.OK {
		t.Fatalf("open failed: %+v", resp.Error)
	}

	// The check waits for the successful Remove audit, then takes dc.mu through
	// status.  It therefore reads the key file only after the self-close has
	// returned and released its writer state; a concurrent os.ReadFile during
	// MoveFileEx used to make this test itself fail with ERROR_SHARING_VIOLATION.
	touches := time.NewTicker(idle / 4)
	defer touches.Stop()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for {
		select {
		case action := <-actions:
			if action.Op != "close" || action.DoorID != winkeysID(testDoorID) || action.Err != nil {
				continue
			}
			status := dc.status(controlRequest{ID: "status-after-hard-self-close", Op: "door.status"})
			var result doorStatusResult
			if !status.OK || json.Unmarshal(status.Result, &result) != nil || result.Installed {
				t.Fatalf("hard self-close was audited but the released key file still reports a door: %+v", status)
			}
			return
		case <-touches.C:
			dc.touch()
		case <-timeout.C:
			t.Fatal("hard self-close did not emit a successful close while activity continued")
		}
	}
}
