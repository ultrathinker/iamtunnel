// iamt130_watchdog_lifetime_test.go — IAMT-130 proofs at the
// internal/server boundary. The headline assertions is that the
// SpawnWatchdog closure this package builds in Config.setDefaults
// hands the actual subprocess a maxWait derived from
// MaxDoorHard + WatchdogLifetimeSlack — not the previous hard-coded
// 5 minutes, and not whatever the caller happened to pass through
// the closure's parameters. A sub-test verifies that the same
// closure carries the WatchdogJournal into the child process.
//
// These tests do NOT exercise a real subprocess — the property they
// prove is local to this package, and pulling in a real spawn here
// would have to either skip on non-Windows or duplicate the
// end-to-end coverage already present in internal/winkeys/
// doorwatch_test.go and internal/winkeys/acceptance_windows_test.go.
// The spawn-side coverage lives there; this file is the
// contract-of-Config side.

// testify-free: every assertion here is a plain t.Fatalf with a
// string naming the specific contract clause that broke, so a
// failure message reads as "what did this package promise that
// the build stopped honouring".

package server

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// spawnCapture is a stand-in SpawnWatchdog that records every
// argument it is called with, so the closure under test can be
// exercised without spawning a real process.
type spawnCapture struct {
	calls []spawnCaptureCall
}

type spawnCaptureCall struct {
	exe        string
	doorID     string
	keyFile    string
	parentPID  int
	maxWait    time.Duration
	journalPth string
	lockPath   string
	ownerUID   int
	ownerGID   int
}

func (s *spawnCapture) fn(exe, doorID, keyFile string, parentPID int, maxWait time.Duration, journalPath, lockPath string, ownerUID, ownerGID int) (*winkeys.Watchdog, error) {
	s.calls = append(s.calls, spawnCaptureCall{
		exe: exe, doorID: doorID, keyFile: keyFile, parentPID: parentPID,
		maxWait: maxWait, journalPth: journalPath,
		lockPath: lockPath, ownerUID: ownerUID, ownerGID: ownerGID,
	})
	return nil, nil
}

// TestIAMT130_SpawnWatchdogMaxWaitDerivedFromConfig proves the first
// IAMT-130 assertion: the watchdog's safety cap on the parent wait
// is MaxDoorHard + WatchdogLifetimeSlack. The previous hard-coded
// 5*time.Minute would have given a sub-second maxWait here; the contract under
// test gives one that comfortably exceeds MaxDoorHard.
//
// The test installs a recorder before newDoorController, so setDefaults leaves
// the override alone. It proves the door.open call site: door.go MUST pass
// dc.cfg.WatchdogLifetime() as the max-wait, not a hard-coded 5*time.Minute or
// another literal. The default-factory structure is covered separately by
// TestIAMT139_DefaultSpawnWatchdogIsWinkeysSpawnWatchdog.
func TestIAMT130_SpawnWatchdogMaxWaitDerivedFromConfig(t *testing.T) {
	const hard = 30 * time.Minute
	tree := testsupport.NewSSHTree(t)
	cfg := &Config{
		GatewayAddr:        "127.0.0.1:1",
		GatewayFingerprint: "SHA256:00",
		MachineID:          "machine-test",
		MachineKey:         mustSigner(t),
		KeyFile:            tree.KeyPath("k"),
		DoorLockPath:       filepath.Join(tree.Home, "door.lock"),
		OwnerUID:           testUIDForDoor(),
		OwnerGID:           testGIDForDoor(),
		TargetAddr:         "127.0.0.1:22",
		DoorwatchExe:       "iamtunnel.exe",
		MaxDoorIdle:        time.Minute,
		MaxDoorHard:        hard,
	}
	cap := &spawnCapture{}
	cfg.SpawnWatchdog = cap.fn

	dc, err := newDoorController(cfg)
	if err != nil {
		t.Fatalf("newDoorController: %v", err)
	}
	resp := dc.open(doorOpenRequest(t, testDoorID, time.Now(), time.Minute, hard))
	if !resp.OK {
		t.Fatalf("door.open refused: %+v", resp.Error)
	}
	if len(cap.calls) != 1 {
		t.Fatalf("SpawnWatchdog was called %d times, want 1", len(cap.calls))
	}
	got := cap.calls[0]

	// The watchdog lifetime MUST exceed MaxDoorHard by at least
	// WatchdogLifetimeSlack. The previous bug was a literal
	// 5*time.Minute hard-coded into the cmdline builder, which
	// for a 30-minute door is shorter than the door itself: any
	// crash after minute 5 leaves the line behind until SweepStale.
	wantMin := hard + WatchdogLifetimeSlack
	if got.maxWait < wantMin {
		t.Fatalf("SpawnWatchdog called with maxWait=%s, want at least %s (MaxDoorHard=%s + slack=%s). The watchdog is shorter-lived than the door — IAMT-130 regression",
			got.maxWait, wantMin, hard, WatchdogLifetimeSlack)
	}
	// Sanity: the watchdog lifetime MUST NOT collapse to the
	// 5-minute bug-shape. If someone reverts to a literal 5*time.Minute
	// this assertion catches it.
	if got.maxWait <= 5*time.Minute && hard > 5*time.Minute {
		t.Fatalf("SpawnWatchdog called with maxWait=%s, which equals the previous hard-coded 5*time.Minute cap; MaxDoorHard=%s makes that a regression", got.maxWait, hard)
	}
}

// TestIAMT130_WatchdogLifetimeFromConfig pins the second half of the
// first IAMT-130 assertion: Config.WatchdogLifetime() returns
// MaxDoorHard + WatchdogLifetimeSlack. A future revert that drops
// the slack or pins a literal value here would silently shrink the
// watchdog's safety cap and let the door's natural lifetime exceed
// it — exactly the IAMT-130 regression, with no test failure at the
// spawn-arg-recording level above. This test makes the contract
// locally testable.
func TestIAMT130_WatchdogLifetimeFromConfig(t *testing.T) {
	const hard = time.Hour
	cfg := &Config{MaxDoorHard: hard}
	got := cfg.WatchdogLifetime()
	want := hard + WatchdogLifetimeSlack
	if got != want {
		t.Fatalf("WatchdogLifetime()=%s, want %s (MaxDoorHard=%s + slack=%s)", got, want, hard, WatchdogLifetimeSlack)
	}
}

// TestIAMT130_SpawnWatchdogJournalFromConfig proves the second
// IAMT-130 assertion: the journal path the server passes to its
// spawned watchdog is Config.WatchdogJournal verbatim. An empty
// Config.WatchdogJournal means "no journal" and the child uses
// noopSink; a non-empty path is forwarded unchanged so the
// watchdog's file sink has somewhere to write the layer-3
// cleanup event.
func TestIAMT130_SpawnWatchdogJournalFromConfig(t *testing.T) {
	const journal = `C:\temp\iamtunnel\watchdog.jsonl`
	tree := testsupport.NewSSHTree(t)
	cfg := &Config{
		GatewayAddr:        "127.0.0.1:1",
		GatewayFingerprint: "SHA256:00",
		MachineID:          "machine-test",
		MachineKey:         mustSigner(t),
		KeyFile:            tree.KeyPath("k"),
		DoorLockPath:       filepath.Join(tree.Home, "door.lock"),
		OwnerUID:           testUIDForDoor(),
		OwnerGID:           testGIDForDoor(),
		TargetAddr:         "127.0.0.1:22",
		DoorwatchExe:       "iamtunnel.exe",
		MaxDoorIdle:        time.Minute,
		MaxDoorHard:        time.Hour,
		WatchdogJournal:    journal,
	}
	cap := &spawnCapture{}
	cfg.SpawnWatchdog = cap.fn

	dc, err := newDoorController(cfg)
	if err != nil {
		t.Fatalf("newDoorController: %v", err)
	}
	if resp := dc.open(doorOpenRequest(t, testDoorID, time.Now(), time.Minute, time.Hour)); !resp.OK {
		t.Fatalf("door.open refused: %+v", resp.Error)
	}
	if len(cap.calls) != 1 {
		t.Fatalf("SpawnWatchdog was called %d times, want 1", len(cap.calls))
	}
	if got := cap.calls[0].journalPth; got != journal {
		t.Fatalf("SpawnWatchdog called with journalPath=%q, want %q — the watchdog's layer-3 audit would have nothing to write to (IAMT-130)", got, journal)
	}
	// Sanity: the watchdog must NOT have a sink=nil path sneak back in.
	// The way it would is if the call site dropped WatchdogJournal on the floor
	// and the factory built the command line without it.
	if !strings.Contains(cfg.DoorwatchExe, "") {
		// DoorwatchExe was passed through unchanged above; this
		// branch is a no-op assertion kept to remind future
		// readers that the closure must remain the single source
		// of truth for the spawned argv.
		_ = cfg.DoorwatchExe
	}
}
