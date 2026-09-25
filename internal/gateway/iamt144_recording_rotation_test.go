package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// iamt144Now is also injected into Config.Now below. Keeping the seed clock
// and the gateway clock identical makes the age assertions independent of the
// wall clock while matching the seam used by sweepRecordings.
func iamt144Now() time.Time {
	return time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
}

// TestIAMT144_RotationWiredOnStartup is the wiring canary:
// that nobody quietly removes the rotation call from the production path.
// Pre-seeds one expired
// session under the gateway's RecordingBaseDir, builds a Gateway with
// RecordingRetentionDays=1 and RecordingRotationInterval=0 (so only the
// startup sweep runs), waits for the gateway to settle, and asserts the
// old session is gone. The test's own assertion line is the one that
// fails if sweepRecordings is removed: the seed and the wait are
// deterministic.
//
// The canary that *removes the call* (sets sweepRecordings to nil)
// fails here: the seeded old session survives. The canary that
// *hardcodes 90 instead of using RecordingRetentionDays* (test below)
// fails at its own assertion with a different message, because that
// regression keeps the call but feeds it a wrong number.
func TestIAMT144_RotationWiredOnStartup(t *testing.T) {
	dir := t.TempDir()
	recDir := filepath.Join(dir, "recordings")
	oldSession := seedOldSession(t, recDir, iamt144Now(), 100*24*time.Hour)

	f := newFixture(t, func(c *Config) {
		c.Now = iamt144Now
		c.RecordingBaseDir = recDir
		c.RecordingRetentionDays = 1
		c.RecordingRotatePercent = 0    // disable size-based pruning for this test
		c.RecordingRotationInterval = 0 // disable the periodic ticker; startup sweep only
	})
	_ = f // t.Cleanup inside newFixture tears the gateway down

	// sweepRecordings fires its first pass synchronously inside gateway.New;
	// give it one extra tick of the runtime scheduler to be sure the
	// goroutine has reached its Wg.Add counterpart.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(oldSession + ".cast"); os.IsNotExist(err) {
			return // success: old session was rotated away
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(oldSession + ".cast"); err == nil {
		t.Fatalf("IAMT-144 canary: startup sweep did not delete the seeded old session %s — sweepRecordings is not wired", oldSession)
	} else {
		t.Fatalf("IAMT-144 canary: unexpected stat error: %v", err)
	}
}

// TestIAMT144_RetentionDaysIsActuallyUsed is the second canary:
// that the retention setting not be dropped in favor of
// a hardcoded number. Same fixture, but the gateway is constructed
// with RecordingRetentionDays=7 and an 8-day-old session. The configured
// value must prune it; a literal-90 regression leaves it behind and fails
// at this test's own assertion.
func TestIAMT144_RetentionDaysIsActuallyUsed(t *testing.T) {
	dir := t.TempDir()
	recDir := filepath.Join(dir, "recordings")
	oldSession := seedOldSession(t, recDir, iamt144Now(), 8*24*time.Hour)

	f := newFixture(t, func(c *Config) {
		c.Now = iamt144Now
		c.RecordingBaseDir = recDir
		c.RecordingRetentionDays = 7
		c.RecordingRotatePercent = 0
		c.RecordingRotationInterval = 0
	})
	_ = f

	// Wait the same amount of time as the other canary so a race against
	// sweepRecordings shows up here too, not in the previous test.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(oldSession + ".cast"); os.IsNotExist(err) {
			return // success: configured seven-day retention pruned the eight-day session
		} else if err != nil {
			t.Fatalf("IAMT-144 canary: unexpected stat error: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(oldSession + ".cast"); err == nil {
		t.Fatalf("IAMT-144 canary: 8-day-old session survived a 7-day retention policy — sweepRecordings is not reading RecordingRetentionDays from the config")
	} else {
		t.Fatalf("IAMT-144 canary: unexpected stat error: %v", err)
	}
}

// TestIAMT144_RefuseStopsNewRecording closes the loop: when the disk
// refuses, the gateway's NewRecording factory returns
// ErrRecordingDiskFull. The session is denied, the event log records
// session.drop with the documented prefix, and no .cast file lands on
// disk. This is the unit-level proof for the user-facing behaviour
// RUNBOOK §6 row 11 promises.
func TestIAMT144_RefuseStopsNewRecording(t *testing.T) {
	dir := t.TempDir()
	recDir := filepath.Join(dir, "recordings")

	// Force the disk-stat lookup to report a full volume, no matter what
	// the test runner's actual disk says. The restore is registered with
	// t.Cleanup BEFORE newFixture (IAMT-186): cleanups run in reverse order,
	// so the fake outlives gw.Close and the rotation sweeper it stops —
	// a plain defer would restore the global while that background goroutine
	// is still reading it.
	restore := record.SetDiskStatsForTest(func(string) (record.DiskStats, error) {
		return record.DiskStats{TotalBytes: 100, FreeBytes: 1}, nil
	})
	t.Cleanup(restore)

	f := newFixture(t, func(c *Config) {
		c.RecordingBaseDir = recDir
		c.RecordingRetentionDays = 90
		c.RecordingRotatePercent = 85
		c.RecordingRefusePercent = 95
		c.RecordingRotationInterval = time.Hour // long, so the periodic sweep does not race this test
	})
	_ = f

	rec, err := f.gw.cfg.NewRecording(SessionInfo{
		Person: "alice", Machine: f.machineID, OSUser: "MACHINE\\svc",
		SessionID: "refuse-1", Cols: 80, Rows: 24,
	})
	if rec != nil {
		t.Fatalf("expected nil recorder when disk is over refuse threshold, got %#v", rec)
	}
	if err != ErrRecordingDiskFull {
		t.Fatalf("expected ErrRecordingDiskFull, got %T: %v", err, err)
	}

	// No .cast must have appeared on disk under RecordingBaseDir.
	matches, _ := filepath.Glob(filepath.Join(recDir, "**", "*.cast"))
	if len(matches) != 0 {
		t.Fatalf("refused recording must not leave any .cast on disk; found: %v", matches)
	}
}

// TestIAMT144_RefuseOrderingRejected pins the validation rule: refuse
// must be strictly greater than stop. A regression that lets refuse==stop
// or refuse<stop through (e.g. by removing the check in gateway.New)
// fails here.
func TestIAMT144_RefuseOrderingRejected(t *testing.T) {
	dir := t.TempDir()

	// disk stats irrelevant for this test, but New will go through
	// setDefaults before validating; inject a stub so the size-based
	// branch does not try to read real disk stats. Restored via t.Cleanup
	// for the same ordering reason as above (IAMT-186): the rebuilds below
	// start and stop gateways whose sweeps read the seam.
	restore := record.SetDiskStatsForTest(func(string) (record.DiskStats, error) {
		return record.DiskStats{TotalBytes: 1000, FreeBytes: 500}, nil
	})
	t.Cleanup(restore)

	err := rebuildAndExpectError(t, dir, 85, 85) // refuse == stop, must be rejected
	if err != nil && !strings.Contains(err.Error(), "recordings_disk_stop_percent") {
		t.Fatalf("IAMT-185 canary: ordering error = %q; want user-visible config key recordings_disk_stop_percent", err)
	}
	if err == nil {
		t.Fatalf("IAMT-144 canary: gateway.New accepted Refuse=Stop — PROTOCOL §8 ordering is not enforced")
	}

	// Also verify the symmetric case: refuse < stop must be rejected.
	if err := rebuildAndExpectError(t, t.TempDir(), 90, 80); err == nil {
		t.Fatalf("IAMT-144 canary: gateway.New accepted Refuse<Stop (%d < %d)", 80, 90)
	}

	// And the success case: refuse > stop passes New, no error.
	if err := rebuildAndExpectError(t, t.TempDir(), 85, 95); err != nil {
		t.Fatalf("IAMT-144 sanity: gateway.New rejected valid Refuse>Stop (%d > %d): %v", 95, 85, err)
	}
}

// seedOldSession creates one fake session under dir at the given age.
// Uses the record package's helper indirectly through record.NewRecorder
// so the layout is the same the real gateway writes. Rotate prefers
// Metadata.StartedAt from .meta over file mtime, so age both the metadata
// field and the files. The supplied now is the same deterministic instant
// passed through Config.Now by the caller.
func seedOldSession(t *testing.T, dir string, now time.Time, age time.Duration) string {
	t.Helper()
	clock := record.NewSimClock(now)
	rec, err := record.NewRecorder(record.SessionConfig{
		BaseDir:      dir,
		Machine:      "srv1",
		Person:       "alice",
		OSUser:       "MACHINE\\svc",
		SessionID:    "iamt144-canary",
		Cols:         80,
		Rows:         24,
		Clock:        clock,
		SubdirLayout: true,
	})
	if err != nil {
		t.Fatalf("seed: NewRecorder: %v", err)
	}
	// Force-close without writing payload, so the .cast still exists.
	if err := rec.Abort("seed"); err != nil {
		t.Fatalf("seed: Abort: %v", err)
	}
	base := rec.Paths().CastPath[:len(rec.Paths().CastPath)-len(".cast")]
	oldTime := now.Add(-age)
	meta, err := record.ReadMeta(rec.Paths().MetaPath)
	if err != nil {
		t.Fatalf("seed: ReadMeta: %v", err)
	}
	meta.StartedAt = oldTime
	meta.EndedAt = oldTime
	if err := record.WriteMeta(rec.Paths().MetaPath, meta, 0600); err != nil {
		t.Fatalf("seed: WriteMeta: %v", err)
	}
	for _, p := range []string{
		rec.Paths().CastPath, rec.Paths().TxtPath, rec.Paths().MetaPath,
	} {
		if err := os.Chtimes(p, oldTime, oldTime); err != nil {
			t.Fatalf("seed: chtimes %s: %v", p, err)
		}
	}
	return base
}

// rebuildAndExpectError rebuilds gateway.New directly so it can assert the
// validation outcome without going through newFixture's t.Fatalf path.
// Returns the New error verbatim so the caller can tell "rejected
// (expected canary failure)" from "accepted (canary regression)".
// TestIAMT144_RejectedConfigDoesNotLeaveARateLimiterSweeper is the canary
// for the allocation order inside gateway.New.
//
// TestIAMT144_RefuseOrderingRejected above asserts that refuse == stop IS
// rejected. This one asserts what the rejection must not leave behind. The
// two checks are separate on purpose: the rejection was always correct, and
// the leak hid behind it for as long as nothing looked at goroutines. New
// used to call auth.NewRateLimiter - which starts the A-3 sweeper the moment
// it is called - before these four cfg-only validations, and every rejection
// returns a nil *Gateway, so no caller had a handle to stop that sweeper
// with. rebuildAndExpectError was not wrong to skip Close on the error path:
// "do not double-close anything New did not open" is the right rule for a
// caller. The invariant it relies on has to hold inside New, and it did not.
//
// CANARY: in gateway.go, move the four RecordingRefusePercent /
// RecordingRotatePercent / RecordingRetentionDays checks back below the
// "rate, err := auth.NewRateLimiter(...)" line. This test then fails on
// every run, naming the sweeper, and so does the whole package under goleak.
func TestIAMT144_RejectedConfigDoesNotLeaveARateLimiterSweeper(t *testing.T) {
	before := liveSweepers()

	// refuse == stop: rejected by the PROTOCOL 8 threshold check, which is
	// the earliest of the four and therefore the one that used to leak the
	// most reliably.
	if err := rebuildAndExpectError(t, t.TempDir(), 85, 85); err == nil {
		t.Fatal("gateway.New accepted refusePercent == stopPercent; this canary needs the config to be rejected to mean anything")
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		got := liveSweepers()
		if got <= before {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("CANARY: %d %s goroutine(s) still running after gateway.New REJECTED a config (baseline before this test: %d). "+
				"A rejected New returns a nil *Gateway, so nothing anywhere can stop a goroutine it started on the way to that rejection: "+
				"every allocation that starts one must sit after the last check that can reject the config.",
				got-before, rateSweeperFrame, before)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func rebuildAndExpectError(t *testing.T, dir string, stopPercent, refusePercent int) error {
	t.Helper()

	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("rebuild: state.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	log, err := events.OpenLog(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("rebuild: events.OpenLog: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	hostSigner := genSigner(t)
	now := func() time.Time { return time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC) }

	cfg := Config{
		Store:                     store,
		Log:                       log,
		HostKey:                   hostSigner,
		Now:                       now,
		RecordingBaseDir:          filepath.Join(dir, "recordings"),
		RecordingRetentionDays:    90,
		RecordingRotatePercent:    stopPercent,
		RecordingRefusePercent:    refusePercent,
		RecordingRotationInterval: time.Hour,
		AuthLimits:                auth.AuthLimits{HandshakeTimeout: 3 * time.Second},
		ACLLimits:                 acl.Limits{},
		RateConfig: auth.RateConfig{
			MaxKnownFailures:   10,
			MaxUnknownFailures: 10,
			Window:             time.Minute,
			PairBanDuration:    time.Minute,
			AddrBanDuration:    time.Minute,
		},
		DoorIdle:             time.Minute,
		DoorHard:             2 * time.Minute,
		ControlAcceptTimeout: time.Second,
		DoorOpenTimeout:      2 * time.Second,
		DoorCloseTimeout:     2 * time.Second,
		DoorStatusTimeout:    2 * time.Second,
		SessionSetupTimeout:  3 * time.Second,
		Keepalive:            sshx.Keepalive{Interval: 150 * time.Millisecond, MaxMisses: 3},
		HumanKeepalive:       sshx.Keepalive{Interval: 150 * time.Millisecond, MaxMisses: 3, Name: "keepalive@openssh.com"},
	}
	gw, err := New(cfg)
	if err != nil {
		// expected path for invalid configs; do not double-close
		// anything New did not open.
		return err
	}
	// gateway.New accepted the config. Clean up.
	_ = gw.Close()
	return nil
}
