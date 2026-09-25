package gateway

// iamt167_findings_test.go — the watchdog tests of IAMT-167 (findings H4
// and H11 of the phase-2 reconciliation, the round-4 review report). No
// production code changes here: both tests hold already existing lines
// of gateway.go that no test had read until now.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// TestIAMT167_RotationPruneEventPerDeletion — finding H4: SPEC §6.5
// demands "a deletion is an event"; the code writes admin.op with result
// "rotation.prune" for every deletion (gateway.go, the loop over
// result.DeletedSessions), but no test read the journal after a
// rotation. We seed an expired session, wait for the deletion, read
// events.jsonl: exactly one admin.op event with result
// "rotation.prune" and the session's path in object.
//
// The canary: remove the `for _, deleted := range result.DeletedSessions`
// loop in sweepRecordings -- the event is gone, the first wait assertion
// turns red.
func TestIAMT167_RotationPruneEventPerDeletion(t *testing.T) {
	dir := t.TempDir()
	recDir := filepath.Join(dir, "recordings")
	expired := seedOldSession(t, recDir, iamt144Now(), 100*24*time.Hour)

	f := newFixture(t, func(c *Config) {
		c.Now = iamt144Now
		c.RecordingBaseDir = recDir
		c.RecordingRetentionDays = 1
		c.RecordingRotatePercent = 0    // age only: the event is tested on the age branch
		c.RecordingRotationInterval = 0 // the startup rotation pass, no ticker
	})
	_ = f

	waitUntil(t, "expired session was not pruned by the startup sweep", func() bool {
		_, err := os.Stat(expired + ".cast")
		return os.IsNotExist(err)
	})

	// The file disappeared inside Rotate; the event is appended right
	// after the return -- we wait for the journal line itself to appear,
	// not only for the file to go away.
	waitUntil(t, "journal did not record a rotation.prune event for the deleted session", func() bool {
		evs, _, err := f.log.Read(events.Filter{
			Types:  []events.EventType{events.EventAdminOp},
			Result: "rotation.prune",
		})
		return err == nil && len(evs) == 1 && evs[0].Object == expired
	})

	evs, _, err := f.log.Read(events.Filter{
		Types:  []events.EventType{events.EventAdminOp},
		Result: "rotation.prune",
	})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected exactly one rotation.prune event, got %d", len(evs))
	}
	if evs[0].Object != expired {
		t.Fatalf("rotation.prune must name the deleted session path %s in object, got %q", expired, evs[0].Object)
	}
	if evs[0].Actor != "gateway" {
		t.Fatalf("rotation.prune actor must be \"gateway\", got %q", evs[0].Actor)
	}
}

// seedCompletedSession puts one completed (status "completed") session
// with an exact StartedAt into dir -- the age is set by the caller via
// the at moment, so the two seeded sessions do not conflict over the
// file name.
func seedCompletedSession(t *testing.T, dir, sessionID string, at time.Time) string {
	t.Helper()
	rec, err := record.NewRecorder(record.SessionConfig{
		BaseDir:      dir,
		Machine:      "srv1",
		Person:       "alice",
		OSUser:       `MACHINE\svc`,
		SessionID:    sessionID,
		Cols:         80,
		Rows:         24,
		Clock:        record.NewSimClock(at),
		SubdirLayout: true,
	})
	if err != nil {
		t.Fatalf("seed: NewRecorder: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("seed: Close: %v", err)
	}
	return rec.Paths().CastPath[:len(rec.Paths().CastPath)-len(".cast")]
}

// TestIAMT167_GatewayDiskThresholdPrunesBySpace — finding H11: the line
// `MaxTotalBytesPercent: g.cfg.RecordingRotatePercent` in
// sweepRecordings was held by no test (the iamt144 tests switch the
// size branch off with zero) and could be silently deleted. Here the
// gateway is built with a non-zero space threshold and a substituted
// disk statistic (90% taken by unrelated data, the recordings
// kilobytes): rotation must delete the oldest session -- by filesystem
// fullness, as IAMT-171/PROTOCOL §8 decided.
//
// The canary: remove the `MaxTotalBytesPercent: g.cfg.RecordingRotatePercent`
// argument in gateway.go -- Rotate receives percent=0, the size branch
// switches off, the oldest session outlives the wait, and the first
// assertion turns red.
func TestIAMT167_GatewayDiskThresholdPrunesBySpace(t *testing.T) {
	dir := t.TempDir()
	recDir := filepath.Join(dir, "recordings")
	now := iamt144Now()
	older := seedCompletedSession(t, recDir, "iamt167-older", now.Add(-2*time.Hour))
	newer := seedCompletedSession(t, recDir, "iamt167-newer", now.Add(-1*time.Hour))

	// A disk occupied NOT by recordings: 90% unrelated data with the
	// recordings at kilobytes. The seam is substituted before newFixture
	// -- the startup rotation pass reads the very same one. The restore
	// is t.Cleanup BEFORE newFixture (IAMT-186): cleanups run in reverse
	// order, so the substitution outlives gw.Close and the background
	// rotation goroutine it stops; a defer would restore the global
	// while sweep is still reading it.
	restore := record.SetDiskStatsForTest(func(string) (record.DiskStats, error) {
		return record.DiskStats{TotalBytes: 1 << 30, FreeBytes: (1 << 30) / 10}, nil
	})
	t.Cleanup(restore)

	f := newFixture(t, func(c *Config) {
		c.Now = iamt144Now
		c.RecordingBaseDir = recDir
		c.RecordingRetentionDays = 0 // age off: the space branch is what we test
		c.RecordingRotatePercent = 85
		c.RecordingRotationInterval = 0
	})
	_ = f

	waitUntil(t, "gateway with RecordingRotatePercent=85 and a 90%-full disk did not prune the oldest session — the rotation-percent wiring is not reaching Rotate", func() bool {
		_, err := os.Stat(older + ".cast")
		return os.IsNotExist(err)
	})
	if _, err := os.Stat(newer + ".cast"); err != nil {
		t.Fatalf("newest session must survive (never wipe the archive to 0): %v", err)
	}
}
