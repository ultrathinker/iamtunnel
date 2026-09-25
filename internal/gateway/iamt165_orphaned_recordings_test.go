package gateway

// iamt165_orphaned_recordings_test.go — IAMT-165: recordings orphaned
// by a gateway crash. Meta with status:"recording" cannot survive the
// restart of a live gateway (the gateway is the sole owner of the
// recordings), so gateway.New repairs such metas before the first
// sweepRecordings: status:"aborted", exit_reason "gateway restart", an
// admin.op event into the journal for every repaired session. The
// first test pins the repair itself (no race with rotation), the second
// one -- that a repaired orphan is deleted by the very first rotation
// pass.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// seedOrphanedRecording puts a session into dir in exactly the state a
// kill -9 of the gateway leaves it: three files on disk, meta with
// status:"recording", zero EndedAt/Duration. The recorder is created
// and closed for real (file descriptors must not leak in a test on
// Windows), and then the meta is returned to its pre-death look -- as
// if Close/Abort never happened.
func seedOrphanedRecording(t *testing.T, dir, sessionID string, startedAt time.Time) string {
	t.Helper()
	rec, err := record.NewRecorder(record.SessionConfig{
		BaseDir:      dir,
		Machine:      "srv1",
		Person:       "alice",
		OSUser:       `MACHINE\svc`,
		SessionID:    sessionID,
		Cols:         80,
		Rows:         24,
		Clock:        record.NewSimClock(startedAt),
		SubdirLayout: true,
	})
	if err != nil {
		t.Fatalf("seed: NewRecorder: %v", err)
	}
	if err := rec.Abort("seed-cleanup"); err != nil {
		t.Fatalf("seed: Abort: %v", err)
	}
	meta, err := record.ReadMeta(rec.Paths().MetaPath)
	if err != nil {
		t.Fatalf("seed: ReadMeta: %v", err)
	}
	meta.StartedAt = startedAt
	meta.EndedAt = time.Time{}
	meta.DurationSeconds = 0
	meta.Status = "recording"
	meta.Aborted = false
	meta.ExitReason = ""
	if err := record.WriteMeta(rec.Paths().MetaPath, meta, 0600); err != nil {
		t.Fatalf("seed: WriteMeta: %v", err)
	}
	for _, p := range []string{rec.Paths().CastPath, rec.Paths().TxtPath, rec.Paths().MetaPath} {
		if err := os.Chtimes(p, startedAt, startedAt); err != nil {
			t.Fatalf("seed: chtimes %s: %v", p, err)
		}
	}
	base := rec.Paths().CastPath[:len(rec.Paths().CastPath)-len(".cast")]
	return base
}

// TestIAMT165_OrphanedRecordingMarkedAbortedAtStartup pins the startup
// repair itself. Retention 3650 days so that the first sweep deletes
// nothing and the meta can be read without a race: the repair runs
// synchronously in New, before newFixture returns. The canary: remove
// the record.AbortOrphanedRecordings call in gateway.New (or the
// status rewrite inside AbortOrphanedRecordings itself) -- the meta
// stays "recording", and the first status assertion turns red.
func TestIAMT165_OrphanedRecordingMarkedAbortedAtStartup(t *testing.T) {
	dir := t.TempDir()
	recDir := filepath.Join(dir, "recordings")
	orphan := seedOrphanedRecording(t, recDir, "iamt165-orphan", iamt144Now().Add(-100*24*time.Hour))

	f := newFixture(t, func(c *Config) {
		c.Now = iamt144Now
		c.RecordingBaseDir = recDir
		c.RecordingRetentionDays = 3650 // delete nothing: only the repair is under test
		c.RecordingRotatePercent = 0
		c.RecordingRotationInterval = 0
	})
	_ = f

	meta, err := record.ReadMeta(orphan + ".meta")
	if err != nil {
		t.Fatalf("ReadMeta orphan: %v", err)
	}
	if meta.Status != "aborted" {
		t.Fatalf("orphaned \"recording\" meta must be repaired to status \"aborted\" at startup, got %q", meta.Status)
	}
	if !meta.Aborted {
		t.Fatalf("repaired orphan meta must have aborted=true")
	}
	if meta.ExitReason != "gateway restart" {
		t.Fatalf("repaired orphan meta must carry exit_reason \"gateway restart\", got %q", meta.ExitReason)
	}
	for _, ext := range []string{".cast", ".txt", ".meta"} {
		if _, err := os.Stat(orphan + ext); err != nil {
			t.Fatalf("repair must not delete session files (%s): %v", ext, err)
		}
	}

	evs, _, err := f.log.Read(events.Filter{
		Types:  []events.EventType{events.EventAdminOp},
		Result: "recording.abort:gateway restart",
	})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("expected exactly one admin.op repair event, got %d", len(evs))
	}
	if evs[0].Object != orphan {
		t.Fatalf("repair event must name the orphaned session path %s, got %q", orphan, evs[0].Object)
	}
	if evs[0].Actor != "gateway" {
		t.Fatalf("repair event actor must be \"gateway\", got %q", evs[0].Actor)
	}
}

// TestIAMT165_RepairedOrphanRotatesOnFirstSweep closes finding H3 in
// full: after the repair the orphaned session is no longer protected
// by its status, and the very first sweepRecordings pass deletes it by
// age (100 days > 90), with a rotation.prune event. The canary is the
// same as for the repair: without the AbortOrphanedRecordings call in
// New the meta stays "recording", the sweep protects it, and the files
// outlive the wait -- a red first wait assertion.
func TestIAMT165_RepairedOrphanRotatesOnFirstSweep(t *testing.T) {
	dir := t.TempDir()
	recDir := filepath.Join(dir, "recordings")
	orphan := seedOrphanedRecording(t, recDir, "iamt165-prune", iamt144Now().Add(-100*24*time.Hour))

	f := newFixture(t, func(c *Config) {
		c.Now = iamt144Now
		c.RecordingBaseDir = recDir
		c.RecordingRetentionDays = 90
		c.RecordingRotatePercent = 0
		c.RecordingRotationInterval = 0
	})
	_ = f

	waitUntil(t, "repaired orphan was not pruned by the startup rotation sweep (files still on disk)", func() bool {
		_, err := os.Stat(orphan + ".cast")
		return os.IsNotExist(err)
	})

	waitUntil(t, "journal did not record rotation.prune for the repaired orphan", func() bool {
		evs, _, err := f.log.Read(events.Filter{
			Types:  []events.EventType{events.EventAdminOp},
			Result: "rotation.prune",
		})
		return err == nil && len(evs) == 1 && evs[0].Object == orphan
	})

	// The repair must be journalled BEFORE the deletion -- both events are
	// in place.
	aborts, _, err := f.log.Read(events.Filter{
		Types:  []events.EventType{events.EventAdminOp},
		Result: "recording.abort:gateway restart",
	})
	if err != nil {
		t.Fatalf("read journal: %v", err)
	}
	if len(aborts) != 1 || aborts[0].Object != orphan {
		t.Fatalf("expected one repair event naming the orphan, got %v", aborts)
	}
}
