package record

// Canaries for the IAMT-4 review findings (phase-2 review, the r4 report).
// TestIAMT4H3 once lived here under t.Skip — finding H3 was closed by task
// IAMT-165, the Skip was lifted and the test rewritten against the real seam
// (startup repair via AbortOrphanedRecordings + rotation). No tests under
// Skip remain in this file.

import (
	"os"
	"testing"
	"time"
)

// TestIAMT4H3_OrphanedRecordingStillRotatesAfterCrash — finding H3, closed
// by IAMT-165. After a kill -9 of the gateway the recording is left with
// status:"recording" (recorder.go writes the initial meta before the first
// byte), and Rotate protects that status from deletion both by age and by
// space (rotation.go, steps 1 and 2/3). The fix is the gateway's startup
// sweep: New calls AbortOrphanedRecordings BEFORE the first
// sweepRecordings, and the orphaned metas become "aborted" with reason
// "gateway restart". This test checks the composition at the record
// package's seam: the repair (what the gateway does at startup) plus a
// subsequent rotation by age — a century-old orphaned session must be
// deleted like any ordinary expired one.
//
// Canary: remove the status rewrite in AbortOrphanedRecordings (or the call
// from gateway.New — a mirror test in internal/gateway holds that side) —
// Rotate protects "recording" again and the deletion assertion goes red.
func TestIAMT4H3_OrphanedRecordingStillRotatesAfterCrash(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	// A session whose meta is stuck in "recording" forever: the gateway that
	// wrote it died 100 days ago — older than any retention window.
	orphan := createFakeSession(t, tmpDir, "srv1", "u1", "orphan", now.Add(-100*24*time.Hour), 1000, "recording")
	// A live session of the same age — the repair must not touch it: only
	// the gateway that owns a recording can tell an "orphaned" one from a
	// "live" one, and it knows no live ones remain after a restart; at the
	// package level that limitation is pinned by a separate assertion below
	// (do not touch non-recording).
	finished := createFakeSession(t, tmpDir, "srv1", "u2", "finished", now.Add(-100*24*time.Hour), 1000, "aborted")

	repaired, err := AbortOrphanedRecordings(tmpDir, "gateway restart")
	if err != nil {
		t.Fatalf("AbortOrphanedRecordings: %v", err)
	}
	if len(repaired) != 1 || repaired[0] != orphan {
		t.Fatalf("expected exactly the orphan repaired, got %v", repaired)
	}
	meta, err := ReadMeta(orphan + ".meta")
	if err != nil {
		t.Fatalf("ReadMeta orphan: %v", err)
	}
	if meta.Status != "aborted" || !meta.Aborted || meta.ExitReason != "gateway restart" {
		t.Fatalf("orphan meta must be aborted/aborted:true/exit_reason \"gateway restart\", got status=%q aborted=%v exit_reason=%q", meta.Status, meta.Aborted, meta.ExitReason)
	}
	finMeta, err := ReadMeta(finished + ".meta")
	if err != nil {
		t.Fatalf("ReadMeta finished: %v", err)
	}
	if finMeta.Status != "aborted" || finMeta.ExitReason != "" {
		t.Fatalf("already-finished session must not be re-repaired, got status=%q exit_reason=%q", finMeta.Status, finMeta.ExitReason)
	}

	res, err := Rotate(RotateConfig{Dir: tmpDir, MaxAge: 90 * 24 * time.Hour, Clock: clock})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	deleted := 0
	for _, d := range res.DeletedSessions {
		if d == orphan || d == finished {
			deleted++
		}
	}
	if deleted != 2 {
		t.Fatalf("both 100-day-old sessions (repaired orphan and previously aborted) must rotate away; deleted=%v", res.DeletedSessions)
	}
	for _, base := range []string{orphan, finished} {
		for _, ext := range []string{".cast", ".txt", ".meta"} {
			if _, err := os.Stat(base + ext); !os.IsNotExist(err) {
				t.Errorf("file %s of an expired session must be deleted: %v", base+ext, err)
			}
		}
	}
}
