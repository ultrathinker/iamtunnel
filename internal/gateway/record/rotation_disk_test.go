package record

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestRotationByDiskPercent pins the IAMT-171 semantics: the percent
// threshold measures the FULLNESS OF THE FILESYSTEM holding cfg.Dir
// (used/total, the same quantity ShouldRefuseNewRecording consults), not a
// ceiling on the recordings' own bytes.
//
// The disk here is 90% full of OTHER data while the two recordings are a
// few kilobytes. Under the pre-IAMT-171 formula (ceiling =
// TotalBytes*pct/100 compared against the recordings' own byte sum) tiny
// recordings could never reach the ceiling and nothing would be deleted;
// under the decided semantics rotation must still run and delete the oldest
// completed session. That asymmetry is exactly the canary this rule
// needs: "a disk filled with NON-recording data — rotation must still delete".
//
// After the deletion the (still 90% full) disk is re-measured: the newer
// session is the only deletable one left, so the never-wipe invariant keeps
// it and Rotate reports DiskStillOverThreshold instead of wiping the
// archive chasing a threshold other data holds up.
func TestRotationByDiskPercent(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	older := createFakeSession(t, tmpDir, "srv1", "u1", "older", now.Add(-3*time.Hour), 1000, "completed")
	newer := createFakeSession(t, tmpDir, "srv1", "u2", "newer", now.Add(-1*time.Hour), 1000, "completed")

	// A 1 TiB volume that is 90% full: the ~4 KiB of recordings are noise.
	restore := SetDiskStatsForTest(func(string) (DiskStats, error) {
		return DiskStats{TotalBytes: 1 << 40, FreeBytes: (1 << 40) / 10}, nil
	})
	defer restore()

	cfg := RotateConfig{Dir: tmpDir, MaxAge: 0, MaxTotalBytesPercent: 85, Clock: clock}
	res, err := Rotate(cfg)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if len(res.DeletedSessions) != 1 {
		t.Fatalf("expected 1 deleted, got %d (%v)", len(res.DeletedSessions), res.DeletedSessions)
	}
	if res.DeletedSessions[0] != older {
		t.Fatalf("expected the older session deleted; got %s", res.DeletedSessions[0])
	}
	if _, err := os.Stat(older + ".cast"); !os.IsNotExist(err) {
		t.Fatalf("older session must be deleted from a 90%%-full disk: %v", err)
	}
	if _, err := os.Stat(newer + ".cast"); err != nil {
		t.Fatalf("newer session must survive (never wipe the archive to 0): %v", err)
	}
	if !res.DiskStillOverThreshold {
		t.Fatalf("disk is still 90%% used with only the protected newest session left; DiskStillOverThreshold must be true")
	}
}

// TestRotationByDiskPercentRechecksAfterEachDeletion proves fullness is
// RE-MEASURED after every deletion (through the disk-stats seam) rather
// than assumed to fall. The fake disk reports 90% used on the first read
// and 80% on every later one: exactly one deletion must happen, because the
// second read is already below the 85% threshold. An implementation that
// kept its initial "90%" notion would delete every candidate up to the
// never-wipe invariant and fail the "exactly 1 deleted" assertion.
func TestRotationByDiskPercentRechecksAfterEachDeletion(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	oldest := createFakeSession(t, tmpDir, "srv1", "u1", "oldest", now.Add(-3*time.Hour), 1000, "completed")
	mid := createFakeSession(t, tmpDir, "srv1", "u2", "mid", now.Add(-2*time.Hour), 1000, "completed")
	newest := createFakeSession(t, tmpDir, "srv1", "u3", "newest", now.Add(-1*time.Hour), 1000, "completed")

	reads := 0
	restore := SetDiskStatsForTest(func(string) (DiskStats, error) {
		reads++
		if reads == 1 {
			return DiskStats{TotalBytes: 1000, FreeBytes: 100}, nil // 90% used
		}
		return DiskStats{TotalBytes: 1000, FreeBytes: 200}, nil // 80% used
	})
	defer restore()

	res, err := Rotate(RotateConfig{Dir: tmpDir, MaxAge: 0, MaxTotalBytesPercent: 85, Clock: clock})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if len(res.DeletedSessions) != 1 || res.DeletedSessions[0] != oldest {
		t.Fatalf("expected exactly the oldest session deleted after the re-read dropped below threshold, got %v", res.DeletedSessions)
	}
	for _, s := range []string{mid, newest} {
		if _, err := os.Stat(s + ".cast"); err != nil {
			t.Fatalf("session %s must survive once the re-read reports 80%% used: %v", s, err)
		}
	}
	if res.DiskStillOverThreshold {
		t.Fatalf("re-read reported 80%% used (< 85%%); DiskStillOverThreshold must be false")
	}
}

// TestRotationByDiskPercentNothingDeletable pins the "no infinite loop"
// half of IAMT-171: when the disk is over the threshold and every remaining
// session is protected ("recording"), Rotate returns at once with
// DiskStillOverThreshold set and deletes nothing.
func TestRotationByDiskPercentNothingDeletable(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	live := createFakeSession(t, tmpDir, "srv1", "u1", "live", now.Add(-1*time.Hour), 1000, "recording")

	restore := SetDiskStatsForTest(func(string) (DiskStats, error) {
		return DiskStats{TotalBytes: 1000, FreeBytes: 10}, nil // 99% used
	})
	defer restore()

	res, err := Rotate(RotateConfig{Dir: tmpDir, MaxAge: 0, MaxTotalBytesPercent: 85, Clock: clock})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if len(res.DeletedSessions) != 0 {
		t.Fatalf("a protected live session must not be deleted by the disk loop: %v", res.DeletedSessions)
	}
	if !res.DiskStillOverThreshold {
		t.Fatalf("disk is 99%% used and nothing deletable remains; DiskStillOverThreshold must be true")
	}
	if _, err := os.Stat(live + ".cast"); err != nil {
		t.Fatalf("live session files must be untouched: %v", err)
	}
}

// TestRotationConfigChangesBehavior is the canary for
// "both settings genuinely govern behavior: a test with a different
// value gives a different result". One 100-day-old session, same
// fixture, two consecutive Rotate calls: first with MaxAge that does
// not prune (100 days > MaxAge), then with the same session reused and
// a tighter MaxAge that does prune.
//
// The point is to assert the bytes on disk change in response to the
// setting, not to assert the harness around Rotate (that already exists
// in rotation_test.go).
func TestRotationConfigChangesBehavior(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	old := createFakeSession(t, tmpDir, "srv1", "u1", "old-sess", now.Add(-100*24*time.Hour), 500, "completed")

	// Pass 1: retention window so wide that nothing is pruned.
	res, err := Rotate(RotateConfig{Dir: tmpDir, MaxAge: 200 * 24 * time.Hour, Clock: clock})
	if err != nil {
		t.Fatalf("Rotate(pass 1): %v", err)
	}
	if len(res.DeletedSessions) != 0 {
		t.Fatalf("pass 1 should not prune anything, deleted=%v", res.DeletedSessions)
	}
	if _, err := os.Stat(old + ".cast"); err != nil {
		t.Fatalf("pass 1 must leave the old session on disk: %v", err)
	}

	// Pass 2: tighter window so the same session gets pruned.
	if _, err := Rotate(RotateConfig{Dir: tmpDir, MaxAge: 30 * 24 * time.Hour, Clock: clock}); err != nil {
		t.Fatalf("Rotate(pass 2): %v", err)
	}
	if _, err := os.Stat(old + ".cast"); !os.IsNotExist(err) {
		t.Fatalf("pass 2 must have deleted the old session: stat err = %v", err)
	}
}

// TestShouldRefuseNewRecording is the disk-percent gate (RUNBOOK §6
// line 11, PROTOCOL §8 recordingRefusePercent).
func TestShouldRefuseNewRecording(t *testing.T) {
	tmpDir := t.TempDir()

	cases := []struct {
		name       string
		total      int64
		free       int64
		refuse     int
		wantRefuse bool
	}{
		{"below threshold is allowed", 100, 80, 95, false}, // 20% used < 95%
		{"at threshold refuses", 100, 5, 95, true},         // 95% used >= 95%
		{"above threshold refuses", 100, 0, 95, true},      // 100% used >= 95%
		{"tighter gate still refuses at 95", 100, 5, 50, true},
		{"looser gate allows 50% full", 100, 50, 95, false},
		{"zero gate disables check", 100, 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restore := SetDiskStatsForTest(func(string) (DiskStats, error) {
				return DiskStats{TotalBytes: tc.total, FreeBytes: tc.free}, nil
			})
			defer restore()

			refuse, used, err := ShouldRefuseNewRecording(tmpDir, tc.refuse)
			if err != nil {
				t.Fatalf("ShouldRefuseNewRecording: %v", err)
			}
			if refuse != tc.wantRefuse {
				t.Fatalf("refuse=%v want=%v (used=%d)", refuse, tc.wantRefuse, used)
			}
		})
	}
}

// TestRotatePercentZeroIsNoSizeCap documents the contract "zero
// MaxTotalBytesPercent disables size-based pruning". A test that tries
// to remove this guard by hardcoding 85 must fail here.
func TestRotatePercentZeroIsNoSizeCap(t *testing.T) {
	tmpDir := t.TempDir()
	now := testBaseTime
	clock := NewSimClock(now)

	// disk stats deliberately bogus; size-based path must be off entirely.
	restore := SetDiskStatsForTest(func(string) (DiskStats, error) {
		return DiskStats{TotalBytes: 1, FreeBytes: 1}, nil
	})
	defer restore()

	s := createFakeSession(t, tmpDir, "srv1", "u1", "fat", now.Add(-1*time.Hour), 10000, "completed")

	res, err := Rotate(RotateConfig{Dir: tmpDir, MaxTotalBytesPercent: 0, Clock: clock})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if len(res.DeletedSessions) != 0 {
		t.Fatalf("percent=0 must not prune by size; deleted=%v", res.DeletedSessions)
	}
	if _, err := os.Stat(filepath.Join(s + ".cast")); err != nil {
		t.Fatalf("session must still be on disk: %v", err)
	}
}

// TestUsedPercentArithmetic pins the percent math so a future refactor
// cannot quietly turn UsedPercent() into a different formula.
func TestUsedPercentArithmetic(t *testing.T) {
	cases := []struct {
		name string
		s    DiskStats
		want int
	}{
		{"empty disk", DiskStats{TotalBytes: 0}, 0},
		{"half used", DiskStats{TotalBytes: 100, FreeBytes: 50}, 50},
		{"all used", DiskStats{TotalBytes: 100, FreeBytes: 0}, 100},
		{"over-allocated clamps to 100", DiskStats{TotalBytes: 100, FreeBytes: 200}, 100},
		{"slight free", DiskStats{TotalBytes: 1000, FreeBytes: 999}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.s.UsedPercent(); got != tc.want {
				t.Fatalf("UsedPercent=%v want=%v", got, tc.want)
			}
		})
	}
}
