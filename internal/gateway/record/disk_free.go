package record

import (
	"errors"
	"fmt"
	"sync/atomic"
)

// DiskStats is the disk-usage snapshot the rotation and refuse logic consult.
// It deliberately mirrors the shape of `df`: bytes available to a non-priv
// caller, plus the total bytes of the volume, so a percent threshold can be
// expressed either way without the caller doing the arithmetic.
type DiskStats struct {
	TotalBytes int64
	FreeBytes  int64
}

// UsedPercent reports disk usage as an integer percent in [0,100].
// It returns 0 when TotalBytes is zero (the disk has no size, or statfs
// returned zeros) so the caller's threshold check does not divide by zero.
func (s DiskStats) UsedPercent() int {
	if s.TotalBytes <= 0 {
		return 0
	}
	// A free count outside [0, TotalBytes] cannot describe a real volume.
	// Treat it as full, not empty: using a corrupt or inconsistent snapshot to
	// admit a recording would violate the gateway's fail-closed disk policy.
	if s.FreeBytes < 0 || s.FreeBytes > s.TotalBytes {
		return 100
	}
	used := s.TotalBytes - s.FreeBytes
	if used <= 0 {
		return 0
	}
	pct := int(used * 100 / s.TotalBytes)
	if pct > 100 {
		pct = 100
	}
	return pct
}

// diskStatsFnFunc is the signature of the disk-stats seam: one call per
// directory, mirroring one statfs/GetDiskFreeSpaceEx call.
type diskStatsFnFunc func(string) (DiskStats, error)

// diskStatsFn is the seam tests use to make the disk usage deterministic.
// Production leaves it untouched (reads fall through to diskStats); tests
// inject a fake via SetDiskStatsForTest. It stays package state rather than
// a Config field on purpose: every other recording decision (clock,
// recorder, paths) already goes through a constructor argument, but disk
// stats are ambient and reading them once per call from real OS calls is
// fine.
//
// It is held in an atomic.Pointer, not a plain variable, because the
// gateway's rotation sweeper calls it from a background goroutine
// (sweepRecordings -> Rotate) while a test that swapped it may be restoring
// it: with a plain function value that store races the sweeper's load under
// -race (IAMT-186). Readers go through diskStatsFor; nothing else touches
// the pointer.
var diskStatsFn atomic.Pointer[diskStatsFnFunc]

// diskStatsFor returns the disk stats for dir from whichever seam function
// is installed right now: the test-injected one while SetDiskStatsForTest
// is active, the real platform implementation otherwise. The nil pointer of
// a never-swapped seam resolves to diskStats without needing a package
// init. This is the single read site, so every consumer (refusal gate,
// rotation) sees the same atomic view.
func diskStatsFor(dir string) (DiskStats, error) {
	if fn := diskStatsFn.Load(); fn != nil {
		return (*fn)(dir)
	}
	return diskStats(dir)
}

// SetDiskStatsForTest swaps the disk stats implementation. Tests pass a
// function that returns canned numbers; production code never calls this.
// Returns a restore closure so tests can undo the swap on cleanup. Both the
// swap and the restore are atomic stores, so they are safe even while the
// gateway's rotation sweeper is mid-call on another goroutine — though a
// test driving a live gateway should still register the restore with
// t.Cleanup BEFORE building the gateway, so the swap outlives gw.Close and
// no sweep pass ever runs on the host's real disk numbers (IAMT-186).
func SetDiskStatsForTest(fn func(string) (DiskStats, error)) func() {
	var prev diskStatsFnFunc = diskStats
	if p := diskStatsFn.Load(); p != nil {
		prev = *p
	}
	swapped := diskStatsFnFunc(fn)
	diskStatsFn.Store(&swapped)
	return func() { diskStatsFn.Store(&prev) }
}

// diskStats is the real platform implementation. Its body lives in
// disk_free_unix.go and disk_free_windows.go behind build tags.
func diskStats(path string) (DiskStats, error) {
	if path == "" {
		return DiskStats{}, errors.New("diskStats: empty path")
	}
	return platformDiskStats(path)
}

func (s DiskStats) String() string {
	return fmt.Sprintf("total=%d free=%d used=%d%%", s.TotalBytes, s.FreeBytes, s.UsedPercent())
}

// DiskUsedPercent is how full the file system holding dir is, the number
// the refusal threshold and the rotation compare against - what
// gateway.status reports as diskPercent (IAMT-466).
func DiskUsedPercent(dir string) (int, error) {
	stats, err := diskStatsFor(dir)
	if err != nil {
		return 0, err
	}
	return stats.UsedPercent(), nil
}

// ShouldRefuseNewRecording reports whether a fresh recording must be
// refused because the disk holding dir has crossed the refusal threshold.
// It returns (refuse, usedPercent, err); err is non-nil only if the disk
// stats lookup itself failed (the caller cannot then say "refuse" or
// "allow", so a refuse is the safe default — same fail-closed doctrine the
// existing recorder already follows when NewRecorder returns an error).
//
// refusePercent is 1..99; the caller is responsible for validating that.
// Used as the second return so a test can assert the exact percent the
// implementation saw, not just the boolean.
func ShouldRefuseNewRecording(dir string, refusePercent int) (bool, int, error) {
	if refusePercent <= 0 {
		return false, 0, nil
	}
	stats, err := diskStatsFor(dir)
	if err != nil {
		return true, 0, err
	}
	used := stats.UsedPercent()
	if used >= refusePercent {
		return true, used, nil
	}
	return false, used, nil
}
