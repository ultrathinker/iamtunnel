//go:build linux || darwin

package winkeys

// iamt332_round9_lock_test.go — the planted-entry tests for the door's
// cross-process lock on Linux and Darwin (IAMT-332 round nine). The
// lock only excludes real writers if the descriptor is on the entry the
// lock path names NOW: the old os.OpenFile followed a plant, so a
// symlink swapped in mid-life moved every later acquire onto the
// attacker's inode while the legitimate holders kept flocking the
// original one — two "holders", no exclusion.
//
// There is no hard-link row: a hard link at the lock path is a regular
// file the datafile contract legitimately opens, and flock(2) is
// per-inode, so a planted link cannot join a flock held by another
// inode in the first place. The plant kinds that matter here are the
// ones whose old open was wrong or blocking.

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// TestIAMT332R9AcquireFileLockRefusesPlantedName pins the refusals of
// AcquireFileLock: a symlink, a directory and a FIFO at the lock path
// must each be refused in the contract's own words. The old
// os.OpenFile(O_RDWR|O_CREATE) SUCCEEDED on the symlink (locking the
// plant's target) and on the FIFO (Linux opens O_RDWR on a FIFO without
// blocking), and answered the directory with a raw "is a directory"
// error no contract ever pinned.
func TestIAMT332R9AcquireFileLockRefusesPlantedName(t *testing.T) {
	for _, row := range []struct {
		name    string
		refusal string
		plant   func(t *testing.T, at string) []byte
	}{
		{"symlink", "is a symlink", func(t *testing.T, at string) []byte {
			_, s := testsupport.PlantSymlinkAt(t, at)
			return s
		}},
		{"directory", "not a regular file", func(t *testing.T, at string) []byte {
			testsupport.PlantDirectoryAt(t, at)
			return nil
		}},
		{"fifo", "not a regular file", func(t *testing.T, at string) []byte {
			testsupport.PlantFIFOAt(t, at)
			return nil
		}},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			at := filepath.Join(dir, "door.lock")
			sentinel := row.plant(t, at)
			err := testsupport.RunBounded(t, 5*time.Second, "AcquireFileLock on a planted "+row.name, func() error {
				l, e := AcquireFileLock(at)
				if e == nil {
					_ = l.Release()
				}
				return e
			})
			testsupport.RequireRefusal(t, err, row.refusal)
			if sentinel != nil {
				testsupport.AssertBytesUnchanged(t, at+".sentinel", sentinel)
			}
		})
	}
}

// TestIAMT332R9AcquireFileLockStillWorks pins the benign path the
// refusal rows must not have broken: a lock file that does not exist is
// created, acquired, and re-acquired only after release — the ordinary
// Install/Remove interleaving.
func TestIAMT332R9AcquireFileLockStillWorks(t *testing.T) {
	dir := t.TempDir()
	at := filepath.Join(dir, "door.lock")
	first, err := AcquireFileLock(at)
	if err != nil {
		t.Fatalf("AcquireFileLock on a fresh lock path: %v", err)
	}
	second, err := AcquireFileLock(at)
	if err == nil {
		_ = second.Release()
		t.Fatal("a second acquire while the lock was held succeeded — the mutual exclusion the lock exists for is gone")
	}
	if err := first.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
	third, err := AcquireFileLock(at)
	if err != nil {
		t.Fatalf("AcquireFileLock after Release: %v", err)
	}
	if err := third.Release(); err != nil {
		t.Fatalf("Release: %v", err)
	}
}
