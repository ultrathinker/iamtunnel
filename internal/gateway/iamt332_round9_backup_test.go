package gateway

// iamt332_round9_backup_test.go — the planted-entry tests for the
// backup/restore pair (IAMT-332 round nine): "gateway backup --out"
// writes wherever the operator points, and "gateway restore" is a
// documented sudo run (RUNBOOK §3.3), so every name they touch can be a
// plant. The rows plant at the archive's FINAL name: the backup's
// replace acts on the entry (so the plant itself is not required to
// survive — its sentinel is), and the restore refuses the plant in the
// contract's own words instead of reading through it.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// seedBackupSource writes the two members a backup packs, so the
// archive produced is a real one.
func seedBackupSource(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"people":{}}`), 0o600); err != nil {
		t.Fatalf("seed state.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "events.jsonl"), []byte("{\"type\":\"t\"}\n"), 0o600); err != nil {
		t.Fatalf("seed events.jsonl: %v", err)
	}
}

// TestIAMT332R9WriteBackupIgnoresPlantedOutName pins WriteBackupTarGz
// against plants at the --out name: the archive carries the full
// people/machines/grants state, and the old O_TRUNC open wrote it
// THROUGH a planted symlink or hard link — on Windows a hard link needs
// no privilege at all, so that was a one-call exfiltration of the whole
// gateway state into a file the attacker already controls. The FIFO row
// pins the wedge: the old open blocked on the plant forever.
//
// The plants sit at the archive's FINAL name, and a replace acts on that
// name — so the plant itself is consumed by the successful rename and
// the only thing that must survive byte-for-byte is the sentinel the
// link aims at. The backup must land as a plain regular file at --out.
func TestIAMT332R9WriteBackupIgnoresPlantedOutName(t *testing.T) {
	for _, p := range []struct {
		name string
		// plant sets up the plant at out and returns the sentinel bytes
		// the write must leave untouched (nil when there is none).
		plant func(t *testing.T, out string) []byte
		// promptFailure marks the one plant kind a replace cannot get
		// past on any platform (a directory holds the name), so the row
		// pins only the no-hang contract.
		promptFailure bool
	}{
		{"symlink", func(t *testing.T, out string) []byte {
			_, s := testsupport.PlantSymlinkAt(t, out)
			return s
		}, false},
		{"hard link", func(t *testing.T, out string) []byte {
			s := testsupport.WriteSentinelFile(t, out+".sentinel")
			testsupport.PlantHardLinkAt(t, out, out+".sentinel")
			return s
		}, false},
		{"fifo", func(t *testing.T, out string) []byte {
			testsupport.PlantFIFOAt(t, out)
			return nil
		}, false},
		{"directory", func(t *testing.T, out string) []byte {
			testsupport.PlantDirectoryAt(t, out)
			return nil
		}, true},
	} {
		t.Run(p.name, func(t *testing.T) {
			src := t.TempDir()
			seedBackupSource(t, src)
			outDir := t.TempDir()
			out := filepath.Join(outDir, "backup.tar.gz")
			sentinel := p.plant(t, out)
			err := testsupport.RunBounded(t, 5*time.Second, "WriteBackupTarGz with a planted "+p.name+" at --out", func() error {
				return WriteBackupTarGz(out, src)
			})
			if p.promptFailure {
				// A directory holding the --out name fails the replace
				// on every platform, promptly and without touching
				// anything else. This row pins the no-hang half.
				return
			}
			if err != nil {
				t.Fatalf("WriteBackupTarGz failed: %v — the writer must work around the plant, not fail because of it", err)
			}
			if sentinel != nil {
				testsupport.AssertBytesUnchanged(t, out+".sentinel", sentinel)
			}
			st, serr := os.Stat(out)
			if serr != nil {
				t.Fatalf("the backup was not written: %v", serr)
			}
			if !st.Mode().IsRegular() {
				t.Fatalf("the backup at %s is not a regular file: %v", out, st.Mode())
			}
		})
	}
}

// TestIAMT332R9RestoreRefusesPlantedArchive pins RestoreBackupTarGz
// against plants at the archive's name: the old os.Open read straight
// through a symlink (so the privileged restore unpacked whatever bytes
// the plant aimed it at) and wedged forever on a FIFO.
func TestIAMT332R9RestoreRefusesPlantedArchive(t *testing.T) {
	for _, p := range []struct {
		name  string
		kind  string
		plant func(t *testing.T, at string)
	}{
		{"symlink", "is a symlink", func(t *testing.T, at string) {
			// The link aims at a REAL backup, so the old reader did not
			// merely fail to parse the plant — it happily unpacked it.
			src := t.TempDir()
			seedBackupSource(t, src)
			real := filepath.Join(src, "real.tar.gz")
			if err := WriteBackupTarGz(real, src); err != nil {
				t.Fatalf("build the real archive the link aims at: %v", err)
			}
			if serr := os.Symlink(real, at); serr != nil {
				t.Skipf("this host does not grant symlink creation (%v)", serr)
			}
		}},
		{"directory", "not a regular file", func(t *testing.T, at string) {
			testsupport.PlantDirectoryAt(t, at)
		}},
		{"fifo", "not a regular file", func(t *testing.T, at string) {
			testsupport.PlantFIFOAt(t, at)
		}},
	} {
		t.Run(p.name, func(t *testing.T) {
			dst := t.TempDir()
			at := filepath.Join(dst, "planted.tar.gz")
			p.plant(t, at)
			err := testsupport.RunBounded(t, 5*time.Second, "RestoreBackupTarGz on a planted "+p.name, func() error {
				_, e := RestoreBackupTarGz(at, dst)
				return e
			})
			testsupport.RequireRefusal(t, err, p.kind)
		})
	}
}
