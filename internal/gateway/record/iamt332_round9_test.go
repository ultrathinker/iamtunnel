package record

// iamt332_round9_test.go — the planted-entry tests for the recorder's
// file writes (IAMT-332 round nine). The recordings tree lives under the
// gateway data directory, which a privileged run can be aimed at, and
// the base name of a session is attacker-influenceable (machine, person,
// session id) — so every name the recorder touches can be a plant.
//
// The .cast rows plant at a name datafile.Create opens inside
// NewRecorder: the refusal must happen at OPEN time, before a single
// cast byte is written, so the strongest statement of the contract is
// "NewRecorder refuses" — the old tree instead ran the whole session and
// wrote the header through the plant.
//
// The .txt rows plant at the transcript's FINAL name, which finalize's
// atomic replace acts on: the plant itself is consumed by the successful
// rename and the sentinel it aims at is what must survive byte for byte.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// round9RecorderCfg builds a session config whose files land at exactly
// <base>.cast/.txt/.meta, via the BasePath override, so the tests know
// the precise names to plant.
func round9RecorderCfg(dir, base string) SessionConfig {
	return SessionConfig{
		BaseDir:   dir,
		BasePath:  base,
		Machine:   "srv-corp-01",
		Person:    "alex",
		SessionID: "round9-plant",
		Clock:     NewSimClock(testBaseTime),
	}
}

// runRound9Session runs a short recorded session. It returns the
// OPEN-time error from NewRecorder separately from everything that
// happened later: on the old tree the finalize path's own round-six
// hash open refuses a plant with the same wording the fix uses, so a
// test that asserted on "some error" could pass while the defect — the
// open — went through. RunBounded is the no-hang rule: a plant the old
// code wedged on (a FIFO open) must fail the test with the operation
// named, not deadlock the suite.
func runRound9Session(t *testing.T, what, dir, base string) (openErr, err error) {
	t.Helper()
	testsupport.RunBounded(t, 5*time.Second, what, func() error {
		rec, oerr := NewRecorder(round9RecorderCfg(dir, base))
		if oerr != nil {
			openErr = oerr
			return nil
		}
		if _, werr := rec.Write([]byte("srv-corp-01: round nine transcript line\r\n")); werr != nil {
			err = werr
			_ = rec.Abort("round nine: write failed")
			return nil
		}
		err = rec.Abort("round nine plant test")
		return nil
	})
	return openErr, err
}

// TestIAMT332R9CastCreateRefusesPlantedName pins the .cast open: the old
// O_TRUNC create truncated THROUGH a planted symlink (destroying the
// sentinel the link aims at), hard-linked straight into a sentinel file
// (no privilege needed on Windows), and went straight past a directory
// error nobody worded as a refusal. The recorder must refuse the plant
// before the header is written.
func TestIAMT332R9CastCreateRefusesPlantedName(t *testing.T) {
	for _, row := range []struct {
		name string
		// plant sets up the plant at at and returns the sentinel bytes
		// that must survive (nil when there is none).
		plant func(t *testing.T, at string) []byte
		// refusal is the wording the refusal must carry; empty for the
		// hard-link row, where the contract is the plain pre-existing
		// regular-file refusal of Create (an O_EXCL name collision), not
		// a kind refusal — the entry IS a regular file.
		refusal string
	}{
		{"symlink", func(t *testing.T, at string) []byte {
			_, s := testsupport.PlantSymlinkAt(t, at)
			return s
		}, "is a symlink"},
		{"hard link", func(t *testing.T, at string) []byte {
			s := testsupport.WriteSentinelFile(t, at+".sentinel")
			testsupport.PlantHardLinkAt(t, at, at+".sentinel")
			return s
		}, ""},
		{"directory", func(t *testing.T, at string) []byte {
			testsupport.PlantDirectoryAt(t, at)
			return nil
		}, "not a regular file"},
		{"fifo", func(t *testing.T, at string) []byte {
			testsupport.PlantFIFOAt(t, at)
			return nil
		}, "not a regular file"},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "sess")
			at := base + ".cast"
			sentinel := row.plant(t, at)
			openErr, _ := runRound9Session(t, "a recorded session against a planted "+row.name+" at the .cast name", dir, base)
			if openErr == nil {
				t.Fatalf("NewRecorder ran a whole session against a planted %s at the .cast name instead of refusing it — the refusal must happen at OPEN time, before the cast header is written; later finalize-path errors do not count", row.name)
			}
			if row.refusal != "" {
				testsupport.RequireRefusal(t, openErr, row.refusal)
			}
			if sentinel != nil {
				testsupport.AssertBytesUnchanged(t, at+".sentinel", sentinel)
			}
		})
	}
}

// TestIAMT332R9TxtFinalizeIgnoresPlantedName pins the .txt write in
// finalize: the old flat os.WriteFile truncated THROUGH a planted
// symlink or hard link and wedged forever on a planted FIFO (a
// write-only open of a FIFO blocks until a reader appears). The replace
// acts on the entry, never through it.
func TestIAMT332R9TxtFinalizeIgnoresPlantedName(t *testing.T) {
	for _, row := range []struct {
		name  string
		plant func(t *testing.T, at string) []byte
		// promptFailure marks the one plant kind a replace cannot get
		// past (a directory holds the final name), so the row pins only
		// the no-hang contract.
		promptFailure bool
	}{
		{"symlink", func(t *testing.T, at string) []byte {
			_, s := testsupport.PlantSymlinkAt(t, at)
			return s
		}, false},
		{"hard link", func(t *testing.T, at string) []byte {
			s := testsupport.WriteSentinelFile(t, at+".sentinel")
			testsupport.PlantHardLinkAt(t, at, at+".sentinel")
			return s
		}, false},
		{"fifo", func(t *testing.T, at string) []byte {
			testsupport.PlantFIFOAt(t, at)
			return nil
		}, false},
		{"directory", func(t *testing.T, at string) []byte {
			testsupport.PlantDirectoryAt(t, at)
			return nil
		}, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "sess")
			at := base + ".txt"
			sentinel := row.plant(t, at)
			_, err := runRound9Session(t, "finalize against a planted "+row.name+" at the .txt name", dir, base)
			if row.promptFailure {
				return
			}
			if err != nil {
				t.Fatalf("finalize failed against a planted %s at the .txt name: %v — the transcript write must work around the plant, not fail because of it", row.name, err)
			}
			if sentinel != nil {
				testsupport.AssertBytesUnchanged(t, at+".sentinel", sentinel)
			}
			got, rerr := os.ReadFile(at)
			if rerr != nil {
				t.Fatalf("the transcript was not written: %v", rerr)
			}
			if !strings.Contains(string(got), "round nine transcript line") {
				t.Fatalf("the transcript at %s does not hold the session's output: %q", at, got)
			}
		})
	}
}
