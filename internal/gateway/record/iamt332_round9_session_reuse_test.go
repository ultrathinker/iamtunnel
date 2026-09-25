package record

// iamt332_round9_session_reuse_test.go — the regression the round-nine
// migration introduced (IAMT-332 round 9i), and the tests that pin it
// shut.
//
// A session id is derived from the gateway's injectable clock —
// internal/gateway/human_role.go:271 builds
// "<UnixNano>-<person>-<machine>" — so two sessions of the same person
// on the same machine carry the SAME id whenever that clock does not
// advance between them. That is not a hypothetical: it is what every
// fixture with a frozen clock produces, and the e2e fixture is one
// (test/e2e/harness_test.go:947 pins cfg.Now to a fakeClock frozen at
// 2026-09-12 10:00:00 UTC), so TestScenario19_SessionLimitsEnforced and
// TestScenario21_DoorReopensAfterAutoClose drive the real product
// through two sessions that share one id.
//
// Round nine briefly opened the .cast and the .exec.jsonl with
// datafile.Create — O_CREATE|O_EXCL — which turned that id collision
// into a failed recording, and the gateway treats a failed recording as
// a refused session on purpose (human_role.go:297: "no unrecorded
// access"). Both e2e scenarios then died at the second session, several
// layers away from the cause: scenario 19's limit looked stuck and
// scenario 21's second cycle was cut off right after door.open, which is
// why the first instinct — the door's locking — was the wrong place to
// look.
//
// The name a session derives from its own clock is not evidence of a
// plant. What protects the name is the no-follow, regular-file-only
// discipline of datafile.Open — a symlink, FIFO, junction or directory
// planted there is refused in words before a byte is written — not
// exclusivity, which costs a refused session every time two sessions
// share an id. So the second recorder must succeed exactly as it did
// before round nine, and a planted name must still be refused.
//
// Red-first note: these rows compile against the pre-round-nine tree as
// well (they use only the record package and internal/testsupport, never
// internal/datafile), so the reuse rows can be run against 1b92fad and
// against the round-nine tree that introduced the regression.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// reuseRecorderCfg is the fixture-shaped session: two sessions of the
// same person on the same machine, with a clock that does not advance
// between them, which is precisely the identity human_role.go:271 turns
// into one session id.
func reuseRecorderCfg(dir, base string) SessionConfig {
	return SessionConfig{
		BaseDir:   dir,
		BasePath:  base,
		Machine:   "srv-corp-01",
		Person:    "alex",
		SessionID: "round9-reuse",
		Clock:     NewSimClock(testBaseTime),
	}
}

// TestIAMT332R9ASecondSessionWithTheSameIDStillRecords is the regression
// itself: the same session config twice, in the same directory, must
// produce two working recorders — and two recordings. On the tree that
// made the create O_EXCL, the second NewRecorder fails with "file
// exists" and the gateway drops the session
// (human_role.go:297 answers a recording failure with a dropped
// session), so the second session of any clock that stands still was an
// outage.
func TestIAMT332R9ASecondSessionWithTheSameIDStillRecords(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "2026-09-12", "100000-alex-round9-reuse")
	cfg := reuseRecorderCfg(dir, base)

	first, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("the first session must open: %v", err)
	}
	if _, werr := first.Write([]byte("first session line\r\n")); werr != nil {
		t.Fatalf("the first session must record: %v", werr)
	}
	if aerr := first.Abort("round 9i: first session done"); aerr != nil {
		t.Fatalf("the first session must finalise: %v", aerr)
	}

	// The second session carries the very same id — the clock did not
	// move — and must record exactly like the first one did. A recorder
	// that refuses this name refuses a legitimate session: the gateway
	// answers a recording failure with a refused session
	// (human_role.go:297), which is the functional break this pins.
	second, err := NewRecorder(cfg)
	if err != nil {
		t.Fatalf("the second session with the same id must still open — a session id derived from the clock (human_role.go:271) repeats whenever the clock does not advance, and a repeated name must not refuse the session (round 9i): %v", err)
	}
	if _, werr := second.Write([]byte("second session line\r\n")); werr != nil {
		t.Fatalf("the second session must record: %v", werr)
	}
	if aerr := second.Abort("round 9i: second session done"); aerr != nil {
		t.Fatalf("the second session must finalise: %v", aerr)
	}

	// Two recordings now exist, each holding its own session's output.
	// The name repeats, so the second session took the next name
	// (sessionname.go, the same rule the journal archives follow) — it
	// neither refused the session nor destroyed the earlier recording,
	// which is evidence.
	txts, gerr := filepath.Glob(filepath.Join(filepath.Dir(base), "*.txt"))
	if gerr != nil {
		t.Fatalf("list the transcripts: %v", gerr)
	}
	if len(txts) != 2 {
		t.Fatalf("expected two recordings after two sessions with the same id, got %d (%v) — the second session must take the next name, not refuse the session and not overwrite the first recording", len(txts), txts)
	}
	want := map[string]string{
		base + ".txt":   "first session line",
		base + "_1.txt": "second session line",
	}
	for path, marker := range want {
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Errorf("the transcript %s must exist: %v", path, rerr)
			continue
		}
		if !contains(string(raw), marker) {
			t.Errorf("the transcript %s does not carry %q: %q", path, marker, string(raw))
		}
	}
	// The successor's name must sort after its predecessor's: the
	// recordings tree is read in name order (rotation.go sorts sessions
	// by base path; the fixtures take the last .txt in the walk as "the
	// newest"), so a variant that sorted first would make a later
	// session unreadable as the latest one.
	if !(base+"_1.txt" > base+".txt") {
		t.Errorf("the successor transcript %s does not sort after %s — a later recording must never sort before the one it follows", base+"_1.txt", base+".txt")
	}
}

// TestIAMT332R9ASecondExecSessionWithTheSameIDStillRecords is the same
// regression on the exec recorder, whose .exec.jsonl had the identical
// O_EXCL migration.
func TestIAMT332R9ASecondExecSessionWithTheSameIDStillRecords(t *testing.T) {
	dir := t.TempDir()
	// No BasePath here: the exec recorder builds its base from BaseDir,
	// the person and the session id alone (recordingBasePath in
	// exec_recorder.go does not consult BasePath, unlike NewRecorder's
	// own path construction) — and that clock-derived base is exactly
	// what repeats.
	cfg := reuseRecorderCfg(dir, "")

	first, err := NewExecRecorder(ExecConfig{SessionConfig: cfg, Command: "hostname"})
	if err != nil {
		t.Fatalf("the first exec session must open: %v", err)
	}
	if ferr := first.Finish(); ferr != nil {
		t.Fatalf("the first exec session must finalise: %v", ferr)
	}

	second, err := NewExecRecorder(ExecConfig{SessionConfig: cfg, Command: "hostname"})
	if err != nil {
		t.Fatalf("the second exec session with the same id must still open — the .exec.jsonl name is derived the same way and repeats the same way (round 9i): %v", err)
	}
	if ferr := second.Finish(); ferr != nil {
		t.Fatalf("the second exec session must finalise: %v", ferr)
	}

	execs, gerr := filepath.Glob(filepath.Join(dir, "*.exec.jsonl"))
	if gerr != nil {
		t.Fatalf("list the exec recordings: %v", gerr)
	}
	if len(execs) != 2 {
		t.Fatalf("expected two exec recordings after two sessions with the same id, got %d (%v) — the second session must take the next name instead of failing the recording, which the gateway answers with a dropped session (human_role.go:297)", len(execs), execs)
	}
}

// TestIAMT332R9ACollidingNameIsStillRefusedWhenItIsAPlant is the other
// half of the contract, and it must keep holding after the reuse fix:
// restoring the pre-round-nine reuse semantics must not restore the
// pre-round-nine willingness to open whatever stands at the name. A
// directory is the portable plant (it works on every platform, and on
// Windows it is what a junction lands as), so it anchors this table.
func TestIAMT332R9ACollidingNameIsStillRefusedWhenItIsAPlant(t *testing.T) {
	for _, row := range []struct {
		name  string
		plant func(t *testing.T, path string)
		kind  string
	}{
		{
			name:  "directory at the .cast name",
			plant: func(t *testing.T, path string) { testsupport.PlantDirectoryAt(t, path) },
			kind:  "not a regular file",
		},
		{
			name:  "symlink at the .cast name",
			plant: func(t *testing.T, path string) { testsupport.PlantSymlinkAt(t, path) },
			kind:  "is a symlink",
		},
		{
			name:  "FIFO at the .cast name",
			plant: func(t *testing.T, path string) { testsupport.PlantFIFOAt(t, path) },
			kind:  "not a regular file",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "planted")
			row.plant(t, base+".cast")

			var openErr error
			testsupport.RunBounded(t, 5*time.Second, "NewRecorder over the plant at "+base+".cast", func() error {
				rec, err := NewRecorder(reuseRecorderCfg(dir, base))
				if err != nil {
					openErr = err
					return nil
				}
				_ = rec.Abort("round 9i: the plant was not refused")
				return nil
			})
			testsupport.RequireRefusal(t, openErr, row.kind)
			testsupport.AssertKindStillThere(t, base+".cast", plantKind(row.name))
		})
	}
}

// plantKind maps a row to the entry kind AssertKindStillThere expects.
func plantKind(row string) string {
	switch {
	case contains(row, "directory"):
		return "directory"
	case contains(row, "symlink"):
		return "symlink"
	default:
		return "fifo"
	}
}

// contains is the local substring helper: this file deliberately imports
// nothing beyond the standard library, the record package and
// internal/testsupport, so it keeps compiling against the pre-round-nine
// tree it has to be able to prove the bug in.
func contains(haystack, needle string) bool {
	return len(needle) == 0 || len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
