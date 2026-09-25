package winkeys

// iamt332_round9_marker_test.go — the planted-entry test for the
// rotation marker's content (IAMT-332 round nine). The marker lives in
// the data directory a privileged run can be aimed at, so its content —
// one attacker-choiceable path — used to be stat'ed and
// ".partial"-removed verbatim: a marker naming a foreign path made the
// privileged recovery delete a file it had no business touching. The
// name is now pinned to this journal's own archive names; anything else
// is reported as corrupt and dropped without acting on it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// TestIAMT332R9MarkerNamingForeignPathIsNotActedOn pins the
// corrupt-marker branch of recoverRotationOnOpen: a marker naming a
// path that is not one of this journal's own archive names must cost
// the named file nothing — including the "<archive>.partial" removal
// the old recovery ran unconditionally against whatever path the marker
// carried.
func TestIAMT332R9MarkerNamingForeignPathIsNotActedOn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	seedRawJSONLLines(t, path, 3)

	// The foreign victim: a sibling directory's file whose ".partial"
	// staging name holds the sentinel. The marker will name the victim;
	// the old recovery removed "<victim>.partial" no matter what the
	// victim was.
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "victim.jsonl")
	victimPartial := victim + partialSuffix
	sentinel := testsupport.WriteSentinelFile(t, victimPartial)

	writeRawRotationMarker(t, path, victim)

	var reported []error
	sink, err := NewJournalSink(path, JournalOptions{Role: RotatorRole, OnError: func(e error) { reported = append(reported, e) }})
	if err != nil {
		t.Fatalf("NewJournalSink refused to open over a corrupt rotation marker: %v", err)
	}
	if sink == nil {
		t.Fatal("NewJournalSink returned a nil sink alongside a nil error")
	}
	defer sink.(*fileSink).Close()

	// The victim's staging file must still hold its bytes: the old code
	// removed "<archivePath>.partial" for whatever path the marker named,
	// so this is the line the old tree fails on.
	testsupport.AssertBytesUnchanged(t, victimPartial, sentinel)

	// The corrupt marker must be dropped (it is bookkeeping for a
	// rotation that never existed) and the corruption must be reported,
	// not swallowed.
	if _, statErr := os.Stat(path + ".rotate.marker"); !os.IsNotExist(statErr) {
		t.Fatalf("a rotation marker naming a foreign path was kept: recovery must drop a marker it refused to act on (%v)", statErr)
	}
	found := false
	for _, e := range reported {
		if strings.Contains(e.Error(), "not one of this journal's own archive names") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("a corrupt rotation marker was not reported as corrupt; reported: %v", reported)
	}

	// And the journal itself must be none the worse: the sink still
	// accepts writes, and the seeded lines are all still there.
	sink.OnDoor(Action{Op: "open", DoorID: "after-corrupt-marker", At: time.Now()})
	lines := readSingleJSONLFile(t, path)
	if len(lines) != 4 {
		t.Fatalf("the journal lost or duplicated lines across a corrupt-marker recovery: got %d lines, want 4", len(lines))
	}
}
