package events

// R2-CX F-08 of the round-2 review (24.09.2026), medium: when a
// rotation published its archive and could not open a fresh file, the
// journal came back by itself on the next write (R1-MX F-08) - but it came
// back as a file that BEGINS the journal. Rotate writes the log.rotate line
// that names the archive, and it writes it only after the fresh file is
// open, so the recovery path had no such line and nothing else carried the
// archive's last hash: the next write took the empty file for the start of
// the history and stamped genesis on it. The archive was still there, in
// front of it, unmentioned - and verify-journal, the command that answers
// whether the journal was rewritten, reported the gateway's own journal as
// rewritten. Nobody had touched it; a full disk had.
//
// The fix ties the chain in the recovery, the way Rotate ties it on the
// successful path: the file opened by the recovery, when it is empty and an
// archive was published, gets the log.rotate line whose prev_hash is the
// archive's last line hash.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestR2CXF08_AJournalRecoveredAfterAFailedRotationKeepsItsChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, DefaultLogFileName)
	l, err := OpenChainedLog(logPath)
	if err != nil {
		t.Fatalf("OpenChainedLog: %v", err)
	}
	defer func() { _ = l.Close() }()

	now, _ := state.ParseZonedTime("2026-09-24T12:00:00Z")
	for _, result := range []string{"before-1", "before-2"} {
		if err := l.Append(Event{Time: now, Type: EventDoorOpen, Actor: "gateway", Object: "vm1", Result: result}); err != nil {
			t.Fatalf("Append before the rotation: %v", err)
		}
	}

	// The disk refuses the fresh file: the archive is published and the
	// journal is left without one (the branch R1-MX F-08 covers).
	orig := openAfterRotate
	openAfterRotate = func(string, int, os.FileMode) (*os.File, error) {
		return nil, errors.New("the disk is full")
	}
	archive := filepath.Join(dir, ArchiveName(time.Now()))
	if err := l.Rotate(archive); err == nil {
		t.Fatalf("Rotate reported success although no fresh file could be opened")
	}
	openAfterRotate = orig

	// The disk lets go: the next write brings the journal back by itself.
	if err := l.Append(Event{Time: now, Type: EventDoorOpen, Actor: "gateway", Object: "vm1", Result: "after"}); err != nil {
		t.Fatalf("the write that was to bring the journal back: %v", err)
	}

	// And the file it came back as is not the beginning of the history:
	// the archive in front of it is named, and the chain runs through it.
	rep, err := VerifyChain(dir)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !rep.Intact() {
		t.Errorf("the journal of a gateway whose rotation failed and recovered does not verify: %s — the archive holds the earlier records and the file after it begins the history on its own, so verify-journal reports a journal nobody rewrote as rewritten (F-08)", rep.Summary())
	}

	// The link is the log.rotate line Rotate writes on its successful path,
	// with the archive's last hash - written late, and saying so.
	evs, _, err := ReadFile(logPath, Filter{Types: []EventType{EventLogRotate}})
	if err != nil {
		t.Fatalf("reading the recovered file: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("the recovered file holds %d log.rotate lines, want exactly the one that ties it to the archive: %+v", len(evs), evs)
	}
	if got := evs[0].Details["archive"]; got != archive {
		t.Errorf("the recovered file's log.rotate names the archive as %v, want %s", got, archive)
	}
	last, _, err := lastLine(archive)
	if err != nil {
		t.Fatalf("last line of the archive: %v", err)
	}
	if evs[0].PrevHash != LineHash(last) {
		t.Errorf("the recovered file's first line carries prev_hash %q, want the hash of the archive's last line (%q): the chain has to run through the archive, not restart after it (F-08)", evs[0].PrevHash, LineHash(last))
	}
	if recovered, _ := evs[0].Details["recovered"].(bool); !recovered {
		t.Errorf("the late log.rotate line does not say it was written by the recovery: %+v", evs[0].Details)
	}
	if strings.Contains(rep.Summary(), "BROKEN") {
		t.Errorf("the report reads %q", rep.Summary())
	}
}
