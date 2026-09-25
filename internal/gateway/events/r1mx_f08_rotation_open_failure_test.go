package events

// F-08 of the round-1 review (24.09.2026): Rotate renames the
// current journal into an archive and only then opens a fresh file. When
// that open fails, the archive IS published, the log.rotate line - which
// belongs in the new file, as its first line, telling a reader where the
// previous records went - is never written, and nothing anywhere says a
// rotation happened: every later write reported "log is closed", which
// blames the gateway's own shutdown for a rotation the disk refused.
//
// The line itself cannot be saved by writing it into the archive instead:
// a log.rotate line in the archive says the opposite of what it is for
// (it names where the CURRENT records go), and the reading side
// (ReadHistory) walks the archives for the records themselves. What the
// fix does instead is make the failure name itself - the rotation, the
// archive it published, and the open that failed - and let the journal
// come back on its own when whatever refused the open lets go.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestR1MXF08_ARotationThatCannotOpenItsNewFileSaysSoOnEveryLaterWrite(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, DefaultLogFileName)
	l, err := OpenLog(logPath)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	defer func() { _ = l.Close() }()

	now, _ := state.ParseZonedTime("2026-09-24T12:00:00Z")
	before := Event{Time: now, Type: EventDoorOpen, Actor: "gateway", Object: "vm1", Result: "ok"}
	if err := l.Append(before); err != nil {
		t.Fatalf("Append before the rotation: %v", err)
	}

	// The disk fills up exactly between the rename and the fresh file.
	orig := openAfterRotate
	openAfterRotate = func(string, int, os.FileMode) (*os.File, error) {
		return nil, errors.New("there is not enough space on the disk")
	}
	t.Cleanup(func() { openAfterRotate = orig })

	archive := filepath.Join(dir, ArchiveName(time.Now()))
	if err := l.Rotate(archive); err == nil {
		t.Fatalf("Rotate reported success although no fresh file could be opened")
	}
	// The rotation itself did happen: the archive holds the record.
	if _, err := os.Stat(archive); err != nil {
		t.Fatalf("the archive was not published: %v", err)
	}

	// Every later write has to name the rotation and the archive, not the
	// gateway's own close (F-08): this error text is what the gateway
	// publishes as the reason its journal stopped (IAMT-451), so an
	// operator reading gateway status has to be able to see a rotation
	// that could not finish rather than a shutdown that never happened.
	err = l.Append(Event{Time: now, Type: EventDoorOpen, Actor: "gateway", Object: "vm1", Result: "ok"})
	if err == nil {
		t.Fatalf("a write after the failed rotation succeeded")
	}
	if strings.Contains(err.Error(), "log is closed") {
		t.Errorf("a write after a rotation that could not open a fresh file says %q: that blames the gateway's own shutdown, and the rotation - and the archive it did publish - goes unmentioned (F-08)", err)
	}
	if !strings.Contains(err.Error(), "rotated to") || !strings.Contains(err.Error(), filepath.Base(archive)) {
		t.Errorf("the write after the failed rotation says %q, want it to name the rotation and the archive it published (%s)", err, filepath.Base(archive))
	}

	// And the journal comes back by itself: whatever refused the open may
	// let go, and IAMT-451's contract is that the gateway fails until a
	// write succeeds - not until somebody restarts it.
	openAfterRotate = orig
	if err := l.Append(Event{Time: now, Type: EventDoorOpen, Actor: "gateway", Object: "vm1", Result: "recovered"}); err != nil {
		t.Errorf("the journal did not write again once the disk let go: %v", err)
	}
	evs, _, err := l.ReadAll(Filter{})
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	recovered := false
	for _, e := range evs {
		if e.Result == "recovered" {
			recovered = true
		}
	}
	if !recovered {
		t.Errorf("the journal after the recovery holds %+v, want the event written after it", evs)
	}
}

func TestR1MXF08_AClosedLogStillSaysItIsClosed(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLog(filepath.Join(dir, DefaultLogFileName))
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	now, _ := state.ParseZonedTime("2026-09-24T12:00:00Z")
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err = l.Append(Event{Time: now, Type: EventDoorOpen, Actor: "gateway", Object: "vm1", Result: "ok"})
	if err == nil || !strings.Contains(err.Error(), "log is closed") {
		t.Errorf("a write to a closed log says %v, want it to keep saying the log is closed (F-08 keeps a lost file and a closed log apart)", err)
	}
}
