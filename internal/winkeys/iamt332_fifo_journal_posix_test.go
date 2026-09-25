//go:build !windows

package winkeys

// iamt332_fifo_journal_posix_test.go — IAMT-332 round seven, the POSIX
// half of the machine audit journal's write-side fix. The journal sink
// opened the journal by final pathname (NewJournalSink), re-opened it by
// name after a deletion (ensureOpenLocked), re-opened it by name again
// inside every rotation (copyCurrentToLocked's read and truncateToZero's
// truncate), and recovery read the rotation marker by name — all raw
// opens with no no-follow protection and no regular-file check, so a
// FIFO planted at the journal's or marker's name hung "server start"
// inside open(2), and a symlink planted mid-life was followed by the
// rotation's second handle. Round seven routes all of them through the
// same state contract as every other data-file open.
//
// The bounded-wait pattern is part of the test's meaning: a genuine hang
// fails the test naming the open that hung, it does not wedge the suite.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestIAMT332Round7JournalSinkRefusesAFIFOPlantedAtTheName plants a FIFO
// at the journal's and the rotation marker's name in turn and requires
// each open or read to come back promptly: the journal open with the
// actionable refusal, the marker recovery as a reported, non-fatal
// refusal (F-307-7: recovery governs nothing about whether a healthy
// journal may open).
func TestIAMT332Round7JournalSinkRefusesAFIFOPlantedAtTheName(t *testing.T) {
	t.Run("NewJournalSink's open of the machine audit journal", func(t *testing.T) {
		dir := t.TempDir()
		journal := filepath.Join(dir, "events.jsonl")
		if err := syscall.Mkfifo(journal, 0o600); err != nil {
			t.Fatalf("plant the FIFO: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := NewJournalSink(journal, JournalOptions{})
			done <- err
		}()
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("NewJournalSink opened a FIFO planted at %s — a data file's name must be refused when it is not a regular file (IAMT-332 round 7)", journal)
			}
			if !strings.Contains(err.Error(), "not a regular file") {
				t.Errorf("NewJournalSink refused %s with %q — the error must say the name is not a regular file and what to do", journal, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("NewJournalSink did not return within 3s — it is blocked on the FIFO planted at %s instead of refusing a non-regular file at the machine audit journal's name (IAMT-332 round 7)", journal)
		}
		if st, serr := os.Lstat(journal); serr != nil || st.Mode()&os.ModeNamedPipe == 0 {
			t.Errorf("the planted FIFO did not survive the refused open (Lstat: %v, %#v) — the refusal must leave the name as it found it", serr, st)
		}
	})

	t.Run("recoverRotationOnOpen's read of the rotation marker (the server's rotator)", func(t *testing.T) {
		reported := openSinkOverAFIFOMarker(t, RotatorRole)
		found := false
		for _, e := range reported {
			if strings.Contains(e.Error(), "not a regular file") {
				found = true
			}
		}
		if !found {
			t.Errorf("opening over a FIFO marker reported %v — the refusal must be named, recovery governs nothing and must say why", reported)
		}
	})

	t.Run("recoverRotationOnOpen's read of the rotation marker (the watchdog's appender)", func(t *testing.T) {
		reported := openSinkOverAFIFOMarker(t, AppenderRole)
		// The appender's report is best-effort and the wording is the
		// rotator's business (F-307-10); what round seven buys here is
		// that the read is PROMPT instead of a hang, asserted above.
		_ = reported
	})
}

// openSinkOverAFIFOMarker plants a healthy journal plus a FIFO at its
// rotation marker's name, opens a sink of the given role under the
// bounded wait, and requires the open to come back promptly with a sink
// (marker failures are reported, never fatal). It also asserts the FIFO
// survived untouched.
func openSinkOverAFIFOMarker(t *testing.T, role JournalRole) []error {
	t.Helper()
	dir := t.TempDir()
	journal := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(journal, []byte("{\"op\":\"seed\"}\n"), 0o600); err != nil {
		t.Fatalf("seed the journal: %v", err)
	}
	marker := journal + ".rotate.marker"
	if err := syscall.Mkfifo(marker, 0o600); err != nil {
		t.Fatalf("plant the FIFO: %v", err)
	}
	var reported []error
	done := make(chan error, 1)
	go func() {
		s, err := NewJournalSink(journal, JournalOptions{Role: role, OnError: func(e error) { reported = append(reported, e) }})
		if s != nil {
			s.(*fileSink).Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("NewJournalSink refused to open over a FIFO planted at the marker %s: %v — recovery failures are reported, not fatal (F-307-7)", marker, err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("NewJournalSink did not return within 3s — recovery is blocked reading the FIFO planted at the rotation marker %s instead of refusing it (IAMT-332 round 7)", marker)
	}
	if st, serr := os.Lstat(marker); serr != nil || st.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("the planted FIFO at the marker did not survive the refused read (Lstat: %v, %#v) — recovery must leave the name as it found it", serr, st)
	}
	return reported
}

// TestIAMT332Round7RotationNeverOpensThroughAPlantedName swaps the live
// journal's name (and the marker draft's name) for a symlink after the
// sink holds its descriptor, and requires every name-based re-open the
// rotation performs to refuse the plant instead of following it: the
// symlink's target must come out of the rotation byte-for-byte intact.
func TestIAMT332Round7RotationNeverOpensThroughAPlantedName(t *testing.T) {
	t.Run("the rotation's copy and truncate of the live journal's name", func(t *testing.T) {
		dir := t.TempDir()
		journal := filepath.Join(dir, "events.jsonl")
		target := filepath.Join(dir, "outside-target.txt")
		sentinel := "iamt332 sentinel: a rotation must not re-open the journal's name through a plant"
		if err := os.WriteFile(target, []byte(sentinel), 0o600); err != nil {
			t.Fatalf("write the sentinel: %v", err)
		}
		var reported []error
		sink, err := NewJournalSink(journal, JournalOptions{MaxBytes: 1, MaxArchives: 5, OnError: func(e error) { reported = append(reported, e) }})
		if err != nil {
			t.Fatalf("NewJournalSink: %v", err)
		}
		defer sink.(*fileSink).Close()
		sink.OnDoor(Action{Op: "open", DoorID: "d1", At: time.Now()})
		// Swap the name out from under the pinned descriptor: the sink
		// keeps writing to the real file it opened; the rotation's
		// name-based re-opens would meet the plant.
		hold := journal + ".hold"
		if err := os.Rename(journal, hold); err != nil {
			t.Fatalf("move the real journal aside: %v", err)
		}
		if err := os.Symlink(target, journal); err != nil {
			t.Fatalf("plant the symlink: %v", err)
		}
		sink.OnDoor(Action{Op: "close", DoorID: "d2", At: time.Now()})
		found := false
		for _, e := range reported {
			if strings.Contains(e.Error(), "symlink") || strings.Contains(e.Error(), "not a regular file") {
				found = true
			}
		}
		if !found {
			t.Errorf("rotating over a symlink planted at the live journal's name %s reported %v — the rotation's re-open must refuse the planted name and say so (IAMT-332 round 7)", journal, reported)
		}
		data, rerr := os.ReadFile(target)
		if rerr != nil || string(data) != sentinel {
			t.Errorf("the rotation followed the symlink planted at %s and destroyed or rewrote its target (read %q, %v) — copy and truncate must refuse the planted name, never follow it (IAMT-332 round 7)", journal, data, rerr)
		}
	})

	t.Run("the rotation marker's draft write at the predictable .partial name", func(t *testing.T) {
		dir := t.TempDir()
		journal := filepath.Join(dir, "events.jsonl")
		draftTarget := filepath.Join(dir, "draft-target.txt")
		sentinel := "iamt332 sentinel: the marker draft must be created, never opened through a plant"
		if err := os.WriteFile(draftTarget, []byte(sentinel), 0o600); err != nil {
			t.Fatalf("write the sentinel: %v", err)
		}
		sink, err := NewJournalSink(journal, JournalOptions{MaxBytes: 1, MaxArchives: 5})
		if err != nil {
			t.Fatalf("NewJournalSink: %v", err)
		}
		defer sink.(*fileSink).Close()
		sink.OnDoor(Action{Op: "open", DoorID: "d1", At: time.Now()})
		draft := journal + ".rotate.marker.partial"
		if err := os.Symlink(draftTarget, draft); err != nil {
			t.Fatalf("plant the symlink at the draft name: %v", err)
		}
		sink.OnDoor(Action{Op: "close", DoorID: "d2", At: time.Now()})
		data, rerr := os.ReadFile(draftTarget)
		if rerr != nil || string(data) != sentinel {
			t.Errorf("the marker draft followed the symlink planted at %s and destroyed or rewrote its target (read %q, %v) — a draft at a predictable temp name must be created O_EXCL, never opened through a plant (IAMT-332 round 7)", draft, data, rerr)
		}
		archives, gerr := filepath.Glob(filepath.Join(dir, "events-*.jsonl"))
		if gerr != nil || len(archives) == 0 {
			t.Fatalf("the rotation did not complete after discarding the planted draft name (archives=%v, %v) — discarding a planted draft must not break the rotation", archives, gerr)
		}
	})
}
