package winkeys

// iamt332_journal_test.go — IAMT-332 round seven. The machine-side audit
// journal sink — winkeys.NewJournalSink behind "server start" — opened
// <server data dir>/events.jsonl by final pathname with plain
// O_CREATE|O_WRONLY|O_APPEND: no no-follow, no regular-file check, so a
// planted entry at the name was opened through or, for a FIFO, hung the
// privileged start inside open(2) — the write-side twin of the read-side
// class rounds five and six closed. Round seven routes the open through
// the same state contract.
//
// This file plants a DIRECTORY at the name: the portable non-regular
// entry this package's Windows-running tests can plant without
// privilege. (The FIFO — the entry that actually wedges open(2) — is
// proven against the same open in iamt332_fifo_journal_posix_test.go,
// which runs on POSIX.) Before the fix the open answered a planted
// directory with the raw OS error, not the actionable refusal, so the
// wording assertion below is what goes red.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIAMT332Round7JournalSinkRefusesANonRegularEntryAtTheName plants a
// directory at the machine audit journal's name and requires the sink to
// refuse it with the actionable refusal, leaving the name as it found it.
func TestIAMT332Round7JournalSinkRefusesANonRegularEntryAtTheName(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "events.jsonl")
	if err := os.Mkdir(journal, 0o700); err != nil {
		t.Fatalf("plant the directory: %v", err)
	}
	_, err := NewJournalSink(journal, JournalOptions{})
	if err == nil {
		t.Fatalf("NewJournalSink opened a non-regular entry planted at %s — a data file's name must be refused when it is not a regular file (IAMT-332 round 7)", journal)
	}
	if !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("NewJournalSink refused %s with %q — the error must say the name is not a regular file and what to do, not the raw OS open error", journal, err)
	}
	if st, serr := os.Lstat(journal); serr != nil || !st.IsDir() {
		t.Errorf("the planted entry did not survive the refused open (Lstat: %v, %#v) — the refusal must leave the name as it found it, never replace it", serr, st)
	}
}
