package winkeys

// iamt332_round10_journal_linked_test.go — IAMT-332 round ten. Round
// nine's REJECT named this call site by name, so the proof lives
// here at the caller and not only in internal/datafile's own suite.
//
// The scenario, in full: an unprivileged user owns a directory that a
// later elevated "server start" is aimed at (--data-dir, the preserved
// IAMTUNNEL_DATA_DIR, a config-file path — the threat model the datafile
// package states, where ANY role directory may be attacker-controlled).
// Before the start, that user plants a HARD LINK at events.jsonl
// pointing at a file they cannot write themselves. On Windows this
// costs nothing: a hard link needs no privilege at all, unlike a
// symlink. NewJournalSink then opens the journal for append, and on
// every round up to nine the link passed — it is a regular file, it is
// not a symlink, it is not a reparse point — so the elevated process
// appended its audit records straight into the victim's file through the
// shared inode.
//
// Round ten refuses the name instead, and the assertions below are the
// two halves of that: the sink must not come back, and the file behind
// the link must be byte-for-byte what it was. The second half is the one
// that matters — a refusal that still wrote is not a refusal.
//
// The same open serves the defensive reopen (ensureOpenLocked) and the
// rotation truncate (truncateToZero) reaches the linked name through
// datafile.OpenExisting, so both inherit this refusal from the same
// place rather than needing a guard of their own.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// TestIAMT332Round10JournalSinkRefusesAHardLinkAtTheName plants a hard
// link at the machine audit journal's name and requires the privileged
// open to refuse it in words, with the victim's file untouched.
func TestIAMT332Round10JournalSinkRefusesAHardLinkAtTheName(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim.txt")
	sentinel := testsupport.WriteSentinelFile(t, victim)
	journal := filepath.Join(dir, "events.jsonl")
	testsupport.PlantHardLinkAt(t, journal, victim)

	sink, err := NewJournalSink(journal, JournalOptions{})
	if err == nil {
		// Drive one record through, so a sink that was wrongly handed
		// back proves the write-through rather than merely implying it.
		sink.OnDoor(Action{Op: "open", DoorID: "iamt332-round10-probe"})
		if c, ok := sink.(interface{ Close() error }); ok {
			_ = c.Close()
		}
		t.Errorf("NewJournalSink opened a hard link planted at %s — the elevated journal open must refuse a name that is a link to another file (IAMT-332 round 10)", journal)
	} else if !strings.Contains(err.Error(), "links") {
		t.Errorf("NewJournalSink refused %s with %q — the refusal must name the link count and what to do about it, not a raw OS error", journal, err)
	}

	testsupport.AssertBytesUnchanged(t, victim, sentinel)
	testsupport.AssertKindStillThere(t, journal, "file")
}
