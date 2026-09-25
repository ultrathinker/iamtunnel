package events

// F-02 of the round-1 review (24.09.2026): a line that is not JSON
// at all was counted in ChainReport.Unreadable — and nothing else. Intact()
// looked only at Broken and Unvouched, and Summary() had no case for it,
// so a journal with a hole in the middle of it was reported as "intact:
// N line(s) ... every one names the one before it" and `gateway
// verify-journal` exited 0. The command exists to answer one question —
// is the journal whole — and it answered "yes" for a journal with an
// event missing from it.
//
// Two shapes, one verdict, two sentences: a line cut off at the end (a
// crash mid-write) and damage in the middle. The chain still runs through
// an unreadable line — the line after it names its hash — but the journal
// is not intact either way: an event is gone.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestR1CXF02_AJournalWithAnUnreadableLineIsNotIntact(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	iamt467Write(t, path, 0, 2, OpenChainedLog)

	// Damage in the middle: a line that is not JSON, then the chain
	// carries on over it (the next line names its hash, so the link
	// itself still holds).
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("not-json\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	iamt467Write(t, path, 2, 3, OpenChainedLog)

	rep, err := VerifyChain(dir)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if rep.Unreadable != 1 || rep.FirstUnreadableLine != 3 {
		t.Fatalf("precondition: the unreadable line was not found: %+v", rep)
	}
	if rep.Intact() {
		t.Errorf("a journal with a line nobody can read verifies as intact (%q): an event is gone from it, and verify-journal — the command that answers whether the journal is whole — says it is whole (F-02)", rep.Summary())
	}
	if !strings.Contains(rep.Summary(), "could not be read") {
		t.Errorf("the report does not say a line could not be read: %q", rep.Summary())
	}
	if rep.UnreadableAtEnd {
		t.Errorf("damage in the middle is reported as a torn tail: %q", rep.Summary())
	}
	if rep.Broken {
		t.Errorf("the chain through the unreadable line is broken, though the line after it names its hash: %+v", rep)
	}
}

func TestR1CXF02_ATornTailIsNamedAsATornTail(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	iamt467Write(t, path, 0, 2, OpenChainedLog)

	// A crash mid-write: a partial line with no line end.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"time":"2026-09-24T12:00:00Z","type":"admin.op"`); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	rep, err := VerifyChain(dir)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if rep.Intact() {
		t.Errorf("a journal cut off mid-write verifies as intact (%q): the last event never finished, and that is exactly what the operator has to be told (F-02)", rep.Summary())
	}
	if !rep.UnreadableAtEnd {
		t.Errorf("the torn last line is not reported as the end of the journal: %+v (%q)", rep, rep.Summary())
	}
	if !strings.Contains(rep.Summary(), "cut off") {
		t.Errorf("the report does not name the cut-off write: %q", rep.Summary())
	}
}
