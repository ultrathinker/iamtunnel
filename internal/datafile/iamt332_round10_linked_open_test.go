package datafile

// iamt332_round10_linked_open_test.go — the link-count guard on the
// REUSED-EXISTING-FILE path (IAMT-332 round 10).
//
// Round 9i put the guard on Create, and the round-9 review found the
// half that was missing: Create refuses a linked name, OpenExisting
// accepts one. Everything that reuses a long-lived data file goes
// through OpenExisting — ReadFile, Open's second leg, and above all
// OpenAppend, which is how the machine audit journal
// (internal/winkeys/file_sink.go's NewJournalSink) gets its handle. So
// an unprivileged user who owns a data directory could plant a hard link
// at events.jsonl and have the elevated "server start" append audit
// records into somebody else's file through it: the link is a perfectly
// ordinary regular file, and every check on that path was satisfied.
//
// The hard link is the plant this matters most for because on Windows it
// needs NO privilege at all — unlike a symlink, which wants admin or
// Developer Mode. It is also the only plant in the class that survives
// the "is this a regular file" predicate, which is why the link count is
// the only thing that can separate it from a file of ours.
//
// The guard is on the ALREADY-OPEN DESCRIPTOR, not on the name: fstat on
// POSIX, GetFileInformationByHandle on the Windows handle. That ordering
// is the point — the descriptor is pinned, so there is no check/use gap
// for a link swapped in between the measurement and the open.
//
// Red-first note: every test below fails on 88a139f, where OpenExisting
// returns the opened hard link and the sentinel behind it is appended to.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// plantLinkedName writes a sentinel and plants a hard link to it at the
// data file's name, returning both paths and the bytes that must survive.
func plantLinkedName(t *testing.T, dir, name string) (linked, target string, sentinel []byte) {
	t.Helper()
	target = filepath.Join(dir, name+".sentinel")
	sentinel = testsupport.WriteSentinelFile(t, target)
	linked = filepath.Join(dir, name)
	testsupport.PlantHardLinkAt(t, linked, target)
	return linked, target, sentinel
}

// requireLinkedRefusal is the positive assertion of every row: the error
// must be the typed linked refusal carrying a count of at least two, not
// a bare OS error and not the benign os.ErrExist the callers advance on.
func requireLinkedRefusal(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s accepted a hard link — a linked name must be refused in words, never opened", what)
	}
	var re *RefusalError
	if !errors.As(err, &re) || re.Kind != KindLinked {
		t.Fatalf("%s over a hard link must report the linked refusal, got: %v", what, err)
	}
	if re.Links < 2 {
		t.Errorf("%s: the linked refusal must carry the link count (got %d)", what, re.Links)
	}
	if errors.Is(err, os.ErrExist) {
		t.Errorf("%s: a planted hard link must not read as a benign os.ErrExist — callers advance on that", what)
	}
}

// TestIAMT332R10OpenAppendRefusesALinkedName is the round-9 finding
// verbatim: the journal's append open is the direct write-through
// primitive, and it must refuse the link before the first byte.
func TestIAMT332R10OpenAppendRefusesALinkedName(t *testing.T) {
	dir := t.TempDir()
	linked, target, sentinel := plantLinkedName(t, dir, "events.jsonl")

	f, err := OpenAppend(linked)
	if err == nil {
		_, werr := f.Write([]byte("an audit record the attacker wanted in somebody else's file\n"))
		_ = f.Close()
		t.Errorf("OpenAppend accepted a hard link (the subsequent write returned %v)", werr)
	}
	requireLinkedRefusal(t, err, "OpenAppend")
	testsupport.AssertBytesUnchanged(t, target, sentinel)
	testsupport.AssertKindStillThere(t, linked, "file")
}

// TestIAMT332R10OpenExistingRefusesALinkedName covers the primitive
// itself, in both the read and the write direction: a reader through a
// link is a disclosure, a writer through one is the destruction.
func TestIAMT332R10OpenExistingRefusesALinkedName(t *testing.T) {
	for _, row := range []struct {
		name  string
		flags int
	}{
		{name: "read", flags: os.O_RDONLY},
		{name: "write", flags: os.O_WRONLY},
		{name: "append", flags: os.O_WRONLY | os.O_APPEND},
	} {
		t.Run(row.name, func(t *testing.T) {
			dir := t.TempDir()
			linked, target, sentinel := plantLinkedName(t, dir, "state.json")

			f, err := OpenExisting(linked, row.flags)
			if err == nil {
				_ = f.Close()
			}
			requireLinkedRefusal(t, err, "OpenExisting("+row.name+")")
			testsupport.AssertBytesUnchanged(t, target, sentinel)
		})
	}
}

// TestIAMT332R10OpenRefusesALinkedName covers the two-legged Open: the
// O_EXCL creation leg fails on an existing name, and the second leg must
// carry the same refusal rather than handing back the link. This is the
// door lock's open (internal/winkeys/doors_unix.go).
func TestIAMT332R10OpenRefusesALinkedName(t *testing.T) {
	dir := t.TempDir()
	linked, target, sentinel := plantLinkedName(t, dir, "doors.lock")

	f, err := Open(linked, os.O_RDWR, 0o600)
	if err == nil {
		_ = f.Close()
	}
	requireLinkedRefusal(t, err, "Open")
	testsupport.AssertBytesUnchanged(t, target, sentinel)
}

// TestIAMT332R10ReadFileRefusesALinkedName is the read half of the
// contract: the bytes of a file the caller has no business reading must
// not come back just because a link made them reachable under our name.
func TestIAMT332R10ReadFileRefusesALinkedName(t *testing.T) {
	dir := t.TempDir()
	linked, target, sentinel := plantLinkedName(t, dir, "known_hosts")

	got, err := ReadFile(linked)
	if err == nil {
		t.Errorf("ReadFile returned %d bytes through a hard link", len(got))
	}
	requireLinkedRefusal(t, err, "ReadFile")
	testsupport.AssertBytesUnchanged(t, target, sentinel)
}

// TestIAMT332R10PlainFilesStillOpen is the other half, and the one that
// keeps the guard from being a denial of service against ourselves: an
// ordinary singly-linked data file — the overwhelmingly normal case, a
// journal or a lock left by the previous run — must still open through
// every entry point, and OpenAppend must still create a missing name.
func TestIAMT332R10PlainFilesStillOpen(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(existing, []byte("a record from the previous run\n"), 0o600); err != nil {
		t.Fatalf("write the existing journal: %v", err)
	}

	f, err := OpenAppend(existing)
	if err != nil {
		t.Fatalf("OpenAppend refused an ordinary singly-linked journal: %v", err)
	}
	if _, werr := f.Write([]byte("a record from this run\n")); werr != nil {
		t.Errorf("appending to an ordinary journal failed: %v", werr)
	}
	_ = f.Close()

	raw, rerr := ReadFile(existing)
	if rerr != nil {
		t.Fatalf("ReadFile refused an ordinary singly-linked journal: %v", rerr)
	}
	if string(raw) != "a record from the previous run\na record from this run\n" {
		t.Errorf("the ordinary append did not land: got %q", raw)
	}

	fresh := filepath.Join(dir, "fresh.jsonl")
	nf, nerr := OpenAppend(fresh)
	if nerr != nil {
		t.Fatalf("OpenAppend must still create a genuinely missing name: %v", nerr)
	}
	_ = nf.Close()
	if _, serr := os.Lstat(fresh); serr != nil {
		t.Errorf("the missing name was not created: %v", serr)
	}
}
