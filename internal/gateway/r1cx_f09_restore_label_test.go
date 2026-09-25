package gateway

// F-09 of the round-1 review (24.09.2026): the names a restore keeps
// its recovery points under were the UTC moment to the second and nothing
// else — state.json.pre-restore-<label> and events-<label>.jsonl. Two
// restores in the same second therefore landed on the same two names: on
// Unix the second one silently replaced the first one's copy of the state
// (the recovery point the operator was told about in the printout), and on
// Windows the journal rename could fail against an occupied name after the
// state had already been replaced.
//
// The clock stands still in this test — the seam exists for exactly this
// question — and the two restores have to come out with two recovery
// points, both readable, both holding what they held.

import (
	"path/filepath"
	"testing"
	"time"
)

func TestR1CXF09_TwoRestoresInTheSameSecondKeepTheirOwnRecoveryPoints(t *testing.T) {
	dir := t.TempDir()
	m8SeedState(t, dir)
	r1cxAppendChained(t, dir, "first")
	archiveA := filepath.Join(t.TempDir(), "a.tar.gz")
	if err := WriteBackupTarGz(archiveA, dir); err != nil {
		t.Fatalf("WriteBackupTarGz A: %v", err)
	}
	m8AddPerson(t, dir, "bob")
	archiveB := filepath.Join(t.TempDir(), "b.tar.gz")
	if err := WriteBackupTarGz(archiveB, dir); err != nil {
		t.Fatalf("WriteBackupTarGz B: %v", err)
	}

	frozen := time.Now().UTC()
	orig := restoreNowFn
	restoreNowFn = func() time.Time { return frozen }
	t.Cleanup(func() { restoreNowFn = orig })

	first, err := RestoreBackupTarGz(archiveA, dir)
	if err != nil {
		t.Fatalf("first restore: %v", err)
	}
	second, err := RestoreBackupTarGz(archiveB, dir)
	if err != nil {
		t.Fatalf("second restore: %v", err)
	}

	if first.StateKeptAs == "" || second.StateKeptAs == "" {
		t.Fatalf("a restore kept no copy of the state it replaced: first=%+v second=%+v", first, second)
	}
	if first.StateKeptAs == second.StateKeptAs {
		t.Errorf("two restores in the same second kept their copy of state.json under one name (%q): the second replaced the first, and the operator who was told about the first recovery point no longer has it (F-09)", first.StateKeptAs)
	}
	if first.JournalKeptAs == second.JournalKeptAs {
		t.Errorf("two restores in the same second rotated the journal to one archive name (%q): the first restore's archive was replaced by the second (F-09)", first.JournalKeptAs)
	}

	// Both recovery points are really there, and the second restore did
	// not eat the first one's archive.
	copies := m8PreRestoreCopies(t, dir)
	if len(copies) != 2 {
		t.Errorf("state.json copies kept across two restores = %v, want two", copies)
	}
	archives := m8JournalArchives(t, dir)
	for _, name := range []string{first.JournalKeptAs, second.JournalKeptAs} {
		if _, ok := archives[name]; !ok {
			t.Errorf("the archive %q a restore reported is not in %v", name, keysOf(archives))
		}
	}
	// And the whole history is still readable through them.
	if evs := m8History(t, dir); !m8HasMarker(evs, "first") {
		t.Errorf("the history no longer holds the event written before the restores: %+v", evs)
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
