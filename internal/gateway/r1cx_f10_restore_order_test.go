package gateway

// F-10 of the round-1 review (24.09.2026): the restore wrote the new
// state.json FIRST and only then rotated the journal and recorded what it
// had done. Every later step could fail — and did nothing to the state
// that had already been replaced — so a failed restore left a gateway
// whose state came from the backup while its journal still described the
// state before it, with no line anywhere saying a restore had been tried.
//
// The order in the fix is: keep what is replaced, do the journal work that
// is safe to leave half-done (a rotation keeps the whole history), THEN
// replace the state, then record it. A failure before the state write
// leaves the gateway exactly as it was; a failure after it (installing the
// archive's own journal, or the record) says in the error what was
// installed and what was not.
//
// This test makes the journal step fail for real — the journal is made
// read-only, so opening it for the rotation is refused — and asks the one
// question the finding asks: is the state still the one that was here
// before?

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestR1CXF10_AFailedRestoreLeavesTheStateItFound(t *testing.T) {
	dir := t.TempDir()
	m8SeedState(t, dir)
	r1cxAppendChained(t, dir, "beforeBackup")
	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := WriteBackupTarGz(archive, dir); err != nil {
		t.Fatalf("WriteBackupTarGz: %v", err)
	}

	// The state moves on after the backup: bob exists here and not in the
	// archive, and he is what a failed restore must not lose.
	m8AddPerson(t, dir, "bob")
	journalPath := filepath.Join(dir, events.DefaultLogFileName)
	if err := os.Chmod(journalPath, 0o400); err != nil {
		t.Skipf("cannot make the journal read-only here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(journalPath, 0o600) })

	if _, err := RestoreBackupTarGz(archive, dir); err == nil {
		t.Fatalf("the restore reported success although the journal could not be opened for the rotation")
	}

	// What the operator is left with has to be the gateway they had, not
	// half of the backup: the state write is the commit point, and nothing
	// after it may have run.
	st, err := readStateForTest(dir)
	if err != nil {
		t.Fatalf("read the state after the failed restore: %v", err)
	}
	found := false
	for _, p := range st.People {
		if p.Name == "bob" {
			found = true
		}
	}
	if !found {
		t.Errorf("a restore that failed at the journal step had already replaced state.json (people now %v): the operator is told the restore failed while their gateway silently runs on the backup's state, with a journal that describes the one before it (F-10)", peopleNames(st))
	}
	// And the journal is still the one that was here: the history lost
	// nothing to a failed attempt.
	if evs := m8History(t, dir); !m8HasMarker(evs, "beforeBackup") {
		t.Errorf("the failed restore damaged the history: %+v", evs)
	}
}

// readStateForTest reads state.json the way any reader does - the file the
// gateway itself writes.
func readStateForTest(dir string) (state.State, error) {
	var st state.State
	data, err := state.ReadDataFile(filepath.Join(dir, state.StateFileName))
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, err
	}
	return st, nil
}

// peopleNames lists the people of a state, for an assertion message.
func peopleNames(st state.State) []string {
	out := make([]string, 0, len(st.People))
	for _, p := range st.People {
		out = append(out, p.Name)
	}
	return out
}
