package gateway

// R2-CX F-10 of the round-2 review (24.09.2026), medium: the backup
// fix of the first round (R2-MX F-22) made a backup read state.json and
// events.jsonl under accessPublishMu and keep the pair only if two reads
// agree - which covers every writer that takes that mutex. Most
// state-changing commands did not: people.add, people.keys.add/remove,
// machines.rename/set-user/rekey, machines.enrol-code and goal.set wrote
// the state, then wrote the line that records it, with nothing holding the
// two together. A backup taken between them read the NEW state twice and
// the OLD journal twice, found both reads identical and accepted an
// archive whose state its own journal does not describe - the pair the
// backup is for, broken, with every file in it valid.
//
// The fix is the one the grants commands already make: the state write and
// the line that records it are one publication, and accessPublishMu is
// held from the first to the second.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestR2CXF10_ABackupWaitsForACommandThatHasNotRecordedItselfYet(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// The command has written its state and stops inside the journal write
	// of its own record: the window F-10 is about, and the window a backup
	// used to read straight through.
	atJournal, letItWrite := make(chan struct{}), make(chan struct{})
	var once sync.Once
	seam := func(e events.Event) error {
		if e.Type == events.EventAdminOp && e.Result == "people.add:ok" {
			once.Do(func() { close(atJournal) })
			<-letItWrite
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&seam)
	defer f.gw.journalAppendFn.Store(nil)

	addDone := make(chan error, 1)
	go func() {
		_, err := root.PeopleAdd("carol", "user", []string{authorizedLine(genSigner(t).PublicKey())})
		addDone <- err
	}()
	<-atJournal

	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	done := make(chan error, 1)
	go func() { done <- WriteBackupTarGz(archive, f.gw.cfg.DataDir) }()

	// The backup either waits for the command (the fix: the publication
	// lock the command holds is the lock the backup takes) or finishes
	// without it (the defect).
	var backupErr error
	finished := false
	select {
	case backupErr = <-done:
		finished = true
	case <-time.After(250 * time.Millisecond):
	}
	close(letItWrite)
	if !finished {
		backupErr = <-done
	}
	if aerr := <-addDone; aerr != nil {
		t.Fatalf("the parked people.add: %v", aerr)
	}
	if backupErr != nil {
		t.Fatalf("backup: %v", backupErr)
	}

	members := r1cxReadArchive(t, archive)
	stateBytes, ok := members[state.StateFileName]
	if !ok {
		t.Fatalf("the archive has no state.json: %v", keysOf(members))
	}
	journal := string(members["events.jsonl"])
	var st state.State
	if err := json.Unmarshal(stateBytes, &st); err != nil {
		t.Fatalf("the archive's state.json: %v", err)
	}
	inState := false
	for _, p := range st.People {
		if p.Name == "carol" {
			inState = true
		}
	}
	inJournal := strings.Contains(journal, `"people.add:ok"`) && strings.Contains(journal, `carol`)

	if inState != inJournal {
		t.Errorf("the archive pairs a state with a journal from another moment (carol in state=%v, her record in journal=%v): the command published half of itself, and an operator restoring this gets a gateway whose people and whose history disagree while every file of the archive is valid (F-10)", inState, inJournal)
	} else if !inState {
		t.Errorf("the backup was taken before the parked command finished at all (state=%v journal=%v), so this test proves nothing about the pair", inState, inJournal)
	}
}
