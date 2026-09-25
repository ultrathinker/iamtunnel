package gateway

// R3 extra of the round-3 review (24.09.2026): the sweep of every
// state+journal writer that the round asked for (grep over the whole
// package, then the call graph of every command in commandTable) turned up
// one more writer of the R2-CX F-10 class, and it is one the first sweep
// walked past: risk.key writes the state one level down.
//
// cmdRiskKeyReplace itself has no Store.Update in its body - it calls
// replaceExternalRiskKey, which does - so "look for Store.Update inside
// the command" never saw it, and the command took no publication lock. The
// pair is the usual one: the state's classifier-key metadata becomes the
// new key, and the admin.op line that says so is written after it. A backup
// taken between the two reads the new state twice and the old journal
// twice, accepts the pair, and archives a gateway whose journal names a key
// the state does not have (or names none at all).
//
// The sweep is the point here: this is the fourth instance of the same
// class found in three rounds, and the one place the mechanical search
// missed was the one where the write is indirect.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestR3Extra_ABackupWaitsForARiskKeyChangeThatHasNotRecordedItself(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "classifier.key")
	if err := os.WriteFile(keyPath, []byte("old-classifier-test-key\n"), 0o600); err != nil {
		t.Fatalf("write the classifier key: %v", err)
	}
	f := newFixture(t, func(c *Config) {
		c.RiskClassifier = RiskClassifierAI
		c.ExternalRiskObservationKeyFile = keyPath
		c.externalRiskClassifierFactory = func(string) risk.ExternalClassifier { return &iamt403KeyClassifier{} }
	})
	addPerson(t, f, "root", "admin", genSigner(t))

	// The command has written the new key metadata into the state and stops
	// inside the journal write of its own line.
	atJournal, letItWrite := make(chan struct{}), make(chan struct{})
	var once sync.Once
	seam := func(e events.Event) error {
		if e.Type == events.EventAdminOp && e.Result == "risk.key.replace:ok" {
			once.Do(func() { close(atJournal) })
			<-letItWrite
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&seam)
	defer f.gw.journalAppendFn.Store(nil)

	const newKey = "new-classifier-test-key"
	want := externalRiskKeyFingerprint(newKey)
	done := make(chan *cmdError, 1)
	go func() {
		_, cerr := f.gw.runCommand("root", "risk.key", []byte(`{"proto":1,"key":"`+newKey+`"}`))
		done <- cerr
	}()
	<-atJournal

	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	backup := make(chan error, 1)
	go func() { backup <- WriteBackupTarGz(archive, f.gw.cfg.DataDir) }()

	var backupErr error
	finished := false
	select {
	case backupErr = <-backup:
		finished = true
	case <-time.After(250 * time.Millisecond):
	}
	close(letItWrite)
	if !finished {
		backupErr = <-backup
	}
	if cerr := <-done; cerr != nil {
		t.Fatalf("the parked risk.key: %s (%s)", cerr.message, cerr.code)
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
	inState := st.ExternalRiskKey != nil && st.ExternalRiskKey.Fingerprint == want
	inJournal := strings.Contains(journal, `"risk.key.replace:ok"`)
	if !inJournal {
		// The refusal has its own shape (also a line): accept either.
		inJournal = strings.Contains(journal, `"risk.key.replace:`)
	}

	if inState != inJournal {
		t.Errorf("the archive pairs a state with a journal from another moment (new classifier key in state=%v, risk.key.replace in journal=%v): the command published half of itself, and a restore of this archive leaves a gateway whose state holds a classifier key no line ever named (F-10's class, found by the round-3 sweep)", inState, inJournal)
	} else if !inState {
		t.Errorf("the backup was taken before the parked command finished at all (state=%v journal=%v), so this test proves nothing about the pair", inState, inJournal)
	}
}
