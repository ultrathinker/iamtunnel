package gateway

// R3 F-01 of the round-3 review (24.09.2026), medium: the publication
// lock of R2-CX F-10 (state.json and its journal line are one publication,
// held under accessPublishMu) reached the eight admin commands, enrol and
// bootstrap - and stopped there. Pairing was left out of that commit
// because pairing_role.go belonged to another finding in the same round,
// and the lock never came back to it.
//
// Pairing is the one path that creates a NEW ADMINISTRATOR: the state
// transaction appends the person, and the admin.pair line is written after
// it. A backup taken in between reads the new state twice and the old
// journal twice, finds both reads identical and accepts an archive whose
// state knows an administrator its own journal never mentions - which is
// the whole promise of the pair (RUNBOOK §3, readBackupMembers). The same
// window covers a burned window and its pairing.burn line.

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

func TestR3F01_ABackupWaitsForAPairingThatHasNotRecordedItselfYet(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "123456", time.Minute)

	key := genSigner(t)
	body, err := json.Marshal(pairingRequest{Proto: 1, Pin: "123456", Pubkey: authorizedLine(key.PublicKey())})
	if err != nil {
		t.Fatalf("marshal the pairing request: %v", err)
	}
	peopleBefore := len(f.store.Get().People)

	// The pairing has written its state (the new administrator) and stops
	// inside the journal write of its own record: the window F-01 is about.
	atJournal, letItWrite := make(chan struct{}), make(chan struct{})
	var once sync.Once
	seam := func(e events.Event) error {
		if e.Type == events.EventAdminOp && e.Result == "admin.pair:ok" {
			once.Do(func() { close(atJournal) })
			<-letItWrite
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&seam)
	defer f.gw.journalAppendFn.Store(nil)

	pairDone := make(chan *cmdError, 1)
	go func() {
		_, cerr := f.gw.runPairing(body, "203.0.113.9", fingerprintOf(t, key.PublicKey()),
			pairingWindowBindingHex(f.store.Get().PairingPending), f.clock.Now())
		pairDone <- cerr
	}()
	<-atJournal

	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	done := make(chan error, 1)
	go func() { done <- WriteBackupTarGz(archive, f.gw.cfg.DataDir) }()

	// The backup either waits for the pairing (the fix: the publication
	// lock the pairing holds is the lock the backup takes) or finishes
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
	if cerr := <-pairDone; cerr != nil {
		t.Fatalf("the parked pairing: %s (%s)", cerr.message, cerr.code)
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
	inState := len(st.People) > peopleBefore
	inJournal := strings.Contains(journal, `"admin.pair:ok"`)

	if inState != inJournal {
		t.Errorf("the archive pairs a state with a journal from another moment (new administrator in state=%v, admin.pair in journal=%v): pairing published half of itself, and a restore of this archive installs an administrator the journal never mentions - the one record that would say where that administrator came from (F-01)", inState, inJournal)
	} else if !inState {
		t.Errorf("the backup was taken before the parked pairing finished at all (state=%v journal=%v), so this test proves nothing about the pair", inState, inJournal)
	}
}
