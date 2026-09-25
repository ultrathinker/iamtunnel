package gateway

// R3 F-03 of the round-3 review (24.09.2026), low: the same class as
// F-01 - a state write and the journal line that explains it - in the two
// AUTOMATIC writers, which no command drives and which R2-CX F-10 never
// reached: the sshd probe (which pins what it observed and may mark the
// machine suspect) and recordHostKeyObservation (which records what a
// human's login saw).
//
// The probe's half is worse than a missing lock: pinSSHDHostKeyWithMismatch
// Clear wrote HostKeyStatus: "mismatch" into the state with NO journal line
// at all. The state says the machine is suspect, the sticky rule (only an
// administrator's explicit verify clears it) is read from that state, and
// the journal - where the audit of such a decision lives - said nothing
// about why. The line appears now, under the same publication lock, in the
// shape the human path already writes (hostkey.mismatch, §3.5).

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestR3F03_ABackupWaitsForAHostKeyObservationThatHasNotRecordedItself(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	different := genSigner(t)
	f.sshd.setSigner(different)
	observedFP := auth.Fingerprint(different.PublicKey())

	st := f.store.Get()
	m, ok := st.MachineByID(f.machineID)
	if !ok || m.SSHDHostKey == nil {
		t.Fatalf("machine %s or its pinned SSHD host key is not in the state", f.machineID)
	}
	pinnedFP, err := state.ComputeFingerprint(*m.SSHDHostKey)
	if err != nil {
		t.Fatalf("pinned fingerprint: %v", err)
	}

	// The observation has written the state (the key does not match) and
	// stops inside the journal write of the line that says so.
	atJournal, letItWrite := make(chan struct{}), make(chan struct{})
	var once sync.Once
	seam := func(e events.Event) error {
		if e.Type == events.EventHostKeyMismatch {
			once.Do(func() { close(atJournal) })
			<-letItWrite
		}
		return f.log.Append(e)
	}
	f.gw.journalAppendFn.Store(&seam)
	defer f.gw.journalAppendFn.Store(nil)

	observed := make(chan struct{})
	go func() {
		f.gw.recordHostKeyObservation(f.person, f.machineID, different.PublicKey(), pinnedFP, false)
		close(observed)
	}()
	<-atJournal

	archive := filepath.Join(t.TempDir(), "backup.tar.gz")
	done := make(chan error, 1)
	go func() { done <- WriteBackupTarGz(archive, f.gw.cfg.DataDir) }()

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
	<-observed
	if backupErr != nil {
		t.Fatalf("backup: %v", backupErr)
	}

	members := r1cxReadArchive(t, archive)
	stateBytes, ok := members[state.StateFileName]
	if !ok {
		t.Fatalf("the archive has no state.json: %v", keysOf(members))
	}
	journal := string(members["events.jsonl"])
	var archived state.State
	if err := json.Unmarshal(stateBytes, &archived); err != nil {
		t.Fatalf("the archive's state.json: %v", err)
	}
	inState := false
	for _, mm := range archived.Machines {
		if mm.ID == f.machineID && mm.HostKeyStatus == state.HostKeyStatusMismatch {
			inState = true
		}
	}
	inJournal := strings.Contains(journal, `"hostkey.mismatch"`) && strings.Contains(journal, observedFP)

	if inState != inJournal {
		t.Errorf("the archive pairs a state with a journal from another moment (mismatch in state=%v, hostkey.mismatch in journal=%v): the observation published half of itself, and a restore of this archive marks the machine suspect with nothing on record saying which key was seen (F-03)", inState, inJournal)
	} else if !inState {
		t.Errorf("the backup was taken before the parked observation finished at all (state=%v journal=%v), so this test proves nothing about the pair", inState, inJournal)
	}
}

func TestR3F03_AProbesMismatchIsOnRecord(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	// A target whose key is not the pinned one: the next probe sees it.
	f.sshd.setSigner(genSigner(t))

	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatalf("machine %s is not registered", f.machineID)
	}
	if err := f.gw.runSSHDProbeForAdmin(mc); err == nil {
		t.Fatalf("the probe accepted a target whose host key does not match the pinned one")
	}

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventHostKeyMismatch}})
	if err != nil {
		t.Fatalf("reading the journal: %v", err)
	}
	found := false
	for _, e := range evs {
		if e.Object == f.machineID && e.Actor == "gateway" && e.Details["path"] == "sshd-probe" {
			found = true
		}
	}
	if !found {
		t.Errorf("the probe marked machine %s as hostkey mismatch in the state and the journal holds no hostkey.mismatch line for it: the state says the machine is suspect, the journal does not say why, and the sticky rule reads the state while the audit of it reads the journal (F-03); events=%+v", f.machineID, evs)
	}
}
