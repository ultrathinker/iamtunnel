package gateway

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func seedHostKeyMismatch(t *testing.T, f *fixture, observed string) {
	t.Helper()
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID != f.machineID {
				continue
			}
			st.Machines[i].HostKeyStatus = state.HostKeyStatusMismatch
			st.Machines[i].ObservedSSHDHostKey = &observed
			return nil
		}
		return nil
	}); err != nil {
		t.Fatalf("seed host-key mismatch: %v", err)
	}
}

func TestAdmin_MachinesVerifyClearsMismatchAfterExplicitReverification(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	rootKey := genSigner(t)
	addPerson(t, f, "verify-root", "admin", rootKey)
	root := dialAdmin(t, f, "verify-root", rootKey)

	foreign := authorizedLine(genSigner(t).PublicKey())
	seedHostKeyMismatch(t, f, foreign)

	mv, err := root.MachinesVerify(f.machineID)
	if err != nil {
		t.Fatalf("machines.verify: %v", err)
	}
	if mv.HostKeyStatus != state.HostKeyStatusMatch {
		t.Fatalf("machines.verify hostKeyStatus = %q, want %q", mv.HostKeyStatus, state.HostKeyStatusMatch)
	}
	postVerify := f.store.Get()
	got, ok := postVerify.MachineByID(f.machineID)
	if !ok || got.HostKeyStatus != state.HostKeyStatusMatch {
		t.Fatalf("machines.verify did not clear the recorded mismatch: %+v", got)
	}
}

func TestAdmin_MachinesRekeyRequiresObservedFingerprint(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "rekey-root", "admin", rootKey)
	root := dialAdmin(t, f, "rekey-root", rootKey)

	foreign := authorizedLine(genSigner(t).PublicKey())
	seedHostKeyMismatch(t, f, foreign)
	foreignFP, err := state.ComputeFingerprint(foreign)
	if err != nil {
		t.Fatalf("foreign fingerprint: %v", err)
	}
	oldFP := fingerprintOf(t, f.sshd.signer.PublicKey())
	old, new, err := root.MachinesRekey(f.machineID, foreignFP)
	if err != nil {
		t.Fatalf("machines.rekey with observed fingerprint: %v", err)
	}
	if old != oldFP || new != foreignFP {
		t.Fatalf("machines.rekey fingerprints = (%q, %q), want (%q, %q)", old, new, oldFP, foreignFP)
	}
	postRekey := f.store.Get()
	got, ok := postRekey.MachineByID(f.machineID)
	if !ok || got.HostKeyStatus != state.HostKeyStatusMatch || got.SSHDHostKey == nil || *got.SSHDHostKey != foreign {
		t.Fatalf("machines.rekey did not trust the confirmed observed key: %+v", got)
	}

	secondForeign := authorizedLine(genSigner(t).PublicKey())
	seedHostKeyMismatch(t, f, secondForeign)
	before := f.store.Get()
	if _, _, err := root.MachinesRekey(f.machineID, fingerprintOf(t, genSigner(t).PublicKey())); err == nil {
		t.Fatal("machines.rekey with a different fingerprint succeeded")
	} else if !strings.Contains(err.Error(), "E_MACHINE_REKEY_CONFIRMATION") {
		t.Fatalf("machines.rekey with a different fingerprint returned an unclear error: %v", err)
	}
	after := f.store.Get()
	beforeM, _ := before.MachineByID(f.machineID)
	afterM, _ := after.MachineByID(f.machineID)
	if afterM.HostKeyStatus != state.HostKeyStatusMismatch || afterM.SSHDHostKey == nil || beforeM.SSHDHostKey == nil || *afterM.SSHDHostKey != *beforeM.SSHDHostKey || afterM.ObservedSSHDHostKey == nil || beforeM.ObservedSSHDHostKey == nil || *afterM.ObservedSSHDHostKey != *beforeM.ObservedSSHDHostKey {
		t.Fatalf("rejected machines.rekey changed the recorded mismatch: before=%+v after=%+v", beforeM, afterM)
	}

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
	if err != nil {
		t.Fatalf("read admin-op journal: %v", err)
	}
	seenOK, seenFailed := false, false
	for _, event := range evs {
		if event.Actor != "rekey-root" || event.Object != f.machineID {
			continue
		}
		seenOK = seenOK || event.Result == "machines.rekey:ok"
		seenFailed = seenFailed || event.Result == "machines.rekey:failed"
	}
	if !seenOK || !seenFailed {
		t.Fatalf("machines.rekey audit entries = %+v, want both success and failed entries", evs)
	}
}
