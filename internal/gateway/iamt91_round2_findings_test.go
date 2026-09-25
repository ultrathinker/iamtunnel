package gateway

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestFinding01_PinWriterPreservesRecordedMismatch guards the defect found
// in IAMT-91's independent second review. The renamed name reflects what
// the test actually exercises: the phase-one writer at the core of the
// sshd probe (internal/gateway/sshd_probe.go:230) refuses to overwrite a
// recorded mismatch when a later observation agrees with the pinned key.
// The "automatic probe" half of the original IAMT-91 promise is guarded
// separately, by IAMT-134's three new tests in sshd_probe_test.go; that
// rule lives at three different call sites and one test on the core
// function cannot tell whether any of them still routes through the
// non-clearing branch.
func TestFinding01_PinWriterPreservesRecordedMismatch(t *testing.T) {
	f := newFixture(t, nil) // newFixture confines state, recordings and fake sshd to t.TempDir.
	foreign := authorizedLine(genSigner(t).PublicKey())
	if err := f.store.Update(func(st *state.State) error {
		m, ok := st.MachineByID(f.machineID)
		if !ok {
			t.Fatalf("test setup error: machine %q is absent", f.machineID)
		}
		for i := range st.Machines {
			if st.Machines[i].ID == m.ID {
				st.Machines[i].HostKeyStatus = state.HostKeyStatusMismatch
				st.Machines[i].ObservedSSHDHostKey = &foreign
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("test setup error: seed mismatch: %v", err)
	}

	// This is exactly phase 1's successful re-observation.  It goes
	// through pinSSHDHostKey, the wrapper that hardcodes
	// mayClearMismatch=false; runSSHDProbe also reaches the same core
	// function, but with the decision at sshd_probe.go:36 left to a
	// separate test (TestSSHDProbe_AutomaticProbeDoesNotClearStickyMismatch).
	if err := f.gw.pinSSHDHostKey(f.machineID, authorizedLine(f.sshd.signer.PublicKey())); err != nil {
		t.Fatalf("test setup error: a re-observation equal to the pinned key failed: %v", err)
	}
	got := f.store.Get()
	m, ok := got.MachineByID(f.machineID)
	if !ok {
		t.Fatalf("machine disappeared")
	}
	if m.HostKeyStatus != state.HostKeyStatusMismatch {
		t.Fatalf("F-01: pinSSHDHostKey changed hostKeyStatus to %q; the phase-one writer must preserve a recorded mismatch until an administrator clears it", m.HostKeyStatus)
	}
	if m.ObservedSSHDHostKey == nil || *m.ObservedSSHDHostKey != foreign {
		t.Fatalf("F-01: pinSSHDHostKey replaced the foreign observedSSHDHostKey; it must remain available for administrator review")
	}
}

// TestFinding04_MachinesRekeyIsActuallyAnAdminCommand guards that the CLI and
// admin client advertise machines.rekey, and the gateway registers that
// authorised recovery command as well.
func TestFinding04_MachinesRekeyIsActuallyAnAdminCommand(t *testing.T) {
	if _, ok := commandTable["machines.rekey"]; !ok {
		t.Fatalf("F-04: gateway does not register machines.rekey; the documented administrator recovery path returns E_EXEC_UNKNOWN")
	}
}
