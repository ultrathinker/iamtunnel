package gateway

// hostkey_mismatch_sticky_test.go covers the "mismatch is sticky" rule of
// SPEC §4.3 / §6.2, with the exact wording IAMT-127 pinned it: a recorded
// hostKeyStatus = mismatch is a recorded suspicion of substitution, and
// only an administrator's re-verification (machines.verify / machines.rekey)
// may clear it. A later nested handshake that happens to agree with the
// pinned key MUST leave the machine record untouched.
//
// The two defences in recordHostKeyObservation
// (internal/gateway/human_role.go around lines 342 and 355) - the external
// "alreadyRecorded" check before the transaction and the "return nil" check
// inside it - are deliberate and redundant: killing one leaves the other to
// hold the line. The canary for this test removes BOTH; if either defence
// is left in place, the canary still passes (false negative), which is the
// whole reason both must be removed before judging the
// rule unproven.

// The direct call to recordHostKeyObservation below is deliberate and the
// only honest choice under the testing prohibitions. A through-path test would
// have to reach a nested handshake whose comparison callback invokes
// recordHostKeyObservation with matched = true on a machine recorded as
// mismatch. Today no such handshake exists: serveHumanSession (same file,
// around line 91) refuses such a machine BEFORE its door opens, so the
// callback never runs for a "matched on a recorded mismatch" call.
// Weakening that guard to let a through-path test reach this rule would
// change product behaviour just to satisfy a test, which is not
// acceptable. Calling recordHostKeyObservation directly from the same package
// is the supported seam for "the rule under test lives here, and today
// nothing upstream can put this combination on its doorstep".

import (
	"bytes"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestHostKeyMismatch_IsStickyAcrossLaterHandshake(t *testing.T) {
	f := newFixture(t, nil)

	// Seed: the machine has already recorded a mismatch, with the foreign
	// key that triggered it kept on the record (so a later admin has
	// something to compare a re-keying against, per the comment on
	// ObservedSSHDHostKey in state/model.go).
	foreignSigner := genSigner(t)
	foreignLine := authorizedLine(foreignSigner.PublicKey())

	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID != f.machineID {
				continue
			}
			st.Machines[i].HostKeyStatus = state.HostKeyStatusMismatch
			v := foreignLine
			st.Machines[i].ObservedSSHDHostKey = &v
		}
		return nil
	}); err != nil {
		t.Fatalf("test setup error: seed machine %s as mismatch: %v", f.machineID, err)
	}

	// Sanity-check the seed so a failed assertion later cannot be blamed
	// on a missed setup step. These are t.Fatalf with "test setup error"
	// wording - they are NOT the assertion under test.
	pre := f.store.Get()
	preM, ok := pre.MachineByID(f.machineID)
	if !ok {
		t.Fatalf("test setup error: machine %s disappeared after seeding", f.machineID)
	}
	if preM.HostKeyStatus != state.HostKeyStatusMismatch {
		t.Fatalf("test setup error: seeded hostKeyStatus = %q, want %q",
			preM.HostKeyStatus, state.HostKeyStatusMismatch)
	}
	if preM.ObservedSSHDHostKey == nil || *preM.ObservedSSHDHostKey != foreignLine {
		t.Fatalf("test setup error: seeded observedSSHDHostKey = %v, want %q",
			preM.ObservedSSHDHostKey, foreignLine)
	}

	// Sanity check: the presented (pinned) key and the recorded observed
	// (foreign) key must be distinct, so a write that overwrites
	// observedSSHDHostKey would produce a value visibly different from the
	// seed and could not be confused with a no-op. (Collision of two
	// independently generated ed25519 keys is negligible; this guards the
	// case where a future reader wires the same signer into both slots by
	// mistake.)
	presented := f.sshd.signer.PublicKey()
	if bytes.Equal(presented.Marshal(), foreignSigner.PublicKey().Marshal()) {
		t.Fatalf("test setup error: presented (pinned) key and recorded observed (foreign) key have the same wire-format blob, so an observedSSHDHostKey rewrite would be indistinguishable from a no-op and the second assertion could not fail")
	}

	f.gw.recordHostKeyObservation(f.person, f.machineID, presented, "", true)

	// The rule under test, with the SPEC paragraph it implements named in
	// the failure text:
	//
	//   SPEC §4.3 / §6.2: hostKeyStatus = mismatch is a recorded suspicion
	//   of substitution. Only an administrator's re-verification
	//   (machines.verify / machines.rekey) may clear it. A later nested
	//   handshake that happens to agree MUST leave the record untouched.
	//
	// The two assertions below cover both fields the rule protects:
	//   - hostKeyStatus: must remain "mismatch" (the suspicion itself).
	//   - observedSSHDHostKey: must remain the foreign key that triggered
	//     the suspicion, NOT the key the later handshake agreed with.
	post := f.store.Get()
	postM, ok := post.MachineByID(f.machineID)
	if !ok {
		t.Fatalf("test setup error: machine %s disappeared after recordHostKeyObservation", f.machineID)
	}
	if postM.HostKeyStatus != state.HostKeyStatusMismatch {
		t.Fatalf("rule under test: hostKeyStatus was rewritten to %q by a later matching handshake; hostKeyStatus = mismatch is sticky (SPEC §4.3, §6.2) and only machines.verify / machines.rekey may clear it",
			postM.HostKeyStatus)
	}
	if postM.ObservedSSHDHostKey == nil {
		t.Fatalf("rule under test: observedSSHDHostKey was cleared by a later matching handshake; mismatch is sticky and the foreign key that triggered it must stay on record until an administrator acts")
	}
	if *postM.ObservedSSHDHostKey != foreignLine {
		t.Fatalf("rule under test: observedSSHDHostKey was rewritten to %q by a later matching handshake; mismatch is sticky and the foreign key that triggered it (%q) must stay on record until an administrator acts",
			*postM.ObservedSSHDHostKey, foreignLine)
	}
}
