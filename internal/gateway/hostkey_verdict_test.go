package gateway

// hostkey_verdict_test.go covers IAMT-91 steps 2-4: the verdict of the host key
// comparison is REMEMBERED (step 2), the remembered mismatch FORBIDS the door
// (step 3), and an administrator can SEE both on machines.list (step 4).
//
// The live defence - comparing the target sshd's key inside HostKeyCallback and
// refusing on a mismatch - already worked and is covered by
// hostkey_mismatch_event_test.go. What these tests add is the memory of that
// refusal and its consequences.

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// attemptHumanSession dials as the fixture's person and opens one session
// channel, returning the text the gateway wrote back. The gateway accepts the
// channel before it decides anything (handleHuman's n.Accept), so a refusal
// always has somewhere to be said.
func attemptHumanSession(t *testing.T, f *fixture) string {
	t.Helper()
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()

	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("the session channel was refused before the gateway could say anything: %v", err)
	}
	defer ch.Close()
	go discardSSHRequests(reqs)
	return readAll(t, ch, 2*time.Second)
}

// waitForHostKeyStatus waits until the machine record carries want.
func waitForHostKeyStatus(t *testing.T, f *fixture, want string) {
	t.Helper()
	waitUntil(t, "the host key verdict never reached the machine record", func() bool {
		st := f.store.Get()
		m, ok := st.MachineByID(f.machineID)
		return ok && m.HostKeyStatus == want
	})
}

// doorOpenEvents (door_lifecycle_events_test.go) already returns the door.open
// events of the fixture's machine; the count of them is what "mismatch forbids
// the door" has to leave alone.

// mismatchEvents returns the hostkey.mismatch events recorded for the machine.
func mismatchEvents(t *testing.T, f *fixture) []events.Event {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventHostKeyMismatch}})
	if err != nil {
		t.Fatalf("read the journal for hostkey.mismatch events: %v", err)
	}
	var out []events.Event
	for _, e := range evs {
		if e.Object == f.machineID {
			out = append(out, e)
		}
	}
	return out
}

// TestHostKeyVerdict_MismatchIsRecordedWithItsEvent is step 2 on the mismatch
// side: the foreign key the sshd presented is remembered in the machine record,
// and the record and the journal describe the same observation - that is what
// writing them from one place, in one order, buys.
func TestHostKeyVerdict_MismatchIsRecordedWithItsEvent(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// A foreign sshd key: state.json still pins the original one.
	foreign := genSigner(t)
	f.sshd.setSigner(foreign)
	foreignLine := authorizedLine(foreign.PublicKey())

	_ = attemptHumanSession(t, f) // the refusal itself is checked in step 3's test
	waitForHostKeyStatus(t, f, state.HostKeyStatusMismatch)

	st := f.store.Get()
	m, ok := st.MachineByID(f.machineID)
	if !ok {
		t.Fatalf("machine %s is missing from the state after a mismatch", f.machineID)
	}
	if m.ObservedSSHDHostKey == nil {
		t.Fatalf("observedSSHDHostKey is absent: the foreign key was never written down, so nothing can later be compared with it")
	}
	if *m.ObservedSSHDHostKey != foreignLine {
		t.Fatalf("observedSSHDHostKey = %q, want the key that was actually presented (%q)", *m.ObservedSSHDHostKey, foreignLine)
	}

	evs := mismatchEvents(t, f)
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 hostkey.mismatch event for %s, got %d", f.machineID, len(evs))
	}
	recordedFP, err := state.ComputeFingerprint(*m.ObservedSSHDHostKey)
	if err != nil {
		t.Fatalf("compute the fingerprint of the recorded key: %v", err)
	}
	if recordedFP != evs[0].Fingerprint {
		t.Fatalf("the record and the journal disagree about one comparison: observedSSHDHostKey is %s, the event names %s", recordedFP, evs[0].Fingerprint)
	}
	if want := auth.Fingerprint(foreign.PublicKey()); recordedFP != want {
		t.Fatalf("the recorded key hashes to %s, want the fingerprint of the key the sshd presented (%s)", recordedFP, want)
	}
}

// TestHostKeyVerdict_MatchIsRecordedWithoutAnEvent is step 2 on the match side:
// agreement is remembered too, and it writes no event - §3.5's dictionary is
// closed and holds no "the keys agreed" type; the absence of the mismatch event
// is what agreement looks like in the journal.
func TestHostKeyVerdict_MatchIsRecordedWithoutAnEvent(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	pinnedLine := authorizedLine(f.sshd.signer.PublicKey())

	_ = attemptHumanSession(t, f)
	waitForHostKeyStatus(t, f, state.HostKeyStatusMatch)

	st := f.store.Get()
	m, ok := st.MachineByID(f.machineID)
	if !ok {
		t.Fatalf("machine %s is missing from the state", f.machineID)
	}
	if m.ObservedSSHDHostKey == nil || *m.ObservedSSHDHostKey != pinnedLine {
		t.Fatalf("observedSSHDHostKey = %v, want the key the target sshd actually presented (%q)", m.ObservedSSHDHostKey, pinnedLine)
	}
	if evs := mismatchEvents(t, f); len(evs) != 0 {
		t.Fatalf("an agreeing comparison must not write a mismatch event, found %d", len(evs))
	}
}

// TestHostKeyMismatch_ForbidsTheDoorOnTheNextAttempt is step 3: once the
// mismatch is on record, the next attempt must be refused BEFORE the door - not
// merely fail again behind it - and the refusal must carry the reason.
func TestHostKeyMismatch_ForbidsTheDoorOnTheNextAttempt(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// First attempt: a foreign key. The door does open this time - the
	// comparison happens inside the nested handshake, behind it - and the
	// handshake then fails, which is what records the mismatch.
	foreign := genSigner(t)
	f.sshd.setSigner(foreign)
	_ = attemptHumanSession(t, f)
	waitForHostKeyStatus(t, f, state.HostKeyStatusMismatch)

	opensAfterFirst := len(doorOpenEvents(t, f))
	if opensAfterFirst == 0 {
		t.Fatalf("the first attempt never opened a door, so this test cannot tell a forbidden door from a door that was never asked")
	}

	// Second attempt: the machine is on record as mismatch, and SPEC §4.3
	// forbids opening a door on such a machine.
	resp := attemptHumanSession(t, f)
	if !strings.Contains(resp, "Access to this machine is currently unavailable") {
		t.Fatalf("the person must still recognise a refusal, got %q", resp)
	}
	if !strings.Contains(resp, "does not match the pinned key") {
		t.Fatalf("the refusal must say WHY the machine is closed, not merely deny it; got %q", resp)
	}

	if got := len(doorOpenEvents(t, f)); got != opensAfterFirst {
		t.Fatalf("the door was opened for a machine recorded as host-key mismatch: door.open events went from %d to %d", opensAfterFirst, got)
	}
	if got := len(mismatchEvents(t, f)); got != 1 {
		t.Fatalf("a refusal before the door must not reach the sshd at all, so no second comparison can happen; hostkey.mismatch events went from 1 to %d", got)
	}

	waitUntil(t, "the refusal was not journalled with its typed reason", func() bool {
		drops, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
		if err != nil {
			return false
		}
		for _, e := range drops {
			if e.Object == f.machineID && e.Result == acl.DenyMachineHostKeyMismatch.String() {
				return true
			}
		}
		return false
	})
}

// TestMachinesList_ShowsTheHostKeyAndOSUserVerdicts is step 4: an administrator
// who cannot see the mismatch cannot act on it, so machines.list carries the
// §4.3 fields. It also pins the client/server view mirror: internal/admin
// decodes this response with DisallowUnknownFields, so a field the gateway
// renders and the client does not know turns the whole command into an error.
func TestMachinesList_ShowsTheHostKeyAndOSUserVerdicts(t *testing.T) {
	f := newFixture(t, nil)
	// This assertion is about a machine whose user has NEVER been proved.
	// newFixture deliberately seeds a proved user because nearly every human
	// session test needs the IAMT-96 precondition. Undo just that shared happy
	// path here, before the machine comes online and before machines.list is
	// called, so this test keeps its own premise.
	configured := false
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID != f.machineID {
				continue
			}
			st.Machines[i].RequestedOSUser = ""
			st.Machines[i].VerifiedOSUser = nil
			st.Machines[i].OSUserStatus = state.OSUserStatusPending
			st.Machines[i].HostKeyStatus = state.HostKeyStatusUnverified
			configured = true
			return nil
		}
		return nil
	}); err != nil {
		t.Fatalf("test setup error: make the fixture machine's OS user unverified: %v", err)
	}
	if !configured {
		t.Fatalf("test setup error: the fixture has no machine %q", f.machineID)
	}
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	c := dialAdmin(t, f, "root", rootKey)

	view := func() admin.MachineView {
		t.Helper()
		list, _, err := c.MachinesList()
		if err != nil {
			t.Fatalf("machines.list: %v", err)
		}
		for _, m := range list {
			if m.ID == f.machineID {
				return m
			}
		}
		t.Fatalf("machines.list does not name machine %s", f.machineID)
		return admin.MachineView{}
	}

	// Nothing has been compared yet: the list must say so rather than stay silent.
	before := view()
	if before.HostKeyStatus != state.HostKeyStatusUnverified {
		t.Fatalf("machines.list shows hostKeyStatus %q for a machine that was never compared, want %q", before.HostKeyStatus, state.HostKeyStatusUnverified)
	}
	if before.OSUserStatus != state.OSUserStatusPending {
		t.Fatalf("machines.list shows osUserStatus %q for a machine whose OS user was never proved, want %q", before.OSUserStatus, state.OSUserStatusPending)
	}

	// The host-key half below deliberately reaches the target sshd. Restore a
	// proved OS user first: otherwise IAMT-96 correctly refuses this attempt
	// before the comparison and the rest of this test would no longer exercise
	// its host-key premise.
	provedUser := `MACHINE\svc`
	configured = false
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID != f.machineID {
				continue
			}
			st.Machines[i].RequestedOSUser = provedUser
			st.Machines[i].VerifiedOSUser = &provedUser
			st.Machines[i].OSUserStatus = state.OSUserStatusVerified
			configured = true
			return nil
		}
		return nil
	}); err != nil {
		t.Fatalf("test setup error: restore the fixture machine's verified OS user: %v", err)
	}
	if !configured {
		t.Fatalf("test setup error: the fixture has no machine %q while restoring the verified OS user", f.machineID)
	}

	// Now fail the comparison and ask again.
	foreign := genSigner(t)
	f.sshd.setSigner(foreign)
	_ = attemptHumanSession(t, f)
	waitForHostKeyStatus(t, f, state.HostKeyStatusMismatch)

	after := view()
	if after.HostKeyStatus != state.HostKeyStatusMismatch {
		t.Fatalf("machines.list shows hostKeyStatus %q for a machine that failed its host key check, want %q: an administrator who cannot see this cannot act on it", after.HostKeyStatus, state.HostKeyStatusMismatch)
	}
	if after.ObservedSSHDHostKey != authorizedLine(foreign.PublicKey()) {
		t.Fatalf("machines.list shows observedSSHDHostKey %q, want the key that was presented (%q)", after.ObservedSSHDHostKey, authorizedLine(foreign.PublicKey()))
	}
}
