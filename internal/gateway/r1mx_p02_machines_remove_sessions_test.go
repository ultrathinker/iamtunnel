package gateway

// P-02 of the round-1 review (24.09.2026). The proposal said the
// journal has no count of the sessions a revocation ended. For
// grants.revoke it does - the admin.op line has carried killedSessions
// since before this review - but machines.remove was the one that said
// nothing: it ends every session on the machine it removes (the store
// withdraws the machine's grants and acl.Engine kills their sessions) and
// wrote a bare "ok". A second administrator reading the journal back
// could not tell a removal that cost somebody a live session from one
// that cost nothing.
//
// The fix counts them there the way its siblings do. The journal's field
// name stays killedSessions, which every other access-changing command
// writes and which the owner's existing journals already carry; the wire
// name (terminatedSessions) is PROTOCOL §6's and is untouched.

import (
	"fmt"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestR1MXP02_RemovingAMachineSaysHowManySessionsItEnded(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)

	// The machine has to be online for the ACL engine to open a session on
	// it - the same gate the human path passes before it reserves a door.
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// One live session on the machine, opened in the ACL engine the way
	// the human path opens it.
	if _, err := f.gw.aclE.OpenSession(f.person, f.machineID, f.clock.Now(), func(acl.DenyReason) {}); err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	if _, cerr := f.gw.runCommand("root", "machines.remove", []byte(`{"proto":1,"id":"`+f.machineID+`"}`)); cerr != nil {
		t.Fatalf("machines.remove: %v", cerr)
	}

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}, Result: "machines.remove:ok"})
	if err != nil {
		t.Fatalf("read the admin-op journal: %v", err)
	}
	if len(evs) != 1 {
		t.Fatalf("machines.remove wrote %d journal entries, want 1: %+v", len(evs), evs)
	}
	if got := fmt.Sprint(evs[0].Details["killedSessions"]); got != "1" {
		t.Errorf("machines.remove journaled killedSessions = %v for a removal that ended one live session (details: %v): without the number the journal cannot tell a removal that cut somebody off from one that cost nothing (P-02)", evs[0].Details["killedSessions"], evs[0].Details)
	}

	// The sessions really are gone: the count is the engine's, not a
	// separate guess that could disagree with what happened.
	if _, perMachine := f.gw.aclE.SessionCounts(); perMachine[f.machineID] != 0 {
		t.Errorf("acl.Engine still holds %d sessions on the removed machine", perMachine[f.machineID])
	}
}
