package gateway

// IAMT-461, the sshd probe's half (IAMT-440 extra). IAMT-461 taught a
// person's nested handshake to ask door.status before blaming sshd for a
// refused door key: the machine closes its door on its own timers and does
// not say so. The probe of the OS user did not learn it. machines.verify
// on a machine whose door the machine had closed itself, while a session
// kept the gateway's automaton at open, joined that dead door, was refused
// the key, and wrote the verdict of a bad account: osUserStatus rejected,
// the machine back to enrolled - every login refused until somebody
// verified it again, for an account with nothing wrong with it.

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT461_AProbeThroughADoorTheMachineClosedItselfDoesNotRejectTheAccount(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	mc, _ := f.gw.reg.get(f.machineID)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// A session holds the door open, and the machine's own timer removes
	// the line under it.
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "the session was not counted", func() bool { return mc.doorMachine.Snapshot().Sessions == 1 })
	fm.iamt461SelfClose()

	if _, err := root.MachinesVerify(f.machineID); err != nil {
		t.Errorf("machines.verify through a door the machine had closed itself: %v", err)
	}
	st := f.store.Get()
	m, _ := st.MachineByID(f.machineID)
	if m.OSUserStatus != state.OSUserStatusVerified || m.State != "verified" {
		t.Fatalf("the account was judged by a door that was gone: osUserStatus=%s state=%s", m.OSUserStatus, m.State)
	}
}
