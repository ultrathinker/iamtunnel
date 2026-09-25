//go:build windows

package gateway

// IAMT-469: machines.set-user closes the machine's live door before the new
// OS account is probed - a door opened for one account must not serve the
// next - and it closed it with door.close reason "os-user-changed", a word
// the machine's closed dictionary (PROTOCOL §5.1) does not have. A real
// machine refused the close, the closing row's terminal cell had the
// gateway cut the machine's transport, and the new account was not probed
// on that connection at all. The fake machine of the other tests takes any
// reason, which is how no test saw it; this one runs the real machine role
// (internal/server) against its real key file.

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT469_ChangingTheOSUserClosesTheDoorOnARealMachine(t *testing.T) {
	f := newFixture(t, nil)
	rm := startRealMachineOnce(t, f, nil)
	f.waitMachineOnline(t)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "the session's door never reached the real key file", func() bool { return rm.fileHasDoorLine(t) })
	mc, _ := f.gw.reg.get(f.machineID)

	const newUser = `MACHINE\other`
	if err := root.MachinesSetUser(f.machineID, newUser); err != nil {
		t.Fatalf("machines.set-user: %v", err)
	}

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventDoorClose}})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range evs {
		if e.Result == "failed" {
			t.Fatalf("the real machine refused the door.close of an OS user change, and the gateway cut it off for it: %+v", e)
		}
	}
	if cur, ok := f.gw.reg.get(f.machineID); !ok || cur != mc {
		t.Fatal("the machine lost its connection to the gateway over an OS user change")
	}
	waitUntil(t, "the door opened for the old OS user stayed on the machine", func() bool { return !rm.fileHasDoorLine(t) })
	waitUntil(t, "the new OS user was never verified over the machine's connection", func() bool {
		st := f.store.Get()
		m, ok := st.MachineByID(f.machineID)
		return ok && m.OSUserStatus == state.OSUserStatusVerified && m.VerifiedOSUser != nil && *m.VerifiedOSUser == newUser
	})
}
