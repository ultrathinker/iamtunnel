package gateway

// IAMT-461: the machine closes its door on its own - after maxDoorIdle
// without bytes, or at maxDoorHard (server/door.go, selfClose) - and says
// nothing: the protocol has no machine-to-gateway message for it. The
// gateway went on believing the door was open for as long as one session
// kept it so, handed the next person that door, and the nested handshake
// failed on authentication: "the target machine's sshd service rejected
// the door key", and a session.drop that sent an administrator to repair
// an sshd with nothing wrong with it.
//
// Two halves. The gateway asks (door.status) when sshd refuses the door
// key, and on "not installed" takes a new door instead of blaming sshd.
// And it keeps the hard deadline it proposed itself, rather than trusting
// the machine alone to end the door.

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// iamt461SelfClose is what server/door.go's selfClose does to the line:
// it is gone from authorized_keys, and the gateway is not told.
func (fm *fakeMachine) iamt461SelfClose() {
	fm.mu.Lock()
	fm.installedBlob = nil
	fm.installedID = ""
	fm.mu.Unlock()
}

func TestIAMT461_ADoorTheMachineClosedItselfIsReopenedNotBlamedOnSSHD(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	mc, _ := f.gw.reg.get(f.machineID)

	// The first session holds the door open.
	first, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer first.Close()
	hs1 := openHumanSession(t, first, f)
	hs1.shell(t)
	waitUntil(t, "the first session was not counted", func() bool { return mc.doorMachine.Snapshot().Sessions == 1 })
	_, firstDoor := fm.doorInstalled()

	// The machine's own timer removes the line while that session lives.
	fm.iamt461SelfClose()

	second, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer second.Close()
	hs2 := openHumanSession(t, second, f)
	ok, err := hs2.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err != nil || !ok {
		t.Fatalf("the second session was refused though only the door had been closed, by the machine itself: %s", hs2.refusalDiagnostic(ok, err))
	}
	if ok, err := hs2.ch.SendRequest("shell", true, nil); err != nil || !ok {
		t.Fatalf("shell: ok=%v err=%v", ok, err)
	}
	if drop := f.lastSessionDropResult(f.person, f.machineID); strings.Contains(drop, "rejected") {
		t.Errorf("the journal blames sshd (%q) for a door the machine had closed", drop)
	}
	installed, door := fm.doorInstalled()
	if !installed || door == firstDoor {
		t.Errorf("the second session did not come in through a new door: installed=%v id=%q (first was %q)", installed, door, firstDoor)
	}
	if s := mc.doorMachine.Snapshot(); s.State != core.Open || s.Sessions != 2 {
		t.Errorf("after the reopen the door is %s with %d sessions, want open with both", s.State, s.Sessions)
	}

	// The first session was never touched: it does not need the door.
	const marker = "iamt-461-first-still-here"
	if _, err := hs1.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write to the first session: %v", err)
	}
	readUntil(t, hs1.ch, marker)
}

func TestIAMT461_AKeySSHDReallyRefusesIsStillReportedAsSuch(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	f.sshd.setKeyAllowed(func([]byte) bool { return false })

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	before := fm.doorStatusRequests()
	ch, reqs, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	go discardSSHRequests(reqs)
	msg := readAll(t, ch, 5*time.Second)
	if !strings.Contains(msg, "the target machine's sshd service rejected the door key") {
		t.Fatalf("a key sshd refused while the door is installed must still be named so, got %q", msg)
	}
	if fm.doorStatusRequests() == before {
		t.Errorf("the gateway did not ask the machine about its door before blaming sshd")
	}
}

func TestIAMT461_TheGatewayEndsTheDoorAtItsOwnHardDeadline(t *testing.T) {
	f := newFixture(t, nil) // DoorHard: 2 minutes of the fixture's clock
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	mc, _ := f.gw.reg.get(f.machineID)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "the session was not counted", func() bool { return mc.doorMachine.Snapshot().Sessions == 1 })

	// The fake machine keeps no timers of its own: whatever ends this door
	// now is the gateway.
	f.clock.Advance(2*time.Minute + time.Second)
	waitUntil(t, "the gateway kept the door open past the hard deadline it proposed itself", func() bool {
		installed, _ := fm.doorInstalled()
		return !installed
	})

	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventDoorClose}})
	if err != nil {
		t.Fatal(err)
	}
	hard := false
	for _, ev := range evs {
		if ev.Details["reason"] == "hard" {
			hard = true
		}
	}
	if !hard {
		t.Errorf("no door.close with reason \"hard\" in the journal: %+v", evs)
	}

	// The door is an entrance: the session already inside goes on, and the
	// counter still has it, so its end is counted when it comes.
	const marker = "iamt-461-after-the-hard-deadline"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write: %v", err)
	}
	readUntil(t, hs.ch, marker)
	if s := mc.doorMachine.Snapshot(); s.Sessions != 1 {
		t.Errorf("the session inside is no longer counted after the door closed: %+v", s)
	}
}
