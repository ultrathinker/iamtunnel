package gateway

// F-02 of the round-1 review (24.09.2026) says that an sshd
// which refuses the door key for reasons of its own - overloaded, a
// restarted service, a broken authorized_keys - makes the gateway
// silently take another door, that the journal shows pairs of door.open
// with nothing to explain them, and that the gateway retries until the
// idle timer runs out.
//
// Reading the code, none of the three holds:
//
//   - the second door is taken only when the machine's own door.status
//     says the line is NOT installed (machine_conn.go, recheckDoor: the
//     "gone" branch), which is IAMT-461's legitimate case; a status that
//     still reports the line installed returns doorStillInstalled and the
//     person is refused with sshd named as the cause;
//   - that refusal IS journaled, by the caller
//     (human_role.go, denyHumanSSHAuthFailed -> session.drop with
//     acl.DenyMachineSSHAuthFailed);
//   - when the door is gone, the door.close "gone" event already carries
//     the link the finding asks for, in its "why" detail: "found by
//     door.status after sshd refused the door key" (machine_conn.go,
//     recheckDoor);
//   - and the retry is bounded by construction: one recheck and one
//     further nested handshake per session setup, in a straight line, not
//     a loop (human_role.go, the doorReopened case re-runs handshake once
//     and the next failure goes to the deny branches).
//
// These two tests are the evidence for that reading. They fail if the
// gateway starts churning doors on a refusing sshd, or if the line
// linking the refusal to the reopen disappears from the journal.

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestR1MXF02_SSHDRefusingForItsOwnReasonsIsNotAnsweredWithAnotherDoor(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	mc, _ := f.gw.reg.get(f.machineID)

	first, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer first.Close()
	hs1 := openHumanSession(t, first, f)
	hs1.shell(t)
	waitUntil(t, "the first session was not counted", func() bool { return mc.doorMachine.Snapshot().Sessions == 1 })
	_, firstDoor := fm.doorInstalled()

	// The sshd side loses the line while the machine's own control side
	// still reports it installed: sshd refuses the door key, and the door
	// is NOT gone. That is the shape of the finding's scenario - a refusal
	// with nothing to do with the door's state.
	fm.mu.Lock()
	fm.installedBlob = nil
	fm.mu.Unlock()
	opens, statuses := fm.openReqs, fm.doorStatusRequests()

	second, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer second.Close()
	hs2 := openHumanSession(t, second, f)
	ok, err := hs2.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err == nil && ok {
		t.Errorf("the second session was let in although sshd had refused the door key, and the door it was handed was not gone: %s", hs2.refusalDiagnostic(ok, err))
	}

	// The gateway asked before blaming anything (the door.status round
	// trip), and then did NOT take a new door: the refusal is sshd's.
	if now := fm.doorStatusRequests(); now <= statuses {
		t.Errorf("the gateway did not ask the machine about the door before answering the refusal (door.status requests %d -> %d)", statuses, now)
	}
	if now := fm.openReqs; now != opens {
		t.Errorf("the gateway wrote %d more door.open requests for a refusal that was sshd's own, with the door still installed", now-opens)
	}
	if installed, door := fm.doorInstalled(); !installed || door != firstDoor {
		t.Errorf("the door the first session holds changed under it: installed=%v id=%q (was %q)", installed, door, firstDoor)
	}

	// And the person's refusal is on record, naming sshd - an operator
	// reading the journal is not left with a bare pair of door events.
	drop := f.lastSessionDropResult(f.person, f.machineID)
	if !strings.Contains(drop, "sshd") {
		t.Errorf("the journal's last session.drop for the refused person is %q, which does not name sshd as the cause", drop)
	}
}

func TestR1MXF02_ADoorTheMachineClosedLinksTheRefusalToTheReopenInTheJournal(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	mc, _ := f.gw.reg.get(f.machineID)

	first, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer first.Close()
	hs1 := openHumanSession(t, first, f)
	hs1.shell(t)
	waitUntil(t, "the first session was not counted", func() bool { return mc.doorMachine.Snapshot().Sessions == 1 })
	_, firstDoor := fm.doorInstalled()

	// This time the door really is gone: the machine closed it on its own
	// timer, silently (IAMT-461).
	fm.iamt461SelfClose()
	opens := fm.openReqs

	second, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer second.Close()
	hs2 := openHumanSession(t, second, f)
	hs2.shell(t)
	if installed, door := fm.doorInstalled(); !installed || door == firstDoor {
		t.Fatalf("the second session did not come in through a new door: installed=%v id=%q (first was %q)", installed, door, firstDoor)
	}
	// One new door, not a run of them.
	if now := fm.openReqs; now != opens+1 {
		t.Errorf("the gateway wrote %d door.open requests for one person's setup, want exactly 1", now-opens)
	}

	// The link the finding asks for: the door.close that records the
	// discovery says why the gateway asked, and it is the sshd refusal.
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventDoorClose}})
	if err != nil {
		t.Fatalf("read the door.close journal: %v", err)
	}
	linked := ""
	for _, e := range evs {
		if e.Result != "gone" {
			continue
		}
		if why, _ := e.Details["why"].(string); strings.Contains(why, "sshd refused the door key") {
			linked = why
		}
	}
	if linked == "" {
		t.Errorf("no door.close in the journal says the reopen followed an sshd refusal; an operator sees a door.open with nothing to explain it: %+v", evs)
	}
}
