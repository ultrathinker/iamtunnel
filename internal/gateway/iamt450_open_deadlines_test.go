package gateway

// IAMT-450: of everything the gateway waits for from a machine, only the
// sshd probe had a bound. The iamtunnel-control open - PROTOCOL §5.1:
// accepted within 10 s, or the transport is closed; ControlAcceptTimeout
// was declared for it and never read - the iamtunnel-target open, the
// nested SSH handshake with the machine's sshd and the session channel
// inside it all waited as long as the machine cared to take
// (ssh.ClientConfig.Timeout on the nested handshake is read only by
// ssh.Dial). A machine that answered its keepalives and nothing else held
// its registry slot for good; one whose sshd hung held every session's
// reservation - the door could not close on idle - and the person at
// "connecting".

import (
	"testing"
)

func TestIAMT450_AMachineThatNeverTakesTheControlChannelIsDisconnected(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{hangControlOpen: true})
	waitUntil(t, "precondition: the machine was never registered", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return ok
	})
	waitUntil(t, "a machine that has not taken the control channel is still connected, well past ControlAcceptTimeout", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})
}

// iamt450StartSession opens a session for the fixture's person and waits
// until the gateway has reserved the door for it.
func iamt450StartSession(t *testing.T, f *fixture) {
	t.Helper()
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	openHumanSession(t, client, f)
	waitUntil(t, "precondition: the gateway never reserved the door for the session", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Reservations == 1
	})
}

func iamt450SetupOver(f *fixture) func() bool {
	return func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		if !ok {
			return false
		}
		s := mc.doorMachine.Snapshot()
		return s.Reservations == 0 && s.Sessions == 0
	}
}

func TestIAMT450_ASessionGivesUpOnAMachineThatNeverAnswersTheTargetOpen(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{hangTargetOpen: true})
	f.waitMachineOnline(t)
	iamt450StartSession(t, f)
	waitUntil(t, "the session is still waiting for iamtunnel-target, holding the door's reservation, well past SessionSetupTimeout", iamt450SetupOver(f))
}

func TestIAMT450_ASessionGivesUpOnAnSSHDThatNeverSpeaks(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	f.sshd.setSilent(true)
	iamt450StartSession(t, f)
	waitUntil(t, "the session is still in the SSH handshake with an sshd that never sent a byte, holding the door's reservation, well past SessionSetupTimeout", iamt450SetupOver(f))
}

func TestIAMT450_ASessionGivesUpOnAnSSHDThatNeverOpensTheSession(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	f.sshd.setHangSessionOpen(true)
	iamt450StartSession(t, f)
	waitUntil(t, "the session is still waiting for the sshd to open its session channel, holding the door's reservation, well past SessionSetupTimeout", iamt450SetupOver(f))
}
