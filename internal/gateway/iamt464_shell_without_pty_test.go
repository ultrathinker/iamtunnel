package gateway

// IAMT-464: a shell with no terminal ran - and its stderr went nowhere.
// Without a pty-req the machine keeps the program's stderr apart, and a
// terminal session's bridge carries and records only the output stream:
// what the program said on stderr reached neither the person nor the
// recording. The product never promised this mode; the owner's decision
// (23.09) is to refuse it, with a line that says why and what to do.

import (
	"io"
	"strings"
	"testing"
)

func TestIAMT464_AShellWithoutATerminalIsRefusedWithAReason(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)

	ok, err := hs.ch.SendRequest("shell", true, nil)
	if err == nil && ok {
		t.Fatalf("a shell without a terminal was started: whatever it writes to stderr reaches neither the person nor the recording")
	}
	said, _ := io.ReadAll(hs.ch.Stderr())
	if !strings.Contains(string(said), "terminal") {
		t.Errorf("the refusal does not tell the person why: %q", said)
	}
	waitUntil(t, "the refused session is still counted", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0 && mc.doorMachine.Snapshot().Reservations == 0
	})
	if got := f.lastSessionDropResult(f.person, f.machineID); got != "E_SSH_SHELL_NO_PTY" {
		t.Errorf("session.drop says %q, want E_SSH_SHELL_NO_PTY", got)
	}
}
