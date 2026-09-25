package gateway

// iamt197_reject_paths_test.go — tests for candidates #3 and #5 of the
// THREATS audit (IAMT-196):
//
//   - after registration the machine tries itself to open a channel to
//     the gateway and send an arbitrary global request -- PROTOCOL §5:
//     "any other channel-open ... receives channel failure", "any other
//     global request of the machine receives request failure". PROTOCOL
//     requires no event for this (machine.rejected is normative only
//     for the duplicate connection), so only the wire-level refusal
//     and a live transport are asserted; the divergence from what
//     THREATS T:138 wants ("Detection in the journal") is recorded in
//     REPORT_197.md.
//
//   - an admin calls door.open / door.close / door.status /
//     door.sanitize through exec -- THREATS T:57: the door is opened
//     exclusively by the automatic reservation path, door.* is outside
//     the exec table (PROTOCOL §6), the answer is E_EXEC_UNKNOWN, the
//     door is untouched.

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
)

func TestIAMT197_MachineChannelOpenAndGlobalRequestAreRefused(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// An arbitrary channel-open from the machine must receive a channel
	// failure. The observation is bounded in time: if the canary (someone
	// removed the refusing goroutine in machine_role.go) makes
	// channel-open never answer, the test turns red with a clear line
	// instead of a timeout.
	type openResult struct {
		ch  ssh.Channel
		err error
	}
	res := make(chan openResult, 1)
	go func() {
		ch, _, oerr := fm.conn.OpenChannel("session", nil)
		res <- openResult{ch: ch, err: oerr}
	}()
	select {
	case r := <-res:
		if r.err == nil {
			if r.ch != nil {
				_ = r.ch.Close()
			}
			t.Fatal("IAMT-197: the gateway accepted the machine's channel-open \"session\"; PROTOCOL §5: the machine opens no channels, only iamtunnel-control/iamtunnel-target opened by the gateway are allowed")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("IAMT-197: the machine's channel-open got no refusal within 3s -- the gateway stopped refusing machine channels (PROTOCOL §5: channel failure)")
	}

	// An arbitrary global request of the machine -- request failure...
	ok, _, err := fm.conn.SendRequest("tcpip-forward", true, nil)
	if err != nil || ok {
		t.Fatalf("IAMT-197: global request \"tcpip-forward\" from the machine = ok:%v err:%v; want request failure (PROTOCOL §5: any other global request of the machine receives request failure)", ok, err)
	}
	// ...while the regular keepalive@iamtunnel keeps answering success:
	// the refusal is targeted, the transport is alive, the machine stays
	// online.
	ok, _, err = fm.conn.SendRequest("keepalive@iamtunnel", true, nil)
	if err != nil || !ok {
		t.Fatalf("IAMT-197: regular keepalive@iamtunnel after the refusals = ok:%v err:%v; the transport must stay alive", ok, err)
	}
	mc, stillOnline := f.gw.reg.get(f.machineID)
	if !stillOnline || !mc.doorMachine.Snapshot().Online {
		t.Fatal("IAMT-197: the machine dropped out of online after its own refused requests")
	}
}

func TestIAMT197_AdminExecDoorCommandsAreUnknown(t *testing.T) {
	f := newFixture(t, nil)
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	c := dialAdmin(t, f, "root", rootKey)

	for _, cmd := range []string{"door.open", "door.close", "door.status", "door.sanitize"} {
		_, err := c.Exec(cmd, map[string]any{"proto": 1, "id": f.machineID})
		if err == nil {
			t.Fatalf("IAMT-197: the admin exec %q went through; the door cannot be controlled by exec commands (PROTOCOL §6: door.* outside the table, THREATS T:57)", cmd)
		}
		var cmdErr *admin.CommandError
		if !errors.As(err, &cmdErr) || cmdErr.Code != "E_EXEC_UNKNOWN" {
			t.Fatalf("IAMT-197: exec %q returned %v, want the E_EXEC_UNKNOWN refusal", cmd, err)
		}
	}

	// The door was not open for a single moment -- "the door is opened
	// exclusively by the automatic reservation path" (THREATS T:57) --
	// and there is not a single door.open event in the journal.
	if fm.doorEverOpened() {
		t.Fatal("IAMT-197: the door opened as a result of admin exec door.* -- the exec table stopped being free of door.*")
	}
	if evs := doorOpenEvents(t, f); len(evs) != 0 {
		t.Fatalf("IAMT-197: exec door.* wrote %d door.open events to the journal; the door was never supposed to be touched", len(evs))
	}
}
