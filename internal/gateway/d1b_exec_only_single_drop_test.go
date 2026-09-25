package gateway

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// TestD1b_ExecOnlyRepeatedPtyReqSingleDropEvent — the canary for D1(b):
// repeated pty-req on an exec-only session after a running exec must
// produce exactly one session.drop event, not one per rejected
// request — otherwise the journal fills up with identical entries.
func TestD1b_ExecOnlyRepeatedPtyReqSingleDropEvent(t *testing.T) {
	f := newFixture(t, nil)
	iamt351SetGrantCaps(t, f, []string{"exec"})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer client.Close()

	hs := openHumanSession(t, client, f)
	// Send the exec — it must go through.
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "cmd /c echo d1b"}))
	if err != nil || !ok {
		t.Fatalf("exec with exec-only grant: ok=%v err=%v", ok, err)
	}

	// Send three pty-req in a row — all are refused on the wire.
	ptyPayload := sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24})
	for i := 0; i < 3; i++ {
		ok, err = hs.ch.SendRequest("pty-req", true, ptyPayload)
		if err != nil {
			break // the channel may have closed after the first refusal, that is fine
		}
		if ok {
			t.Fatalf("pty-req #%d with exec-only grant unexpectedly accepted", i+1)
		}
	}

	// Wait so that the first event is surely recorded.
	waitUntil(t, "D1(b) canary: at least one session.drop for E_SSH_SHELL_FORBIDDEN", func() bool {
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
		if err != nil {
			t.Fatalf("read events: %v", err)
		}
		for _, ev := range evs {
			if ev.Actor == f.person && ev.Object == f.machineID && ev.Result == "E_SSH_SHELL_FORBIDDEN" {
				return true
			}
		}
		return false
	})

	// A small pause so that concurrent goroutines get to write any extra events.
	time.Sleep(100 * time.Millisecond)

	// Assert: exactly one event.
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	count := 0
	for _, ev := range evs {
		if ev.Actor == f.person && ev.Object == f.machineID && ev.Result == "E_SSH_SHELL_FORBIDDEN" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("D1(b) canary: want exactly 1 session.drop with E_SSH_SHELL_FORBIDDEN, got %d", count)
	}
	_ = hs.ch.Close()
}

// A stub so the ssh import does not complain — the package is already used via SendRequest.
var _ ssh.Channel
