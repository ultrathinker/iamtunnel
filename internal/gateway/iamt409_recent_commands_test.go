package gateway

// IAMT-409: a ring buffer of the recent exec commands PER person+machine
// PAIR (like goals -- GoalRecord, not per session: in exec mode every
// command is its own session). The maintainer's idea on 21.09: give the
// person the last ten commands the agent sent and the answers to them...
// then the agent's train of thought becomes clear. A live log from
// 21.09 18:03-18:05: writing car.jpg to the desktop -> green, deleting
// the same file 40 seconds later -> red, destroys=0.87 -- the person was
// cleaning up their own file, while the classifier saw one line in a vacuum.
//
// The canary drives a real exec session through the gateway and requires
// that after it completes the pair's state holds the command -- scrubbed
// AT WRITE TIME, with the exit code and the first lines of the machine's answer.

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// waitRecentCommand polls the pair's buffer until a deadline: the buffer
// write happens in the session teardown goroutine, and the moment of the
// session.stop journal event does not pin it -- an honest wait here is polling the state only.
func waitRecentCommand(t *testing.T, f *fixture) (state.CommandHistoryRecord, bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st := f.store.Get()
		rec, ok := st.RecentCommandsFor(f.person, f.machineID)
		if ok && len(rec.Entries) > 0 {
			return rec, true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return state.CommandHistoryRecord{}, false
}

func TestIAMT409_CompletedExecLandsInPairRecentCommands(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "type C:\\car.jpg --token=hunter2"}))
	if err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}
	// The echo machine returns what was written: that is the command's answer,
	// whose first lines are exactly what must land in the buffer.
	if _, err := hs.ch.Write([]byte("car.jpg already exists\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	readUntil(t, hs.ch, "car.jpg already exists")
	// The end of the command: closing our side -- the machine sees EOF,
	// flushes the rest and sends exit-status 0.
	if err := hs.ch.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	f.waitSessionEnd(t, "iamt409 exec session")

	rec, found := waitRecentCommand(t, f)
	if !found {
		t.Fatal("after a completed exec command the pair's buffer is empty -- the classifier " +
			"has nothing to judge the agent's train of thought with (IAMT-409)")
	}
	if len(rec.Entries) != 1 {
		t.Fatalf("the buffer holds %d entries, want 1: %v", len(rec.Entries), rec.Entries)
	}
	e := rec.Entries[0]
	if e.Command != "type C:\\car.jpg --token=<redacted>" {
		t.Errorf("the buffer holds the command %q -- a secret must be scrubbed AT WRITE TIME, "+
			"not when sending to the classifier", e.Command)
	}
	if e.Exit != "0" {
		t.Errorf("the exit code in the buffer = %q, want \"0\"", e.Exit)
	}
	if e.Response != "car.jpg already exists" {
		t.Errorf("the answer in the buffer = %q, want the first line of the machine's answer", e.Response)
	}
	if e.At.IsZero() {
		t.Error("a buffer entry without a time -- the \"what came first\" order cannot be reconstructed")
	}
}

// The buffer is not a refusal history: a command the classifier stopped
// before the machine never ran; it has neither an exit code nor an answer.
func TestIAMT409_BlockedCommandDoesNotLandInBuffer(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionBlock })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "mkfs C:\\ --token=hunter2"}))
	if err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}
	if err := hs.ch.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	f.waitSessionEnd(t, "iamt409 blocked exec session")

	time.Sleep(100 * time.Millisecond)
	st := f.store.Get()
	if rec, ok := st.RecentCommandsFor(f.person, f.machineID); ok && len(rec.Entries) > 0 {
		t.Fatalf("a stopped command landed in the buffer: %v -- the buffer holds what was REALLY executed", rec.Entries)
	}
}
