package gateway

// IAMT-454: awaitSessionStart ended the session's setup at pty-req. A
// pty-req starts nothing, but it stopped the setup timer (PROTOCOL §1.4
// gives 20 s from channel-open to a successful shell or exec) and it
// decided the session's shape: a terminal recording with no command. So
//   - a pty-req and then silence held the session - door open, counted -
//     for as long as the person cared to wait, with no program ever run;
//   - "ssh -t gw command" - pty-req, then exec - ran a command that was
//     nowhere on record: not in session.start (the command went there only
//     for an exec with no pty-req), not in the .meta, not in the .cast
//     (an exec is not echoed to the terminal). For a green command
//     nothing else wrote it down either.

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestIAMT454_APtyReqAloneDoesNotEndTheSetup(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err != nil || !ok {
		t.Fatalf("pty-req: ok=%v err=%v", ok, err)
	}
	// No shell, no exec - ever. The setup has SessionSetupTimeout (3 s in
	// the fixture) to see one, and then the session is over.
	waitUntil(t, "a session that got a pty-req and never a shell or an exec is still counted, its door held open, well past SessionSetupTimeout", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		if !ok {
			return false
		}
		s := mc.doorMachine.Snapshot()
		return s.Sessions == 0 && s.Reservations == 0
	})
}

func TestIAMT454_AnExecAfterAPtyReqIsOnRecord(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err != nil || !ok {
		t.Fatalf("pty-req: ok=%v err=%v", ok, err)
	}
	const command = "cmd /c echo iamt-454"
	ok, err = hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command}))
	if err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}

	var start *events.Event
	waitUntil(t, "no session.start in the journal", func() bool {
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionStart}})
		if err != nil || len(evs) == 0 {
			return false
		}
		start = &evs[len(evs)-1]
		return true
	})
	if got, _ := start.Details["command"].(string); got != command {
		t.Fatalf("session.start of \"ssh -t gw %s\" carries command %q: the journal does not say what ran", command, got)
	}

	casts, _ := filepath.Glob(filepath.Join(f.recordingsDir(), "*", "*", "*.cast"))
	if len(casts) != 1 {
		t.Fatalf("a terminal session should leave one .cast, found %v", casts)
	}
	file, err := os.Open(casts[0])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	line, _ := bufio.NewReader(file).ReadBytes('\n')
	var header struct {
		Command string `json:"command"`
	}
	if err := json.Unmarshal(line, &header); err != nil || header.Command != command {
		t.Errorf(".cast header %q does not name the command (err=%v)", line, err)
	}
	meta, err := record.ReadMeta(casts[0][:len(casts[0])-len(".cast")] + ".meta")
	if err != nil {
		t.Fatalf("read .meta: %v", err)
	}
	var metaFields map[string]any
	raw, _ := json.Marshal(meta)
	_ = json.Unmarshal(raw, &metaFields)
	if metaFields["command"] != command {
		t.Errorf(".meta %s does not name the command", raw)
	}
}
