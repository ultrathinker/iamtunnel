package gateway

// r4_f09_session_start_scrub_test.go — R4 F-09.
//
// session.start carries the exec command in Details["command"] (IAMT-210).
// THREATS promises that command and goal pass the same scrubber before
// "journal output"; session.risk and risk.approval scrub, and the goal in
// this very event is scrubbed. The command must be too, or the secret the
// neighbouring rows hide sits in plain text one line above them. The full
// command stays in the session record (.exec.jsonl/.meta, 0600).

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestR4F09_SessionStartScrubsTheExecCommand(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dialHuman: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)

	const secret = "S3cretR4F09"
	command := "curl -u admin:" + secret + " https://example.invalid/"
	if ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command})); err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}
	const marker = "r4f09-marker"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write exec stdin: %v", err)
	}
	readUntil(t, hs.ch, marker)
	_ = hs.ch.CloseWrite()
	_ = hs.ch.Close()

	deadline := f.clock.Now().Add(10 * time.Second)
	var starts []events.Event
	waitUntil(t, "no session.start in the journal", func() bool {
		evs, _, err := f.log.Read(events.Filter{
			Types:  []events.EventType{events.EventSessionStart},
			Actor:  f.person,
			Object: f.machineID,
			Until:  &deadline,
		})
		if err != nil {
			return false
		}
		starts = evs
		return len(evs) > 0
	})
	cmd, _ := starts[0].Details["command"].(string)
	if cmd == "" {
		t.Fatalf("session.start has no Details[\"command\"]; details=%+v", starts[0].Details)
	}
	if strings.Contains(cmd, secret) {
		t.Fatalf("R4 F-09: session.start journals the exec command unscrubbed: %q (the secret %q must not reach events.jsonl)", cmd, secret)
	}
	if !strings.Contains(cmd, "curl") {
		t.Fatalf("scrubbed command lost its shape: %q", cmd)
	}
}
