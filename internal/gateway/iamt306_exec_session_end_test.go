package gateway

// iamt306_exec_session_end_test.go: live repro on a real Ubuntu 24.04 host
// (gateway + machine + a raw OpenSSH client, main 7ac7da8) found that
//
//	ssh -p 2022 -i ~/.ssh/id_ed25519 'person:machine'@127.0.0.1 'id -un; hostname; echo MARKER'
//
// ran, printed its output, and then the ssh CLIENT never exited: ssh -vv
// showed a completely normal channel ending (exit-status, eof, the
// client's own channel freed) and then nothing - the gateway's own journal
// showed no session.stop until an unrelated ten-minute idle-close finally
// forced it. Root cause: a plain "ssh gw 'cmd'" client with a live,
// non-redirected stdin is not obliged to close its own side of the exec
// channel just because it received the command's output and exit-status -
// many well-behaved clients wait for the SERVER to close first (exactly the
// behaviour every daily interactive `ssh host cmd` relies on). core.Bridge's
// human -> target copy (human_role.go's serveHumanSession) blocks forever on
// exactly that Read, and nothing in the gateway ever closed the human
// channel to prompt the client's own (protocol-mandatory) close reply,
// because that close was only ever sent from closeAfterMachineDrain - AFTER
// core.Bridge returns, which is exactly what never happened.
//
// TestIAMT306_ExecSessionEndsWithoutHumanEverClosing reproduces this without
// a real ssh binary: the human side of the fixture only reads, and never
// writes, CloseWrite()s or Close()s its own channel - modelling the live
// client's live tty precisely. Before the fix this test times out inside
// waitUntil's 10s bound (a genuine, unbounded deadlock; no timer in the
// product ever unsticks it during a test run - "idle" door-close is a
// synchronous side effect of FinishSession, not a periodic timer, so nothing
// in-process rescues a stuck build the way the live host's connection
// eventually did).
//
// TestIAMT306_ExitStatusRecordedAfterFinalOutput reproduces the second,
// independent defect from the same live run: the fetched .exec.jsonl had
// exit-status (sequence 3) before the command's own last stdout chunk
// (sequence 4) - a transcript that finishes the command before its own last
// line. exit-status travels on proxyMachineRequests' own request stream
// (mreqs), a different Go channel from the one core.Bridge's target->human
// data copy reads, so committing exit-status to the recorder as soon as it
// arrives races that copy instead of waiting for it.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

type execJSONLEvent struct {
	Sequence int    `json:"sequence"`
	Type     string `json:"type"`
	Command  string `json:"command"`
	Stream   string `json:"stream"`
	Data     string `json:"data"`
}

// readExecRecording finds the one .exec.jsonl this fixture must have created
// and parses every line - the same shape iamt163_exec_recording_test.go's
// inline parsing uses, pulled out here so both this file's tests can share
// it.
func readExecRecording(t *testing.T, f *fixture) []execJSONLEvent {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(f.recordingsDir(), "*", "*", "*.exec.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("expected exactly one .exec.jsonl, paths=%v err=%v", paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatalf("read exec recording: %v", err)
	}
	var events []execJSONLEvent
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var e execJSONLEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("unmarshal exec recording line %q: %v", line, err)
		}
		events = append(events, e)
	}
	return events
}

func decodeExecChunk(t *testing.T, base64Data string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		t.Fatalf("decode exec chunk: %v", err)
	}
	return string(decoded)
}

func TestIAMT306_ExecSessionEndsWithoutHumanEverClosing(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	const marker = "iamt306-exec-marker"
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		_, _ = ch.Write([]byte("dana-vb\n"))
		_, _ = ch.Write([]byte(marker + "\n"))
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
		_ = ch.CloseWrite()
		_ = ch.Close()
	})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "id -un; hostname; echo " + marker}))
	if err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("did not receive the machine's exec output %q; got %q", marker, got)
	}

	// The live repro's client: it has already read the command's output
	// and exit-status, and from here on deliberately writes nothing, sends
	// no CloseWrite, and never calls Close() itself - exactly a raw `ssh
	// gw 'cmd'` run against a live interactive terminal.
	waitUntil(t, "IAMT-306 canary: an exec session whose human side never closes its own channel never ended - "+
		"the gateway is waiting on a peer (a plain SSH exec client) that has no reason to close first, so the "+
		"door stays installed indefinitely", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})
}

func TestIAMT306_ExitStatusRecordedAfterFinalOutput(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	const command = "id -un; hostname; echo IAMT_EXEC_MARKER_251"
	const lastLine = "IAMT_EXEC_MARKER_251"
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		_, _ = ch.Write([]byte("dana-vb\n"))
		// The live repro's exact shape: exit-status is sent on the request
		// stream immediately after the data, with nothing serializing it
		// against a reader that is still catching up on that data - the
		// two travel on independent Go channels inside the gateway
		// (regular channel data vs. the request stream), so without an
		// explicit wait, which one gets recorded first is a race.
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
		_, _ = ch.Write([]byte(lastLine + "\n"))
		_ = ch.CloseWrite()
		_ = ch.Close()
	})

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command}))
	if err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}
	_ = readUntil(t, hs.ch, lastLine)

	waitUntil(t, "exec session did not end", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	events := readExecRecording(t, f)
	lastChunkSeq := -1
	exitStatusSeq := -1
	for _, e := range events {
		if e.Type == "chunk" && strings.Contains(decodeExecChunk(t, e.Data), lastLine) {
			lastChunkSeq = e.Sequence
		}
		if e.Type == "exit-status" {
			exitStatusSeq = e.Sequence
		}
	}
	if lastChunkSeq == -1 {
		t.Fatalf("IAMT-306 canary precondition failed: .exec.jsonl never recorded the command's last stdout chunk %q; got %#v", lastLine, events)
	}
	if exitStatusSeq == -1 {
		t.Fatalf("IAMT-306 canary precondition failed: .exec.jsonl never recorded exit-status; got %#v", events)
	}
	if exitStatusSeq < lastChunkSeq {
		t.Fatalf("IAMT-306 canary: .exec.jsonl recorded exit-status (sequence %d) before the command's own last "+
			"stdout chunk (sequence %d) - a transcript that finishes the command before its own last line; got %#v",
			exitStatusSeq, lastChunkSeq, events)
	}
}
