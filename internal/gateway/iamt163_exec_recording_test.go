package gateway

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestIAMT163_ExecWithoutPTYUsesLosslessRecording(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	const command = "cmd /c echo iamt163"
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command}))
	if err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}
	const marker = "lossless-output-\x00-\xff"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write exec stdin: %v", err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("IAMT-163 canary: person did not receive the exec output %q; got %q", marker, got)
	}
	_ = hs.ch.CloseWrite()
	_ = hs.ch.Close()
	waitUntil(t, "exec session did not close", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})
	paths, err := filepath.Glob(filepath.Join(f.recordingsDir(), "*", "*", "*.exec.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("IAMT-163 canary: exec without pty must create exactly one .exec.jsonl, paths=%v err=%v", paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatalf("read exec recording: %v", err)
	}
	var events []struct {
		Type    string `json:"type"`
		Command string `json:"command"`
		Stream  string `json:"stream"`
		Data    string `json:"data"`
	}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var event struct {
			Type    string `json:"type"`
			Command string `json:"command"`
			Stream  string `json:"stream"`
			Data    string `json:"data"`
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("unmarshal exec recording: %v", err)
		}
		events = append(events, event)
	}
	if len(events) == 0 || events[0].Type != "command" || events[0].Command != command {
		t.Fatalf("IAMT-163 canary: first exec JSONL record must be command %q; got %#v", command, events)
	}
	foundOutput := false
	for _, event := range events {
		if event.Stream == "stdout" {
			decoded, _ := base64.StdEncoding.DecodeString(event.Data)
			foundOutput = foundOutput || strings.Contains(string(decoded), marker)
		}
	}
	if !foundOutput {
		t.Fatalf("IAMT-163 canary: .exec.jsonl must losslessly contain machine output %q; got %s", marker, raw)
	}
	if _, err := os.Stat(strings.TrimSuffix(paths[0], ".exec.jsonl") + ".cast"); !os.IsNotExist(err) {
		t.Fatalf("IAMT-163 canary: exec without pty must not fall back to .cast, stat err=%v", err)
	}
	entries, err := scanRecordings(f.recordingsDir())
	if err != nil || len(entries) != 1 {
		t.Fatalf("IAMT-163 canary: recordings.list scan must include exec metadata, entries=%v err=%v", entries, err)
	}
	listBody, _ := json.Marshal(map[string]any{"proto": 1})
	listResult, cerr := cmdRecordingsList(f.gw, "admin", f.clock.Now(), listBody)
	if cerr != nil {
		t.Fatalf("IAMT-163 round-2 canary: recordings.list must read exec counters: %v", cerr)
	}
	views := listResult.(map[string]any)["recordings"].([]recordingView)
	if len(views) != 1 || views[0].BytesIn != int64(len(marker)) || views[0].BytesOut < int64(len(marker)) {
		t.Fatalf("IAMT-163 round-2 canary: recordings.list must expose exec bytesIn=%d and bytesOut >= %d; got %#v", len(marker), len(marker), views)
	}
	body, _ := json.Marshal(map[string]any{"proto": 1, "id": entries[0].id, "part": "exec", "offset": 0, "limit": 4096})
	result, cerr := cmdRecordingsFetch(f.gw, "admin", f.clock.Now(), body)
	if cerr != nil {
		t.Fatalf("IAMT-163 canary: recordings.fetch must accept exec part: %v", cerr)
	}
	if result.(map[string]any)["part"] != "exec" {
		t.Fatalf("IAMT-163 canary: recordings.fetch must return exec part, got %#v", result)
	}
}

func TestIAMT166_PTYDimensionsReachCastHeader(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 120, Rows: 35}))
	if err != nil || !ok {
		t.Fatalf("pty-req: ok=%v err=%v", ok, err)
	}
	ok, err = hs.ch.SendRequest("shell", true, nil)
	if err != nil || !ok {
		t.Fatalf("shell: ok=%v err=%v", ok, err)
	}
	_ = hs.ch.Close()
	waitUntil(t, "PTY session did not close", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})
	paths, err := filepath.Glob(filepath.Join(f.recordingsDir(), "*", "*", "*.cast"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("IAMT-166 canary: pty session must create one .cast, paths=%v err=%v", paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	header := strings.SplitN(string(raw), "\n", 2)[0]
	if !strings.Contains(header, `"width":120`) || !strings.Contains(header, `"height":35`) {
		t.Fatalf("IAMT-166 canary: .cast header must retain pty-req 120x35, got %s", header)
	}
}
