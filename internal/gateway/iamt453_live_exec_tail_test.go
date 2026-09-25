package gateway

// IAMT-453: a live exec session could not be watched. The live registry
// took a recording's file from `Paths() record.SessionPaths`; an exec
// recording answers `Paths() ExecPaths`, so the type assertion was always
// false and no exec session ever reached the registry - sessions.tail
// answered "nothing live here" for every one of them, from the Admin tab
// and from the machine's own window alike. The two recordings are read
// differently, too: a reader has to be told which it has before it opens
// the bytes (PROTOCOL §6, recordings.list's mode), and sessions.tail said
// nothing of the kind.

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestIAMT453_ALiveExecSessionCanBeWatched(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "cmd /c more"}))
	if err != nil || !ok {
		t.Fatalf("exec: ok=%v err=%v", ok, err)
	}
	const marker = "iamt-453-live-output"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write: %v", err)
	}
	readUntil(t, hs.ch, marker)

	live, err := root.SessionsActive()
	if err != nil || len(live) != 1 {
		t.Fatalf("sessions.active: %v %v", live, err)
	}
	raw, err := root.Exec("sessions.tail", map[string]any{"proto": 1, "id": live[0].ID, "offset": 0, "limit": 1 << 16})
	if err != nil {
		t.Fatalf("sessions.tail: %v", err)
	}
	var tail struct {
		Live bool   `json:"live"`
		Data string `json:"data"`
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &tail); err != nil {
		t.Fatal(err)
	}
	data, _ := base64.StdEncoding.DecodeString(tail.Data)
	if !tail.Live || len(data) == 0 {
		t.Fatalf("sessions.tail of a running exec session answers live=%v with %d bytes: the session cannot be watched", tail.Live, len(data))
	}
	if tail.Mode != "exec" {
		t.Errorf("sessions.tail does not say the bytes are an exec recording (mode %q): a reader would run them through the terminal emulator", tail.Mode)
	}
}
