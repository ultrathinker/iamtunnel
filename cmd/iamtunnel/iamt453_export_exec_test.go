//go:build !nogui

package main

// IAMT-453, the machine's Export button. sessions.mine has always listed
// exec sessions, but until the gateway registered them live their tail
// answered nothing and Export refused. Now the tail serves the bytes, and
// they are an exec recording: read as a cast they give an empty text, and
// kept as session.cast they would be a file that says it is asciicast and
// is not.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/proto"
	"github.com/ultrathinker/iamtunnel/internal/server"
)

func TestIAMT453_ExportOfALiveExecSessionIsItsText(t *testing.T) {
	recording := []byte(`{"seq":0,"type":"command","command":"uptime"}` + "\n" +
		`{"seq":1,"type":"chunk","stream":"stdout","data":"` +
		base64.StdEncoding.EncodeToString([]byte("load average: 0.42\r\n")) + `"}` + "\n")
	inner := &chunkedTail{cast: recording, serve: 16, live: true}
	tail := func(ctx context.Context, req server.TailRequest) (server.TailAnswer, error) {
		ans, err := inner.call(ctx, req)
		if err != nil {
			return ans, err
		}
		var body map[string]any
		if err := json.Unmarshal(ans.Result, &body); err != nil {
			return ans, err
		}
		body["mode"] = "exec"
		ans.Result, err = json.Marshal(body)
		return ans, err
	}
	dir := exportTestServer(t, tail, staticMine([]proto.MineSession{{
		ID: exportTestSessionID, Person: "alice", Started: "2026-01-05T14:12:05Z",
	}}))
	exportTestMachine(t, dir, "vm-nine")

	msg, err := guiSessionExport(dir, exportTestSessionID)
	if err != nil {
		t.Fatalf("guiSessionExport: %v", err)
	}
	wantDir := filepath.Join(dir, exportRootName, "2026-01-05", "vm-nine_alice_141205_"+exportTestSessionID)
	if !strings.Contains(msg, wantDir) {
		t.Fatalf("message %q does not name the folder %q", msg, wantDir)
	}

	text, terr := os.ReadFile(filepath.Join(wantDir, "0001.txt"))
	if terr != nil {
		t.Fatalf("0001.txt: %v", terr)
	}
	if want := "$ uptime\nload average: 0.42"; string(text) != want {
		t.Fatalf("0001.txt = %q, want %q: the exec recording was read as a cast", text, want)
	}
	if _, serr := os.Stat(filepath.Join(wantDir, "session.cast")); !os.IsNotExist(serr) {
		t.Fatalf("an exec recording was exported as session.cast (stat: %v): the file says asciicast and is not", serr)
	}
}
