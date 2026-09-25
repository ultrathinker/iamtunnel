package gateway

// IAMT-442: the terminal size a person's client asks for was believed as
// sent. pty-req and window-change carry columns and rows as uint32, the
// gateway handed them to the recording, and the recording's terminal
// emulator allocates rows*cols cells at once - so any person with a grant
// could ask the gateway, with one pty-req, for more memory than it has, and
// the Go runtime ends a process that runs out of memory: no recover, every
// session gone. There was no bound anywhere, neither where the request is
// parsed nor in the emulator.
//
// The size is clamped as soon as the request is parsed, and the CLAMPED
// size is what the machine gets as well: IAMT-217's rule - the recording
// parses in the machine's own geometry - holds for a clamped size just as
// it does for a substituted one.
//
// The test asks for a size just past the bound (1000x500), not for
// 2^32-1: the gateway before the fix had to live through this test in
// order to fail it on its own line.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestIAMT442_OversizedPTYIsClampedForMachineAndRecording(t *testing.T) {
	const wantCols, wantRows = 1000, 500

	var mu sync.Mutex
	var ptyCols, ptyRows, winCols, winRows int
	ptySeen := make(chan struct{}, 1)
	winSeen := make(chan struct{}, 1)

	f := newFixture(t, nil)
	f.sshd.setOnPTYReq(func(cols, rows int) {
		mu.Lock()
		ptyCols, ptyRows = cols, rows
		mu.Unlock()
		select {
		case ptySeen <- struct{}{}:
		default:
		}
	})
	f.sshd.setOnWindowChange(func(cols, rows int) {
		mu.Lock()
		winCols, winRows = cols, rows
		mu.Unlock()
		select {
		case winSeen <- struct{}{}:
		default:
		}
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)

	ok, err := hs.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 1500, Rows: 800}))
	if err != nil || !ok {
		t.Fatalf("pty-req 1500x800: ok=%v err=%v", ok, err)
	}
	ok, err = hs.ch.SendRequest("shell", true, nil)
	if err != nil || !ok {
		t.Fatalf("shell: ok=%v err=%v", ok, err)
	}
	select {
	case <-ptySeen:
	case <-time.After(3 * time.Second):
		t.Fatal("precondition: the fake machine sshd never saw the forwarded pty-req")
	}
	mu.Lock()
	gotCols, gotRows := ptyCols, ptyRows
	mu.Unlock()
	if gotCols != wantCols || gotRows != wantRows {
		t.Fatalf("the machine got pty-req %dx%d for a request of 1500x800, want the bound %dx%d", gotCols, gotRows, wantCols, wantRows)
	}

	// A real client sends window-change with want-reply=false (IAMT-216).
	if _, err := hs.ch.SendRequest("window-change", false, sshx.MarshalWindow(sshx.WindowChange{Columns: 1600, Rows: 900})); err != nil {
		t.Fatalf("send window-change: %v", err)
	}
	select {
	case <-winSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("precondition: the fake machine sshd never saw the forwarded window-change")
	}
	mu.Lock()
	gotCols, gotRows = winCols, winRows
	mu.Unlock()
	if gotCols != wantCols || gotRows != wantRows {
		t.Fatalf("the machine got window-change %dx%d for a request of 1600x900, want the bound %dx%d", gotCols, gotRows, wantCols, wantRows)
	}

	_ = hs.ch.CloseWrite()
	_ = hs.ch.Close()
	waitUntil(t, "PTY session did not close", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	paths, err := filepath.Glob(filepath.Join(f.recordingsDir(), "*", "*", "*.cast"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("the session must leave exactly one .cast, paths=%v err=%v", paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	headerLine := raw
	if i := bytes.IndexByte(raw, '\n'); i >= 0 {
		headerLine = raw[:i]
	}
	var header struct{ Width, Height int }
	if err := json.Unmarshal(headerLine, &header); err != nil {
		t.Fatalf("decode cast header: %v", err)
	}
	if header.Width != wantCols || header.Height != wantRows {
		t.Errorf("the .cast header is %dx%d, want %dx%d - the size the machine got", header.Width, header.Height, wantCols, wantRows)
	}
	if !strings.Contains(string(raw), `"r","1000x500"`) {
		t.Errorf("the .cast has no \"r\" event for the clamped window-change 1000x500:\n%s", raw)
	}
}
