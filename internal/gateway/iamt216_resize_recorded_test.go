package gateway

// iamt216_resize_recorded_test.go is the canary for IAMT-216: a real
// golang.org/x/crypto/ssh client's Session.WindowChange always sends the
// "window-change" channel request with want-reply=false (RFC 4254 §6.7,
// PROTOCOL §4.1's table row for it says the same: "false"). Every other test
// in this package that exercises window-change sends it with wantReply=true
// instead (see iamt195_close_waits_for_proxy_writers_test.go's file doc
// comment) - a workaround that hid this bug from `go test` even though it
// fires on every real resize, exactly as the live corpus
// capture showed: resize_probe_session.cast has a header of 80x24, 37 "o"
// events and 0 "r" events, even though the machine side visibly resized
// (its own CSI 8;40;120t redraw and "size-after 120x40" are in the "o"
// stream).
//
// Root cause: internal/sshx/requests.go's ApplyDisposition, Forward case,
// used forward()'s own "ok" return value as the verdict regardless of
// wantReply. golang.org/x/crypto/ssh's Channel.SendRequest ALWAYS returns
// ok=false when wantReply is false - it does not wait for or read a reply,
// so it has nothing to report as true (see ssh/channel.go: the wantReply
// branch that reads ch.msg is skipped entirely). ApplyDisposition then read
// that "false" as "the forward failed" and returned Reject, so
// proxyChannelRequests (human_role.go)'s `if applied != sshx.Forward {
// continue }` skipped the resizeRecording switch - even though forward()
// had already put the request on the wire to the machine successfully.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// TestIAMT216_MidSessionResizeRecordedInCast drives a PTY session, resizes it
// mid-session exactly the way a real client (or a resize probe)
// does - "window-change" with want-reply=false - and checks both ends of the
// bug: the new size reaches the machine (this test's fake sshd observes
// cols=120/rows=40) AND the gateway's own .cast recording gains an "r" event
// for it.
//
// Canary: revert internal/sshx/requests.go's ApplyDisposition Forward case
// from `if err != nil || (wantReply && !ok)` back to `if err != nil || !ok`
// and this test fails at the final assertion with:
//
//	IAMT-216 canary: .cast must contain an "r" event for the mid-session
//	window-change to 120x40; got <the recorded .cast bytes, all "o", no "r">
//
// - the machine-side precondition still passes (the request was always put on
// the wire; only the gateway's own bookkeeping of that fact was wrong), which
// is exactly what makes this bug easy to miss without a test that sends
// want-reply=false like a real client does.
func TestIAMT216_MidSessionResizeRecordedInCast(t *testing.T) {
	var mu sync.Mutex
	var gotCols, gotRows int
	seen := make(chan struct{}, 1)

	f := newFixture(t, nil)
	f.sshd.setOnWindowChange(func(cols, rows int) {
		mu.Lock()
		gotCols, gotRows = cols, rows
		mu.Unlock()
		select {
		case seen <- struct{}{}:
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
	hs.shell(t)

	w := sshx.WindowChange{Columns: 120, Rows: 40}
	if _, err := hs.ch.SendRequest("window-change", false, sshx.MarshalWindow(w)); err != nil {
		t.Fatalf("send window-change: %v", err)
	}

	select {
	case <-seen:
	case <-time.After(3 * time.Second):
		t.Fatal("IAMT-216 canary precondition failed: the fake machine sshd never observed the forwarded window-change")
	}
	mu.Lock()
	cols, rows := gotCols, gotRows
	mu.Unlock()
	if cols != 120 || rows != 40 {
		t.Fatalf("IAMT-216 canary precondition failed: machine side saw %dx%d, want 120x40", cols, rows)
	}

	_ = hs.ch.CloseWrite()
	_ = hs.ch.Close()
	waitUntil(t, "PTY session did not close", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	paths, err := filepath.Glob(filepath.Join(f.recordingsDir(), "*", "*", "*.cast"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("IAMT-216: pty session must create exactly one .cast, paths=%v err=%v", paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatalf("read cast: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	found := false
	for _, line := range lines[1:] { // lines[0] is the asciicast v2 header object, not an event
		var ev [3]json.RawMessage
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		var kind string
		if err := json.Unmarshal(ev[1], &kind); err != nil || kind != "r" {
			continue
		}
		var data string
		if err := json.Unmarshal(ev[2], &data); err == nil && data == "120x40" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("IAMT-216 canary: .cast must contain an \"r\" event for the mid-session window-change to 120x40; got %s", raw)
	}
}
