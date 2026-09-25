package ui

// IAMT-453, the window's half. Once the gateway lets a live exec session
// be watched, every reader of sessions.tail has to open its bytes with
// the exec reader: record.ParseCast over an .exec.jsonl returns no error
// and no text, so a window that ignored the answer's `mode` would show an
// empty screen for a session that is plainly producing output. There are
// three such readers - the Admin tab's Watch, the transcript window, and
// the machine owner's Session tab - and each is pinned here.

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

const iamt453Output = "load average: 0.42"

// iamt453ExecRecording is what a live exec recording holds after one
// command wrote one line: the command, then its output in a chunk.
func iamt453ExecRecording() []byte {
	return []byte(`{"seq":0,"type":"command","command":"uptime"}` + "\n" +
		`{"seq":1,"type":"chunk","stream":"stdout","data":"` +
		base64.StdEncoding.EncodeToString([]byte(iamt453Output+"\r\n")) + `"}` + "\n")
}

func TestIAMT453_WatchingALiveExecSessionShowsItsOutput(t *testing.T) {
	f := newBareFrame(t)
	data := iamt453ExecRecording()
	f.cfg.Actions.AdminSessionTail = func(ctx context.Context, id string, offset int64) ([]byte, int64, int64, bool, string, error) {
		if offset >= int64(len(data)) {
			return nil, offset, int64(len(data)), true, record.LiveModeExec, nil
		}
		return data[offset:], int64(len(data)), int64(len(data)), true, record.LiveModeExec, nil
	}

	f.watchSession("session:exec", "alice", "win-test-vm")

	deadline := time.Now().Add(5 * time.Second)
	for {
		f.mu.Lock()
		busy := f.working[ctlAdminLive]
		f.mu.Unlock()
		if !busy {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the watch never finished reading its first slice")
		}
		time.Sleep(5 * time.Millisecond)
	}

	f.watch.mu.Lock()
	got := f.watch.vt.Transcript()
	f.watch.mu.Unlock()
	if !strings.Contains(got, iamt453Output) {
		t.Fatalf("watching a live exec session showed %q, want its output %q: the exec recording was read as a cast", got, iamt453Output)
	}
	if !strings.Contains(got, "$ uptime") {
		t.Errorf("the watched exec session does not name its command:\n%s", got)
	}
}

func TestIAMT453_TheTranscriptWindowReadsALiveExecSessionAsExec(t *testing.T) {
	for _, tc := range []struct {
		mode string
		exec bool
	}{
		{record.LiveModeExec, true},
		{record.LiveModeCast, false},
		{"", false}, // a gateway older than the field: a cast, as before
	} {
		ask := func(ctx context.Context, id string, offset int64) ([]byte, int64, int64, bool, string, error) {
			return []byte("x"), offset + 1, offset + 1, true, tc.mode, nil
		}
		chunk, err := liveTranscriptFeed(ask, "session:1")(context.Background(), 0)
		if err != nil {
			t.Fatalf("mode %q: %v", tc.mode, err)
		}
		if chunk.Exec != tc.exec {
			t.Errorf("mode %q: the transcript window picked Exec=%v, want %v", tc.mode, chunk.Exec, tc.exec)
		}
	}
}

func TestIAMT453_TheSessionTabReadsALiveExecSessionAsExec(t *testing.T) {
	s := &sessionScreenState{views: map[string]*sessionView{}}
	v := &sessionView{id: "session:exec", vt: record.NewVT(80, 24), live: true}
	s.views[v.id] = v

	data := iamt453ExecRecording()
	s.applyForwardFetch(v, SessionTailResp{Data: data, Total: uint64(len(data)), Live: true, Mode: record.LiveModeExec})

	s.mu.Lock()
	got := v.vt.Transcript()
	s.mu.Unlock()
	if !strings.Contains(got, iamt453Output) {
		t.Fatalf("the Session tab showed %q for a live exec session, want its output %q", got, iamt453Output)
	}

	// The emulator is rebuilt from the held bytes on a resize or a
	// scroll back; the rebuild must use the same reader, or the screen
	// empties the first time the window changes size.
	fresh := record.NewVT(80, 24)
	record.ParserFor(v.mode)(v.held, nil, fresh)
	if !strings.Contains(fresh.Transcript(), iamt453Output) {
		t.Errorf("rebuilding from the held bytes lost the exec output: %q", fresh.Transcript())
	}
}
