//go:build windows || linux || darwin

package ui

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// Canary: a transcript from History is read as a FINISHED recording,
// not a live tail.
//
// 22.09.2026. The maintainer had just run a session, opened History,
// pressed Transcript and got a window with "read 0 of 0 bytes" and
// "(nothing yet)". Nothing was broken: the recording had been on disk
// the whole time. The button simply asked the wrong question.
//
// sessions.tail looks the identifier up in the registry of OPEN
// recordings and, through drainGrace after the session's end,
// honestly answers with emptiness. On screen that is
// indistinguishable from a session in which the person typed nothing
// -- that is, from "they did nothing". For an access journal this is
// the worst possible answer: it looks like an answer.
//
// A History row by definition describes a finished visit, so
// recordings.fetch must be the one to read it. The canary reads the
// source: history.go must contain no call of the live window.
func TestCanary_HistoryReadsFinishedRecordings(t *testing.T) {
	src, err := os.ReadFile("history.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "f.openTranscriptWindow(") {
		t.Error("history.go opens the transcript with the live reader (openTranscriptWindow). " +
			"A history row is a finished visit; the live tail answers it with an empty window. " +
			"openHistoryTranscript is needed")
	}
	if !strings.Contains(string(src), "f.openHistoryTranscript(") {
		t.Error("history.go no longer opens a transcript at all -- the Transcript button is orphaned")
	}
}

// The same question, but by behaviour: the feed from History must
// translate the session identifier into the recording identifier and
// request the part matching the format.
func TestHistoryTranscriptFeed_ResolvesTheSessionAndPicksTheFormat(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		wantPart string
		wantExec bool
	}{
		{mode: "exec", wantPart: "exec", wantExec: true},
		{mode: "", wantPart: "cast", wantExec: false},
	} {
		lists := 0
		gotPart, gotID := "", ""
		feed := historyTranscriptFeed(
			func(ctx context.Context, machine, from, to string) ([]RecordingRef, error) {
				lists++
				if machine != "win-test-vm" {
					t.Errorf("the feed did not narrow the list by the row's machine: %q", machine)
				}
				return []RecordingRef{
					{ID: "other", SessionID: "not-this-one"},
					{ID: "wanted", SessionID: "sess-1", Mode: tc.mode},
				}, nil
			},
			func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error) {
				gotID, gotPart = id, part
				return []byte("bytes"), 5, 5, nil
			},
			"sess-1", "win-test-vm",
		)

		c, err := feed(context.Background(), 0)
		if err != nil {
			t.Fatal(err)
		}
		if gotID != "wanted" {
			t.Errorf("mode %q: recording %q was requested, but the one with the matching sessionId is needed", tc.mode, gotID)
		}
		if gotPart != tc.wantPart {
			t.Errorf("mode %q: part %q was requested, want %q", tc.mode, gotPart, tc.wantPart)
		}
		if c.Exec != tc.wantExec {
			t.Errorf("mode %q: Exec=%v, want %v -- the reader is chosen from metadata, not from bytes", tc.mode, c.Exec, tc.wantExec)
		}
		if c.Live {
			t.Errorf("mode %q: a finished recording declared live -- the window will poll it forever", tc.mode)
		}

		// The second call must not scan the gateway again.
		if _, err := feed(context.Background(), 5); err != nil {
			t.Fatal(err)
		}
		if lists != 1 {
			t.Errorf("mode %q: the recording list was requested %d times; the lookup happens once per window", tc.mode, lists)
		}
	}
}

// A recording already removed by rotation is not an error. The
// journal lives longer than the recordings by design, and a row from
// two quarters back is an ordinary occurrence. A red error line would
// read as a malfunction.
func TestHistoryTranscriptFeed_SaysWhenTheRecordingIsGone(t *testing.T) {
	feed := historyTranscriptFeed(
		func(ctx context.Context, machine, from, to string) ([]RecordingRef, error) {
			return []RecordingRef{{ID: "x", SessionID: "someone-else"}}, nil
		},
		func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error) {
			t.Error("the feed went after the bytes of a recording that is not in the list")
			return nil, 0, 0, nil
		},
		"sess-gone", "",
	)
	c, err := feed(context.Background(), 0)
	if err != nil {
		t.Fatalf("a vanished recording is an answer, not an error: %v", err)
	}
	if c.Note == "" {
		t.Fatal("the window received neither bytes nor an explanation -- the screen will show \"(nothing yet)\", that is, a lie")
	}
	if !strings.Contains(strings.ToLower(c.Note), "recording") {
		t.Errorf("the explanation is not about the recording: %q", c.Note)
	}
}

// A gateway failure must reach the window as a failure.
func TestHistoryTranscriptFeed_PassesTheGatewayFailureOn(t *testing.T) {
	feed := historyTranscriptFeed(
		func(ctx context.Context, machine, from, to string) ([]RecordingRef, error) {
			return nil, errors.New("gateway refused")
		},
		func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error) {
			return nil, 0, 0, nil
		},
		"sess-1", "",
	)
	if _, err := feed(context.Background(), 0); err == nil {
		t.Fatal("the gateway refusal was swallowed -- the window will show emptiness instead of the cause")
	}
}
