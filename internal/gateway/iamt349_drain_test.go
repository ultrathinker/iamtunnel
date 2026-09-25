package gateway

// iamt349_drain_test.go — the last thing the specialist did is the one
// thing the owner used to be unable to see.
//
// Found by the review of the merged 1.5 wave. A viewer polls once
// a second. The session ends; the registry entry was dropped the same
// instant; the next poll was answered "nothing here — and, by the way,
// your own offset is the total", a number chosen so the viewer would
// stop rather than because it was true. Everything written between the
// final poll and the end of the session was then unreachable forever,
// and that is precisely the stretch a person leans in for: the last
// command and what it printed.
//
// The answer is a grace period (drainGrace): a finished recording stays
// readable just long enough for somebody already watching to catch up.
// Nothing about WHO may read changes — the access rule still admits only
// the machine the session belonged to.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIAMT349_TheLastOutputBeforeTheSessionEndedIsStillReadable.
//
// Canary: make remove() delete the entry outright again (its behaviour
// before this fix). The tail then reports total == the offset asked for
// and no data, and this goes red naming the bytes that were lost.
func TestIAMT349_TheLastOutputBeforeTheSessionEndedIsStillReadable(t *testing.T) {
	g := &Gateway{}
	dir := t.TempDir()
	castPath := filepath.Join(dir, "s.cast")

	const firstHalf = "{\"version\":2}\n[0.1,\"o\",\"seen by the watcher\\r\\n\"]\n"
	const lastWords = "[0.2,\"o\",\"rm -rf something\\r\\n\"]\n"

	if err := os.WriteFile(castPath, []byte(firstHalf), 0o600); err != nil {
		t.Fatalf("writing the recording: %v", err)
	}
	g.live.add("s1", castPath, "vm1")

	// The watcher catches up with what exists so far.
	out, cerr := cmdSessionsTail(g, "", time.Time{}, []byte(`{"proto":1,"id":"s1","offset":0,"limit":65536}`))
	if cerr != nil {
		t.Fatalf("first poll: %s", cerr.code)
	}
	body := out.(map[string]any)
	caughtUpTo := body["total"].(int64)
	if int(caughtUpTo) != len(firstHalf) {
		t.Fatalf("the watcher caught up to %d bytes, want %d", caughtUpTo, len(firstHalf))
	}

	// Between two polls, the specialist types one last command and the
	// session ends.
	f, err := os.OpenFile(castPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("appending: %v", err)
	}
	if _, err := f.WriteString(lastWords); err != nil {
		t.Fatalf("appending: %v", err)
	}
	_ = f.Close()
	g.live.remove("s1")

	// The next poll. It must carry those bytes, and it must say the
	// session is over so the viewer stops of its own accord.
	out, cerr = cmdSessionsTail(g, "", time.Time{}, []byte(`{"proto":1,"id":"s1","offset":`+itoa(int(caughtUpTo))+`,"limit":65536}`))
	if cerr != nil {
		t.Fatalf("poll after the session ended: %s", cerr.code)
	}
	body = out.(map[string]any)

	if body["live"].(bool) {
		t.Error("the answer still claims the session is live after it ended")
	}
	if got := body["total"].(int64); int(got) != len(firstHalf)+len(lastWords) {
		t.Errorf("total = %d, want the real size %d — an invented total is what silently truncated the view", got, len(firstHalf)+len(lastWords))
	}
	raw, err := base64.StdEncoding.DecodeString(body["data"].(string))
	if err != nil {
		t.Fatalf("data is not base64: %v", err)
	}
	if string(raw) != lastWords {
		t.Fatalf("the last output before the session ended did not come back:\n got %q\nwant %q\nthis is the stretch a person opens the tab for, and it was unreachable for good", raw, lastWords)
	}
}

// TestIAMT349_AFinishedRecordingStopsBeingReadableAfterTheGrace keeps
// the other half honest: the grace is a grace, not a second life. A
// finished session must not stay readable, or the registry becomes a
// way to read recordings long after the fact through a door meant for
// live watching.
func TestIAMT349_AFinishedRecordingStopsBeingReadableAfterTheGrace(t *testing.T) {
	var now time.Time
	g := &Gateway{}
	g.live.now = func() time.Time { return now }
	now = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

	dir := t.TempDir()
	castPath := filepath.Join(dir, "s.cast")
	if err := os.WriteFile(castPath, []byte("{\"version\":2}\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	g.live.add("s1", castPath, "vm1")
	g.live.remove("s1")

	now = now.Add(drainGrace + time.Second)

	out, cerr := cmdSessionsTail(g, "", time.Time{}, []byte(`{"proto":1,"id":"s1","offset":0,"limit":65536}`))
	if cerr != nil {
		t.Fatalf("poll: %s", cerr.code)
	}
	body := out.(map[string]any)
	if body["data"].(string) != "" || body["live"].(bool) {
		t.Fatal("a session that finished long ago is still being served: the grace period is for draining a view already open, not for reading recordings afterwards")
	}
}
