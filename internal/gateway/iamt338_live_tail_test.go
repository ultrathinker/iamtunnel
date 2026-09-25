package gateway

// iamt338_live_tail_test.go — watching a session while it is still
// happening (IAMT-338).
//
// The registry is the whole reason this feature can exist at all. A
// finished session is found by walking the recordings directory for
// `.meta` files, and `.meta` is written by finalize — at the end. A
// session in progress has no `.meta`, and its file name is not
// derivable from outside either: when the name a recording wants is
// already taken, the recorder takes the NEXT one rather than refuse the
// session or overwrite the earlier recording (record/sessionname.go).
// So the only party that knows where a live session is being written is
// the session itself.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIAMT338_TheRegistryDoesNotLeak is the property that makes this
// safe to run on a busy gateway: an entry that outlives its session
// would keep a watcher polling a file nobody writes to any more, and
// the map would grow without bound.
//
// Canary: drop the `defer g.live.remove(sessionID)` in human_role.go and
// the equivalent of this goes red at the product level; here the unit
// itself is pinned.
func TestIAMT338_TheRegistryDoesNotLeak(t *testing.T) {
	// The clock is the test's, so the grace period can be waited out
	// without waiting.
	var now time.Time
	live := liveRecordings{now: func() time.Time { return now }}
	now = time.Date(2026, 9, 18, 12, 0, 0, 0, time.UTC)

	live.add("s1", `C:\rec\s1.cast`, "vm1")
	live.add("s2", `C:\rec\s2.cast`, "vm1")
	if live.len() != 2 {
		t.Fatalf("registry holds %d entries, want 2", live.len())
	}

	// A session ends. The entry does NOT vanish at once: whoever was
	// watching is one poll behind, and the bytes written just before
	// the end are the ones worth seeing. It is known, and not live.
	live.remove("s1")
	if _, known, isLive := live.path("s1"); !known || isLive {
		t.Fatalf("after the session ended the recording is known=%v live=%v, want known and not live - a viewer must be able to drain what was written just before the end", known, isLive)
	}

	// And then it does vanish, on its own, without anybody asking.
	now = now.Add(drainGrace + time.Second)
	if _, known, _ := live.path("s1"); known {
		t.Fatal("the finished recording outlived its grace period: an entry that never expires keeps a watcher polling a file nobody writes to, and on a busy gateway the map would never stop growing")
	}

	live.remove("s2")
	now = now.Add(drainGrace + time.Second)
	if n := live.len(); n != 0 {
		// len() does not sweep, so ask for the entry to force it.
		live.path("s2")
		if n := live.len(); n != 0 {
			t.Errorf("registry still holds %d entries well past the grace period", n)
		}
	}

	// Removing something that was never there is what every exit path
	// of a refused session does, and it must not panic or resurrect.
	live.remove("never-registered")
	if _, known, _ := live.path("never-registered"); known {
		t.Error("removing an unknown session brought it into being")
	}
}

// TestIAMT338_ARecorderThatCannotNameItsFilesRegistersNothing. The
// recording behind core.Recording is an interface, and this package's
// own test doubles implement it without a Paths method. Registering an
// empty path would hand a watcher a file name of "" and turn a missing
// double into a confusing read error much later.
func TestIAMT338_ARecorderThatCannotNameItsFilesRegistersNothing(t *testing.T) {
	var live liveRecordings
	live.add("s1", "", "vm1")
	live.add("", `C:\rec\x.cast`, "vm1")
	if n := live.len(); n != 0 {
		t.Errorf("registry accepted %d incomplete entries; a nameless recording is not watchable and must simply not be listed", n)
	}
}

// TestIAMT338_TailRefusesAnOffsetOrLimitOutsideTheContract keeps the
// wire shape identical to recordings.fetch, which is the whole reason
// the command looks the way it does: one bounded chunk, caller walks.
func TestIAMT338_TailRefusesAnOffsetOrLimitOutsideTheContract(t *testing.T) {
	g := &Gateway{}
	for _, bad := range []struct {
		name string
		body string
	}{
		{"negative offset", `{"proto":1,"id":"s1","offset":-1,"limit":1024}`},
		{"zero limit", `{"proto":1,"id":"s1","offset":0,"limit":0}`},
		{"limit past the ceiling", `{"proto":1,"id":"s1","offset":0,"limit":1048577}`},
	} {
		t.Run(bad.name, func(t *testing.T) {
			if _, cerr := cmdSessionsTail(g, "alice", time.Time{}, []byte(bad.body)); cerr == nil {
				t.Fatalf("sessions.tail accepted %s — the bound exists so that one JSON object stays one JSON object (PROTOCOL §1.2)", bad.name)
			}
		})
	}
}

// TestIAMT338_ASessionThatIsNotLiveIsAnAnswerNotAnError. A watcher that
// attaches just as the session ends, or that names a session that never
// existed, must get the same plain answer: nothing more is coming. An
// error there would make the ordinary end of every session look like a
// failure in the window, and telling the two cases apart would leak
// whether a session id ever existed.
func TestIAMT338_ASessionThatIsNotLiveIsAnAnswerNotAnError(t *testing.T) {
	g := &Gateway{}
	out, cerr := cmdSessionsTail(g, "alice", time.Time{}, []byte(`{"proto":1,"id":"gone","offset":40,"limit":1024}`))
	if cerr != nil {
		t.Fatalf("a finished session was reported as an error: %v — the end of a session is not a failure", cerr)
	}
	m, ok := out.(map[string]any)
	if !ok {
		t.Fatalf("sessions.tail returned %T", out)
	}
	if m["live"] != false {
		t.Errorf("live = %v, want false", m["live"])
	}
	if m["total"] != int64(40) {
		t.Errorf("total = %v, want the caller's own offset (40) so the watcher stops instead of re-reading", m["total"])
	}
	if m["data"] != "" {
		t.Errorf("data = %q, want empty", m["data"])
	}
}

// TestIAMT338_TailServesTheBytesWrittenSoFar is the feature itself: a
// file that is still being appended to is readable up to its current
// size, and the answer says there is more to come.
//
// Canary: make cmdSessionsTail report total as the offset it was given
// rather than the file's size, and this goes red on "the watcher would
// never see anything".
func TestIAMT338_TailServesTheBytesWrittenSoFar(t *testing.T) {
	dir := t.TempDir()
	cast := filepath.Join(dir, "live.cast")
	first := []byte(`{"version":2}` + "\n" + `[0.1,"o","hello"]` + "\n")
	if err := os.WriteFile(cast, first, 0o600); err != nil {
		t.Fatalf("seed the cast file: %v", err)
	}

	g := &Gateway{}
	g.live.add("s1", cast, "vm1")

	out, cerr := cmdSessionsTail(g, "alice", time.Time{}, []byte(`{"proto":1,"id":"s1","offset":0,"limit":1024}`))
	if cerr != nil {
		t.Fatalf("sessions.tail: %v", cerr)
	}
	m := out.(map[string]any)
	if m["live"] != true {
		t.Error("a session still in the registry was reported as finished")
	}
	if m["total"] != int64(len(first)) {
		t.Errorf("total = %v, want %d — a watcher that is told the file is as long as its own offset never sees anything", m["total"], len(first))
	}
	got, derr := base64.StdEncoding.DecodeString(m["data"].(string))
	if derr != nil {
		t.Fatalf("data is not base64: %v", derr)
	}
	if string(got) != string(first) {
		t.Errorf("served %q, want %q", got, first)
	}

	// The session writes more; the watcher asks from where it stopped
	// and gets only the new bytes. This is the whole polling loop.
	more := []byte(`[0.9,"o","world"]` + "\n")
	f, err := os.OpenFile(cast, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if _, err := f.Write(more); err != nil {
		t.Fatalf("append: %v", err)
	}
	f.Close()

	out, cerr = cmdSessionsTail(g, "alice", time.Time{}, []byte(`{"proto":1,"id":"s1","offset":`+itoa(len(first))+`,"limit":1024}`))
	if cerr != nil {
		t.Fatalf("second tail: %v", cerr)
	}
	m = out.(map[string]any)
	got, _ = base64.StdEncoding.DecodeString(m["data"].(string))
	if string(got) != string(more) {
		t.Errorf("the follow-up chunk was %q, want only the newly written %q", got, more)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
