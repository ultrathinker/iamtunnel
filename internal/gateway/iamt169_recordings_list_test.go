package gateway

// IAMT-169 (recordings.list per PROTOCOL §6):
//
//   - bytesIn (human -> machine) and bytesOut (machine -> human)
//     are present in the recordings.list answer;
//   - from / to filter sessions by StartedAt (inclusive).
//
// The behavioral tests raise a real gateway fixture (a new recorder
// + a real network), run a full person session with a known-in-advance
// number of human and machine bytes, and check the numbers through
// admin.RecordingsList and the from/to filter behavior.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
)

// recordOneSession raises a person session on f, writes INPUT and END
// to the input and waits for their echo from fakeTargetSSHD. Then it
// closes the session and returns. It uses a fakeClocked StartedAt stamp;
// suitable for from/to filtering.
func recordOneSession(t *testing.T, f *fixture) {
	t.Helper()
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	acc := drain(hs.ch)
	if _, err := hs.ch.Write([]byte("INPUT")); err != nil {
		t.Fatalf("write INPUT: %v", err)
	}
	if !waitContains(t, acc, "INPUT", 3*time.Second) {
		t.Fatalf("the INPUT echo never arrived: %q", acc.get())
	}
	if _, err := hs.ch.Write([]byte("END")); err != nil {
		t.Fatalf("write END: %v", err)
	}
	if !waitContains(t, acc, "END", 3*time.Second) {
		t.Fatalf("the END echo never arrived: %q", acc.get())
	}
	_ = client.Close()
}

func dialRootAdmin(t *testing.T, f *fixture) *admin.Conn {
	t.Helper()
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	return dialAdmin(t, f, "root", rootKey)
}

// waitForNFinalizedRecordings was the IAMT-193 helper that polled
// recordings.list (WalkDir + JSON parse) every 2 ms waiting for n
// finalized entries (BytesOut>0). It is removed under IAMT-211: the
// test now waits on a terminal session event in events.jsonl (via
// (*fixture).waitSessionEnd, which polls f.log.Read with a type
// filter), and the recordings.list query becomes a one-shot call
// that runs strictly after the writer has finished, so the
// mid-rewrite .meta gap (record.WriteMeta on Windows: os.Remove then
// os.Rename) cannot race the reader. The previous failure mode was
// that gap landing in front of every poll iteration for long enough
// to time out the 10 s deadline (-race -count=30 parallel, gate 11).
//
// Round 1 of IAMT-211 routed the same signal through a
// Config.OnSessionEnd field and a per-fixture channel; round 2
// removed that field (production structs carry no test-only
// fields) and reads events.jsonl instead.

// TestIAMT169_RecordingsList_BytesInBytesOut_SessionVisible —
// behavioral test "all we know: the human INPUT/END and their echo
// from the machine". After the session closes, recordings.list must
// return a single record with bytesIn>=10 and bytesOut>0.
func TestIAMT169_RecordingsList_BytesInBytesOut_SessionVisible(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	root := dialRootAdmin(t, f)

	recordOneSession(t, f)

	// IAMT-211: wait on events.jsonl for the next terminal session event
	// (session.stop on a clean end, session.drop otherwise) instead of
	// polling recordings.list for BytesOut>0. By the time
	// waitSessionEnd returns, the journal has been fsync'd (Append
	// does file.Sync, events/log.go:175) with the terminal event for
	// (f.person, f.machineID), and the gateway has already run the
	// path through core.Bridge→rec.Close (PTY) or execRec.Finish
	// (exec) — human_role.go runs appendEvent strictly after those
	// calls. The one-shot RecordingsList query below therefore cannot
	// race the writer.
	f.waitSessionEnd(t, "session never reached its terminal event")

	list, err := root.RecordingsList(f.machineID, "", "")
	if err != nil {
		t.Fatalf("RecordingsList: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("recordings.list: want exactly 1 record, got %d", len(list))
	}

	rv := list[0]
	if rv.Machine != f.machineID {
		t.Fatalf("recordings.list: machine want %q, got %q", f.machineID, rv.Machine)
	}
	if rv.Person != f.person {
		t.Fatalf("recordings.list: person want %q, got %q", f.person, rv.Person)
	}
	// bytesOut: everything target->human that went through Recorder.Write.
	// fakeTargetSSHD echoes every chunk back, plus there may be pty-req
	// hints/banners -- the final number is > 0.
	if rv.BytesOut <= 0 {
		t.Fatalf("recordings.list: bytesOut must be > 0 (the echo and/or a banner); got %d", rv.BytesOut)
	}
	// bytesIn: human -> machine, at least INPUT + END = 10 bytes.
	if rv.BytesIn < int64(len("INPUTEND")) {
		t.Fatalf("recordings.list: bytesIn want >= %d (INPUT + END), got %d", len("INPUTEND"), rv.BytesIn)
	}
}

// TestIAMT169_RecordingsList_FromTo_FiltersByStartedAt -- two sessions
// at moments far apart in time; from/to filter by StartedAt
// inclusively.
func TestIAMT169_RecordingsList_FromTo_FiltersByStartedAt(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	root := dialRootAdmin(t, f)

	// The fixture's default grant is only valid for 1h from construction
	// (newFixture: until = clock.Now().Add(time.Hour)); this test advances
	// the fake clock by 2h between sessions, which would otherwise expire
	// the grant mid-test and make the second recordOneSession's pty-req
	// fail with "ok=false err=EOF" (ACL denies the session, not a transport
	// bug). GrantAccess refuses a second grant for the same (person,
	// machine) pair, so replace the short-lived fixture grant with one
	// that outlives both sessions instead of trying to "extend" it in
	// place.
	if _, err := root.GrantsRevoke(f.person, f.machineID); err != nil {
		t.Fatalf("revoke fixture's default 1h grant: %v", err)
	}
	if _, err := root.GrantsGrant(f.person, f.machineID, f.clock.Now().Add(6*time.Hour).UTC().Format(time.RFC3339), "shell"); err != nil {
		t.Fatalf("re-grant with a longer window before clock advance: %v", err)
	}

	recordOneSession(t, f)
	// IAMT-211 (round 2): wait on events.jsonl for the next terminal
	// session event instead of polling recordings.list for BytesOut>0.
	// The previous helper (waitForNFinalizedRecordings, IAMT-193) polled
	// WalkDir every 2 ms for up to 10 s, and under -race -count=30
	// parallel runs (gate 11) the .meta gap of record.WriteMeta could
	// land in front of every poll iteration for long enough to time
	// out. f.waitSessionEnd polls events.jsonl (a single file with
	// fsync on every write) for a new session.stop / session.drop
	// matching (f.person, f.machineID); the journal entry is appended
	// strictly after the recording finalize (PTY: rec.Close inside
	// core.Bridge; exec: execRec.Finish on human_role.go:415), so by
	// the time the journal reports it, the .meta is durable on disk.
	session1Started := f.clock.Now().UTC().Format(time.RFC3339)
	f.waitSessionEnd(t, "session 1 never reached its terminal event")

	f.clock.Advance(2 * time.Hour)
	session2Started := f.clock.Now().UTC().Format(time.RFC3339)
	recordOneSession(t, f)
	// Same IAMT-211 (round 2) fix for session 2: deterministic
	// session-end signal in events.jsonl, not a 10 s poll. Both
	// recordings are now durable on disk by the time we drop into
	// the from/to range checks below.
	f.waitSessionEnd(t, "session 2 never reached its terminal event")

	// One-shot recordings.list query: now that the terminal events
	// have landed, both .meta files have been written and the
	// WalkDir-based listing cannot race the writer (IAMT-193's
	// Remove-then-Rename window has long since closed).
	all, err := root.RecordingsList("", "", "")
	if err != nil {
		t.Fatalf("RecordingsList (all): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("after two session-ends want exactly 2 finalized records, got %d: %+v", len(all), all)
	}

	// A narrow window catching only the second session: from=current-2h
	// -- the session sits at current-1h ~ +inf (i.e. StartedAt > from),
	// to=current+1h -- the session sits <= to. The first session at
	// current-2h is cut off (StartedAt < from).
	from := f.clock.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	to := f.clock.Now().Add(1 * time.Hour).Format(time.RFC3339)

	narrowList, err := root.RecordingsList("", from, to)
	if err != nil {
		t.Fatalf("RecordingsList(from, to): %v", err)
	}
	if len(narrowList) != 1 {
		t.Fatalf("the narrow window [from=%s, to=%s] must leave exactly one (the second) session; got %d records (of %d total)", from, to, len(narrowList), len(all))
	}
	// The exact value, not only the range: the second session must be
	// exactly at the known-in-advance f.clock moment+2h (IAMT-193).
	if narrowList[0].Started != session2Started {
		t.Fatalf("the narrow window returned a record with started=%s, want exactly started=%s (the second session)", narrowList[0].Started, session2Started)
	}

	// Even narrower: the first session exactly at f.clock-2h-minute ...
	// +2h+minute, and its started is also known in advance and exact.
	firstOnly, err := root.RecordingsList("",
		f.clock.Now().Add(-2*time.Hour-time.Minute).Format(time.RFC3339),
		f.clock.Now().Add(-2*time.Hour+time.Minute).Format(time.RFC3339))
	if err != nil {
		t.Fatalf("RecordingsList(from, to) around the first session: %v", err)
	}
	if len(firstOnly) != 1 {
		t.Fatalf("the narrow window around the first session must return 1, got %d", len(firstOnly))
	}
	if firstOnly[0].Started != session1Started {
		t.Fatalf("the narrow window around the first session returned started=%s, want exactly started=%s", firstOnly[0].Started, session1Started)
	}
}

// TestIAMT169_RecordingsList_OldMetaWithoutBytesOut_FallsBackToTotalBytes —
// a .meta file written before IAMT-169 (no "bytes_out"/"bytes_in" keys at
// all, only the pre-existing "total_bytes") must still surface a usable
// bytesOut in recordings.list: cmdRecordingsList's fallback (BytesOut==0 ->
// use TotalBytes) is the only thing standing between an operator and a
// recordings.list entry that silently reports 0 bytes for every recording
// made before this feature shipped. bytesIn has no pre-existing field to
// fall back to and must read as 0, not panic or error the whole listing.
func TestIAMT169_RecordingsList_OldMetaWithoutBytesOut_FallsBackToTotalBytes(t *testing.T) {
	f := newFixture(t, nil)
	root := dialRootAdmin(t, f)

	oldMeta := map[string]any{
		"person":           f.person,
		"machine":          f.machineID,
		"session_id":       "old-format-1",
		"started_at":       f.clock.Now().Format(time.RFC3339),
		"ended_at":         f.clock.Now().Add(time.Minute).Format(time.RFC3339),
		"duration_seconds": 60,
		"status":           "completed",
		"aborted":          false,
		"window_size":      map[string]any{"cols": 80, "rows": 24},
		"cast_file":        map[string]any{"name": "old-format-1.cast"},
		"txt_file":         map[string]any{"name": "old-format-1.txt"},
		"total_bytes":      4096,
		// Deliberately no "bytes_out" / "bytes_in" keys: this is the shape
		// a .meta file written before IAMT-169 actually has on disk.
	}
	data, err := json.Marshal(oldMeta)
	if err != nil {
		t.Fatalf("marshal fixture old-format meta: %v", err)
	}
	metaPath := filepath.Join(f.gw.cfg.RecordingBaseDir, "old-format-1.meta")
	if err := os.MkdirAll(filepath.Dir(metaPath), 0700); err != nil {
		t.Fatalf("mkdir recordings dir: %v", err)
	}
	if err := os.WriteFile(metaPath, data, 0600); err != nil {
		t.Fatalf("write fixture old-format .meta: %v", err)
	}

	list, err := root.RecordingsList(f.machineID, "", "")
	if err != nil {
		t.Fatalf("RecordingsList: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("recordings.list: want exactly 1 record (the old .meta), got %d", len(list))
	}
	if list[0].BytesOut != 4096 {
		t.Fatalf("recordings.list: bytesOut must substitute total_bytes=4096 for the old .meta without bytes_out, got %d", list[0].BytesOut)
	}
	if list[0].BytesIn != 0 {
		t.Fatalf("recordings.list: bytesIn for the old .meta without bytes_in must be 0, got %d", list[0].BytesIn)
	}
}
