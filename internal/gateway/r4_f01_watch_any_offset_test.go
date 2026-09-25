package gateway

// r4_f01_watch_any_offset_test.go — R4 F-01.
//
// session.watch (and its admin.op) was written only for a sessions.tail
// with offset 0. The offset is the watcher's own choice: a request that
// starts at 1 read the live session and left nothing in events.jsonl —
// against SPEC §5.1, "whether anybody watched can always be checked
// afterwards". The window always starts at 0, so no gate saw it; the
// protocol is open to any admin. Watching is journalled once per
// (watcher, session), whatever offset the watcher starts from.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestR4F01_AWatchStartingPastZeroIsStillJournalled(t *testing.T) {
	f := newFixture(t, nil)
	cast := filepath.Join(t.TempDir(), "r4f01.cast")
	if err := os.WriteFile(cast, []byte("live bytes\n"), 0o600); err != nil {
		t.Fatalf("write live cast: %v", err)
	}
	const sessionID = "r4-f01-session"
	f.gw.live.add(sessionID, cast, f.machineID)

	for _, offset := range []string{"1", "5", "9"} {
		body := []byte(`{"proto":1,"id":"` + sessionID + `","offset":` + offset + `,"limit":1024}`)
		if _, cerr := cmdSessionsTail(f.gw, "mallory", f.clock.Now(), body); cerr != nil {
			t.Fatalf("tail at offset %s: %v", offset, cerr)
		}
	}
	got, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionWatch}})
	if err != nil {
		t.Fatalf("read session.watch: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("R4 F-01: a watcher who never asked for offset 0 read the live session and left %d session.watch events, want exactly 1", len(got))
	}
	if got[0].Actor != "mallory" || got[0].Object != sessionID {
		t.Fatalf("event actor/object = %q/%q, want mallory/%q", got[0].Actor, got[0].Object, sessionID)
	}

	// A second watcher of the same session is a second fact.
	body := []byte(`{"proto":1,"id":"` + sessionID + `","offset":3,"limit":1024}`)
	if _, cerr := cmdSessionsTail(f.gw, "trudy", f.clock.Now(), body); cerr != nil {
		t.Fatalf("second watcher: %v", cerr)
	}
	got, _, _ = f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionWatch}})
	if len(got) != 2 {
		t.Fatalf("a second watcher wrote %d session.watch events in total, want 2", len(got))
	}
}

// TestR4F01_TheMachineDoesNotWatchWhileTheJournalCannotWrite is the
// adjacent half: while the journal is not written (IAMT-451) the admin's
// sessions.tail is refused, but the machine's own path went on handing out
// live bytes, its session.watch lost. SPEC §3.5 refuses everything that
// would have to leave a trace.
func TestR4F01_TheMachineDoesNotWatchWhileTheJournalCannotWrite(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	sess, err := f.gw.aclE.OpenSession(f.person, f.machineID, f.clock.Now(), func(acl.DenyReason) {})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	iamt451BreakJournal(t, f)
	f.gw.appendEvent(events.Event{Type: events.EventSessionWatch, Actor: "probe", Object: "probe", Result: "ok"})

	mc := &machineConn{id: f.machineID, g: f.gw}
	in := mineLine(t)
	in.Op = "sessions.tail"
	in.Tail = &inboundTail{Proto: 1, ID: sess.ID.String(), Offset: 0, Limit: 4096}
	resp := mc.tailForMachine(in)
	if resp.OK || resp.Error == nil || resp.Error.Code != "E_AUDIT_UNAVAILABLE" {
		t.Fatalf("R4 F-01: the machine watched a live session while the journal could not record it: %+v", resp)
	}
}
