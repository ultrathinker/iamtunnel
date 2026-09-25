package gateway

// door_sanitize_event_test.go — IAMT-103. door.sanitize is the only
// control-channel operation that deletes every marked line from
// administrators_authorized_keys without naming one id. Until this
// commit the gateway wrote nothing to events.jsonl about it, which is
// exactly the case where the journal must speak loudest (a corrupted
// marker means either a crash mid-write or someone editing the admin
// key file by hand — both are state the owner has to see).
//
// These tests drive the real machineConn through the real
// control-channel transport (a fake machine in this package's
// harness_test.go) and assert on the events that appear in
// events.jsonl, including the count the sweep took and the
// reason the gateway demanded the sanitize for.

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// sanitizeEvents reads every door.sanitize entry the gateway wrote for the
// machine under test. The filter asks the gateway's own append-only log,
// never the in-memory state, so a regression that drops the append can
// never be mistaken for a green. Outcome (ok / refused / timeout) is in
// e.Result, in line with the rest of the dictionary's convention
// (auth.failure, session.drop — IAMT-104 for door.*).
func sanitizeEvents(t *testing.T, f *fixture) []events.Event {
	t.Helper()
	all, _, err := f.gw.cfg.Log.Read(events.Filter{Types: []events.EventType{events.EventDoorSanitize}})
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	out := make([]events.Event, 0, len(all))
	for _, e := range all {
		if e.Object == f.machineID {
			out = append(out, e)
		}
	}
	return out
}

// TestDriveOne_SanitizeSuccessWritesJournalEvent exercises the happy
// path: the gateway drives a door.sanitize on the live machineConn,
// the fake machine returns ok:true with Removed:3, and the journal
// must contain a door.sanitize event with Details["removed"] == 3 and
// the reason the gateway sent.
//
// The test goes red if the append is removed: the assertion reads the
// event by its type and contents, not by its mere presence, so a
// weaker implementation that writes an empty door.sanitize entry will
// not satisfy it.
func TestDriveOne_SanitizeSuccessWritesJournalEvent(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{reportSanitizeRemoved: 3})
	f.waitMachineOnline(t)

	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("machine not registered")
	}

	mc.driveOne(core.Command{Op: "door.sanitize", Reason: "corrupted"})

	evs := sanitizeEvents(t, f)
	if len(evs) != 1 {
		t.Fatalf("expected exactly one door.sanitize event for %s, got %d: %+v",
			f.machineID, len(evs), evs)
	}
	e := evs[0]
	if e.Result != "ok" {
		t.Fatalf("door.sanitize.Result = %q, want %q", e.Result, "ok")
	}
	if e.Details["reason"] != "corrupted" {
		t.Fatalf("door.sanitize.Details[reason] = %v, want %q", e.Details["reason"], "corrupted")
	}
	// Details["removed"] travels as a JSON number; the round trip
	// json.Marshal -> json.Unmarshal in events.Append may land as
	// float64 on the read side, which is fine for the assertion.
	removed, ok := numericAsInt(e.Details["removed"])
	if !ok {
		t.Fatalf("door.sanitize.Details[removed] is not a number: %T %v",
			e.Details["removed"], e.Details["removed"])
	}
	if removed != 3 {
		t.Fatalf("door.sanitize.Details[removed] = %d, want 3", removed)
	}
	if e.Details["epoch"] == nil {
		t.Fatalf("door.sanitize.Details must carry the tunnel epoch for cross-reference with machine.connected: %+v", e.Details)
	}
}

// TestDriveOne_SanitizeRefusedWritesJournalEvent exercises the refused
// path: the fake machine replies ok:false, and the journal must
// contain a door.sanitize event with Result: "refused", the errCode in
// Details["err"], and the same reason the gateway sent.
//
// This is the "unconfirmed admin line on the machine" state IAMT-103
// asks the journal to record: outcome is in the Result field per the
// dictionary convention, not in a separate event type.
func TestDriveOne_SanitizeRefusedWritesJournalEvent(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{failSanitize: true})
	f.waitMachineOnline(t)

	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("machine not registered")
	}

	mc.driveOne(core.Command{Op: "door.sanitize", Reason: "corrupted"})

	evs := sanitizeEvents(t, f)
	if len(evs) != 1 {
		t.Fatalf("expected exactly one door.sanitize event for %s, got %d: %+v",
			f.machineID, len(evs), evs)
	}
	e := evs[0]
	if e.Result != "refused" {
		t.Fatalf("door.sanitize.Result = %q, want %q", e.Result, "refused")
	}
	if e.Details["reason"] != "corrupted" {
		t.Fatalf("door.sanitize.Details[reason] = %v, want %q", e.Details["reason"], "corrupted")
	}
	if e.Details["err"] == nil {
		t.Fatalf("door.sanitize.Details must carry the machine's errCode on a refused sanitize: %+v", e.Details)
	}
}

// TestDriveOne_SanitizeTimeoutWritesJournalEvent exercises the
// unreachable-machine path: the fake machine never replies, the
// control-channel deadline trips, and the journal must contain a
// door.sanitize event with Result: "timeout". The deadline itself is
// the verdict; there is no errCode, just the reason the gateway sent.
//
// The gateway-side DoorCloseTimeout is trimmed in this fixture so the
// timeout fires while the test goroutine is waiting, instead of the
// default 2s stretching the run.
func TestDriveOne_SanitizeTimeoutWritesJournalEvent(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.DoorCloseTimeout = 50 * time.Millisecond
	})
	f.connectMachine(fakeMachineBehavior{hangSanitize: true})
	f.waitMachineOnline(t)

	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("machine not registered")
	}

	mc.driveOne(core.Command{Op: "door.sanitize", Reason: "corrupted"})

	evs := sanitizeEvents(t, f)
	if len(evs) != 1 {
		t.Fatalf("expected exactly one door.sanitize event for %s, got %d: %+v",
			f.machineID, len(evs), evs)
	}
	e := evs[0]
	if e.Result != "timeout" {
		t.Fatalf("door.sanitize.Result = %q, want %q", e.Result, "timeout")
	}
	if e.Details["reason"] != "corrupted" {
		t.Fatalf("door.sanitize.Details[reason] = %v, want %q", e.Details["reason"], "corrupted")
	}
}

// numericAsInt coerces a json.Number-decoded detail value to an int.
// events.jsonl keeps numbers as JSON numbers; the gateway code writes
// ints and the journal stores them as such, but the read side sees
// them as float64.
func numericAsInt(v interface{}) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	}
	return 0, false
}
