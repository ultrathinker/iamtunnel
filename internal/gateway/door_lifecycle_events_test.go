package gateway

// door_lifecycle_events_test.go covers IAMT-121:
// door.open and successful door.close change state on the machine (authorized_keys)
// and must write audit records into events.jsonl.
// Outcome is placed in Result ("ok", "refused", "timeout") following commit 5c6d0dc
// and IAMT-104.

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func doorOpenEvents(t *testing.T, f *fixture) []events.Event {
	t.Helper()
	all, _, err := f.gw.cfg.Log.Read(events.Filter{Types: []events.EventType{events.EventDoorOpen}})
	if err != nil {
		t.Fatalf("read door.open events: %v", err)
	}
	out := make([]events.Event, 0, len(all))
	for _, e := range all {
		if e.Object == f.machineID {
			out = append(out, e)
		}
	}
	return out
}

func doorCloseEvents(t *testing.T, f *fixture) []events.Event {
	t.Helper()
	all, _, err := f.gw.cfg.Log.Read(events.Filter{Types: []events.EventType{events.EventDoorClose}})
	if err != nil {
		t.Fatalf("read door.close events: %v", err)
	}
	out := make([]events.Event, 0, len(all))
	for _, e := range all {
		if e.Object == f.machineID {
			out = append(out, e)
		}
	}
	return out
}

func TestDoorOpen_SuccessWritesJournalEvent(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("machine not registered")
	}

	doorSigner := genSigner(t)
	const testDoorID = "test-door-open-uuid-1"
	door := core.Door{
		ID:           testDoorID,
		PublicKey:    authorizedLine(doorSigner.PublicKey()),
		PrivateKey:   doorSigner,
		Opened:       time.Now(),
		IdleDeadline: time.Now().Add(time.Minute),
		HardDeadline: time.Now().Add(2 * time.Minute),
	}

	mc.driveOne(core.Command{Op: "door.open", Door: door, Reason: "human-session"})

	evs := doorOpenEvents(t, f)
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 door.open event for %s, got %d", f.machineID, len(evs))
	}

	e := evs[0]
	if e.Type != events.EventDoorOpen {
		t.Fatalf("event.Type = %q, want %q", e.Type, events.EventDoorOpen)
	}
	if e.Result != "ok" {
		t.Fatalf("door.open.Result = %q, want %q", e.Result, "ok")
	}
	if e.Actor != "gateway" {
		t.Fatalf("door.open.Actor = %q, want %q", e.Actor, "gateway")
	}
	if e.Object != f.machineID {
		t.Fatalf("door.open.Object = %q, want %q", e.Object, f.machineID)
	}
	if e.Details["doorId"] != testDoorID {
		t.Fatalf("door.open.Details[doorId] = %v, want %q", e.Details["doorId"], testDoorID)
	}
	if e.Details["installed"] != true {
		t.Fatalf("door.open.Details[installed] = %v, want true", e.Details["installed"])
	}
	if e.Details["reason"] != "human-session" {
		t.Fatalf("door.open.Details[reason] = %v, want 'human-session'", e.Details["reason"])
	}
	if e.Details["epoch"] == nil {
		t.Fatalf("door.open.Details must carry the tunnel epoch, got nil")
	}
}

func TestDoorClose_SuccessWritesJournalEvent(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("machine not registered")
	}

	doorSigner := genSigner(t)
	const testDoorID = "test-door-close-uuid-1"
	door := core.Door{
		ID:           testDoorID,
		PublicKey:    authorizedLine(doorSigner.PublicKey()),
		PrivateKey:   doorSigner,
		Opened:       time.Now(),
		IdleDeadline: time.Now().Add(time.Minute),
		HardDeadline: time.Now().Add(2 * time.Minute),
	}

	// Open the door first so it is installed.
	mc.driveOne(core.Command{Op: "door.open", Door: door, Reason: "human-session"})

	// Now close the door successfully.
	mc.driveOne(core.Command{Op: "door.close", DoorID: testDoorID, Reason: "idle"})

	evs := doorCloseEvents(t, f)
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 door.close event for %s, got %d", f.machineID, len(evs))
	}

	e := evs[0]
	if e.Type != events.EventDoorClose {
		t.Fatalf("event.Type = %q, want %q", e.Type, events.EventDoorClose)
	}
	if e.Result != "ok" {
		t.Fatalf("door.close.Result = %q, want %q", e.Result, "ok")
	}
	if e.Actor != "gateway" {
		t.Fatalf("door.close.Actor = %q, want %q", e.Actor, "gateway")
	}
	if e.Object != f.machineID {
		t.Fatalf("door.close.Object = %q, want %q", e.Object, f.machineID)
	}
	if e.Details["doorId"] != testDoorID {
		t.Fatalf("door.close.Details[doorId] = %v, want %q", e.Details["doorId"], testDoorID)
	}
	if e.Details["removed"] != true {
		t.Fatalf("door.close.Details[removed] = %v, want true", e.Details["removed"])
	}
	if e.Details["reason"] != "idle" {
		t.Fatalf("door.close.Details[reason] = %v, want 'idle'", e.Details["reason"])
	}
	if e.Details["epoch"] == nil {
		t.Fatalf("door.close.Details must carry the tunnel epoch, got nil")
	}
}

func TestDoorOpen_RefusedWritesJournalEvent(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{refuseOpen: true})
	f.waitMachineOnline(t)

	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("machine not registered")
	}

	doorSigner := genSigner(t)
	const testDoorID = "test-door-refuse-uuid-1"
	door := core.Door{
		ID:           testDoorID,
		PublicKey:    authorizedLine(doorSigner.PublicKey()),
		PrivateKey:   doorSigner,
		Opened:       time.Now(),
		IdleDeadline: time.Now().Add(time.Minute),
		HardDeadline: time.Now().Add(2 * time.Minute),
	}

	mc.driveOne(core.Command{Op: "door.open", Door: door, Reason: "human-session"})

	evs := doorOpenEvents(t, f)
	if len(evs) != 1 {
		t.Fatalf("expected exactly 1 door.open event for %s, got %d", f.machineID, len(evs))
	}

	e := evs[0]
	if e.Result != "refused" {
		t.Fatalf("door.open.Result = %q, want %q", e.Result, "refused")
	}
	if e.Details["doorId"] != testDoorID {
		t.Fatalf("door.open.Details[doorId] = %v, want %q", e.Details["doorId"], testDoorID)
	}
	errStr, ok := e.Details["err"].(string)
	if !ok || !strings.Contains(errStr, "E_CONTROL_DOOR_CONFLICT") {
		t.Fatalf("door.open.Details[err] = %v, want containing E_CONTROL_DOOR_CONFLICT", e.Details["err"])
	}
}
