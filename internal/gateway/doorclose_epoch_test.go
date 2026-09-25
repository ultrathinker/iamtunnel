package gateway

// doorclose_epoch_test.go covers IAMT-69 under the rule the runtime chose,
// the one PROTOCOL §5.2 ("closing" row) already wrote down: a refused
// door.close (or the second timeout of close/sanitize) ends the epoch - the
// gateway cuts the transport and waits for the machine's reconnect, and the
// new epoch must pass the initial door.status sweep before the machine is
// called alive again.
//
//   - item 5: TestSingleDoorCloseFailureEndsEpochAndRecoversOnReconnect
//   - item 6: TestRepeatedDoorCloseFailureStillDeniesEveryone
//   - item 7: TestDoorCloseFailureReasonIsVisibleToHumans (journal + runbook;
//     the server-screen leg lives in internal/ui)

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// stuckDoorLine is a §1.3-valid door id standing for a line a previous
// epoch installed and could not remove - exactly what a reconnecting
// machine with a stuck line reports on its initial door.status.
const stuckDoorLine = "0b9e3f2a-6c1d-4e7a-9b3d-1a2b3c4d5e6f"

// closeFailedEvents reads the door.close events the gateway wrote.
func closeFailedEvents(t *testing.T, f *fixture) []events.Event {
	t.Helper()
	evs, _, err := f.gw.cfg.Log.Read(events.Filter{Types: []events.EventType{events.EventDoorClose}})
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	return evs
}

// waitEpochEndedAfterRefusedClose waits for the epoch to end in the order the
// runtime actually ends it: machine_conn.go appends the door.close failure
// event first (the terminalCut branch) and the teardown that unregisters the
// connection follows.
//
// Waiting only for the registry to go empty is a barrier that passes
// vacuously: before handleMachine has registered the connection at all the
// machine is equally absent. Under the load of a full -race package run that
// is exactly what happened - the test observed "not registered" 0.01s in,
// read an empty journal and failed (two of twenty repeats, IAMT-85). The
// journal is append-only, so counting its entries is monotone and cannot be
// satisfied by a state the runtime has not reached yet.
func (f *fixture) waitEpochEndedAfterRefusedClose(t *testing.T, want int, when string) {
	t.Helper()
	waitUntil(t, when+": the gateway wrote no door.close failure for the epoch", func() bool {
		n := 0
		for _, e := range closeFailedEvents(t, f) {
			if e.Object == f.machineID && e.Result == "failed" {
				n++
			}
		}
		return n >= want
	})
	waitUntil(t, when+": epoch did not end", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})
}

// ---- item 5: one refusal must not mean offline forever -----------------------

func TestSingleDoorCloseFailureEndsEpochAndRecoversOnReconnect(t *testing.T) {
	f := newFixture(t, nil)
	fm1 := f.connectMachine(fakeMachineBehavior{failClose: true})
	f.waitMachineOnline(t)

	// One full door cycle: the door opens, a human works, leaves - and the
	// idle door.close is the one refusal of the epoch.
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("human dial: %v", err)
	}
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "session did not become active", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})
	mc, _ := f.gw.reg.get(f.machineID)
	stuckID := mc.doorMachine.Snapshot().DoorID
	if stuckID == "" {
		t.Fatal("no door id while the door was open")
	}
	if err := hs.ch.Close(); err != nil {
		t.Fatalf("close human channel: %v", err)
	}

	// The refusal must end the epoch: the connection leaves the registry
	// and its transport dies - the machine agent's tunnel supervision sees
	// the drop and reconnects. This is the line the pre-IAMT-69 runtime
	// got wrong: it kept the conn registered and offline forever.
	waitUntil(t, "epoch did not end after the refused door.close", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})
	waitUntil(t, "transport survived the refused door.close", func() bool {
		_, _, err := fm1.conn.SendRequest("keepalive@iamtunnel", true, nil)
		return err != nil
	})

	// Recovery needs no admin action: the machine reconnects, its stuck
	// line is still installed (the close was refused, never done), the new
	// epoch's initial door.status finds it, the gateway closes it as a
	// foreign line and only the confirming status turns online on.
	fm2 := f.connectMachine(fakeMachineBehavior{preInstalledDoorID: stuckID})
	f.waitMachineOnline(t)
	if installed, _ := fm2.doorInstalled(); installed {
		t.Fatal("the stuck line survived the new epoch's sweep")
	}
	_ = client.Close()
}

// ---- item 6: a broken machine still never lets anyone in ----------------------

func TestRepeatedDoorCloseFailureStillDeniesEveryone(t *testing.T) {
	f := newFixture(t, nil)

	tryHuman := func(when string) {
		t.Helper()
		client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
		if err != nil {
			t.Fatalf("%s: human dial: %v", when, err)
		}
		defer client.Close()
		ch, reqs, err := client.OpenChannel("session", nil)
		if err != nil {
			t.Fatalf("%s: open session: %v", when, err)
		}
		go discardSSHRequests(reqs)
		line := readAll(t, ch, 2*time.Second)
		if !strings.Contains(line, "Access to this machine is currently unavailable") {
			t.Fatalf("%s: human was not denied, got %q", when, line)
		}
	}

	// Epoch 1: the machine carries a stuck line and refuses to remove it.
	// The sweep close fails, the epoch ends before anyone is admitted.
	fm1 := f.connectMachine(fakeMachineBehavior{failClose: true, preInstalledDoorID: stuckDoorLine})
	f.waitEpochEndedAfterRefusedClose(t, 1, "broken epoch 1")
	tryHuman("epoch 1")
	if fm1.doorEverOpened() {
		t.Fatal("a door.open was sent to a machine whose close never succeeds")
	}

	// Epoch 2: the same machine reconnects and fails the same way. Fixing
	// the single refusal (item 5) must not have opened this hole: a
	// machine that cannot confirm a closed line never becomes a door.
	fm2 := f.connectMachine(fakeMachineBehavior{failClose: true, preInstalledDoorID: stuckDoorLine})
	f.waitEpochEndedAfterRefusedClose(t, 2, "broken epoch 2")
	tryHuman("epoch 2")
	if fm2.doorEverOpened() {
		t.Fatal("a door.open was sent in the second broken epoch too")
	}
}

// ---- item 7: the human-visible reason -----------------------------------------

func TestDoorCloseFailureReasonIsVisibleToHumans(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{failClose: true, preInstalledDoorID: stuckDoorLine})
	f.waitEpochEndedAfterRefusedClose(t, 1, "broken epoch")

	// The journal names the machine and the verdict in plain words, so the
	// runbook's "tail the events" route answers "why is my machine
	// unreachable" without reading gateway source.
	evs := closeFailedEvents(t, f)
	found := false
	for _, e := range evs {
		if e.Object == f.machineID && e.Result == "failed" && e.Details["verdict"] == "new-epoch-required" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("no door.close failure event with the new-epoch verdict for %s; events: %+v", f.machineID, evs)
	}

	// The same norm, in the runbook the duty engineer actually reads.
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "RUNBOOK.md"))
	if err != nil {
		t.Fatalf("read RUNBOOK.md: %v", err)
	}
	book := string(raw)
	for _, phrase := range []string{
		"door.close",
		"new-epoch-required",
	} {
		if !strings.Contains(book, phrase) {
			t.Fatalf("RUNBOOK.md does not explain the door.close norm: %q is missing", phrase)
		}
	}
}
