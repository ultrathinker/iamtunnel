package gateway

// IAMT-457: a machine that keeps its tunnel and answers its keepalives, but
// never answers door.status. The §5.2 reconciliation retried at once, with
// no pause, and by recursion: every unanswered status added
// driveOneUntil -> drive -> driveOne to the stack of the same goroutine,
// for as long as the transport lived - and the epoch, registered and
// offline, turned the machine's own reconnects away as already online.
// PROTOCOL §5.2 asked for a retry with backoff.

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// iamt457ReconcileDepth is the deepest the reconciliation of one machine
// has nested itself right now: the most driveOneUntil frames any one
// goroutine holds.
func iamt457ReconcileDepth() int {
	buf := make([]byte, 1<<22)
	buf = buf[:runtime.Stack(buf, true)]
	deepest := 0
	for _, g := range bytes.Split(buf, []byte("\n\n")) {
		if n := strings.Count(string(g), "(*machineConn).driveOneUntil"); n > deepest {
			deepest = n
		}
	}
	return deepest
}

func TestIAMT457_ASilentMachineIsRetriedWithPausesAndThenLetGo(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		// Unanswered statuses come fast, so the old loop is caught in the
		// act within a second.
		cfg.DoorStatusTimeout = 50 * time.Millisecond
		cfg.DoorCloseTimeout = 50 * time.Millisecond
		cfg.DoorStatusBackoff = 100 * time.Millisecond
	})
	fm := f.connectMachine(fakeMachineBehavior{hangStatus: true})
	waitUntil(t, "the silent machine was not registered", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return ok
	})

	time.Sleep(time.Second)
	if depth := iamt457ReconcileDepth(); depth > 1 {
		t.Fatalf("the reconciliation of a silent machine is %d calls deep after a second: each unanswered door.status nests another", depth)
	}
	if n := fm.doorStatusRequests(); n > 6 {
		t.Errorf("%d door.status in the first second: the retries are not paced", n)
	}

	// Given up on: the epoch ends, so the machine can come back on a new one.
	waitUntilFor(t, 30*time.Second, "the gateway never let go of a machine that does not answer door.status", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventMachineDisconnected}})
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) == 0 || evs[len(evs)-1].Result != "control-unresponsive" {
		t.Errorf("machine.disconnected does not say why: %+v", evs)
	}
}

func TestIAMT457_ALiveSessionKeepsItsMachineThroughUnansweredStatuses(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.DoorStatusBackoff = 10 * time.Millisecond
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	mc, _ := f.gw.reg.get(f.machineID)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "the session was not counted", func() bool { return mc.doorMachine.Snapshot().Sessions == 1 })

	// As many unanswered statuses as it takes to give up on a machine.
	mc.mu.Lock()
	mc.statusMisses = f.gw.cfg.DoorStatusMaxMisses
	mc.mu.Unlock()
	if !mc.statusPause() {
		t.Fatal("a machine with a live session was let go of over its door: the session would be cut with the epoch")
	}
	if _, ok := f.gw.reg.get(f.machineID); !ok {
		t.Fatal("the machine was unregistered with a session live on it")
	}
	const marker = "iamt-457-still-working"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write: %v", err)
	}
	readUntil(t, hs.ch, marker)
}
