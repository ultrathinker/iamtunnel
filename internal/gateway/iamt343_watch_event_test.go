package gateway

// iamt343_watch_event_test.go — watching is said out loud, once
// (IAMT-343, additive half).
//
// The owner may watch a session on his own machine without asking
// anyone. That is his computer. But an act that leaves no trace cannot
// be checked afterwards by anybody, including the owner himself, and a
// facility for watching people that keeps no record of the watching is
// a different product from the one this is meant to be. So the fact is
// journalled.
//
// The half that is NOT here is the banner line telling the specialist,
// in the session, that somebody is looking right now. That is a
// wire-visible change to PROTOCOL §5, deliberately deferred as a
// product decision.

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func watchEvents(t *testing.T, f *fixture) []events.Event {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionWatch}})
	if err != nil {
		t.Fatalf("reading the journal: %v", err)
	}
	return evs
}

// TestIAMT343_WatchingIsJournalledOnceNotOncePerPoll.
//
// Canary: delete the `if !first { return }` guard in noteWatching —
// this goes red with one event per poll, which is what would bury the
// journal under a single window's refresh rate.
func TestIAMT343_WatchingIsJournalledOnceNotOncePerPoll(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	sess, err := f.gw.aclE.OpenSession(f.person, f.machineID, f.clock.Now(), func(acl.DenyReason) {})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	mc := &machineConn{id: f.machineID, g: f.gw}
	in := mineLine(t) // the envelope; the body is replaced below
	in.Op = "sessions.tail"
	in.Tail = &inboundTail{Proto: 1, ID: sess.ID.String(), Offset: 0, Limit: 4096}

	// A watcher polls. Four times here; a real one does it once a second
	// for as long as somebody is looking.
	for i := 0; i < 4; i++ {
		mc.tailForMachine(in)
	}

	got := watchEvents(t, f)
	if len(got) != 1 {
		t.Fatalf("four polls wrote %d session.watch events, want exactly 1 — the live view polls once a second, so an event per poll turns the journal into a log of window refreshes and buries the events an operator actually reads", len(got))
	}
	if got[0].Actor != f.machineID {
		t.Errorf("actor = %q, want the machine that asked (%q)", got[0].Actor, f.machineID)
	}
	if got[0].Object != sess.ID.String() {
		t.Errorf("object = %q, want the session id %q", got[0].Object, sess.ID.String())
	}
	if got[0].Details["person"] != f.person {
		t.Errorf("details.person = %v, want %q — taken from the gateway's own registry, never from what the machine claimed", got[0].Details["person"], f.person)
	}
}

// TestIAMT343_ARefusedWatchIsNotJournalledAsAWatch. The event says
// somebody looked. A machine asking about a session that is not its own
// is refused by the access rule and never sees a byte, so writing the
// event for it would put a false statement in the one record that
// exists to be trusted afterwards.
//
// Canary: move the mc.noteWatching call above the ownsSession check in
// tailForMachine — this goes red with an event for a session the asker
// was never allowed to see.
func TestIAMT343_ARefusedWatchIsNotJournalledAsAWatch(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	sess, err := f.gw.aclE.OpenSession(f.person, f.machineID, f.clock.Now(), func(acl.DenyReason) {})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	// A DIFFERENT machine asks about it.
	mc := &machineConn{id: "laptop", g: f.gw}
	in := mineLine(t)
	in.Op = "sessions.tail"
	in.Tail = &inboundTail{Proto: 1, ID: sess.ID.String(), Offset: 0, Limit: 4096}
	mc.tailForMachine(in)

	if got := watchEvents(t, f); len(got) != 0 {
		t.Fatalf("a refused request wrote %d session.watch event(s): %+v — the journal would then claim somebody watched a session they were never shown", len(got), got)
	}
}
