package gateway

// F-04 of the round-1 review (24.09.2026): a machine asking for
// a control op this gateway does not know is answered E_CONTROL_PROTOCOL
// and then forgotten - no line in the journal. The reply is what the
// machine needs; the record is what the operator needs, because an
// unknown op from a registered machine is a version skew or a bug (a
// newer machine, an older gateway, a machine asking for door.open on the
// inbound channel), and "the machine asked for something this gateway
// does not have" is exactly the kind of fact this journal exists to keep.
// The human side already records every forbidden SSH request
// (human_role.go, recordSSHRequestReject); this is the machine side of
// the same rule.
//
// One line per distinct verb per connection, not per request: a skewed
// machine retrying in a loop is one fact, and the journal must not fill
// with it - the rule session.watch was written under (IAMT-343).

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func TestR1MXF04_AnUnknownControlOpIsAnsweredAndOnRecord(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	mc := &machineConn{id: f.machineID, g: f.gw}
	in := mineLine(t)
	in.Op = "door.open" // not a verb this channel accepts from a machine

	// The machine asks, and asks again: a skewed machine retries.
	mc.handleMachineRequest(in)
	mc.handleMachineRequest(in)

	unknown := func() []events.Event {
		t.Helper()
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}})
		if err != nil {
			t.Fatalf("read the admin-op journal: %v", err)
		}
		out := make([]events.Event, 0, len(evs))
		for _, e := range evs {
			if e.Actor == f.machineID && e.Result == "unknown-control-op" {
				out = append(out, e)
			}
		}
		return out
	}

	got := unknown()
	if len(got) != 1 {
		t.Fatalf("two asks of an op this gateway does not know wrote %d journal entries, want exactly 1 naming the machine and the op (F-04): an operator has no other way to see that %s asked for something the gateway does not have", len(got), f.machineID)
	}
	if got[0].Object != "door.open" {
		t.Errorf("the entry names %q as the object, want the op the machine asked for (%q)", got[0].Object, "door.open")
	}
	if got[0].Details["op"] != "door.open" {
		t.Errorf("details.op = %v, want %q", got[0].Details["op"], "door.open")
	}

	// Bounded: one connection's unknown verbs cannot fill the journal.
	for _, op := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		next := in
		next.Op = op
		mc.handleMachineRequest(next)
	}
	if n := len(unknown()); n > maxUnknownOpsPerConn {
		t.Errorf("one connection wrote %d entries for unknown ops, want at most %d: a machine asking in a loop is one fact, and the journal is not where a loop belongs", n, maxUnknownOpsPerConn)
	}
}
