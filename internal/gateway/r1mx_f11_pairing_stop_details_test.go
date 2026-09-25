package gateway

// F-11 of the round-1 review (24.09.2026): pairing.stop writes
// its event whether or not a window was open - that part is deliberate
// and argued in the code ("the operator asked for a state, the journal
// shows the ask") - but the line said nothing about the answer. A script
// that stops the window every few minutes to check the state left the
// journal full of identical pairing.stop lines, none of which said
// whether there had been anything to stop, so the one thing the line
// exists for (an operator reading back what an administrator did to the
// window) could not be read out of it.
//
// The fix does not split the result into ok/noop: the ask did succeed,
// the command is idempotent by design, and the journal's outcome
// vocabulary stays the two words it has. The answer joins the details
// instead, next to the expiry pairing.start already records.

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func r1mxF11Stops(t *testing.T, f *fixture, person string) []events.Event {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}, Result: "pairing.stop:ok"})
	if err != nil {
		t.Fatalf("read the pairing.stop journal: %v", err)
	}
	out := make([]events.Event, 0, len(evs))
	for _, e := range evs {
		if e.Actor == person {
			out = append(out, e)
		}
	}
	return out
}

func TestR1MXF11_AStopOfAClosedWindowSaysThereWasNothingToStop(t *testing.T) {
	f := newFixture(t, nil)
	person := "pair-stop-root"
	addPerson(t, f, person, "admin", genSigner(t))

	// No window is open: the command is idempotent and answers stopped:false.
	if stopped := pairingStopDirect(t, f, person); stopped {
		t.Fatalf("pairing.stop on a gateway with no open window answered stopped=true")
	}
	evs := r1mxF11Stops(t, f, person)
	if len(evs) != 1 {
		t.Fatalf("the stop wrote %d pairing.stop events, want 1 - the ask is recorded either way, by design", len(evs))
	}
	if got := fmt.Sprint(evs[0].Details["stopped"]); got != "false" {
		t.Errorf("the pairing.stop event carries details.stopped = %v for a window that was not open, want false (F-11): the answer and the record have to say the same thing, or an operator cannot tell a stop that closed a window from a script asking about an empty one (details: %v)", evs[0].Details["stopped"], evs[0].Details)
	}

	// And a stop that really closes a window says that too.
	start := pairingStartDirect(t, f, person)
	if start.Pin == "" {
		t.Fatalf("pairing.start did not return a PIN")
	}
	if stopped := pairingStopDirect(t, f, person); !stopped {
		t.Fatalf("pairing.stop on an open window answered stopped=false")
	}
	evs = r1mxF11Stops(t, f, person)
	if len(evs) != 2 {
		t.Fatalf("stops recorded = %d, want 2", len(evs))
	}
	if got := fmt.Sprint(evs[1].Details["stopped"]); got != "true" {
		t.Errorf("the second pairing.stop event carries details.stopped = %v, want true - it closed the window pairing.start had opened", evs[1].Details["stopped"])
	}
	// The PIN is still nowhere in the journal, in either direction.
	raw, err := json.Marshal(evs)
	if err != nil {
		t.Fatalf("marshal the events: %v", err)
	}
	if strings.Contains(string(raw), start.Pin) {
		t.Errorf("the pairing journal lines carry the PIN %q; PROTOCOL §3.4 keeps it out of events.jsonl", start.Pin)
	}
}
