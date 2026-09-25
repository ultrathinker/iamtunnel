package gateway

// R2-MX F-03 of the round-2 review (24.09.2026), low: both
// people.keys.add and people.keys.remove wrote their admin.op line only
// when they succeeded. Every refusal - a key that belongs to somebody
// else, a person that does not exist, a key the person does not have, the
// last administrator key the gateway has left - was answered to the caller
// and to nobody else. Whoever reads events.jsonl to see who tried what
// reads a history of successes.
//
// IAMT-451 settled the same question for a journal that cannot be written
// ("a journal that is not being written does not keep quiet"); this is its
// neighbour: a command that refused to write does not keep quiet either.
// The gateway already has the shape for it - machines.rekey and the
// lifecycle commands write "failed" with a reason - and these two were
// simply not using it.

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// r2mxFailedOps collects the details of every admin.op in the history whose
// result is exactly this one ("people.keys.add:failed").
func r2mxFailedOps(evs []events.Event, result string) []map[string]interface{} {
	var out []map[string]interface{}
	for _, e := range evs {
		if e.Type == events.EventAdminOp && e.Result == result {
			out = append(out, e.Details)
		}
	}
	return out
}

func TestR2MXF03_ARefusedKeyChangeIsInTheJournal(t *testing.T) {
	f := newFixture(t, nil)
	rootKey, carolKey := genSigner(t), genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	addPerson(t, f, "carol", "user", carolKey)
	addPerson(t, f, "bob", "user", genSigner(t))
	root := dialAdmin(t, f, "root", rootKey)
	strangerFP := fingerprintOf(t, genSigner(t).PublicKey())

	// Five refusals, each of them an errand somebody may want to see
	// afterwards: the key of another person, a person that is not there
	// (twice - add and remove), a key the person does not have, and the
	// last administrator key the gateway has left.
	if _, err := root.PeopleKeysAdd("bob", authorizedLine(carolKey.PublicKey())); err == nil {
		t.Fatalf("carol's key was added to bob")
	}
	if _, err := root.PeopleKeysAdd("nobody", authorizedLine(carolKey.PublicKey())); err == nil {
		t.Fatalf("a key was added to a person that does not exist")
	}
	if err := root.PeopleKeysRemove("bob", strangerFP); err == nil {
		t.Fatalf("a key bob does not have was removed")
	}
	if err := root.PeopleKeysRemove("nobody", strangerFP); err == nil {
		t.Fatalf("a key was removed from a person that does not exist")
	}
	if err := root.PeopleKeysRemove("root", fingerprintOf(t, rootKey.PublicKey())); err == nil {
		t.Fatalf("the last administrator key the gateway has was removed")
	}

	evs, _, err := f.log.ReadAll(events.Filter{})
	if err != nil {
		t.Fatalf("reading the journal: %v", err)
	}

	adds := r2mxFailedOps(evs, "people.keys.add:failed")
	if len(adds) != 2 {
		t.Errorf("the journal holds %d refused people.keys.add, want 2 (a key of another person and a person that does not exist): an operator reading events.jsonl for who tried what sees the successes only (F-03)", len(adds))
	}
	owns := false
	for _, d := range adds {
		if d["existingOwner"] == `person "carol"` {
			owns = true
		}
	}
	if !owns {
		t.Errorf("no refused people.keys.add names the identity the key already belongs to: %v (F-03 asks for the same detail F-01 asks for)", adds)
	}

	removes := r2mxFailedOps(evs, "people.keys.remove:failed")
	if len(removes) != 3 {
		t.Errorf("the journal holds %d refused people.keys.remove, want 3 (a key the person does not have, a person that does not exist, and the last administrator key): the refusals are exactly the errands an audit trail is read for (F-03)", len(removes))
	}
	last := false
	for _, d := range removes {
		if d["reason"] == "last administrator key" {
			last = true
		}
	}
	if !last {
		t.Errorf("the refusal to remove the last administrator key is in the journal as %v, want it to say that is what it refused: an attempt to lock the gateway out is the one refusal nobody may miss (F-03)", removes)
	}

	// The successful errands keep their own line, and the failures do not
	// replace it: nothing here succeeded, so no ok line was written.
	for _, e := range evs {
		if e.Type == events.EventAdminOp && e.Result == "people.keys.add:ok" {
			t.Errorf("a people.keys.add was recorded as done although every one of them was refused: %+v", e)
		}
	}
}
