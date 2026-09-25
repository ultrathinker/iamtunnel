package gateway

import (
	"encoding/json"
	"testing"
)

// Review finding 1, end to end through the real admin commands (not just
// the state package's own Store.Update): a declared goal must not make its
// machine or person permanently unremovable. Before the fix, Validate()
// required every Goals entry to reference an existing person and machine,
// and nothing cascaded Goals on removal - so this would fail with
// E_INTERNAL after the very first "declare a goal, then remove its
// machine/person" sequence.
func TestIAMT402_MachinesRemoveSucceedsAfterGoalWasDeclared(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskClassifier = RiskClassifierRules })
	addPerson(t, f, "root", "admin", genSigner(t))

	setBody, err := json.Marshal(map[string]any{
		"proto": 1, "person": "root", "machine": f.machineID, "goal": "decommission this box",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, cerr := f.gw.runCommand("root", "goal.set", setBody); cerr != nil {
		t.Fatalf("goal.set: %s (%s)", cerr.message, cerr.code)
	}

	removeBody, err := json.Marshal(map[string]any{"proto": 1, "id": f.machineID})
	if err != nil {
		t.Fatal(err)
	}
	if _, cerr := f.gw.runCommand("root", "machines.remove", removeBody); cerr != nil {
		t.Fatalf("machines.remove of a machine with a declared goal was refused: %s (%s)", cerr.message, cerr.code)
	}

	st := f.gw.cfg.Store.Get()
	if _, found := st.GoalFor("root", f.machineID); found {
		t.Fatalf("goal for the removed machine is still present after removal")
	}
}

func TestIAMT402_PeopleRemoveSucceedsAfterGoalWasDeclared(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskClassifier = RiskClassifierRules })
	addPerson(t, f, "root", "admin", genSigner(t))
	addPerson(t, f, "bob", "user", genSigner(t))

	setBody, err := json.Marshal(map[string]any{
		"proto": 1, "person": "bob", "machine": f.machineID, "goal": "decommission this box",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, cerr := f.gw.runCommand("root", "goal.set", setBody); cerr != nil {
		t.Fatalf("goal.set: %s (%s)", cerr.message, cerr.code)
	}

	removeBody, err := json.Marshal(map[string]any{"proto": 1, "name": "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if _, cerr := f.gw.runCommand("root", "people.remove", removeBody); cerr != nil {
		t.Fatalf("people.remove of a person with a declared goal was refused: %s (%s)", cerr.message, cerr.code)
	}

	st := f.gw.cfg.Store.Get()
	if _, found := st.GoalFor("bob", f.machineID); found {
		t.Fatalf("goal for the removed person is still present after removal")
	}
}
