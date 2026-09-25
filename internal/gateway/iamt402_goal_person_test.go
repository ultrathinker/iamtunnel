package gateway

import (
	"encoding/json"
	"testing"
)

// Review finding 3: goal.set must file the goal under the grant holder
// named in the request, not under the admin who issued the command. The
// two only coincide on the owner's one-person stand; on a real gateway
// the admin (root) declares the goal and the grant holder (agent) is the
// one whose session actually reads it back via state.GoalFor.
func TestIAMT402_GoalIsFiledUnderTheGrantHolderNotTheAdmin(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskClassifier = RiskClassifierRules })
	addPerson(t, f, "root", "admin", genSigner(t))
	addPerson(t, f, "agent", "user", genSigner(t))

	body, err := json.Marshal(map[string]any{
		"proto": 1, "person": "agent", "machine": f.machineID, "goal": "rotate the TLS certificate",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, cerr := f.gw.runCommand("root", "goal.set", body); cerr != nil {
		t.Fatalf("goal.set: %s (%s)", cerr.message, cerr.code)
	}

	// The exact lookup serveHumanSession performs for the person who
	// actually opens the session.
	st := f.gw.cfg.Store.Get()
	declared, found := st.GoalFor("agent", f.machineID)
	if !found || declared.Current == "" {
		t.Fatalf("no goal for the grant holder: GoalFor(%q, %q) = %#v, found=%v", "agent", f.machineID, declared, found)
	}

	// The admin's own identity must not have picked up a goal record by
	// virtue of having run the command.
	if _, found := st.GoalFor("root", f.machineID); found {
		t.Fatalf("goal.set also filed a record under the calling admin, not just the named person")
	}

	current, cerr := f.gw.runCommand("root", "goal.current", []byte(`{"proto":1,"person":"agent","machine":"`+f.machineID+`"}`))
	if cerr != nil {
		t.Fatalf("goal.current: %s (%s)", cerr.message, cerr.code)
	}
	view, ok := current.(goalView)
	if !ok || view.Person != "agent" || view.Goal != "rotate the TLS certificate" {
		t.Fatalf("goal.current = %#v, want agent's declared goal", current)
	}
}

// goal.set, goal.current and goal.history must all reject a person who
// does not exist rather than silently filing (or looking up) a goal
// under a name nobody holds a grant as.
func TestIAMT402_GoalCommandsRejectUnknownPerson(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskClassifier = RiskClassifierRules })
	addPerson(t, f, "root", "admin", genSigner(t))

	body, err := json.Marshal(map[string]any{
		"proto": 1, "person": "ghost", "machine": f.machineID, "goal": "anything",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, cerr := f.gw.runCommand("root", "goal.set", body); cerr == nil || cerr.code != "E_NOT_FOUND" {
		t.Fatalf("goal.set for unknown person = %#v, want E_NOT_FOUND", cerr)
	}

	readBody := []byte(`{"proto":1,"person":"ghost","machine":"` + f.machineID + `"}`)
	if _, cerr := f.gw.runCommand("root", "goal.current", readBody); cerr == nil || cerr.code != "E_NOT_FOUND" {
		t.Fatalf("goal.current for unknown person = %#v, want E_NOT_FOUND", cerr)
	}
	if _, cerr := f.gw.runCommand("root", "goal.history", readBody); cerr == nil || cerr.code != "E_NOT_FOUND" {
		t.Fatalf("goal.history for unknown person = %#v, want E_NOT_FOUND", cerr)
	}
}
