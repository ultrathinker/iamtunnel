package gateway

// IAMT-405 canary: goal.list returns EVERY (person, machine) pair that
// carries a goal record, each with its current goal and bounded
// history, in ONE reply. The window's Access tab used to ask
// goal.history once per grant row - a page of N grants cost N round
// trips for facts one reply carries whole.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT405_GoalListReturnsEveryPairInOneReply(t *testing.T) {
	f := newFixture(t, nil)
	addPerson(t, f, "root", "admin", genSigner(t))
	addPerson(t, f, "carol", "user", genSigner(t))
	now := time.Now()
	if err := f.store.Update(func(st *state.State) error {
		if _, err := st.SetGoal("root", f.machineID, "keep the site online", now); err != nil {
			return err
		}
		if _, err := st.SetGoal("root", f.machineID, "rotate the database credentials", now); err != nil {
			return err
		}
		if _, err := st.SetGoal("carol", f.machineID, "keep the printer running", now); err != nil {
			return err
		}
		return nil
	}); err != nil {
		t.Fatalf("seed goals: %v", err)
	}

	body, err := json.Marshal(map[string]any{"proto": 1})
	if err != nil {
		t.Fatal(err)
	}
	result, cerr := f.gw.runCommand("root", "goal.list", body)
	if cerr != nil {
		t.Fatalf("goal.list: %s (%s)", cerr.message, cerr.code)
	}
	list, ok := result.(goalListResult)
	if !ok {
		t.Fatalf("goal.list result = %T, want goalListResult", result)
	}
	if len(list.Goals) != 2 {
		t.Fatalf("goal.list returned %d pairs, want both declared pairs in the one reply (IAMT-405)", len(list.Goals))
	}
	byPair := map[string]goalView{}
	for _, gv := range list.Goals {
		byPair[gv.Person+"\x00"+gv.Machine] = gv
	}
	root, ok := byPair["root\x00"+f.machineID]
	if !ok {
		t.Fatalf("goal.list has no row for root -> %s: %+v", f.machineID, list.Goals)
	}
	if root.Goal != "rotate the database credentials" {
		t.Fatalf("root's current goal = %q, want the newest declaration", root.Goal)
	}
	if len(root.History) != 2 {
		t.Fatalf("root's history = %+v, want both declarations", root.History)
	}
	carol, ok := byPair["carol\x00"+f.machineID]
	if !ok || carol.Goal != "keep the printer running" {
		t.Fatalf("carol's row = %+v, want her pair with its current goal", carol)
	}
}
