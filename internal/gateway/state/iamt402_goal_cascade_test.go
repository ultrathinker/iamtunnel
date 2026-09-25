package state_test

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// Review finding 1: Validate requires every Goals entry to reference an
// existing person and machine, but nothing used to drop a Goals entry when
// its person or machine was removed - so a machine or person that ever had
// a goal declared for it could never be removed again. reconcileGoals now
// cascades the same way reconcileGrants already does for Grants.

func TestIAMT402_MachineRemovalCascadesDeclaredGoal(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	defer store.Close()

	base := baseState(t)
	when := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	if err := store.Update(func(st *state.State) error {
		*st = base
		_, err := st.SetGoal("alice", "vm1", "fix the printer", when)
		return err
	}); err != nil {
		t.Fatalf("declare goal: %v", err)
	}

	// Exactly what gateway.cmdMachinesRemove does inside Store.Update.
	err = store.Update(func(st *state.State) error {
		for i, m := range st.Machines {
			if m.ID == "vm1" {
				st.Machines = append(st.Machines[:i], st.Machines[i+1:]...)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("machines.remove of a machine with a declared goal was refused: %v", err)
	}

	after := store.Get()
	if _, found := after.GoalFor("alice", "vm1"); found {
		t.Fatalf("goal for the removed machine is still present after removal")
	}
}

func TestIAMT402_PersonRemovalCascadesDeclaredGoal(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	defer store.Close()

	base := baseState(t)
	base.People = append(base.People, personWith(t, "bob", "user", 9))
	when := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	if err := store.Update(func(st *state.State) error {
		*st = base
		_, err := st.SetGoal("bob", "vm1", "fix the printer", when)
		return err
	}); err != nil {
		t.Fatalf("declare goal: %v", err)
	}

	err = store.Update(func(st *state.State) error {
		for i, p := range st.People {
			if p.Name == "bob" {
				st.People = append(st.People[:i], st.People[i+1:]...)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("people.remove of a person with a declared goal was refused: %v", err)
	}

	after := store.Get()
	if _, found := after.GoalFor("bob", "vm1"); found {
		t.Fatalf("goal for the removed person is still present after removal")
	}
}
