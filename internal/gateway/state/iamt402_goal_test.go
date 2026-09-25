package state_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT402_GoalHistoryIsBoundedAndSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}

	base := baseState(t)
	when := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	if err := store.Update(func(st *state.State) error {
		*st = base
		for i := 1; i <= 21; i++ {
			if _, err := st.SetGoal("alice", "vm1", fmt.Sprintf("goal-%d", i), when.Add(time.Duration(i)*time.Minute)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		store.Close()
		t.Fatalf("persist goal history: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	reloaded, err := state.Open(dir)
	if err != nil {
		t.Fatalf("reopen state: %v", err)
	}
	defer reloaded.Close()

	st := reloaded.Get()
	record, ok := st.GoalFor("alice", "vm1")
	if !ok {
		t.Fatal("goal record did not survive reload")
	}
	if record.Current != "goal-21" {
		t.Fatalf("current goal = %q, want goal-21", record.Current)
	}
	if len(record.History) != state.MaxGoalHistory {
		t.Fatalf("history length = %d, want %d", len(record.History), state.MaxGoalHistory)
	}
	if record.History[0].Goal != "goal-21" || record.History[len(record.History)-1].Goal != "goal-2" {
		t.Fatalf("history bounds = first %q, last %q; want goal-21 .. goal-2", record.History[0].Goal, record.History[len(record.History)-1].Goal)
	}

	if err := reloaded.Update(func(st *state.State) error {
		_, err := st.SetGoal("alice", "vm1", "", when.Add(22*time.Minute))
		return err
	}); err != nil {
		t.Fatalf("clear current goal: %v", err)
	}
	cleared := reloaded.Get()
	clearedRecord, ok := cleared.GoalFor("alice", "vm1")
	if !ok || clearedRecord.Current != "" || len(clearedRecord.History) != state.MaxGoalHistory {
		t.Fatalf("explicit clear = %+v, want empty current with retained history", clearedRecord)
	}
}
