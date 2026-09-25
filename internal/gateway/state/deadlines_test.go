package state_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// ---------------------------------------------------------------------------
// Write-path rule for door deadlines: a deadline assigned or changed by Set/Update
// must be strictly in the future. Reading is not clock-bound: a state.json that lay
// on disk overnight legitimately holds deadlines that have since passed, so Open,
// Get and an Update that carries those deadlines over unchanged must keep working.
// ---------------------------------------------------------------------------

// doorOn attaches a door opened at opened, with the given deadlines, to the first
// machine of st.
func doorOn(t *testing.T, st *state.State, id string, opened state.ZonedTime, idle, ceiling *state.ZonedTime) {
	t.Helper()
	m := st.Machines[0]
	m.Door = &state.Door{
		ID:                id,
		PubKey:            edPub(4),
		Opened:            opened,
		ClosesWhenIdle:    idle,
		ClosesAtTheLatest: ceiling,
	}
	st.Machines[0] = m
}

// stateWithDoor is a valid state whose only machine carries a door opened an hour
// ago, with the given deadlines. Validate requires opened not to sit after a
// deadline, so deadlines earlier than an hour ago need their own opened moment.
func stateWithDoor(t *testing.T, opened state.ZonedTime, idle, ceiling *state.ZonedTime) state.State {
	t.Helper()
	st := baseState(t)
	doorOn(t, &st, "door-1", opened, idle, ceiling)
	if err := st.Validate(); err != nil {
		t.Fatalf("fixture state is not valid: %v", err)
	}
	return st
}

// openAgedStore writes st to disk behind the store's back and opens it, modelling a
// state file that lay on disk overnight: the door deadlines it holds are already in
// the past, and the store must still come up.
func openAgedStore(t *testing.T, st state.State) *state.Store {
	t.Helper()
	dir := t.TempDir()
	raw, err := json.MarshalIndent(&st, "", "  ")
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, state.StateFileName), raw, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open of a state with already-passed deadlines must succeed, got %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if s.IsReadOnly() {
		t.Fatalf("a store that read a state with passed deadlines must not be read-only")
	}
	return s
}

func TestFreshDeadlines_WritePathRejectsADeadlineInThePast(t *testing.T) {
	pastIdle := zRel(t, -time.Hour)
	pastCeiling := zRel(t, -30*time.Minute)

	t.Run("Update_rejects_a_new_door_with_a_past_idle_deadline", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))
		err := s.Update(func(st *state.State) error {
			doorOn(t, st, "door-1", zRel(t, -time.Minute), &pastIdle, nil)
			return nil
		})
		if !errors.Is(err, state.ErrDeadlineInThePast) {
			t.Fatalf("Update accepted a door whose closesWhenIdle (%s) is already past; "+
				"whether the doorwatch or the next login reads the clock first would decide what the deadline means: %v",
				pastIdle, err)
		}
		if d := s.Get().Machines[0].Door; d != nil {
			t.Fatalf("a rejected transaction must leave the state alone, but a door appeared: %+v", d)
		}
	})

	t.Run("Update_rejects_a_new_door_with_a_past_ceiling_deadline", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))
		err := s.Update(func(st *state.State) error {
			doorOn(t, st, "door-1", zRel(t, -time.Minute), nil, &pastCeiling)
			return nil
		})
		if !errors.Is(err, state.ErrDeadlineInThePast) {
			t.Fatalf("Update accepted a door whose closesAtTheLatest (%s) is already past: %v", pastCeiling, err)
		}
	})

	t.Run("Update_rejects_re-arming_an_aged_door_with_another_past_deadline", func(t *testing.T) {
		aged := stateWithDoor(t, zRel(t, -3*time.Hour), &pastIdle, &pastCeiling)
		s := openAgedStore(t, aged)

		older := zRel(t, -2*time.Hour)
		err := s.Update(func(st *state.State) error {
			st.Machines[0].Door.ClosesWhenIdle = &older
			return nil
		})
		if !errors.Is(err, state.ErrDeadlineInThePast) {
			t.Fatalf("changing an existing deadline to another past moment was accepted (%s -> %s): %v",
				pastIdle, older, err)
		}
	})

	t.Run("Set_rejects_a_state_that_assigns_a_past_deadline", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))
		err := s.Set(stateWithDoor(t, zRel(t, -3*time.Hour), &pastIdle, &pastCeiling))
		if !errors.Is(err, state.ErrDeadlineInThePast) {
			t.Fatalf("Set accepted a state assigning door deadlines that are already past: %v", err)
		}
	})

	t.Run("a_door_carried_onto_another_machine_id_counts_as_assigned", func(t *testing.T) {
		aged := stateWithDoor(t, zRel(t, -3*time.Hour), &pastIdle, &pastCeiling)
		s := openAgedStore(t, aged)

		err := s.Update(func(st *state.State) error {
			st.Machines[0].ID = "vm2" // same door, same past deadlines, new machine id
			return nil
		})
		if !errors.Is(err, state.ErrDeadlineInThePast) {
			t.Fatalf("moving a door with a past deadline onto a machine id that had no door was accepted; "+
				"for the new machine that deadline is a fresh assignment, not history: %v", err)
		}
	})
}

func TestFreshDeadlines_WritePathAcceptsFutureDeadlines(t *testing.T) {
	s, _ := openStore(t, baseState(t))

	idle := zRel(t, time.Hour)
	ceiling := zRel(t, 3*time.Hour)
	err := s.Update(func(st *state.State) error {
		doorOn(t, st, "door-1", zRel(t, -time.Minute), &idle, &ceiling)
		return nil
	})
	if err != nil {
		t.Fatalf("a door with deadlines in the future was refused: %v", err)
	}

	d := s.Get().Machines[0].Door
	if d == nil || d.ClosesWhenIdle == nil || d.ClosesAtTheLatest == nil {
		t.Fatalf("the accepted door did not survive the transaction: %+v", d)
	}
	if !d.ClosesWhenIdle.Equal(idle.Time) || !d.ClosesAtTheLatest.Equal(ceiling.Time) {
		t.Fatalf("the deadlines changed on the way through the store: got %s and %s, wanted %s and %s",
			d.ClosesWhenIdle, d.ClosesAtTheLatest, idle, ceiling)
	}
}

// The overnight contract: what the write paths must NOT do is turn "deadline has
// aged" into an unreadable state file. The gateway comes back up after an idle
// period, reads the aged deadlines, and the doorwatch closes them.
func TestFreshDeadlines_ReadPathIsNotClockBound(t *testing.T) {
	pastIdle := zRel(t, -3*time.Hour)
	pastCeiling := zRel(t, -2*time.Hour)

	s := openAgedStore(t, stateWithDoor(t, zRel(t, -4*time.Hour), &pastIdle, &pastCeiling))

	loaded := s.Get()
	d := loaded.Machines[0].Door
	if d == nil || d.ClosesWhenIdle == nil || !d.ClosesWhenIdle.Equal(pastIdle.Time) {
		t.Fatalf("the aged deadline did not survive the read: %+v", d)
	}

	// An update that does not touch the door carries the aged deadlines over
	// unchanged, and that must not be refused because they are in the past: the
	// transaction assigns nothing.
	err := s.Update(func(st *state.State) error {
		st.People = append(st.People, personWith(t, "bob", "user", 6))
		return nil
	})
	if err != nil {
		t.Fatalf("an update that leaves the aged deadlines untouched was refused: %v", err)
	}
	if d := s.Get().Machines[0].Door; d == nil || d.ClosesWhenIdle == nil || !d.ClosesWhenIdle.Equal(pastIdle.Time) {
		t.Fatalf("the aged deadline was altered by an update that never mentioned it: %+v", d)
	}

	// Removing a deadline is always safe; only assigning one is held to the clock.
	err = s.Update(func(st *state.State) error {
		st.Machines[0].Door.ClosesWhenIdle = nil
		return nil
	})
	if err != nil {
		t.Fatalf("dropping a deadline was refused: %v", err)
	}

	// ...after which the door can be re-armed with fresh, future deadlines.
	freshIdle := zRel(t, 2*time.Hour)
	freshCeiling := zRel(t, 4*time.Hour)
	err = s.Update(func(st *state.State) error {
		st.Machines[0].Door.ClosesWhenIdle = &freshIdle
		st.Machines[0].Door.ClosesAtTheLatest = &freshCeiling
		return nil
	})
	if err != nil {
		t.Fatalf("re-arming the door with fresh future deadlines was refused: %v", err)
	}
}
