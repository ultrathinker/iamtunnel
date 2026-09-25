package state_test

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// The rule must NOT fire on reading an old file: a state that sat on disk
// overnight legitimately holds deadlines that have since passed, and the
// watchdog closes those doors. If reading refused them, the gateway would
// not come back up after an idle night.
func TestOrchProbe_OldFileWithPastDeadlinesStillLoads(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	past := time.Now().Add(-12 * time.Hour)
	st := baseState(t)
	st.Machines[0].Door = &state.Door{
		ID:             "d1",
		PubKey:         edPub(7),
		Opened:         state.NewZonedTime(past.Add(-time.Hour)),
		ClosesWhenIdle: ptrZT(state.NewZonedTime(past)),
	}
	if err := s.Set(st); err == nil {
		t.Log("write with a past deadline was accepted; the rule must at least not break reading")
	}
	_ = s.Close()

	// Reopen: whatever is on disk must load without the freshness rule firing.
	s2, err := state.Open(dir)
	if err != nil {
		t.Fatalf("reopen refused an aged state file: %v", err)
	}
	defer s2.Close()
	if s2.IsReadOnly() {
		t.Fatalf("reopen put the store in read-only mode over aged deadlines")
	}
}

func ptrZT(z state.ZonedTime) *state.ZonedTime { return &z }
