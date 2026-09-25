package state_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// ---------------------------------------------------------------------------
// Audit finding 1. Machine names and machine ids used to live in one map, so a
// grant could resolve through a false match. Fix 1 replaced that machinery; this
// test exists to prove the false match is gone rather than merely rewritten.
// ---------------------------------------------------------------------------

func TestAudit1_NoFalseMatchBetweenNamesAndIDs(t *testing.T) {
	t.Run("a_grant_does_not_resolve_through_another_machines_name", func(t *testing.T) {
		// vm-a is named "ghost". A grant on machine id "ghost" must not find it.
		st := state.NewState()
		st.People = []state.Person{personWith(t, "alice", "admin", 1)}
		st.Machines = []state.Machine{machineWith("vm-a", "ghost", 2)}
		st.Grants = []state.Grant{{
			Person:                "alice",
			Machine:               "ghost",
			MachineKeyFingerprint: fpOf(t, edPub(2)),
			Caps:                  []string{"shell"},
		}}

		err := st.Validate()
		if err == nil {
			t.Fatalf("a grant on machine id %q was accepted because another machine is *named* that", "ghost")
		}
		if !strings.Contains(err.Error(), "by name") {
			t.Fatalf("the diagnosis must say the reference went through a name: %v", err)
		}
	})

	t.Run("the_cascade_does_not_keep_a_grant_alive_through_a_name", func(t *testing.T) {
		// The machine the grant points at is deleted; a different machine happens to
		// carry its id as a name. Under one shared map the grant would look healthy.
		base := state.NewState()
		base.People = []state.Person{personWith(t, "alice", "admin", 1)}
		base.Machines = []state.Machine{machineWith("vm1", "vm1", 2), machineWith("vm2", "vm2", 3)}
		base.Grants = []state.Grant{grantOn(t, base, "alice", "vm1")}
		if err := base.Validate(); err != nil {
			t.Fatalf("base state: %v", err)
		}

		s, _ := openStore(t, *base)
		if err := s.Update(func(st *state.State) error {
			st.Machines = []state.Machine{machineWith("vm2", "vm1", 3)} // vm2 now *named* vm1
			return nil
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if g := s.Get().Grants; len(g) != 0 {
			t.Fatalf("the grant on machine id vm1 survived because machine vm2 took the name vm1: %+v", g)
		}
		revs := s.DrainRevocations()
		if len(revs) != 1 || revs[0].Reason != state.RevokedMachineRemoved {
			t.Fatalf("expected the grant to be revoked as machine-removed, got %+v", revs)
		}
	})
}

// ---------------------------------------------------------------------------
// Audit finding 3. The lock must not answer "another gateway is running" when
// what actually happened was an I/O failure.
// ---------------------------------------------------------------------------

func TestAudit3_LockDistinguishesContentionFromFailure(t *testing.T) {
	held := state.LockErrorForTest("/var/lib/iamtunnel/state.lock", state.ErrnoLockHeldForTest)
	if !errors.Is(held, state.ErrLockHeld) {
		t.Fatalf("genuine contention must be reported as ErrLockHeld, got %v", held)
	}

	for _, raw := range []error{state.ErrnoIOFailureForTest, state.ErrnoOtherFailureForTest} {
		got := state.LockErrorForTest("/var/lib/iamtunnel/state.lock", raw)
		if errors.Is(got, state.ErrLockHeld) {
			t.Errorf("%v was reported as 'the lock is held by another process'; "+
				"the administrator would go looking for a second gateway instead of a broken disk", raw)
		}
		if !errors.Is(got, raw) {
			t.Errorf("the original system error must survive in the chain, got %v", got)
		}
		if !strings.Contains(got.Error(), "state.lock") {
			t.Errorf("the error must name the file it failed on, got %v", got)
		}
	}

	// The real path still works: a second Open of the same directory is contention.
	dir := t.TempDir()
	s1, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s1.Close()
	if _, err := state.Open(dir); !errors.Is(err, state.ErrLockHeld) {
		t.Fatalf("a second gateway on the same directory must get ErrLockHeld, got %v", err)
	}
}
