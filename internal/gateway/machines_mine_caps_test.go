package gateway

// machines_mine_caps_test.go: the 1.8 `caps` feature's own precondition.
// The Client
// tab cannot tell an exec-only grant apart from a shell grant before
// ever attempting "connect" unless machines.mine's own answer says so —
// until 1.8 it did not (PROTOCOL §6's schema carried no `caps` at all).
// cmdMachinesMine (admin_role.go) now copies the field straight from the
// same acl.Grant `until` already comes from.
//
// Canary: TestMachinesMineReportsThisPersonsOwnGrantCaps. Broken on
// purpose during development (dropped the "Caps: append(...)" line from
// cmdMachinesMine's machineMineView construction, restoring the pre-1.8
// silence): the test went red on its own assertion, not on setup.
// Reverted from this file's own saved copy of admin_role.go, not `git
// checkout`.

import (
	"testing"
)

func TestMachinesMineReportsThisPersonsOwnGrantCaps(t *testing.T) {
	f := newFixture(t, nil)
	// The fixture's default grant (f.person on f.machineID) starts as
	// "shell" — iamt351SetGrantCaps (iamt351_exec_only_test.go, same
	// package) is the established way to override it, already proven
	// against the real ACL engine by TestIAMT351_*.
	iamt351SetGrantCaps(t, f, []string{"exec"})

	conn := dialAdmin(t, f, f.person, f.personKey)
	machines, err := conn.MachinesMine()
	if err != nil {
		t.Fatalf("MachinesMine: %v", err)
	}
	var found bool
	for _, m := range machines {
		if m.ID != f.machineID {
			continue
		}
		found = true
		if len(m.Caps) != 1 || m.Caps[0] != "exec" {
			t.Fatalf("machines.mine Caps for an exec-only grant = %v, want [\"exec\"]", m.Caps)
		}
	}
	if !found {
		t.Fatalf("machines.mine did not list %q at all", f.machineID)
	}

	// And the ordinary case: a plain "shell" grant reports exactly that,
	// not an empty/absent Caps that a client would have to special-case.
	iamt351SetGrantCaps(t, f, []string{"shell"})
	machines, err = conn.MachinesMine()
	if err != nil {
		t.Fatalf("MachinesMine (shell): %v", err)
	}
	found = false
	for _, m := range machines {
		if m.ID != f.machineID {
			continue
		}
		found = true
		if len(m.Caps) != 1 || m.Caps[0] != "shell" {
			t.Fatalf("machines.mine Caps for a shell grant = %v, want [\"shell\"]", m.Caps)
		}
	}
	if !found {
		t.Fatalf("machines.mine did not list %q at all (shell case)", f.machineID)
	}
}
