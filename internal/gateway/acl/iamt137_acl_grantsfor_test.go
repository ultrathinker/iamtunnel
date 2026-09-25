package acl

import (
	"testing"
	"time"
)

func TestACL_GrantsFor(t *testing.T) {
	now := time.Date(2026, 9, 13, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	v := &fakeView{
		persons: map[string]bool{"alice": true, "bob": true},
		machines: map[string]fakeMachine{
			"vm1": {verified: true, online: true},
			"vm2": {verified: true, online: true},
			"vm3": {verified: true, online: true},
		},
	}

	e, err := NewEngine(v, Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// 1. alice -> vm1 (active, future)
	if err := e.AddGrant(Grant{Person: "alice", Machine: "vm1", Until: &future, Caps: []string{"shell"}}, past); err != nil {
		t.Fatalf("AddGrant alice vm1: %v", err)
	}
	// 2. alice -> vm2 (indefinite, active)
	if err := e.AddGrant(Grant{Person: "alice", Machine: "vm2", Until: nil, Caps: []string{"shell"}}, past); err != nil {
		t.Fatalf("AddGrant alice vm2: %v", err)
	}
	// 3. bob -> vm3 (bob's grant, alice must not see)
	if err := e.AddGrant(Grant{Person: "bob", Machine: "vm3", Until: &future, Caps: []string{"shell"}}, past); err != nil {
		t.Fatalf("AddGrant bob vm3: %v", err)
	}

	// Alice queries her grants
	aliceGrants := e.GrantsFor("alice", now)
	if len(aliceGrants) != 2 {
		t.Fatalf("GrantsFor(alice) len = %d, want 2", len(aliceGrants))
	}
	for _, g := range aliceGrants {
		if g.Machine == "vm3" {
			t.Fatalf("GrantsFor(alice) isolation breach: saw bob's machine %q", g.Machine)
		}
	}

	// Revoke alice -> vm1
	if _, err := e.Revoke("alice", "vm1", now); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	aliceAfterRevoke := e.GrantsFor("alice", now)
	if len(aliceAfterRevoke) != 1 || aliceAfterRevoke[0].Machine != "vm2" {
		t.Fatalf("GrantsFor(alice) after revoke = %+v, want only vm2", aliceAfterRevoke)
	}

	// Unknown person returns nil
	if unknown := e.GrantsFor("nobody", now); unknown != nil {
		t.Fatalf("GrantsFor(nobody) = %+v, want nil", unknown)
	}

	// Expired grant check
	later := future.Add(time.Minute)
	bobLater := e.GrantsFor("bob", later)
	if len(bobLater) != 0 {
		t.Fatalf("GrantsFor(bob, later) len = %d, want 0 (expired)", len(bobLater))
	}
}
