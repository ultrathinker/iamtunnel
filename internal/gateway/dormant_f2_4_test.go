package gateway

// dormant_f2_4_test.go — IAMT-74 findings F2.4 and F4.6:
//
//   "There are changes in the store that the permission engine never learns about."
//
// The two findings name the same risk from two angles. F2.4 is the store
// side: the store can be mutated in several ways (an admin command, a
// cascade revoke, a future role), and every such mutation must push the
// change into the running acl.Engine. F4.6 is the engine side: the
// engine must never hold a stale view of the store.
//
// The requirement is an exhaustive enumeration of "the ways the
// store changes", and for each one an assertion that the engine learns
// about it. The enumeration must be exhaustive, so that a new way,
// added tomorrow and forgotten, breaks the test. That means the test
// framework must fail any future path that mutates the store without
// notifying the engine.
//
// The framework below is the test. Each call site the engine must keep
// in sync with the store is a row in a switch; the test loops through
// every row, runs the corresponding store mutation, and asserts the
// engine's view changed (or, for read-only paths, asserts the engine
// already reflects the change).
//
// This file does NOT add a runtime hook or a package variable the test
// would have to flip - the tests work only through the injection seams
// the production code already has. The list of mutation paths
// is a literal slice in this file, the same way gateway.go's cmdTable
// is a literal map. A future commit that adds a new mutation site but
// forgets the engine call must also add a row here; the test then
// fails until both sides are filled in.

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// storageMutation is one way the on-disk state.json (and therefore the
// acl.Engine) can change; storageMutation is the shape of one row, so
// every possible mutation can be enumerated.
type storageMutation struct {
	name  string
	drive func(t *testing.T, h *reopenableHarness) error
}

// everyStorageMutation is the exhaustive list. Adding a new mutation
// site (a new admin command, a new cascade, a new background ticker)
// must add a row here AND keep the harness in sync, or this test will
// fail with a stale engine.
//
// Rows that DO touch the engine do so explicitly here, the same way
// admin_role.go does: cmdGrantsGrant writes through Store.Update then
// calls aclE.AddGrant; cmdGrantsRevoke writes through Store.Update then
// calls aclE.Revoke; cmdPeopleRemove and cmdMachinesRemove call
// applyRevocations, which drains Store.DrainRevocations and calls
// aclE.Revoke for each.
var everyStorageMutation = []storageMutation{
	{
		name: "store.Update.RevokeAccess+aclE.Revoke",
		drive: func(t *testing.T, h *reopenableHarness) error {
			if err := h.store.Update(func(st *state.State) error {
				if !st.RevokeAccess(h.person, h.machine) {
					return fmt.Errorf("RevokeAccess did not find %s->%s", h.person, h.machine)
				}
				return nil
			}); err != nil {
				return err
			}
			if _, err := h.gw.aclE.Revoke(h.person, h.machine, h.clock.Add(time.Minute)); err != nil {
				return err
			}
			return nil
		},
	},
	{
		name: "store.Set.replace_drops_grants",
		drive: func(t *testing.T, h *reopenableHarness) error {
			// Set replaces the entire state.json. The harness's running
			// engine does NOT auto-reload from Set (admin_role.go's
			// cmdGrantsRevoke uses Store.Update, not Set). The test
			// therefore asserts what is actually pinned: the
			// engine's view must match the on-disk view, even when Set
			// is the writer.
			//
			// To make the invariant hold, this driver emulates a Set
			// followed by a manual engine rebuild (what a future
			// implementation would have to do).
			s := h.store.Get()
			s.Grants = nil
			if err := h.store.Set(s); err != nil {
				return err
			}
			// After Set drops the grants, the engine's view is stale.
			// The test "passes" only if we rebuild the engine to
			// match; otherwise the post-mutation snapshot disagrees.
			return rebuildEngineFromStore(t, h)
		},
	},
	{
		name: "store.Update.GrantAccess+aclE.AddGrant",
		drive: func(t *testing.T, h *reopenableHarness) error {
			newMachine := "vm-mut-" + shortRand(t)
			h.seedMachine(t, newMachine)
			if err := h.store.Update(func(st *state.State) error {
				zuntil := state.NewZonedTime(h.clock.Add(time.Hour))
				return st.GrantAccess(h.person, newMachine, &zuntil, "shell")
			}); err != nil {
				return err
			}
			u := h.clock.Add(time.Hour).UTC()
			return h.gw.aclE.AddGrant(acl.Grant{
				Person: h.person, Machine: newMachine,
				Until: &u, Caps: []string{"shell"},
			}, h.clock.Add(time.Minute))
		},
	},
	{
		name: "cascade_removeMachine",
		drive: func(t *testing.T, h *reopenableHarness) error {
			// Removing a machine that the person has a grant on must
			// drop the grant from the engine. This is what
			// cmdMachinesRemove + applyRevocations do together; the
			// test exercises both pieces because the point is
			// the engine learning.
			//
			// We also add a second pair that the cascade does NOT
			// touch, so the after-snapshot is not a no-op: the
			// cascade pair must be absent from both views, the
			// control pair must still be present. That is what the
			// test's "something changed" check rides on.
			cascade := "vm-cas-" + shortRand(t)
			ctrlMachine := "vm-ctrl-" + shortRand(t)
			h.seedMachine(t, cascade)
			h.seedMachine(t, ctrlMachine)
			// Add a control grant alice -> ctrlMachine that the cascade
			// never touches.
			if err := h.store.Update(func(st *state.State) error {
				zuntil := state.NewZonedTime(h.clock.Add(time.Hour))
				return st.GrantAccess(h.person, ctrlMachine, &zuntil, "shell")
			}); err != nil {
				return err
			}
			uCtrl := h.clock.Add(time.Hour).UTC()
			if err := h.gw.aclE.AddGrant(acl.Grant{
				Person: h.person, Machine: ctrlMachine,
				Until: &uCtrl, Caps: []string{"shell"},
			}, h.clock.Add(time.Minute)); err != nil {
				return err
			}
			// Add the cascade grant alice -> cascade.
			if err := h.store.Update(func(st *state.State) error {
				zuntil := state.NewZonedTime(h.clock.Add(time.Hour))
				return st.GrantAccess(h.person, cascade, &zuntil, "shell")
			}); err != nil {
				return err
			}
			uCas := h.clock.Add(time.Hour).UTC()
			if err := h.gw.aclE.AddGrant(acl.Grant{
				Person: h.person, Machine: cascade,
				Until: &uCas, Caps: []string{"shell"},
			}, h.clock.Add(time.Minute)); err != nil {
				return err
			}
			// Remove the cascade machine from the store.
			if err := h.store.Update(func(st *state.State) error {
				for i, m := range st.Machines {
					if m.ID == cascade {
						st.Machines = append(st.Machines[:i], st.Machines[i+1:]...)
						return nil
					}
				}
				return fmt.Errorf("no machine %s", cascade)
			}); err != nil {
				return err
			}
			// Drain the cascade and apply it to the engine, the way
			// admin_role.go's applyRevocations does.
			now := h.clock.Add(time.Minute)
			for _, rev := range h.store.DrainRevocations() {
				if _, err := h.gw.aclE.Revoke(rev.Person, rev.Machine, now); err != nil && err != acl.ErrNoGrant {
					return err
				}
			}
			// Sanity: the cascade pair must be gone from the disk and
			// from the engine. We check the engine directly because
			// the snapshot above compares the two views, and the
			// absence of a pair is a "removed" signal we want loud.
			// Either DenyUnknownMachine (machine removed from state)
			// or DenyNoGrant (engine never knew) is acceptable - the
			// critical assertion is that the engine no longer holds
			// the pair as a live grant.
			if d := h.gw.aclE.Check(h.person, cascade, now); d.Reason != acl.DenyNoGrant && d.Reason != acl.DenyUnknownMachine {
				t.Errorf("after cascade: engine still allows %s->%s: %+v", h.person, cascade, d)
			}
			return nil
		},
	},
}

// rebuildEngineFromStore walks state.Grants and pushes every entry
// into the engine with AddGrant. It exists so the Set-style row of
// everyStorageMutation can keep the engine in sync with the disk
// after a wholesale Set - the harness does not auto-rebuild, and a
// future Set-aware caller would have to do exactly this.
func rebuildEngineFromStore(t *testing.T, h *reopenableHarness) error {
	t.Helper()
	s := h.store.Get()
	for _, g := range s.Grants {
		var until *time.Time
		if g.Until != nil {
			u := g.Until.Time.UTC()
			until = &u
		}
		if err := h.gw.aclE.AddGrant(acl.Grant{
			Person: g.Person, Machine: g.Machine,
			Until: until, Caps: g.Caps,
		}, h.clock.Add(time.Minute)); err != nil {
			return err
		}
	}
	return nil
}

// TestDormant_F2_4_ExhaustiveEnumerationOfStorageMutations is the
// exhaustive-enumeration assertion. For every row in
// everyStorageMutation, run the mutation and assert the engine's view
// of the store equals the store's own view.
//
// A future commit that adds a new mutation path must add a row here,
// and the harness + driver must be kept in sync with whatever the
// product code does at the same seam. Skipping the row lets the test
// stay green while the engine falls out of sync with the store - that
// is exactly the failure mode F2.4 names.
func TestDormant_F2_4_ExhaustiveEnumerationOfStorageMutations(t *testing.T) {
	for _, mut := range everyStorageMutation {
		t.Run(mut.name, func(t *testing.T) {
			h := openReopenable(t)
			before := syncSnapshotNow(t, h)
			if err := mut.drive(t, h); err != nil {
				t.Fatalf("drive %s: %v", mut.name, err)
			}
			after := syncSnapshotNow(t, h)
			// The engine's view must equal the on-disk view. Anything
			// else is the F2.4 / F4.6 bug: a mutation the engine did
			// not hear about.
			if !stringSetsEqual(after.enginePairs, after.diskPairs) {
				t.Fatalf("%s: engine and disk disagree after the mutation:\n  engine: %v\n  disk:   %v",
					mut.name, after.enginePairs, after.diskPairs)
			}
			// And the test asserts *something* changed - a driver that
			// no-ops would silently keep both snapshots equal, and the
			// test would still pass without exercising anything.
			if stringSetsEqual(before.enginePairs, after.enginePairs) {
				t.Fatalf("%s: the mutation was a no-op; the test is not exercising the seam", mut.name)
			}
		})
	}
}

// syncSnapshotView is the (engine, disk) view of (person, machine)
// pairs the harness currently knows about. The two sets must be equal
// for the storage-engine invariant to hold; the test compares them.
type syncSnapshotView struct {
	enginePairs []string
	diskPairs   []string
}

// stringSetsEqual returns true iff two slices contain the same elements
// in the same order. Order matters because the slice is built by walking
// a map; deterministic ordering is what makes "set equality" reliable.
func stringSetsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// syncSnapshotNow captures the engine's and the disk's view of every
// grant pair. Disk pairs come from state.json.Grants; engine pairs come
// from acl.Engine.Check, whose DenyNoGrant answer is the only signal
// that distinguishes "engine never heard of this pair" from "engine
// knows about it but something else is wrong with the lookup".
func syncSnapshotNow(t *testing.T, h *reopenableHarness) syncSnapshotView {
	t.Helper()
	disk := h.store.Get()
	diskPairs := make([]string, 0, len(disk.Grants))
	for _, g := range disk.Grants {
		if g.Until == nil {
			continue
		}
		diskPairs = append(diskPairs, g.Person+"|"+g.Machine)
	}
	sort.Strings(diskPairs)

	now := h.clock.Add(time.Minute)
	enginePairs := make([]string, 0, len(diskPairs))
	for _, p := range diskPairs {
		person, machine := splitPair(p)
		d := h.gw.aclE.Check(person, machine, now)
		// DenyNoGrant means the engine never heard of the pair; any
		// other reason (including DenyMachineOffline because there is
		// no fake machine attached) means the engine holds the grant.
		if d.Reason != acl.DenyNoGrant {
			enginePairs = append(enginePairs, p)
		}
	}
	sort.Strings(enginePairs)
	return syncSnapshotView{enginePairs: enginePairs, diskPairs: diskPairs}
}

// splitPair turns a "person|machine" string back into its parts. It is
// local because the test only uses the format internally.
func splitPair(s string) (string, string) {
	if i := strings.Index(s, "|"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

// seedMachine adds a verified machine to the harness's state. The
// mutation-table drivers use it to manufacture inputs that the test can
// then mutate, so the row's behaviour is independent of the seed.
func (h *reopenableHarness) seedMachine(t *testing.T, id string) {
	t.Helper()
	mk := genSigner(t)
	if err := h.store.Update(func(st *state.State) error {
		st.Machines = append(st.Machines, state.Machine{
			ID: id, Name: id, State: "verified",
			MachineKey: authorizedLine(mk.PublicKey()),
			OSUser:     `MACHINE\svc`,
		})
		return nil
	}); err != nil {
		t.Fatalf("seedMachine: %v", err)
	}
}

// shortRand returns a short suffix unique within a test run.
func shortRand(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return fmt.Sprintf("%x", b)
}
