package state_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// ---------------------------------------------------------------------------
// Fix 1. A grant is bound to the identity of a machine, not to its label.
//
// The hole this closes: a machine can be deleted and enrolled again under the same
// name with a different key, and whoever had access to the old box gets access to the
// new one. Binding the grant to the machine id plus the fingerprint of the key the
// machine presented at issue time is what makes that impossible; the cascade that
// removes orphans is the consequence, not the defence.
// ---------------------------------------------------------------------------

func openStore(t *testing.T, initial state.State) (*state.Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if err := s.Set(initial); err != nil {
		t.Fatalf("Set initial state: %v", err)
	}
	// The initial Set counts as issuing those grants; drop whatever it reported.
	s.DrainRevocations()
	return s, dir
}

func TestFix1_GrantIsBoundToMachineIdentity(t *testing.T) {
	t.Run("machine_replaced_under_the_same_name", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))

		// Exactly what a repeated enrol on swapped hardware looks like: same name,
		// new id, new key, new OS account - in one transaction.
		err := s.Update(func(st *state.State) error {
			replacement := machineWith("vm2", "vm1", 42)
			replacement.State = "enrolled"
			replacement.OSUser = `CORP\attacker`
			st.Machines = []state.Machine{replacement}
			return nil
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}

		got := s.Get()
		if len(got.Grants) != 0 {
			t.Fatalf("access resurrected: machine vm1 was replaced by %+v, but the grant %+v survived",
				got.Machines[0], got.Grants)
		}
		revs := s.DrainRevocations()
		if len(revs) != 1 || revs[0].Reason != state.RevokedMachineRemoved || revs[0].Person != "alice" {
			t.Fatalf("expected one machine-removed revocation for alice, got %+v", revs)
		}
	})

	t.Run("machine_rekeyed_under_the_same_id", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))
		oldFP := fpOf(t, edPub(2))
		newFP := fpOf(t, edPub(43))

		err := s.Update(func(st *state.State) error {
			st.Machines[0].MachineKey = edPub(43)
			return nil
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}

		if g := s.Get().Grants; len(g) != 0 {
			t.Fatalf("access resurrected: machine vm1 presents a new key, but the grant %+v survived", g)
		}
		revs := s.DrainRevocations()
		if len(revs) != 1 {
			t.Fatalf("expected exactly one revocation, got %+v", revs)
		}
		r := revs[0]
		if r.Reason != state.RevokedMachineRekeyed || r.PinnedKeyFP != oldFP || r.CurrentKeyFP != newFP {
			t.Fatalf("revocation does not say what happened: %+v (want reason=%s pinned=%s current=%s)",
				r, state.RevokedMachineRekeyed, oldFP, newFP)
		}
		if !strings.Contains(r.String(), "machine key changed") {
			t.Fatalf("revocation text is not usable in a journal: %q", r.String())
		}
	})

	t.Run("transaction_may_not_repin_an_existing_grant", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))

		// The transaction re-keys the machine and rewrites the pin of the existing
		// grant to match - the most direct attempt to keep access alive.
		err := s.Update(func(st *state.State) error {
			st.Machines[0].MachineKey = edPub(44)
			st.Grants[0].MachineKeyFingerprint = fpOf(t, edPub(44))
			return nil
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if g := s.Get().Grants; len(g) != 0 {
			t.Fatalf("a grant re-pinned itself onto the new key: %+v", g)
		}
		if revs := s.DrainRevocations(); len(revs) != 1 || revs[0].Reason != state.RevokedMachineRekeyed {
			t.Fatalf("expected a machine-key-changed revocation, got %+v", revs)
		}
	})

	t.Run("delete_and_readd_the_same_pair_in_one_transaction", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))

		err := s.Update(func(st *state.State) error {
			st.Grants = nil
			st.Machines[0].MachineKey = edPub(45)
			st.Grants = append(st.Grants, state.Grant{
				Person: "alice", Machine: "vm1", Caps: []string{"shell"},
			})
			return nil
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}
		if g := s.Get().Grants; len(g) != 0 {
			t.Fatalf("removing and re-adding the pair inside one transaction resurrected access: %+v", g)
		}
	})

	t.Run("same_replacement_through_Set", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))

		replaced := baseState(t)
		replaced.Machines[0].ID = "vm3"
		replaced.Machines[0].MachineKey = edPub(46)
		replaced.Machines[0].OSUser = `CORP\attacker`
		if err := s.Set(replaced); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if g := s.Get().Grants; len(g) != 0 {
			t.Fatalf("the grant %+v survived a machine replacement performed through Set", g)
		}
		if revs := s.DrainRevocations(); len(revs) != 1 {
			t.Fatalf("Set must report the revocation too, got %+v", revs)
		}
	})

	t.Run("grant_may_not_reference_a_machine_by_name", func(t *testing.T) {
		st := state.NewState()
		st.People = []state.Person{personWith(t, "alice", "admin", 1)}
		st.Machines = []state.Machine{machineWith("vm-7f3a", "build-01", 2)}
		st.Grants = []state.Grant{{
			Person:                "alice",
			Machine:               "build-01", // the name, not the id
			MachineKeyFingerprint: fpOf(t, edPub(2)),
			Caps:                  []string{"shell"},
		}}

		err := st.Validate()
		if err == nil || !strings.Contains(err.Error(), "by name") {
			t.Fatalf("a grant referencing a machine by name must be refused with an explanation, got %v", err)
		}
	})

	t.Run("honest_rekey_then_reissue", func(t *testing.T) {
		// The workflow an owner really goes through when hardware is replaced.
		s, _ := openStore(t, baseState(t))

		if err := s.Update(func(st *state.State) error {
			st.Machines[0].MachineKey = edPub(47)
			return nil
		}); err != nil {
			t.Fatalf("rekey: %v", err)
		}
		revs := s.DrainRevocations()
		if len(revs) != 1 {
			t.Fatalf("the rekey must hand the admin a list of what it took away, got %+v", revs)
		}

		// Re-issuing is a separate, deliberate step - and it works.
		if err := s.Update(func(st *state.State) error {
			return st.GrantAccess("alice", "vm1", nil, "shell")
		}); err != nil {
			t.Fatalf("re-issuing the grant after a rekey must work: %v", err)
		}
		got := s.Get()
		if len(got.Grants) != 1 || got.Grants[0].MachineKeyFingerprint != fpOf(t, edPub(47)) {
			t.Fatalf("the re-issued grant must be pinned to the new key, got %+v", got.Grants)
		}
		if revs := s.DrainRevocations(); len(revs) != 0 {
			t.Fatalf("re-issuing must not revoke anything, got %+v", revs)
		}
	})

	t.Run("person_removed_revokes_explicitly", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))
		if err := s.Update(func(st *state.State) error {
			st.People = nil
			return nil
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if g := s.Get().Grants; len(g) != 0 {
			t.Fatalf("grant of a deleted person survived: %+v", g)
		}
		if revs := s.DrainRevocations(); len(revs) != 1 || revs[0].Reason != state.RevokedPersonRemoved {
			t.Fatalf("expected a person-removed revocation, got %+v", revs)
		}
	})

	t.Run("deleting_the_machine_leaves_nothing_on_disk", func(t *testing.T) {
		s, dir := openStore(t, baseState(t))
		if err := s.Update(func(st *state.State) error {
			st.Machines = nil
			return nil
		}); err != nil {
			t.Fatalf("Update: %v", err)
		}
		raw, err := os.ReadFile(filepath.Join(dir, state.StateFileName))
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		var onDisk state.State
		if err := json.Unmarshal(raw, &onDisk); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if len(onDisk.Grants) != 0 {
			t.Fatalf("orphan grant left on disk: %s", raw)
		}
		if len(s.DrainRevocations()) != 1 {
			t.Fatalf("the cascade must still report what it removed")
		}
	})
}

// ---------------------------------------------------------------------------
// Fix 2. The fingerprint of the decoded blob is the only key of uniqueness.
// ---------------------------------------------------------------------------

func TestFix2_FingerprintComesFromTheKeyItself(t *testing.T) {
	blob := edBlob(1)
	canonical := fpOf(t, "ssh-ed25519 "+blob)

	// Five ways of writing down one and the same key. SSH sees one key in all five,
	// because it only ever sees the decoded blob.
	spellings := []struct {
		name string
		pub  string
	}{
		{"same text", "ssh-ed25519 " + blob},
		{"extra spaces and tabs", "  ssh-ed25519\t\t" + blob + "  "},
		{"trailing comment", "ssh-ed25519 " + blob + " mallory@laptop"},
		{"another type in the prefix", "ssh-rsa " + blob},
		{"no type prefix at all", blob},
	}

	t.Run("all_spellings_hash_to_one_fingerprint", func(t *testing.T) {
		for _, sp := range spellings {
			fp, err := state.ComputeFingerprint(sp.pub)
			if err != nil {
				t.Fatalf("ComputeFingerprint(%s): %v", sp.name, err)
			}
			if fp != canonical {
				t.Errorf("%s: fingerprint %s differs from %s - the fingerprint is not derived from the blob alone",
					sp.name, fp, canonical)
			}
		}
	})

	t.Run("one_key_may_not_belong_to_two_identities", func(t *testing.T) {
		now := zt(t, "2026-09-12T12:00:00Z")
		for _, sp := range spellings {
			st := state.NewState()
			st.People = []state.Person{
				personWith(t, "alice", "admin", 1),
				{Name: "mallory", Role: "user", Keys: []state.Key{
					{Fingerprint: canonical, Pub: sp.pub, Added: now}}},
			}
			if err := st.Validate(); err == nil {
				t.Errorf("%s: two people share one key and the state was accepted; "+
					"§6.1 needs fingerprint -> identity to be a function", sp.name)
			}

			// The same collision with a machine on the other side.
			st2 := state.NewState()
			st2.People = []state.Person{personWith(t, "alice", "admin", 1)}
			m := machineWith("vm1", "vm1", 2)
			m.MachineKey = sp.pub
			st2.Machines = []state.Machine{m}
			if err := st2.Validate(); err == nil {
				t.Errorf("%s: a machine and a person share one key and the state was accepted", sp.name)
			}
		}
	})

	t.Run("declared_fingerprint_must_match_the_key", func(t *testing.T) {
		now := zt(t, "2026-09-12T12:00:00Z")
		st := state.NewState()
		st.People = []state.Person{{Name: "mallory", Role: "user", Keys: []state.Key{
			// mallory writes down the fingerprint of alice's key next to her own key:
			// whoever presents alice's key would be identified as mallory.
			{Fingerprint: canonical, Pub: edPub(2), Added: now}}}}

		err := st.Validate()
		if err == nil || !strings.Contains(err.Error(), "hashes to") {
			t.Fatalf("a key filed under someone else's fingerprint was accepted (err=%v)", err)
		}
	})

	t.Run("a_key_that_does_not_decode_is_not_a_key", func(t *testing.T) {
		if _, err := state.ComputeFingerprint("ssh-ed25519 AAAA..."); !errors.Is(err, state.ErrInvalidKey) {
			t.Fatalf("a body that is not base64 must be refused, not hashed as text; got err=%v", err)
		}

		now := zt(t, "2026-09-12T12:00:00Z")
		st := state.NewState()
		st.People = []state.Person{{Name: "alice", Role: "admin", Keys: []state.Key{
			{Fingerprint: "SHA256:whatever", Pub: "ssh-ed25519 AAAA...", Added: now}}}}
		if err := st.Validate(); !errors.Is(err, state.ErrInvalidKey) {
			t.Fatalf("a person holding an undecodable key was accepted: %v", err)
		}

		st2 := state.NewState()
		m := machineWith("vm1", "vm1", 2)
		m.MachineKey = "ssh-ed25519 not-base64!"
		st2.Machines = []state.Machine{m}
		if err := st2.Validate(); !errors.Is(err, state.ErrInvalidKey) {
			t.Fatalf("a machine holding an undecodable key was accepted: %v", err)
		}
	})

	t.Run("the_type_prefix_may_not_lie_about_the_blob", func(t *testing.T) {
		if err := state.ValidateKeyMaterial("ssh-rsa " + blob); !errors.Is(err, state.ErrInvalidKey) {
			t.Fatalf("an ed25519 blob labelled ssh-rsa was accepted: %v", err)
		}
		if err := state.ValidateKeyMaterial("ssh-ed25519 " + blob); err != nil {
			t.Fatalf("an honestly labelled key was refused: %v", err)
		}
	})

	t.Run("door_key_shares_the_same_namespace", func(t *testing.T) {
		st := state.NewState()
		st.People = []state.Person{personWith(t, "alice", "admin", 1)}
		m := machineWith("vm1", "vm1", 2)
		m.Door = &state.Door{
			ID:     "door-1",
			PubKey: edPub(1), // alice's key handed out as a door key
			Opened: zt(t, "2026-09-12T12:00:00Z"),
		}
		st.Machines = []state.Machine{m}
		if err := st.Validate(); err == nil {
			t.Fatalf("a door key colliding with a person's key was accepted")
		}
	})
}

// ---------------------------------------------------------------------------
// Fix 5. A grant into the void is an error, not a silent cleanup.
// ---------------------------------------------------------------------------

func TestFix5_GrantIntoTheVoidIsReported(t *testing.T) {
	t.Run("Update_refuses_and_changes_nothing", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))

		err := s.Update(func(st *state.State) error {
			st.Grants = append(st.Grants, state.Grant{
				Person: "alice", Machine: "ghost", Caps: []string{"shell"},
			})
			return nil
		})
		if err == nil {
			t.Fatalf("Update accepted a grant on a machine that does not exist; "+
				"the admin who typed `grant add alice ghost` was told it worked (grants now: %+v)",
				s.Get().Grants)
		}
		if !strings.Contains(err.Error(), "ghost") {
			t.Fatalf("the error must name the machine that is missing: %v", err)
		}
		if g := s.Get().Grants; len(g) != 1 || g[0].Machine != "vm1" {
			t.Fatalf("a refused transaction must leave the state alone, got %+v", g)
		}
	})

	t.Run("Update_refuses_a_grant_to_an_unknown_person", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))
		err := s.Update(func(st *state.State) error {
			st.Grants = append(st.Grants, state.Grant{
				Person: "nobody", Machine: "vm1", Caps: []string{"shell"},
			})
			return nil
		})
		if err == nil {
			t.Fatalf("a grant to a person who does not exist was accepted silently")
		}
	})

	t.Run("GrantAccess_refuses_early_with_a_clear_reason", func(t *testing.T) {
		st := baseState(t)
		if err := st.GrantAccess("alice", "ghost", nil, "shell"); err == nil {
			t.Fatalf("GrantAccess accepted a machine that does not exist")
		}
		if err := st.GrantAccess("nobody", "vm1", nil, "shell"); err == nil {
			t.Fatalf("GrantAccess accepted a person who does not exist")
		}
		if err := st.GrantAccess("alice", "vm1", nil, "shell"); err == nil {
			t.Fatalf("GrantAccess created a second grant for a pair that already has one")
		}
	})

	t.Run("Set_and_Open_behave_the_same_way", func(t *testing.T) {
		s, dir := openStore(t, baseState(t))

		broken := baseState(t)
		broken.Grants = append(broken.Grants, state.Grant{
			Person: "alice", Machine: "ghost",
			MachineKeyFingerprint: fpOf(t, edPub(2)), Caps: []string{"shell"},
		})
		if err := s.Set(broken); err == nil {
			t.Fatalf("Set accepted a grant on a machine that does not exist")
		}
		_ = s.Close()

		// The same state, written to disk behind the store's back, must not open.
		raw, err := json.MarshalIndent(broken, "", "  ")
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, state.StateFileName), raw, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		s2, err := state.Open(dir)
		if err == nil {
			_ = s2.Close()
			t.Fatalf("a state file with a grant into the void opened as healthy")
		}
		defer s2.Close()
		if !s2.IsReadOnly() {
			t.Fatalf("expected read-only mode after opening such a file")
		}
	})

	t.Run("a_cascade_is_not_an_error", func(t *testing.T) {
		// The distinction that matters: removing a machine is legitimate and quiet
		// (with an audit record), pointing a grant at nothing is not.
		s, _ := openStore(t, baseState(t))
		if err := s.Update(func(st *state.State) error {
			st.Machines = nil
			return nil
		}); err != nil {
			t.Fatalf("deleting a machine must succeed, got %v", err)
		}
		if revs := s.DrainRevocations(); len(revs) != 1 {
			t.Fatalf("and must report the revocation: %+v", revs)
		}
	})
}

// ---------------------------------------------------------------------------
// Fix 8. Machine ids and names are separate namespaces; a pair has one grant.
// ---------------------------------------------------------------------------

func TestFix8_NamespacesAndDuplicateGrants(t *testing.T) {
	t.Run("a_name_may_not_be_another_machines_id", func(t *testing.T) {
		st := state.NewState()
		st.Machines = []state.Machine{
			machineWith("alpha", "beta", 1),
			machineWith("gamma", "alpha", 2), // named after the id of the first one
		}
		err := st.Validate()
		if err == nil || !strings.Contains(err.Error(), "may not overlap") {
			t.Fatalf("machine names and ids are allowed to collide: %v", err)
		}
	})

	t.Run("a_machine_may_still_use_its_id_as_its_name", func(t *testing.T) {
		st := state.NewState()
		st.Machines = []state.Machine{machineWith("vm1", "vm1", 1), machineWith("vm2", "vm2", 2)}
		if err := st.Validate(); err != nil {
			t.Fatalf("the ordinary case id == name must stay legal: %v", err)
		}
	})

	t.Run("two_grants_for_one_pair_are_refused", func(t *testing.T) {
		st := baseState(t)
		second := st.Grants[0]
		second.Caps = []string{"shell"}
		st.Grants = append(st.Grants, second)

		err := st.Validate()
		if err == nil || !strings.Contains(err.Error(), "duplicate grant") {
			t.Fatalf("two grants for alice -> vm1 were accepted; which deadline applies? (err=%v)", err)
		}
	})

	t.Run("duplicate_machine_name_is_still_refused", func(t *testing.T) {
		st := state.NewState()
		st.Machines = []state.Machine{machineWith("vm1", "dup", 1), machineWith("vm2", "dup", 2)}
		if err := st.Validate(); err == nil {
			t.Fatalf("two machines sharing a name were accepted")
		}
	})
}
