package state_test

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// ============================================================================
// ROUND 3 INDEPENDENT ACCEPTANCE TESTS
// ============================================================================

// 1. Access does not resurrect (and a check of the claimed machine vs person asymmetry)
func TestOwnR3_AccessResurrectionAndAsymmetry(t *testing.T) {
	t.Run("machine_replaced_with_different_key_revokes_grant", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))

		err := s.Update(func(st *state.State) error {
			replacement := machineWith("vm-new", "vm1", 50)
			st.Machines = []state.Machine{replacement}
			return nil
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}

		got := s.Get()
		if len(got.Grants) != 0 {
			t.Fatalf("VULNERABILITY: grant resurrected after machine replacement! got grants: %+v", got.Grants)
		}
		revs := s.DrainRevocations()
		if len(revs) != 1 || revs[0].Reason != state.RevokedMachineRemoved {
			t.Fatalf("expected 1 machine-removed revocation, got %+v", revs)
		}
	})

	t.Run("machine_rekeyed_in_one_transaction_revokes_grant", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))

		err := s.Update(func(st *state.State) error {
			st.Machines[0].MachineKey = edPub(51)
			return nil
		})
		if err != nil {
			t.Fatalf("Update: %v", err)
		}

		got := s.Get()
		if len(got.Grants) != 0 {
			t.Fatalf("VULNERABILITY: grant resurrected after machine rekey! got grants: %+v", got.Grants)
		}
		revs := s.DrainRevocations()
		if len(revs) != 1 || revs[0].Reason != state.RevokedMachineRekeyed {
			t.Fatalf("expected 1 machine-key-changed revocation, got %+v", revs)
		}
	})

	// ASYMMETRY: what happens when a person is deleted and recreated under the same name in one transaction?
	t.Run("ASYMMETRY_person_replaced_in_one_transaction_inherits_grant", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))
		initialGrants := s.Get().Grants
		if len(initialGrants) != 1 {
			t.Fatalf("expected 1 initial grant")
		}

		// Replace alice with a completely different person of the same name "alice", but with a DIFFERENT key (tag 77 instead of tag 1)
		err := s.Update(func(st *state.State) error {
			st.People = []state.Person{personWith(t, "alice", "user", 77)}
			return nil
		})
		if err != nil {
			t.Fatalf("Update failed: %v", err)
		}

		got := s.Get()
		revs := s.DrainRevocations()

		// Verify: the grant SURVIVED! The new person inherited the old person's access!
		if len(got.Grants) == 1 && len(revs) == 0 {
			t.Logf("CONFIRMED ASYMMETRY: When person is replaced under same name with completely new key in 1 transaction, grant SURVIVES (person identified by name only, machine by key+id). New person inherited access to vm1 without any revocation!")
		} else {
			t.Fatalf("unexpected behavior: grants=%+v revs=%+v", got.Grants, revs)
		}
	})

	// ASYMMETRY: what happens when a person's key is rotated (re-key)?
	t.Run("ASYMMETRY_person_rekeyed_preserves_grants", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))

		// Rotate alice's key to tag 88
		err := s.Update(func(st *state.State) error {
			st.People[0].Keys = []state.Key{{
				Fingerprint: fpOf(t, edPub(88)),
				Pub:         edPub(88),
				Added:       zt(t, "2026-09-12T12:00:00Z"),
			}}
			return nil
		})
		if err != nil {
			t.Fatalf("Update failed: %v", err)
		}

		got := s.Get()
		revs := s.DrainRevocations()
		if len(got.Grants) == 1 && len(revs) == 0 {
			t.Logf("CONFIRMED ASYMMETRY: Person rekey does not revoke grants. Person holds grants by name, not by key fingerprint.")
		} else {
			t.Fatalf("unexpected behavior: grants=%+v revs=%+v", got.Grants, revs)
		}
	})
}

// 2. A fingerprint belongs to exactly one
func TestOwnR3_FingerprintBelongsToOne(t *testing.T) {
	t.Run("same_key_shared_by_two_people_rejected", func(t *testing.T) {
		st := state.NewState()
		pub := edPub(10)
		fp := fpOf(t, pub)
		now := zt(t, "2026-09-12T10:00:00Z")

		st.People = []state.Person{
			{Name: "alice", Role: "admin", Keys: []state.Key{{Fingerprint: fp, Pub: pub, Added: now}}},
			{Name: "bob", Role: "user", Keys: []state.Key{{Fingerprint: fp, Pub: pub, Added: now}}},
		}

		err := st.Validate()
		if err == nil || !strings.Contains(err.Error(), "duplicate key fingerprint") {
			t.Fatalf("expected duplicate key error for two people, got %v", err)
		}
	})

	t.Run("same_key_shared_between_person_and_machine_rejected", func(t *testing.T) {
		st := state.NewState()
		pub := edPub(11)
		fp := fpOf(t, pub)
		now := zt(t, "2026-09-12T10:00:00Z")

		st.People = []state.Person{
			{Name: "alice", Role: "admin", Keys: []state.Key{{Fingerprint: fp, Pub: pub, Added: now}}},
		}
		st.Machines = []state.Machine{
			{ID: "vm1", Name: "vm1", State: "verified", MachineKey: pub, OSUser: `CORP\svc`},
		}

		err := st.Validate()
		if err == nil || !strings.Contains(err.Error(), "conflicts with") {
			t.Fatalf("expected conflict between person and machine keys, got %v", err)
		}
	})

	t.Run("same_key_with_different_decorations_rejected", func(t *testing.T) {
		blob := edBlob(12)
		fp, err := state.ComputeFingerprint(blob)
		if err != nil {
			t.Fatalf("ComputeFingerprint: %v", err)
		}
		now := zt(t, "2026-09-12T10:00:00Z")

		// Four different spellings of the same key
		decorations := []string{
			"ssh-ed25519 " + blob,
			"   ssh-ed25519    " + blob + "    ",
			"ssh-ed25519 " + blob + " comment@host",
			blob, // no prefix
		}

		for _, d1 := range decorations {
			for _, d2 := range decorations {
				st := state.NewState()
				st.People = []state.Person{
					{Name: "user1", Role: "user", Keys: []state.Key{{Fingerprint: fp, Pub: d1, Added: now}}},
					{Name: "user2", Role: "user", Keys: []state.Key{{Fingerprint: fp, Pub: d2, Added: now}}},
				}
				err := st.Validate()
				if err == nil {
					t.Fatalf("duplicate key accepted despite different formatting: %q vs %q", d1, d2)
				}
			}
		}
	})

	t.Run("declared_fingerprint_mismatch_rejected", func(t *testing.T) {
		st := state.NewState()
		pub := edPub(13)
		fakeFP := "SHA256:fakefakefakefakefakefakefakefakefakefakefake"
		now := zt(t, "2026-09-12T10:00:00Z")

		st.People = []state.Person{
			{Name: "alice", Role: "admin", Keys: []state.Key{{Fingerprint: fakeFP, Pub: pub, Added: now}}},
		}
		err := st.Validate()
		if err == nil || !strings.Contains(err.Error(), "fingerprint must be derived from the key") {
			t.Fatalf("expected declared fingerprint mismatch error, got %v", err)
		}
	})

	t.Run("invalid_key_blob_rejected", func(t *testing.T) {
		st := state.NewState()
		now := zt(t, "2026-09-12T10:00:00Z")

		st.People = []state.Person{
			{Name: "alice", Role: "admin", Keys: []state.Key{{Fingerprint: "SHA256:xxx", Pub: "ssh-ed25519 !!!not-base64!!!", Added: now}}},
		}
		err := st.Validate()
		if err == nil || !errors.Is(err, state.ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey on malformed base64, got %v", err)
		}
	})
}

// 3. A grant into the void, through every write path
func TestOwnR3_GrantIntoVoidAllWritePaths(t *testing.T) {
	// Path 1: Store.Update
	t.Run("Update_rejects_grant_to_nonexistent_person", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))
		err := s.Update(func(st *state.State) error {
			st.Grants = append(st.Grants, state.Grant{
				Person: "ghost-person", Machine: "vm1", Caps: []string{"shell"},
			})
			return nil
		})
		if err == nil {
			t.Fatalf("Update accepted grant to non-existent person")
		}
	})

	t.Run("Update_rejects_grant_to_nonexistent_machine", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))
		err := s.Update(func(st *state.State) error {
			st.Grants = append(st.Grants, state.Grant{
				Person: "alice", Machine: "ghost-machine", Caps: []string{"shell"},
			})
			return nil
		})
		if err == nil {
			t.Fatalf("Update accepted grant to non-existent machine")
		}
	})

	// Path 2: Store.Set
	t.Run("Set_rejects_grant_into_void", func(t *testing.T) {
		s, _ := openStore(t, baseState(t))
		st := baseState(t)
		st.Grants = append(st.Grants, state.Grant{
			Person: "alice", Machine: "ghost-machine", Caps: []string{"shell"},
			MachineKeyFingerprint: fpOf(t, edPub(2)),
		})
		err := s.Set(st)
		if err == nil {
			t.Fatalf("Set accepted state with grant into void")
		}
	})

	// Path 3: State.GrantAccess
	t.Run("GrantAccess_rejects_nonexistent_person_or_machine", func(t *testing.T) {
		st := baseState(t)
		if err := st.GrantAccess("ghost-person", "vm1", nil, "shell"); err == nil {
			t.Fatalf("GrantAccess accepted non-existent person")
		}
		if err := st.GrantAccess("alice", "ghost-machine", nil, "shell"); err == nil {
			t.Fatalf("GrantAccess accepted non-existent machine")
		}
	})

	// Path 4: Open from disk with invalid grant into void
	t.Run("Open_with_grant_into_void_enters_read_only", func(t *testing.T) {
		dir := t.TempDir()
		st := baseState(t)
		st.Grants = append(st.Grants, state.Grant{
			Person: "alice", Machine: "ghost-machine", Caps: []string{"shell"},
			MachineKeyFingerprint: fpOf(t, edPub(2)),
		})

		raw, err := json.MarshalIndent(st, "", "  ")
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, state.StateFileName), raw, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		s, err := state.Open(dir)
		if err == nil {
			_ = s.Close()
			t.Fatalf("Open succeeded on state with grant into void, expected CorruptStateError")
		}
		defer s.Close()
		if !s.IsReadOnly() {
			t.Fatalf("expected store to enter read-only mode")
		}
	})
}

// 4. Atomic write and a corrupted file
func TestOwnR3_AtomicityAndCorruptedFileRecovery(t *testing.T) {
	t.Run("crash_before_rename_preserves_disk_file", func(t *testing.T) {
		dir := t.TempDir()
		s, err := state.Open(dir)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		defer s.Close()

		if err := s.Set(baseState(t)); err != nil {
			t.Fatalf("Set: %v", err)
		}

		statePath := filepath.Join(dir, state.StateFileName)
		orig, _ := os.ReadFile(statePath)

		// Simulate a crash before the rename
		state.SetBeforeRenameHook(s, func(tmpPath string) error {
			return errors.New("simulated power cut")
		})

		err = s.Update(func(st *state.State) error {
			st.People = append(st.People, personWith(t, "mallory", "admin", 99))
			return nil
		})
		if err == nil {
			t.Fatalf("Update should fail under hook")
		}

		current, _ := os.ReadFile(statePath)
		if string(current) != string(orig) {
			t.Fatalf("state.json was modified despite failure before rename!")
		}

		// The store remains operational
		state.SetBeforeRenameHook(s, nil)
		err = s.Update(func(st *state.State) error {
			st.People = append(st.People, personWith(t, "bob", "user", 5))
			return nil
		})
		if err != nil {
			t.Fatalf("Update after hook cleared failed: %v", err)
		}
		if len(s.Get().People) != 2 {
			t.Fatalf("expected 2 people, got %d", len(s.Get().People))
		}
	})

	t.Run("corrupted_file_enters_read_only_and_forbids_modifications", func(t *testing.T) {
		dir := t.TempDir()
		statePath := filepath.Join(dir, state.StateFileName)

		badJSON := []byte(`{"schema": 1, "people": [ {"name": "truncated`)
		if err := os.WriteFile(statePath, badJSON, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		s, err := state.Open(dir)
		if err == nil {
			t.Fatalf("expected CorruptStateError, got nil")
		}
		defer s.Close()

		if !s.IsReadOnly() {
			t.Fatalf("expected store to be read-only")
		}

		var corrupt *state.CorruptStateError
		if !errors.As(err, &corrupt) {
			t.Fatalf("expected CorruptStateError, got %T", err)
		}

		// Write attempts are refused
		if err := s.Save(); !errors.Is(err, state.ErrReadOnly) {
			t.Fatalf("expected ErrReadOnly on Save, got %v", err)
		}
		if err := s.Update(func(st *state.State) error { return nil }); !errors.Is(err, state.ErrReadOnly) {
			t.Fatalf("expected ErrReadOnly on Update, got %v", err)
		}

		// The disk was not overwritten
		content, _ := os.ReadFile(statePath)
		if string(content) != string(badJSON) {
			t.Fatalf("corrupted file was overwritten!")
		}
	})
}

// 5. The lock and a stale lock file
func TestOwnR3_StaleLockRecovery(t *testing.T) {
	dir := t.TempDir()
	lockPath := filepath.Join(dir, state.LockFileName)

	// First process acquires the lock
	fl1, err := state.AcquireFileLock(lockPath)
	if err != nil {
		t.Fatalf("AcquireFileLock: %v", err)
	}

	// The second process must get ErrLockHeld
	fl2, err := state.AcquireFileLock(lockPath)
	if !errors.Is(err, state.ErrLockHeld) {
		if fl2 != nil {
			_ = fl2.Unlock()
		}
		t.Fatalf("expected ErrLockHeld for second lock acquisition, got %v", err)
	}

	// The first process releases the lock (simulating process exit)
	if err := fl1.Unlock(); err != nil {
		t.Fatalf("fl1 Unlock: %v", err)
	}

	// The lock file still exists on disk (a stale lock file)
	if _, err := os.Stat(lockPath); err != nil {
		t.Fatalf("lock file disappeared from disk: %v", err)
	}

	// A new process must acquire the lock over the existing file successfully
	fl3, err := state.AcquireFileLock(lockPath)
	if err != nil {
		t.Fatalf("failed to acquire lock over stale lock file: %v", err)
	}
	defer fl3.Unlock()
}

// 7. Time: absence != zero, zoneless time is rejected
func TestOwnR3_TimeAndDeadlines(t *testing.T) {
	t.Run("absent_until_vs_zero_until", func(t *testing.T) {
		gAbsent := state.Grant{Person: "alice", Machine: "vm1", Caps: []string{"shell"}}
		if gAbsent.HasUntil() {
			t.Fatalf("HasUntil returned true for absent until")
		}

		zeroTime := state.NewZonedTime(time.Time{})
		gZero := state.Grant{Person: "alice", Machine: "vm1", Until: &zeroTime, Caps: []string{"shell"}}
		if !gZero.HasUntil() {
			t.Fatalf("HasUntil returned false for present zero until")
		}
		if !gZero.IsUntilZero() {
			t.Fatalf("IsUntilZero returned false for zero until")
		}
	})

	t.Run("time_without_zone_is_rejected", func(t *testing.T) {
		invalidTimes := []string{
			"2026-09-12T12:00:00",
			"2026-09-12 12:00:00",
			"2026-09-12",
			"12:00:00",
		}
		for _, raw := range invalidTimes {
			_, err := state.ParseZonedTime(raw)
			if err == nil || !errors.Is(err, state.ErrInvalidTime) {
				t.Fatalf("expected ErrInvalidTime for %q, got %v", raw, err)
			}
		}

		validTimes := []string{
			"2026-09-12T12:00:00Z",
			"2026-09-12T12:00:00+02:00",
			"2026-09-12T12:00:00-05:00",
		}
		for _, raw := range validTimes {
			_, err := state.ParseZonedTime(raw)
			if err != nil {
				t.Fatalf("expected valid ZonedTime for %q, got %v", raw, err)
			}
		}
	})
}
