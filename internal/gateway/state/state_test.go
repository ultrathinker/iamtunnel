package state_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func intPtr(i int) *int {
	return &i
}

// Gate 2: Test atomicity with modeled crash/interruption before rename.
func TestState_Gate2_AtomicityInterruptedCrash(t *testing.T) {
	dir := t.TempDir()

	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	// Initial valid state
	err = s.Update(func(st *state.State) error {
		st.People = append(st.People, personWith(t, "alice", "admin", 1))
		return nil
	})
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	stateFile := filepath.Join(dir, state.StateFileName)
	originalBytes, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Model crash/interruption: inject failure right before rename
	crashSimulated := false
	state.SetBeforeRenameHook(s, func(tmpPath string) error {
		crashSimulated = true
		// Verify temporary file exists and is populated
		info, statErr := os.Stat(tmpPath)
		if statErr != nil || info.Size() == 0 {
			t.Errorf("expected temp file %s to exist with data, got statErr: %v", tmpPath, statErr)
		}
		// Abort write operation before rename occurs
		return errors.New("SIGKILL / simulated power cut before rename")
	})

	// Attempt to update state with bob

	err = s.Update(func(st *state.State) error {
		st.People = append(st.People, personWith(t, "bob", "user", 2))
		return nil
	})

	if err == nil {
		t.Fatalf("expected error from simulated crash, got nil")
	}
	if !crashSimulated {
		t.Fatalf("crash hook was never called")
	}

	// Invariant check: original state.json on disk must remain 100% untouched
	currentBytes, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(currentBytes) != string(originalBytes) {
		t.Fatalf("atomicity violated! state.json on disk was modified despite crash before rename.\nOriginal:\n%s\nCurrent:\n%s", string(originalBytes), string(currentBytes))
	}

	// Re-open from disk in fresh store to ensure reload is unaffected
	s.Close()
	s2, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Re-open failed: %v", err)
	}
	defer s2.Close()

	reloaded := s2.Get()
	if len(reloaded.People) != 1 || reloaded.People[0].Name != "alice" {
		t.Fatalf("expected 1 person 'alice' in reloaded state, got %+v", reloaded.People)
	}
}

// Gate 3: Broken JSON opens in read-only mode with explicit error and no panic.
func TestState_Gate3_CorruptedFile_BrokenJSON(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, state.StateFileName)

	brokenContent := []byte(`{ "schema": 1, "people": [ { "name": "al`)
	if err := os.WriteFile(stateFile, brokenContent, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	s, err := state.Open(dir)
	if err == nil {
		t.Fatalf("expected CorruptStateError, got nil")
	}
	defer s.Close()

	var corruptErr *state.CorruptStateError
	if !errors.As(err, &corruptErr) {
		t.Fatalf("expected errors.As CorruptStateError, got %T: %v", err, err)
	}

	if !s.IsReadOnly() {
		t.Fatalf("expected store to be in read-only mode")
	}

	// Modifying read-only store must be prohibited
	err = s.Save()
	if !errors.Is(err, state.ErrReadOnly) {
		t.Fatalf("expected ErrReadOnly on Save, got %v", err)
	}

	err = s.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "eve", Role: "user"})
		return nil
	})
	if !errors.Is(err, state.ErrReadOnly) {
		t.Fatalf("expected ErrReadOnly on Update, got %v", err)
	}

	// Verify corrupted file was not overwritten
	onDisk, _ := os.ReadFile(stateFile)
	if string(onDisk) != string(brokenContent) {
		t.Fatalf("corrupted file was overwritten! Content changed to: %s", string(onDisk))
	}
}

// Gate 3: Truncated/empty file opens in read-only mode with explicit error and no panic.
func TestState_Gate3_CorruptedFile_Truncated(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, state.StateFileName)

	if err := os.WriteFile(stateFile, []byte(""), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	s, err := state.Open(dir)
	if err == nil {
		t.Fatalf("expected CorruptStateError on empty file, got nil")
	}
	defer s.Close()

	if !s.IsReadOnly() {
		t.Fatalf("expected store to be in read-only mode")
	}

	var corruptErr *state.CorruptStateError
	if !errors.As(err, &corruptErr) {
		t.Fatalf("expected CorruptStateError, got %T: %v", err, err)
	}
}

// Gate 4: Schema 2 is rejected by schema 1 gateway with clear message.
func TestState_Gate4_Schema_TooNewRejected(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, state.StateFileName)

	schema2JSON := []byte(`{
  "schema": 2,
  "people": [],
  "machines": [],
  "grants": []
}`)
	if err := os.WriteFile(stateFile, schema2JSON, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	s, err := state.Open(dir)
	if s != nil {
		defer s.Close()
		t.Fatalf("Gate 4 failure: file with schema: 2 must NOT open (expected s == nil, got non-nil store)")
	}
	if err == nil {
		t.Fatalf("expected schema error opening schema 2, got nil")
	}

	var schemaErr *state.SchemaError
	if !errors.As(err, &schemaErr) {
		t.Fatalf("expected SchemaError, got %T: %v", err, err)
	}

	if schemaErr.FileSchema != 2 || schemaErr.SupportedSchema != state.CurrentSchema {
		t.Fatalf("unexpected schema error details: file=%d supported=%d", schemaErr.FileSchema, schemaErr.SupportedSchema)
	}

	// Verify message clearly mentions schema 2 and supported version 1
	msg := err.Error()
	if !strings.Contains(msg, "schema version 2") || !strings.Contains(msg, "schema version 1") {
		t.Fatalf("schema error message not descriptive enough: %q", msg)
	}
}

// Gate 4: Forward migration registry framework test. Forward means forward: the
// registry moves an older file up to the current schema and refuses to walk back.
func TestState_Gate4_Schema_MigrationFramework(t *testing.T) {
	migrator := state.NewMigrator()

	// A migration of an older file (schema 0) up to the current schema.
	migrator.Register(0, func(raw []byte) ([]byte, error) {
		var m map[string]interface{}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		m["schema"] = state.CurrentSchema
		return json.Marshal(m)
	})

	rawSchema0 := []byte(`{"schema": 0, "people": []}`)
	migrated, err := migrator.Migrate(rawSchema0, 0, state.CurrentSchema)
	if err != nil {
		t.Fatalf("migration failed: %v", err)
	}

	var res struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(migrated, &res); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if res.Schema != state.CurrentSchema {
		t.Fatalf("expected migrated schema %d, got %d", state.CurrentSchema, res.Schema)
	}

	// Verify unregistered migration fails cleanly
	_, err = migrator.Migrate([]byte(`{"schema": -3}`), -3, state.CurrentSchema)
	if !errors.Is(err, state.ErrMigrationRequired) {
		t.Fatalf("expected ErrMigrationRequired for unregistered schema -3, got %v", err)
	}
}

// Gate 5: Name validation with at least 10 inputs per rule [a-z0-9][a-z0-9._-]{0,31}.
func TestState_Gate5_NameValidation_TenInputs(t *testing.T) {
	testCases := []struct {
		input   string
		valid   bool
		comment string
	}{
		{"", false, "empty string"},
		{strings.Repeat("a", 33), false, "33 characters (exceeds max length 32)"},
		{"Alice", false, "uppercase characters"},
		{"alice smith", false, "contains space"},
		{".alice", false, "starts with dot"},
		{"-alice", false, "starts with hyphen"},
		{"_alice", false, "starts with underscore"},
		{"\u0430\u043b\u0438\u0441\u0430", false, "non-ASCII Cyrillic"},
		{"alice@host", false, "contains forbidden character @"},
		{"alice:machine", false, "contains colon"},
		{"alice/machine", false, "contains slash"},
		{"a", true, "single valid character"},
		{"alice", true, "standard valid username"},
		{"server_01.node-east", true, "valid with dots, hyphens, and underscores"},
		{"007agent", true, "starts with digit"},
		{strings.Repeat("a", 32), true, "exact 32 characters (maximum allowed)"},
	}

	if len(testCases) < 10 {
		t.Fatalf("gate 5 requires minimum 10 inputs, got %d", len(testCases))
	}

	for _, tc := range testCases {
		err := state.ValidateName(tc.input)
		if tc.valid && err != nil {
			t.Errorf("expected %q (%s) to be VALID, but got error: %v", tc.input, tc.comment, err)
		} else if !tc.valid && err == nil {
			t.Errorf("expected %q (%s) to be INVALID, but validation succeeded", tc.input, tc.comment)
		}
	}
}

// Gate 6: Missing field != zero value (Until absent vs Until zero time).
func TestState_Gate6_AbsentVsZeroUntil(t *testing.T) {
	// Case 1: Until field is absent
	jsonAbsent := []byte(`{
  "schema": 1,
  "people": [{"name": "alice", "role": "user", "keys": []}],
  "machines": [{"id": "vm1", "name": "vm1", "state": "verified", "machineKey": "key", "osUser": "admin"}],
  "grants": [
    {
      "person": "alice",
      "machine": "vm1",
      "caps": ["shell"]
    }
  ]
}`)

	var stateAbsent state.State
	if err := json.Unmarshal(jsonAbsent, &stateAbsent); err != nil {
		t.Fatalf("Unmarshal absent failed: %v", err)
	}

	grantAbsent := stateAbsent.Grants[0]
	if grantAbsent.HasUntil() {
		t.Fatalf("expected grant Until to be absent (nil), got %v", grantAbsent.Until)
	}
	if grantAbsent.Until != nil {
		t.Fatalf("expected grant Until pointer to be nil for absent field, got %v", grantAbsent.Until)
	}

	// Case 2: Until field is present with zero time (0001-01-01T00:00:00Z)
	jsonZero := []byte(`{
  "schema": 1,
  "people": [{"name": "alice", "role": "user", "keys": []}],
  "machines": [{"id": "vm1", "name": "vm1", "state": "verified", "machineKey": "key", "osUser": "admin"}],
  "grants": [
    {
      "person": "alice",
      "machine": "vm1",
      "until": "0001-01-01T00:00:00Z",
      "caps": ["shell"]
    }
  ]
}`)

	var stateZero state.State
	if err := json.Unmarshal(jsonZero, &stateZero); err != nil {
		t.Fatalf("Unmarshal zero failed: %v", err)
	}

	grantZero := stateZero.Grants[0]
	if !grantZero.HasUntil() {
		t.Fatalf("expected grant Until to be PRESENT (non-nil)")
	}
	if !grantZero.IsUntilZero() {
		t.Fatalf("expected grant Until to be recognized as zero time")
	}

	// Verify Case 1 and Case 2 are strictly distinct
	if grantAbsent.HasUntil() == grantZero.HasUntil() {
		t.Fatalf("Gate 6 failure: absent Until and zero Until must not evaluate to the same state")
	}

	// Case 3: Until field is present with non-zero valid time
	jsonNonZero := []byte(`{
  "schema": 1,
  "people": [{"name": "alice", "role": "user", "keys": []}],
  "machines": [{"id": "vm1", "name": "vm1", "state": "verified", "machineKey": "key", "osUser": "admin"}],
  "grants": [
    {
      "person": "alice",
      "machine": "vm1",
      "until": "2026-09-12T18:00:00Z",
      "caps": ["shell"]
    }
  ]
}`)

	var stateNonZero state.State
	if err := json.Unmarshal(jsonNonZero, &stateNonZero); err != nil {
		t.Fatalf("Unmarshal non-zero failed: %v", err)
	}

	grantNonZero := stateNonZero.Grants[0]
	if !grantNonZero.HasUntil() || grantNonZero.IsUntilZero() {
		t.Fatalf("expected valid non-zero Until")
	}
}

// Test time requiring timezone (ISO-8601 with zone).
func TestState_Time_RequiresTimeZone(t *testing.T) {
	validTimes := []string{
		"2026-09-12T12:34:56Z",
		"2026-09-12T12:34:56+02:00",
		"2026-09-12T12:34:56-05:00",
		"2026-09-12T12:34:56.789Z",
		"2026-09-12 12:34:56+02:00",
	}

	for _, vt := range validTimes {
		_, err := state.ParseZonedTime(vt)
		if err != nil {
			t.Errorf("expected valid zoned time for %q, got: %v", vt, err)
		}
	}

	invalidTimes := []string{
		"2026-09-12T12:34:56", // missing timezone!
		"2026-09-12",          // missing time
		"12:34:56",            // missing date
		"tomorrow",            // text
		"",                    // empty
		"2026-09-12 12:34:56", // space, no zone
	}

	for _, it := range invalidTimes {
		_, err := state.ParseZonedTime(it)
		if err == nil {
			t.Errorf("expected error for non-zoned/invalid time %q, got nil", it)
		}
	}
}

// Test deadline pairs consistency (idle <= ceiling).
func TestState_DeadlinePairs_Consistency(t *testing.T) {
	t1, _ := state.ParseZonedTime("2026-09-12T14:00:00Z")
	t2, _ := state.ParseZonedTime("2026-09-12T16:00:00Z")

	// Valid: idle (14:00) <= ceiling (16:00)
	if err := state.ValidateDeadlinePair(&t1, &t2); err != nil {
		t.Errorf("expected valid pair, got %v", err)
	}

	// Invalid: idle (16:00) > ceiling (14:00)
	err := state.ValidateDeadlinePair(&t2, &t1)
	if !errors.Is(err, state.ErrInconsistentDeadlines) {
		t.Errorf("expected ErrInconsistentDeadlines for idle > ceiling, got %v", err)
	}

	// State validation with door having inconsistent deadlines
	openTime := zt(t, "2026-09-12T12:00:00Z")
	st := state.NewState()
	m := machineWith("vm1", "vm1", 3)
	m.Door = &state.Door{
		ID:                "door1",
		PubKey:            edPub(4),
		Opened:            openTime,
		Sessions:          intPtr(1),
		ClosesWhenIdle:    &t2, // 16:00
		ClosesAtTheLatest: &t1, // 14:00 -> INCONSISTENT!
	}
	st.Machines = append(st.Machines, m)

	if err := st.Validate(); !errors.Is(err, state.ErrInconsistentDeadlines) {
		t.Errorf("expected state validation error on door inconsistent deadlines, got %v", err)
	}
}

// Test lock file preventing second gateway process.
func TestState_LockFile_SecondProcessPrevented(t *testing.T) {
	dir := t.TempDir()

	s1, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open s1 failed: %v", err)
	}
	defer s1.Close()

	// Second instance attempting to open same directory must be rejected
	s2, err := state.Open(dir)
	if !errors.Is(err, state.ErrLockHeld) {
		if s2 != nil {
			s2.Close()
		}
		t.Fatalf("expected ErrLockHeld for second process, got %v", err)
	}

	// Releasing lock on s1 allows opening s3
	if err := s1.Close(); err != nil {
		t.Fatalf("s1 Close failed: %v", err)
	}

	s3, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open s3 failed after s1 closed: %v", err)
	}
	s3.Close()
}

// Test complete state model serialization, validation, and reload.
func TestState_SaveAndReloadFullModel(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	// Deadlines and the grant horizon are anchored to the current time: the write
	// paths reject a newly assigned deadline that is already in the past, so fixture
	// dates cannot be fixed strings that age into the past while the suite lives.
	// The original ordering opened < idle < ceiling < until is preserved.
	tOpened := zRel(t, -2*time.Hour)
	tUntil := zRel(t, 8*time.Hour)
	tIdle := zRel(t, 1*time.Hour)
	tCeil := zRel(t, 5*time.Hour)

	sshdHostKey := edPub(9)

	err = s.Update(func(st *state.State) error {
		st.People = []state.Person{
			personWith(t, "alice", "admin", 1),
			personWith(t, "bob", "user", 2),
		}

		machine := machineWith("target-01", "target-01", 3)
		machine.SSHDHostKey = &sshdHostKey
		machine.OSUser = `CORP\Administrator`
		machine.Door = &state.Door{
			ID:                "door-101",
			PubKey:            edPub(4),
			Opened:            tOpened,
			Sessions:          intPtr(2),
			ClosesWhenIdle:    &tIdle,
			ClosesAtTheLatest: &tCeil,
		}
		st.Machines = []state.Machine{machine}

		return st.GrantAccess("bob", "target-01", &tUntil, "shell")
	})
	if err != nil {
		t.Fatalf("Update full model failed: %v", err)
	}

	// Close and reload in a new Store
	s.Close()
	s2, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Reopen failed: %v", err)
	}
	defer s2.Close()

	loaded := s2.Get()
	if len(loaded.People) != 2 || len(loaded.Machines) != 1 || len(loaded.Grants) != 1 {
		t.Fatalf("unexpected counts: people=%d machines=%d grants=%d", len(loaded.People), len(loaded.Machines), len(loaded.Grants))
	}

	m := loaded.Machines[0]
	if m.Door == nil || m.Door.ID != "door-101" || m.Door.SessionCount() != 2 {
		t.Fatalf("unexpected door contents: %+v", m.Door)
	}
	if *m.SSHDHostKey != sshdHostKey {
		t.Fatalf("sshdHostKey mismatch: got %v", *m.SSHDHostKey)
	}

	g := loaded.Grants[0]
	if !g.HasUntil() || g.Until.Format(time.RFC3339) != tUntil.Format(time.RFC3339) {
		t.Fatalf("grant until mismatch: got %v", g.Until)
	}
	if g.MachineKeyFingerprint != fpOf(t, loaded.Machines[0].MachineKey) {
		t.Fatalf("grant lost the machine key pin after a save/reload round trip: %+v", g)
	}
}

// Test fingerprint uniqueness check.
func TestState_FingerprintUniqueness(t *testing.T) {
	st := state.NewState()
	now := zt(t, "2026-09-12T12:00:00Z")
	pub := edPub(1)
	fp := fpOf(t, pub)

	st.People = []state.Person{
		{
			Name: "alice",
			Role: "admin",
			Keys: []state.Key{{Fingerprint: fp, Pub: pub, Added: now}},
		},
		{
			Name: "bob",
			Role: "user",
			Keys: []state.Key{{Fingerprint: fp, Pub: pub, Added: now}},
		},
	}

	err := st.Validate()
	if err == nil || !strings.Contains(err.Error(), "duplicate key fingerprint") {
		t.Fatalf("expected duplicate key fingerprint error, got %v", err)
	}
}

// Test machine state validation ("enrolled" | "verified").
func TestState_MachineStateValidation(t *testing.T) {
	st := state.NewState()
	st.Machines = []state.Machine{
		{
			ID:         "vm1",
			Name:       "vm1",
			State:      "invalid_state",
			MachineKey: "key",
			OSUser:     `CORP\admin`,
		},
	}

	err := st.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid state") {
		t.Fatalf("expected invalid state error, got %v", err)
	}
}

// Test concurrent state mutations without race conditions.
func TestState_ConcurrentTransactions(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	const numGoroutines = 8

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			person := personWith(t, fmt.Sprintf("user-%d", idx), "user", byte(idx+1))

			err := s.Update(func(st *state.State) error {
				st.People = append(st.People, person)
				return nil
			})
			if err != nil {
				t.Errorf("goroutine %d update failed: %v", idx, err)
			}
		}(i)
	}

	wg.Wait()

	finalState := s.Get()
	if len(finalState.People) != numGoroutines {
		t.Fatalf("expected %d people, got %d", numGoroutines, len(finalState.People))
	}
}

// Test directory and file permissions (0700 for dir, 0600 for state file) (Defect 6).
//
// §3.5 declares the gateway a Linux service, and on Linux this test asserts the
// modes in full. On Windows the file system does not enforce 0700/0600, so there is
// nothing to assert - and the test says so through the standard skip mechanism
// instead of returning silently: a skip that reports itself as a pass is a permission
// check that stopped being checked without anyone noticing. The skip in the run
// output is the standing reminder that this guarantee is verified by the Linux run,
// which §3.5 makes the run that counts.
func TestState_FilePermissions(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gateway_data")

	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer s.Close()

	stateFile := filepath.Join(dir, state.StateFileName)

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat dir failed: %v", err)
	}
	if !dirInfo.IsDir() {
		t.Fatalf("expected %s to be directory", dir)
	}
	fileInfo, err := os.Stat(stateFile)
	if err != nil {
		t.Fatalf("Stat stateFile failed: %v", err)
	}
	if fileInfo.IsDir() {
		t.Fatalf("expected %s to be file", stateFile)
	}

	if !state.POSIXPermissionsEnforced {
		// Windows: the declared guarantee is weaker, and that is all that may be
		// claimed here. Everything the modes are meant to prevent is verified by the
		// Linux run, which §3.5 makes the run that counts.
		t.Skipf("%s: POSIX modes are not enforced by the file system; "+
			"state.POSIXPermissionsEnforced=false says so in the code. "+
			"0700/0600 are asserted on Linux, the only platform the gateway runs on (§3.5)",
			runtime.GOOS)
	}

	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Fatalf("expected dir permission 0700, got %#o", perm)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0600 {
		t.Fatalf("expected file permission 0600, got %#o", perm)
	}
}

// Test corrupt file with non-integer schema.
func TestState_CorruptedFile_NonIntegerSchema(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, state.StateFileName)

	if err := os.WriteFile(stateFile, []byte(`{"schema": "invalid_string_schema"}`), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("expected CorruptStateError, got nil")
	}
	defer s.Close()

	if !s.IsReadOnly() {
		t.Fatalf("expected read-only mode")
	}
}
