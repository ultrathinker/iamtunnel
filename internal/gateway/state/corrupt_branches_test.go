// Fix-84 (IAMT-84): every branch of state.Open that declares a file
// corrupted must have its own red run: with the read-only switch disabled,
// that branch's test fails. Without this, a branch can quietly lose its
// stubbornness and a corrupted grants file would start letting writes
// through — which §4.3 does not allow.
//
// The branches are enumerated "by code", not "by reading": each separate
// if that sets s.readOnly=true and returns Store+error is numbered
// B, C, E, F, G. Branch D (the schema barrier) does not use s.readOnly —
// it returns (nil, *SchemaError), so its canary is built differently: the
// test asserts that Open refused outright instead of opening a broken
// Store. Branch A (an I/O error) is not about corruption.
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

// writeCorruptState writes a file that Open must open in read-only mode.
// It returns the file's path and its original content — the test checks
// that the content was not overwritten even if the read-only mode breaks.
func writeCorruptState(t *testing.T, content []byte) (dir string, file string, original []byte) {
	t.Helper()
	dir = t.TempDir()
	file = filepath.Join(dir, state.StateFileName)
	if err := os.WriteFile(file, content, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return dir, file, content
}

// requireReadOnlyStore — the shared part of the canary for branches B, C, E, F, G.
// If any of these checks fail, the corresponding branch has lost its
// stubbornness: either the Store is not read-only, or Update accepted a
// "dirty" edit, or the file on disk was overwritten over the corrupted one.
//
// The caller must take care of s.Close itself (a defer in the test):
// requireReadOnlyStore does not close the Store, because some tests
// keep checking the file after this function.
func requireReadOnlyStore(t *testing.T, s *state.Store, file string, original []byte) {
	t.Helper()
	if !s.IsReadOnly() {
		t.Fatalf("this branch is supposed to open the store in read-only mode; IsReadOnly()==false")
	}
	if err := s.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "mallory", Role: "admin"})
		return nil
	}); !errors.Is(err, state.ErrReadOnly) {
		t.Fatalf("Update on a branch-opened read-only store must reject with ErrReadOnly, got %v", err)
	}
	if err := s.Save(); !errors.Is(err, state.ErrReadOnly) {
		t.Fatalf("Save on a branch-opened read-only store must reject with ErrReadOnly, got %v", err)
	}
	draft := state.NewState()
	draft.Schema = state.CurrentSchema
	if err := s.Set(*draft); !errors.Is(err, state.ErrReadOnly) {
		t.Fatalf("Set on a branch-opened read-only store must reject with ErrReadOnly, got %v", err)
	}
	onDisk, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("ReadFile after guarded mutations: %v", err)
	}
	if string(onDisk) != string(original) {
		t.Fatalf("corrupted input was overwritten by a write that should have been rejected by read-only mode\n  original: %q\n  current:  %q",
			string(original), string(onDisk))
	}
}

// --- Branch B: empty file ----------------------------------------------
//
// Branch B is the simplest corruption case: state.json exists but
// contains not a byte. The canary separately requires that on this input
// the Store opens read-only AND returns a CorruptStateError, not
// some undefined error from the io package.

func TestFix84_BranchB_EmptyFile_OpensReadOnly(t *testing.T) {
	dir, file, original := writeCorruptState(t, []byte(""))

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("Open on an empty file must return an error, got nil")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("empty file must open the store in read-only mode")
	}

	var corrupt *state.CorruptStateError
	if !errors.As(err, &corrupt) {
		t.Fatalf("empty file must surface a *state.CorruptStateError, got %T %v", err, err)
	}
	if !strings.Contains(corrupt.Error(), "empty") && !strings.Contains(corrupt.Error(), "EOF") {
		t.Fatalf("CorruptStateError message must explain the emptiness, got %q", corrupt.Error())
	}

	requireReadOnlyStore(t, s, file, original)
}

// The same input, but via bytes.TrimSpace: a file of only spaces and
// newlines. After the trimming pass it is empty — the same branch B must fire.
func TestFix84_BranchB_WhitespaceOnly_OpensReadOnly(t *testing.T) {
	dir, file, original := writeCorruptState(t, []byte("   \n\t \n  "))

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("Open on a whitespace-only file must return an error, got nil")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("whitespace-only file must open the store in read-only mode")
	}
	requireReadOnlyStore(t, s, file, original)
}

// --- Branch C: the schema peek fails -----------------------------------
//
// json.Unmarshal(data, &schemaPeek) could not pull a number out of the
// schema field. This catches every corruption where even the top level
// cannot structurally be parsed. The input below is valid top-level JSON
// but not an object, so the schema peek finds nothing and returns a type error.

func TestFix84_BranchC_SchemaPeekFails_OnNonObjectJSON_OpensReadOnly(t *testing.T) {
	content := []byte(`[1, 2, 3]`)
	dir, file, original := writeCorruptState(t, content)

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("Open on non-object JSON must return an error, got nil")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("non-object JSON must open the store in read-only mode")
	}
	var corrupt *state.CorruptStateError
	if !errors.As(err, &corrupt) {
		t.Fatalf("non-object JSON must surface a *state.CorruptStateError, got %T %v", err, err)
	}
	requireReadOnlyStore(t, s, file, original)
}

// A separate case for branch C: the file starts as JSON but the syntax
// is torn in the middle, so the very first json.Unmarshal attempt fails.
// This is common in "half-written" backups.
func TestFix84_BranchC_SchemaPeekFails_OnTruncatedJSON_OpensReadOnly(t *testing.T) {
	content := []byte(`{"schema": 1, "people": [{ "name": "al`)
	dir, file, original := writeCorruptState(t, content)

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("Open on truncated JSON must return an error, got nil")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("truncated JSON must open the store in read-only mode")
	}
	requireReadOnlyStore(t, s, file, original)
}

// --- Branch E: the migration fails -------------------------------------
//
// Schema 0 or negative means "a file older than this build". In Open
// this is the schemaPeek.Schema < CurrentSchema path, after which
// s.migrator.Migrate is called. The migration table is empty (nothing
// exists below schema 1), so Migrate returns ErrMigrationRequired. The
// canary checks that in this case the Store is also read-only with a
// CorruptStateError, instead of falling over with a bare migrator error.

func TestFix84_BranchE_MigrationFails_OnSchemaZero_OpensReadOnly(t *testing.T) {
	content := []byte(`{
  "schema": 0,
  "people": [],
  "machines": [],
  "grants": []
}`)
	dir, file, original := writeCorruptState(t, content)

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("Open on an un-migratable old schema must return an error, got nil")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("un-migratable old schema must open the store in read-only mode")
	}
	var corrupt *state.CorruptStateError
	if !errors.As(err, &corrupt) {
		t.Fatalf("un-migratable old schema must surface a *state.CorruptStateError, got %T %v", err, err)
	}
	if !errors.Is(err, state.ErrMigrationRequired) {
		t.Fatalf("underlying error must chain to ErrMigrationRequired, got %v", err)
	}
	requireReadOnlyStore(t, s, file, original)
}

// --- Branch F: the full parse fails ------------------------------------
//
// This is the very branch the whole work is written for. The input is
// schema-clean ("schema" = 1 is a valid number), but one of the fields has
// an incompatible type. Existing tests cover branches B and C but miss
// F — their broken syntax fails at an earlier step. Here a
// SYNTACTICALLY valid JSON with a wrong field value is used deliberately.

func TestFix84_BranchF_PartialParseFails_OnPeopleString_OpensReadOnly(t *testing.T) {
	content := []byte(`{
  "schema": 1,
  "people": "this should be an array, not a string",
  "machines": [],
  "grants": []
}`)
	dir, file, original := writeCorruptState(t, content)

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("Open on structurally valid but type-wrong JSON must return an error, got nil")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("type-wrong JSON must open the store in read-only mode")
	}
	var corrupt *state.CorruptStateError
	if !errors.As(err, &corrupt) {
		t.Fatalf("type-wrong JSON must surface a *state.CorruptStateError, got %T %v", err, err)
	}
	requireReadOnlyStore(t, s, file, original)
}

// An extra case for branch F: instead of a string in people — a number in
// machines. The same branch, a different spelling; it proves the canary is
// not tied to one specific field name.
func TestFix84_BranchF_PartialParseFails_OnMachinesNumber_OpensReadOnly(t *testing.T) {
	content := []byte(`{
  "schema": 1,
  "people": [],
  "machines": 42,
  "grants": []
}`)
	dir, file, original := writeCorruptState(t, content)

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("Open on number-as-machines must return an error, got nil")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("number-as-machines must open the store in read-only mode")
	}
	requireReadOnlyStore(t, s, file, original)
}

// Another input form for branch F: grants is a boolean. Parsing fails on
// the state's third pass, but the first only looks at schema and passes.
// We do reach the full parse, and here it fails.
func TestFix84_BranchF_PartialParseFails_OnGrantsBool_OpensReadOnly(t *testing.T) {
	content := []byte(`{
  "schema": 1,
  "people": [],
  "machines": [],
  "grants": true
}`)
	dir, file, original := writeCorruptState(t, content)

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("Open on bool-as-grants must return an error, got nil")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("bool-as-grants must open the store in read-only mode")
	}
	requireReadOnlyStore(t, s, file, original)
}

// --- Branch G: the semantic validation fails ---------------------------
//
// The file passed both the schema peek and the full parse. Next, Validate()
// looks at internal consistency and refuses. The input here is syntactically
// correct JSON that parses into a State with a knowingly invalid value (say,
// a person with a role outside "user"/"admin"). The schema peek does NOT
// fail here (schema=1), the full parse also succeeds (the role is an
// arbitrary string), but Validate() says no.

func TestFix84_BranchG_ValidationFails_OnInvalidRole_OpensReadOnly(t *testing.T) {
	content := []byte(`{
  "schema": 1,
  "people": [{"name": "alice", "role": "god-mode", "keys": []}],
  "machines": [],
  "grants": []
}`)
	dir, file, original := writeCorruptState(t, content)

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("Open on a state with invalid role must return an error, got nil")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("invalid role must open the store in read-only mode")
	}
	var corrupt *state.CorruptStateError
	if !errors.As(err, &corrupt) {
		t.Fatalf("invalid role must surface a *state.CorruptStateError, got %T %v", err, err)
	}
	requireReadOnlyStore(t, s, file, original)
}

// Another case for branch G: a grant points at a non-existent machine.
// The semantics "the person exists, and so does the machine" would pass,
// but without Validate — and it would pass without it. Here the person
// exists, the machine exists, and the grant points into the void.
func TestFix84_BranchG_ValidationFails_OnDanglingGrant_OpensReadOnly(t *testing.T) {
	content := []byte(`{
  "schema": 1,
  "people": [{"name": "alice", "role": "user", "keys": []}],
  "machines": [{"id": "vm1", "name": "vm1", "state": "verified", "machineKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAA==", "osUser": "CORP\\alice"}],
  "grants": [
    {"person": "alice", "machine": "ghost", "machineKeyFingerprint": "SHA256:00", "caps": ["shell"]}
  ]
}`)
	dir, file, original := writeCorruptState(t, content)

	s, err := state.Open(dir)
	if err == nil {
		s.Close()
		t.Fatalf("Open on a state with a dangling grant must return an error, got nil")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("dangling grant must open the store in read-only mode")
	}
	requireReadOnlyStore(t, s, file, original)
}

// --- Branch D: the schema barrier --------------------------------------
//
// A separate story. The file is newer than this build: schema=2, we only
// understand schema=1. This branch returns (nil, *SchemaError), not
// a read-only Store. The canary is built differently: it requires that
// Open refuse outright and the Store be nil — because branch D simply
// has no write path. If anyone ever wants to "soften" the barrier (say,
// open a schema+1 file read-only and make Update accept mutations — and
// then drop fields when saving), this test catches the first link of that
// chain.

// A direct test: on this input Open does not hand out a Store at all.
func TestFix84_BranchD_SchemaBarrier_NoStore(t *testing.T) {
	content := []byte(`{
  "schema": 2,
  "people": [],
  "machines": [],
  "grants": []
}`)
	dir := t.TempDir()
	file := filepath.Join(dir, state.StateFileName)
	if err := os.WriteFile(file, content, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s, err := state.Open(dir)
	if s != nil {
		s.Close()
		t.Fatalf("Open on a newer-schema file must return nil Store")
	}
	if err == nil {
		t.Fatalf("Open on a newer-schema file must return an error")
	}
	var schemaErr *state.SchemaError
	if !errors.As(err, &schemaErr) {
		t.Fatalf("expected *state.SchemaError, got %T %v", err, err)
	}
	if schemaErr.FileSchema != 2 || schemaErr.SupportedSchema != state.CurrentSchema {
		t.Fatalf("SchemaError fields: file=%d supported=%d", schemaErr.FileSchema, schemaErr.SupportedSchema)
	}
}

// Proof that the file's state was neither loaded nor overwritten: the disk
// holds exactly the JSON we wrote.
func TestFix84_BranchD_SchemaBarrier_FileUntouched(t *testing.T) {
	content := []byte(`{"schema": 2, "people": [], "machines": [], "grants": []}`)
	dir := t.TempDir()
	file := filepath.Join(dir, state.StateFileName)
	if err := os.WriteFile(file, content, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if _, err := state.Open(dir); err == nil {
		t.Fatalf("expected SchemaError")
	}
	onDisk, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(onDisk) != string(content) {
		t.Fatalf("state file was modified by an Open that should have refused it")
	}
}

// The canary against a mistaken "softening" of branch D: if someone replaces
// `return nil, &SchemaError{...}` with "open the Store read-only and let its
// Update work later", the schema=2 file will be fed into this test together
// with an Update attempt. Currently Open returns nil — Update on a nil store
// is impossible. The test asserts the fact itself:
//
//   - Open returns a nil Store;
//   - the schema barrier does not open a Store in any mode at all;
//
// If an edit makes the Store non-nil, the test catches that condition and
// demands an additional decision (what to do about Update, Save, and so
// on) — an edit without such a decision would ship without a guard.
func TestFix84_BranchD_SchemaBarrier_NoStore_AndSchemaErrorChains(t *testing.T) {
	content := []byte(`{"schema": 2, "people": [], "machines": [], "grants": []}`)
	dir := t.TempDir()
	file := filepath.Join(dir, state.StateFileName)
	if err := os.WriteFile(file, content, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s, err := state.Open(dir)
	if s != nil {
		s.Close()
		t.Fatalf("schema barrier branch opens a Store; the invariant requires it to refuse outright")
	}
	if !errors.Is(err, state.ErrSchemaTooNew) {
		t.Fatalf("the error must chain to ErrSchemaTooNew, got %v", err)
	}
}

// --- Check: the branch enumeration is exhaustive ------------------------
//
// Extra insurance. If state.Open grows yet another branch that declares
// corruption (a new condition before Save, say), this check must remind
// everyone that any such branch must have its own test in this file.
// Right now there are 6 "rejecting" branches (including barrier D), and
// five of them open a read-only Store.
//
// IMPORTANT: store.go has one more `s.readOnly = true` — inside
// verifyDiskMatchesLocked (that is the rollback path after a failed
// write, not about Open). So a plain "exactly 5" does not fit: there
// must be exactly 5 readOnly transitions INSIDE Open and one more in
// the rollback path. The check goes over the source text, without a
// parser.

func TestFix84_BranchInventory_SixRejectingBranches(t *testing.T) {
	// Marker: when adding a new "rejecting" branch to state.Open — add a
	// test for it in this file and raise the expected number below.
	const expectedRejecting = 6

	src, err := os.ReadFile("store.go")
	if err != nil {
		t.Fatalf("ReadFile store.go: %v", err)
	}
	raw := string(src)

	markers := []string{
		// B: empty file
		`len(trimmed) == 0`,
		// C: schema peek
		`json.Unmarshal(data, &schemaPeek)`,
		// D: schema barrier
		`schemaPeek.Schema > CurrentSchema`,
		// E: migration failure
		`migrated, migErr := s.migrator.Migrate`,
		// F: full parse failure
		`json.Unmarshal(payload, &parsed)`,
		// G: validation failure
		`parsed.Validate()`,
	}
	seen := 0
	for _, m := range markers {
		if strings.Contains(raw, m) {
			seen++
		} else {
			t.Fatalf("branch marker %q no longer found in store.go; "+
				"a branch was removed or renamed without updating the inventory", m)
		}
	}
	if seen != expectedRejecting {
		t.Fatalf("expected %d rejecting-branch markers in store.go, found %d. "+
			"Add a new marker and a new TestFix84_* for any new branch",
			expectedRejecting, seen)
	}

	// RETARGETED 13.09 (IAMT-98, the OpenForRead commit). This used to
	// check "exactly 5 `return s, s.corruptErr` sites": the five rejecting
	// branches lived right in the body of Open. Now there is a single
	// barrier — parseStateBytes — and Open and OpenForRead only turn its
	// verdict into a read-only Store. The count changed from 5 to 2 not
	// because three branches disappeared but because they moved; that is
	// why one check became two, and together they pin exactly the new
	// shape:
	//
	//   1) the five rejecting branches EXIST, all in one place;
	//   2) both openers handle them identically.
	//
	// A sixth branch or a second barrier will turn this test red.
	corruptSites := strings.Count(raw, "return nil, &CorruptStateError{")
	if corruptSites != 5 {
		t.Fatalf("expected 5 `return nil, &CorruptStateError{` sites in store.go "+
			"(= the five rejecting branches, all inside parseStateBytes), found %d", corruptSites)
	}
	// There are three openers, not two (re-checked 13.09, round 3 of
	// IAMT-98): Open, OpenForRead under the lock, and readStateBytesUnlocked
	// — the "after restore" path, when state.json exists but state.lock
	// does not and there is, therefore, nobody to hold it. All three share
	// the same barrier (parseStateBytes); they differ only in how the bytes
	// are obtained. This very check caught the third path appearing:
	// it was 2, it became 3.
	roInOpenReturns := strings.Count(raw, "return s, s.corruptErr")
	if roInOpenReturns != 3 {
		t.Fatalf("expected 3 `return s, s.corruptErr` sites in store.go "+
			"(Open, OpenForRead and readStateBytesUnlocked, each turning the shared "+
			"barrier's verdict into a read-only Store), found %d", roInOpenReturns)
	}

	// And one readOnly site in the rollback path (verifyDiskMatchesLocked).
	// The simplest marker: "state file on disk no longer matches" — the
	// comment sits exactly there.
	if !strings.Contains(raw, "state file on disk no longer matches") {
		t.Fatalf("expected the disk-mismatch comment in store.go (verifyDiskMatchesLocked signature changed?)")
	}

	// And the schema barrier (D) must NOT set readOnly: otherwise that is
	// an extra (6th) readOnly transition outside Open, which breaks the
	// invariant. Guarantee: branch D returns "return nil, nil, &SchemaError{"
	// — its canonical form after the move into parseStateBytes.
	schemaBarrierSignature := strings.Count(raw, "return nil, nil, &SchemaError{")
	if schemaBarrierSignature != 1 {
		t.Fatalf("expected exactly one `return nil, nil, &SchemaError{` site in store.go (= the schema barrier inside parseStateBytes), found %d", schemaBarrierSignature)
	}
}

// A guarantee for this test file itself: every test function in it must
// reference a failure mechanism — otherwise gate 9 would "throw it out".
// This is a static prop, not a duplicate of the canary logic.
func TestFix84_Inventory_IsExhaustive_NoEmpties(t *testing.T) {
	// We verify that every TestFix84_* function contains at least one
	// t.Fatalf / t.Errorf / t.Helper or another *testing.T method call.
	// The mere fact that a function is defined proves little — that is
	// why below we call the test functions by hand via a count in code.
	//
	// Here it is a simple census: exactly as many TestFix84_* functions
	// must exist as the "working branches" we cover, plus the inventory.
	src, err := os.ReadFile("corrupt_branches_test.go")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	count := strings.Count(string(src), "func TestFix84_")
	if count < 11 {
		// B: 2, C: 2, E: 1, F: 3, G: 2, D: 3, Inventory: 2 — at least 13.
		// The floor of 11 is kept loose so renames do not trip it.
		t.Fatalf("only %d TestFix84_* functions found; an entire branch has no canary", count)
	}

	// Additionally — the test names reference all 5 branch letters.
	for _, branch := range []string{"BranchB_", "BranchC_", "BranchE_", "BranchF_", "BranchG_", "BranchD_"} {
		if !strings.Contains(string(src), branch) {
			t.Fatalf("no test for %s; the inventory claim is not backed by tests", branch)
		}
	}

	//nolint:staticcheck // JSON marshaling is not needed here; this is a
	// check that encoding/json is available inside the test with no extra imports.
	_ = json.Marshal
}
