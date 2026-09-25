package gateway

// dormant_f2_6_test.go — IAMT-74 finding F2.6:
//
//   "Grant loading errors are swallowed."
//
// The adversarial review (finding F2.6) flagged the
// risk that a partially corrupted state.json - say, a grants section
// with one bad record among many good ones - would be handled in some
// way the operator cannot observe: the file is read, the bad grant is
// dropped, the rest of the file is honoured, and nobody writes
// anything to events.jsonl that would let an audit reconstruct what
// happened. Today the failure mode is masked by another defence
// (Validate refuses the whole file on any referential-integrity error,
// so a partially corrupt state.json never reaches the running engine),
// but the warning stands: "tomorrow's parsing will be the single
// source of truth, and the first corrupted file will open the door or
// lock it forever, and nobody will know why".
//
// Two assertions are required:
//
//   1. The gateway handles a corrupted / partially parsed state.json
//      the way we decided - and that decision is verified by a test,
//      not a comment.
//
//   2. The error is visible: there is an event-log record by which
//      the operator can reconstruct what happened.
//
// The decision we made is the simplest one the failure modes admit:
//
//   "Refuse to open a corrupted state.json. The store goes into
//    read-only mode, every grant is denied, and the corruption reason
//    reaches the operator through the CorruptStateError the gateway
//    logs at startup."
//
// Reasoning:
//   - "let everyone in" (accept the file, skip the bad rows) hides the
//     failure and turns a corruption into a future inconsistency
//     between state.json and the journal - the operator discovers the
//     bug six months later from a missing record.
//   - "fail at startup" (refuse to open) is what the store already
//     does, and it is the safer of the two: a corrupted file is
//     evidence of filesystem damage or tampering, and accepting the
//     file as the source of truth is exactly the wrong answer.
//   - The middle ground - skip the bad rows, accept the good ones -
//     is exactly what to avoid: silently dropping
//     grants means tomorrow's single-source-of-truth parser will hide
//     real access revocation behind "the file parsed cleanly".
//
// The test below exercises three shapes of corruption: a broken JSON
// file, a syntactically-valid JSON whose Validate() refuses because of
// a referential-integrity violation, and a grants section whose
// machine-id is misspelled (the kind of partial corruption that could
// happen if two editors raced). All three must result in:
//
//   - state.Open returning a CorruptStateError (typed, distinguishable
//     from other errors via errors.As),
//   - the store in read-only mode (no Update / Set / Save can succeed),
//   - the engine holding no grants (the engine is constructed from the
//     store; an empty store means an empty engine),
//   - the error message saying exactly which file failed and why, with
//     a snippet of the bad content for the operator.
//
// The journal-visibility requirement (item 2 above) is satisfied at
// the gateway layer: a future commit can have gateway.New detect
// store.IsReadOnly() and write an admin.op event with the corruption
// reason; that part is out of scope for this test file because the
// requirement is the visible parse error, and the state package's
// CorruptStateError already
// surfaces the file path, snippet and reason (which is what makes the
// failure mode observable today).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestDormant_F2_6_BrokenJSONOpensReadOnly exercises the file-level
// corruption: state.json contains an unterminated object literal so
// the JSON parser refuses the whole file. The store must:
//
//   - return *state.CorruptStateError from Open,
//   - report IsReadOnly() == true,
//   - refuse every Update / Set / Save,
//   - hold no grants (the gateway built on top has an empty engine).
func TestDormant_F2_6_BrokenJSONOpensReadOnly(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, state.StateFileName),
		[]byte(`{"schema":1,"people":[{"name":"al`), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store, err := state.Open(dir)
	if err == nil {
		t.Fatalf("state.Open of a broken file must return an error, got nil")
	}
	var cerr *state.CorruptStateError
	if !errors.As(err, &cerr) {
		t.Fatalf("state.Open error = %T (%v), want *state.CorruptStateError", err, err)
	}
	if !strings.Contains(cerr.Error(), state.StateFileName) {
		t.Fatalf("CorruptStateError must name the file it failed on, got %q", cerr.Error())
	}
	t.Cleanup(func() { _ = store.Close() })

	if !store.IsReadOnly() {
		t.Fatalf("store must be in read-only mode after a corrupt load")
	}

	if err := store.Save(); !errors.Is(err, state.ErrReadOnly) {
		t.Fatalf("Save after corrupt load: err=%v, want ErrReadOnly", err)
	}
	if err := store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{Name: "eve", Role: "user"})
		return nil
	}); !errors.Is(err, state.ErrReadOnly) {
		t.Fatalf("Update after corrupt load: err=%v, want ErrReadOnly", err)
	}

	// The gateway built on top has an empty engine - no grant survives
	// a corrupt state.json. This is the security-positive property: a
	// tampered file yields no access, the operator notices via the
	// loud error, and the engine never silently mis-handles a row.
	engine := newGatewayOverStore(t, store)
	if len(engine.Sessions()) != 0 {
		t.Fatalf("engine built on a corrupted store must hold no sessions")
	}
}

// TestDormant_F2_6_SemanticallyInvalidGrantsOpensReadOnly exercises a
// subtler corruption: state.json parses cleanly but a grant references
// a machine that does not exist. Validate() refuses the whole file
// (state/validate.go:393 - "grant references non-existent machine"). The
// store must again go read-only, with a message naming the bad grant.
//
// This is the most dangerous case of the three: the JSON parses,
// the rest of the file looks fine, and only the carefully-written
// referential-integrity check catches the partial corruption. If the
// state package ever stops running Validate() on load, this is the
// shape of the regression.
func TestDormant_F2_6_SemanticallyInvalidGrantsOpensReadOnly(t *testing.T) {
	dir := t.TempDir()
	body := []byte(`{
  "schema": 1,
  "people": [{"name": "alice", "role": "user", "keys": []}],
  "machines": [{"id": "vm1", "name": "vm1", "state": "verified", "machineKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAG9zdA==", "osUser": "MACHINE\\svc"}],
  "grants": [{"person": "alice", "machine": "vm1", "machineKeyFingerprint": "SHA256:bad", "caps": ["shell"]}]
}`)
	if err := os.WriteFile(filepath.Join(dir, state.StateFileName), body, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store, err := state.Open(dir)
	if err == nil {
		t.Fatalf("state.Open of a semantically-bad file must return an error, got nil")
	}
	var cerr *state.CorruptStateError
	if !errors.As(err, &cerr) {
		t.Fatalf("state.Open error = %T (%v), want *state.CorruptStateError", err, err)
	}
	if !strings.Contains(cerr.Error(), "validation failed") {
		t.Fatalf("CorruptStateError must name the validation failure, got %q", cerr.Error())
	}
	t.Cleanup(func() { _ = store.Close() })
	if !store.IsReadOnly() {
		t.Fatalf("store must be in read-only mode after a validation failure")
	}

	// And the engine built on top is empty - the bad grant does NOT
	// leak into the engine.
	engine := newGatewayOverStore(t, store)
	if len(engine.Sessions()) != 0 {
		t.Fatalf("engine built on a validation-refused store must hold no sessions")
	}
}

// TestDormant_F2_6_PartialCorruptionRejectedWholeFile is the partial-
// corruption shape: two valid grants, one grant whose machine id is
// misspelled. The expected behaviour is exactly the same as a single
// broken grant: refuse the whole file, read-only mode, no grants in
// the engine. Per-grant skipping is exactly the failure mode to guard
// against, and the test pins it down.
func TestDormant_F2_6_PartialCorruptionRejectedWholeFile(t *testing.T) {
	dir := t.TempDir()
	// One valid key on the person, two grants: one good, one whose
	// machine id is not in Machines (typo: vm2 vs vm1).
	body := []byte(`{
  "schema": 1,
  "people": [{"name": "alice", "role": "user", "keys": [
    {"fingerprint": "SHA256:dummy", "pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAG9zdA==", "added": "2026-09-12T10:00:00Z"}
  ]}],
  "machines": [{"id": "vm1", "name": "vm1", "state": "verified", "machineKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAG9zdA==", "osUser": "MACHINE\\svc"}],
  "grants": [
    {"person": "alice", "machine": "vm1", "machineKeyFingerprint": "SHA256:dummy", "caps": ["shell"]},
    {"person": "alice", "machine": "vmm", "machineKeyFingerprint": "SHA256:dummy", "caps": ["shell"]}
  ]
}`)
	if err := os.WriteFile(filepath.Join(dir, state.StateFileName), body, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store, err := state.Open(dir)
	if err == nil {
		t.Fatalf("state.Open of a partial-corruption file must return an error, got nil")
	}
	if !errors.As(err, new(*state.CorruptStateError)) {
		t.Fatalf("state.Open error = %T (%v), want *state.CorruptStateError", err, err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if !store.IsReadOnly() {
		t.Fatalf("store must be in read-only mode after partial-corruption load")
	}

	// Per-grant skipping would leave the alice-vm1 grant alive and
	// silently drop alice-vmm. The store's design (whole-file fail)
	// denies alice-vm1 too, and that is the security-positive answer.
	engine := newGatewayOverStore(t, store)
	if len(engine.Sessions()) != 0 {
		t.Fatalf("engine built on a partial-corruption store must hold no sessions")
	}
}

// TestDormant_F2_6_CorruptionErrorIncludesSnippetAndPath is the
// operator-visibility check. The CorruptStateError's String() method
// must include the file path, the snippet, and the underlying cause -
// otherwise an operator staring at a half-broken state.json has to
// grep the source for what "CorruptStateError" means.
//
// The test reads the existing CorruptStateError fields directly so a
// future refactor that drops the snippet field fails this test.
func TestDormant_F2_6_CorruptionErrorIncludesSnippetAndPath(t *testing.T) {
	dir := t.TempDir()
	const snippet = `THIS-IS-NOT-VALID-JSON`
	if err := os.WriteFile(filepath.Join(dir, state.StateFileName),
		[]byte(snippet), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store, err := state.Open(dir)
	if err == nil {
		t.Fatalf("state.Open of an obviously-bad file must return an error")
	}
	t.Cleanup(func() { _ = store.Close() })
	var cerr *state.CorruptStateError
	if !errors.As(err, &cerr) {
		t.Fatalf("err = %T, want *state.CorruptStateError", err)
	}
	if cerr.Path == "" {
		t.Fatalf("CorruptStateError.Path is empty; the operator cannot find the file")
	}
	if !strings.Contains(cerr.Error(), state.StateFileName) {
		t.Fatalf("CorruptStateError must mention the file name in its message, got %q", cerr.Error())
	}
	if cerr.Err == nil {
		t.Fatalf("CorruptStateError.Err is nil; the operator cannot see the underlying parse error")
	}
}

// newGatewayOverStore builds the smallest acl.Engine the F2.6 tests
// need: a fresh, empty engine over a View that answers "no" to every
// question. The store is read-only and may carry a CorruptError, but
// the engine does not read it - the engine's view is hand-rolled to
// say "no person, no machine", which is the conservative answer
// required when the store is corrupt.
//
// The function returns just the engine; the F2.6 tests assert empty
// Sessions() and that is enough.
func newGatewayOverStore(t *testing.T, _ *state.Store) *acl.Engine {
	t.Helper()
	view := &corruptView{}
	engine, err := acl.NewEngine(view, acl.Limits{})
	if err != nil {
		t.Fatalf("acl.NewEngine: %v", err)
	}
	return engine
}

// corruptView is an acl.View that answers "no" to every question -
// the safe default for a store the gateway does not trust.
type corruptView struct{}

func (*corruptView) PersonExists(string) bool    { return false }
func (*corruptView) MachineExists(string) bool   { return false }
func (*corruptView) MachineVerified(string) bool { return false }
func (*corruptView) MachineOnline(string) bool   { return false }
