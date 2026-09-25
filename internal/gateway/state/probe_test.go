package state_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// A state.json written by something other than this code - a restored backup,
// a half-applied migration, an operator with an editor - can name a grant that
// is pinned to a key the machine no longer presents. Every write path strips
// such a grant before validation ever sees it, so the check that catches it on
// load was held by no test: switching it off left the whole suite green.
// Without it the gateway would trust a grant issued against hardware that has
// since been replaced.
func TestOrchProbe_StaleGrantPinOnLoadIsRefused(t *testing.T) {
	dir := t.TempDir()
	st := baseState(t)

	// The machine quietly gets a different key; the grant keeps the old pin.
	st.Machines[0].MachineKey = edPub(9)

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
		t.Fatalf("Open accepted a grant pinned to a key the machine no longer presents")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("store must be read-only after refusing such a file")
	}
}

// The mirror case: a grant that pins nothing at all. Same reasoning, same gap.
func TestOrchProbe_UnpinnedGrantOnLoadIsRefused(t *testing.T) {
	dir := t.TempDir()
	st := baseState(t)
	st.Grants[0].MachineKeyFingerprint = ""

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
		t.Fatalf("Open accepted a grant that pins no machine key at all")
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("store must be read-only after refusing such a file")
	}
}
