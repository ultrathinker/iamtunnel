package state_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// FINDING IAMT-351-1 (REVIEW.md): the IAMT-351 fix narrowed the LOAD contract
// of state.json. Before the fix the validator accepted any non-empty caps list
// whose every element was "shell" (including ["shell","shell"] and longer);
// the new one required exactly one element, "shell" or "exec". A file the old
// gateway loaded, the new one refused to open — and that is not "one lost
// grant" but a start-up refusal: Validate runs on every store open.
//
// No production writer ever created such a file in any version (the
// write-time gates — acl.validateGrant and cmdGrantsGrant — required exactly
// ["shell"] from the very first commit), so the practical probability is low;
// the known way to end up with such a file is a manual state.json recovery,
// a scenario the RUNBOOK describes explicitly.
//
// The finding was closed by normalising AT LOAD (state.applyGrantCapsCompat):
// strict on write, tolerant on read. Writing still accepts exactly
// one element.
//
// The test deliberately goes through a REAL store open rather than calling
// Validate directly: the finding itself reads "the gateway will not start",
// and starting goes through this path. A test calling Validate directly
// would exercise the wrong seam and stay red even after a correct fix.
func TestIAMT351F1_LoaderStillAcceptsPre351DuplicatedShellCaps(t *testing.T) {
	for _, caps := range [][]string{{"shell", "shell"}, {"shell", "shell", "shell"}} {
		dir := t.TempDir()
		writeStateWithGrantCaps(t, dir, caps)

		st, err := state.OpenForRead(dir)
		if err != nil {
			t.Fatalf("caps %v: a state.json that opened before IAMT-351 no longer opens: %v", caps, err)
		}
		got := st.Get().Grants[0].Caps
		if len(got) != 1 || got[0] != "shell" {
			t.Fatalf("caps %v: after loading expected a normalised [\"shell\"], got %v — the value reached the ACL in a form it will reject", caps, got)
		}
	}
}

// TestIAMT351F1_UnknownCapIsStillRefusedOnLoad: tolerance for FORM must not
// become tolerance for MEANING. An unknown capability must keep being
// refused — otherwise normalisation would become a hole.
func TestIAMT351F1_UnknownCapIsStillRefusedOnLoad(t *testing.T) {
	for _, caps := range [][]string{{"ports"}, {"shell", "ports"}, {}} {
		dir := t.TempDir()
		writeStateWithGrantCaps(t, dir, caps)

		if _, err := state.OpenForRead(dir); err == nil {
			t.Fatalf("caps %v: the store opened but must have refused — form normalisation has no right to let an unknown capability through", caps)
		}
	}
}

// writeStateWithGrantCaps writes a valid state.json into dir with the
// single grant's caps replaced.
func writeStateWithGrantCaps(t *testing.T, dir string, caps []string) {
	t.Helper()

	st := baseState(t)
	st.Grants[0].Caps = append([]string(nil), caps...)

	raw, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal state: %v", err)
	}
	// json.Marshal writes a nil slice as null; the empty list is needed literally.
	if len(caps) == 0 {
		raw = []byte(strings.Replace(string(raw), `"caps":null`, `"caps":[]`, 1))
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o600); err != nil {
		t.Fatalf("write state.json: %v", err)
	}
}
