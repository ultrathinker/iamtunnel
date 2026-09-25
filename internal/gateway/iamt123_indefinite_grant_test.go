package gateway

// iamt123_indefinite_grant_test.go — IAMT-123:
//
//   "An indefinite permission prints as a lie".
//
// Two surfaces lie about an indefinite grant:
//
//   1. The CLI printers in cmd/iamtunnel/admin_exec.go: when the gateway
//      returns an empty Until for the wire-string form, the CLI printed
//      "granted ... until ." and "alice -> win01 until " with a trailing
//      dot/space that a tired administrator cannot tell apart from a
//      typo. The fix substitutes the word "indefinite" for the empty
//      deadline so the line is unambiguous. (Covered by inspection of
//      the patch in the report; the printers are pure string formatters
//      with no easy end-to-end seam, and rewriting them as a unit
//      requires extracting them out of the file, which would violate
//      "minimal change".)
//
//   2. The JSON wire field grantView.Until was emitted as "" (an empty
//      string). A machine reader cannot tell "" apart from a misparsed
//      RFC 3339 instant; SPEC §4.3 (line 276) explicitly requires
//      "absence != zero time". The fix flips grantView.Until to *string
//      with `omitempty` so the field is omitted on the wire when the
//      grant has no deadline.
//
// These tests pin the wire-shape half end to end: a real fixture, a
// real dialAdmin, a real Exec over the SSH wire, and a byte-level
// inspection of the response. A regression in the JSON shape flips
// the test red.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestIAMT123_IndefiniteGrant_OmittedFromJSON drives grants.grant over
// the wire with an empty until (the protocol value that means
// "indefinite") and asserts the response has NO "until" key at all.
//
// Canary:
//
//	In internal/gateway/admin_role.go, change grantView.Until back to
//	`string` (drop the pointer / `omitempty`).
//	The test then sees `"until":""` in the response and fails.
func TestIAMT123_IndefiniteGrant_OmittedFromJSON(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// newFixture (harness_test.go:658) already seeds alice -> vm1 with a
	// deadline; revoke it first so this test's own indefinite grant on the
	// same pair isn't blocked by E_CONFLICT.
	if _, err := root.GrantsRevoke(f.person, f.machineID); err != nil {
		t.Fatalf("test setup error: revoke fixture's timed grant %s -> %s: %v", f.person, f.machineID, err)
	}

	raw, err := root.Exec("grants.grant", map[string]any{
		"proto":   1,
		"person":  f.person,
		"machine": f.machineID,
		"until":   "",
		"caps":    []string{"shell"},
	})
	if err != nil {
		t.Fatalf("test setup error: grants.grant (indefinite) for %s -> %s: %v", f.person, f.machineID, err)
	}

	var env struct {
		Grant map[string]json.RawMessage `json:"grant"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("response envelope: %v\nraw: %s", err, raw)
	}
	if _, present := env.Grant["until"]; present {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, raw, "", "  ")
		t.Fatalf("grants.grant for an indefinite grant emitted the \"until\" key on the wire; want the key to be OMITTED entirely per SPEC §4.3 (line 276: \"absence != zero time\").\nresponse:\n%s", pretty.String())
	}
	for _, key := range []string{"person", "machine", "caps"} {
		if _, present := env.Grant[key]; !present {
			t.Fatalf("grants.grant response lost the %q key alongside the indefinite-until omission; raw: %s", key, raw)
		}
	}
}

// TestIAMT123_TimedGrant_UntilFieldIsPresent is the canary's mirror:
// the SAME wire path with a real RFC 3339 deadline MUST include the
// until key, so the omission is conditional on "no deadline", not a
// blanket strip.
//
// Canary:
//
//	In internal/gateway/admin_role.go cmdGrantsGrant, force
//	`untilView = nil` unconditionally. The previous test still passes
//	and THIS test fails — the deadline-carrying case has been silently
//	stripped too.
func TestIAMT123_TimedGrant_UntilFieldIsPresent(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// newFixture (harness_test.go:658) already seeds alice -> vm1 with a
	// deadline; revoke it first so this test can issue its own timed grant
	// on the same pair without E_CONFLICT.
	if _, err := root.GrantsRevoke(f.person, f.machineID); err != nil {
		t.Fatalf("test setup error: revoke fixture's timed grant %s -> %s: %v", f.person, f.machineID, err)
	}

	until := futureRFC3339(f)
	raw, err := root.Exec("grants.grant", map[string]any{
		"proto":   1,
		"person":  f.person,
		"machine": f.machineID,
		"until":   until,
		"caps":    []string{"shell"},
	})
	if err != nil {
		t.Fatalf("test setup error: grants.grant (timed) for %s -> %s: %v", f.person, f.machineID, err)
	}

	var env struct {
		Grant map[string]json.RawMessage `json:"grant"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("response envelope: %v\nraw: %s", err, raw)
	}
	v, present := env.Grant["until"]
	if !present {
		t.Fatalf("grants.grant for a TIMED grant omitted the \"until\" key on the wire; want the deadline present.\nraw: %s", raw)
	}
	var got string
	if err := json.Unmarshal(v, &got); err != nil {
		t.Fatalf("grant.until is not a JSON string: %v", err)
	}
	if got != until {
		t.Fatalf("grant.until = %q, want %q (caller's exact RFC 3339 form)", got, until)
	}
}

// TestIAMT123_GrantsList_OmitsUntilForIndefiniteGrant seeds one timed
// and one indefinite grant, asks grants.list for them, and asserts the
// indefinite row has no "until" key while the timed row carries the
// RFC 3339 string verbatim.
//
// Canary:
//
//	In internal/gateway/admin_role.go cmdGrantsList, drop the
//	pointer-to-string dance and unconditionally set `until = ""` for
//	the indefinite row. The indefinite row then re-emits `"until":""`
//	and THIS test fails on that one entry.
func TestIAMT123_GrantsList_OmitsUntilForIndefiniteGrant(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// newFixture (harness_test.go:658) already seeds alice -> vm1 with a
	// deadline; revoke it first so this test can seed its own timed grant
	// on the same pair without E_CONFLICT.
	if _, err := root.GrantsRevoke(f.person, f.machineID); err != nil {
		t.Fatalf("test setup error: revoke fixture's timed grant %s -> %s: %v", f.person, f.machineID, err)
	}

	untilTimed := futureRFC3339(f)
	if _, err := root.GrantsGrant(f.person, f.machineID, untilTimed); err != nil {
		t.Fatalf("test setup error: grants.grant (timed) for %s -> %s: %v", f.person, f.machineID, err)
	}
	machine2Signer := genSigner(t)
	if err := f.store.Update(func(st *state.State) error {
		st.Machines = append(st.Machines, state.Machine{
			ID: "vm-indef", Name: "vm-indef", State: "verified",
			MachineKey: authorizedLine(machine2Signer.PublicKey()),
			OSUser:     `MACHINE\svc`,
		})
		return nil
	}); err != nil {
		t.Fatalf("test setup error: seed machine vm-indef: %v", err)
	}
	if _, err := root.GrantsGrant(f.person, "vm-indef", ""); err != nil {
		t.Fatalf("test setup error: grants.grant (indefinite) for %s -> vm-indef: %v", f.person, err)
	}

	raw, err := root.Exec("grants.list", map[string]any{"proto": 1})
	if err != nil {
		t.Fatalf("test setup error: grants.list: %v", err)
	}

	var env struct {
		Grants []map[string]json.RawMessage `json:"grants"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("response envelope: %v\nraw: %s", err, raw)
	}
	if len(env.Grants) < 2 {
		t.Fatalf("test setup error: grants.list returned %d grants, want at least 2 (one seeded timed, one seeded indefinite):\n%s", len(env.Grants), raw)
	}

	var timedRow, indefRow map[string]json.RawMessage
	for _, g := range env.Grants {
		var machine string
		_ = json.Unmarshal(g["machine"], &machine)
		switch machine {
		case f.machineID:
			timedRow = g
		case "vm-indef":
			indefRow = g
		}
	}
	if timedRow == nil {
		t.Fatalf("test setup error: grants.list omitted the seeded timed grant on %s; raw:\n%s", f.machineID, raw)
	}
	if indefRow == nil {
		t.Fatalf("test setup error: grants.list omitted the seeded indefinite grant on vm-indef; raw:\n%s", raw)
	}

	if _, present := indefRow["until"]; present {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, raw, "", "  ")
		t.Fatalf("grants.list emitted \"until\" for an indefinite grant; want the key to be OMITTED (SPEC §4.3 line 276: \"absence != zero time\").\nresponse:\n%s", pretty.String())
	}
	v, present := timedRow["until"]
	if !present {
		t.Fatalf("grants.list omitted \"until\" for the timed grant; raw:\n%s", raw)
	}
	var gotUntil string
	if err := json.Unmarshal(v, &gotUntil); err != nil {
		t.Fatalf("grant.until is not a JSON string: %v", err)
	}
	if gotUntil != untilTimed {
		t.Fatalf("grant.until for the timed row = %q, want %q", gotUntil, untilTimed)
	}
}

// TestIAMT123_GrantsList_RawJSONHasNoEmptyUntilString is the
// independent byte-level witness: the literal substring `"until":""`
// must NOT appear anywhere in the grants.list response when the only
// grants in state are indefinite. A regression that emits
// `"until":""` (the old shape) is caught here, even if some other
// layer compensates by re-parsing the value.
//
// Canary:
//
//	In internal/gateway/admin_role.go cmdGrantsList, drop the
//	pointer-to-string dance and unconditionally set `until = ""`
//	for the indefinite row. This test sees `"until":""` in the raw
//	bytes and fails.
func TestIAMT123_GrantsList_RawJSONHasNoEmptyUntilString(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// newFixture (harness_test.go:658) already seeds alice -> vm1 with a
	// deadline; revoke it first so the only grant left in state is the
	// indefinite one this test seeds below.
	if _, err := root.GrantsRevoke(f.person, f.machineID); err != nil {
		t.Fatalf("test setup error: revoke fixture's timed grant %s -> %s: %v", f.person, f.machineID, err)
	}

	if _, err := root.GrantsGrant(f.person, f.machineID, ""); err != nil {
		t.Fatalf("test setup error: seed indefinite grant %s -> %s: %v", f.person, f.machineID, err)
	}

	raw, err := root.Exec("grants.list", map[string]any{"proto": 1})
	if err != nil {
		t.Fatalf("test setup error: grants.list: %v", err)
	}
	if bytes.Contains(raw, []byte(`"until":""`)) {
		var pretty bytes.Buffer
		_ = json.Indent(&pretty, raw, "", "  ")
		t.Fatalf("grants.list response still contains the literal \"until\":\"\" for an indefinite grant; want the field OMITTED entirely.\nresponse:\n%s", pretty.String())
	}
	if bytes.Contains(raw, []byte(`"until"`)) {
		t.Fatalf("grants.list response for an indefinite-only state still mentions the \"until\" key at all; want it absent. raw: %s", raw)
	}
}

// TestIAMT123_GrantsGrant_EmptyUntilInRequestIsAccepted locks the
// OTHER half of the round-trip: the caller is allowed to send "until"
// as an empty string in the request body, and the gateway must accept
// it as "indefinite" (the value SPEC §4.3 calls "absence"). A future
// regression that demands a non-empty until would break this test.
//
// Canary:
//
//	In internal/gateway/admin_role.go cmdGrantsGrant, replace the
//	`if req.Until != ""` guard with `if false` so empty until is
//	refused. This test then fails with E_JSON_INVALID.
func TestIAMT123_GrantsGrant_EmptyUntilInRequestIsAccepted(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// newFixture (harness_test.go:658) already seeds alice -> vm1 with a
	// deadline; revoke it first so the assertion below is decided by
	// whether the gateway accepts an empty until, not by E_CONFLICT.
	if _, err := root.GrantsRevoke(f.person, f.machineID); err != nil {
		t.Fatalf("test setup error: revoke fixture's timed grant %s -> %s: %v", f.person, f.machineID, err)
	}

	if _, err := root.GrantsGrant(f.person, f.machineID, ""); err != nil {
		t.Fatalf("grants.grant with empty until: gateway refused with %v; want indefinite-acceptance per SPEC §4.3 line 276", err)
	}
}

// TestIAMT123_IndefiniteGrant_LoggedAsEmptyInAuditDetails pins the
// audit-trail shape: a "grants.grant" call that issues an indefinite
// grant records `{"until":""}` (the caller's own empty string) in the
// event details, so a grep over events.jsonl finds every indefinite
// issuance with the same pattern the request carried.
//
// Canary:
//
//	In internal/gateway/admin_role.go cmdGrantsGrant, replace
//	`{"until": req.Until}` with `{"until": "<indefinite>"}`. The audit
//	file then reads `"until":"<indefinite>"` and this test fails.
func TestIAMT123_IndefiniteGrant_LoggedAsEmptyInAuditDetails(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	// newFixture (harness_test.go:658) already seeds alice -> vm1 with a
	// deadline; revoke it first so this test's own indefinite grant on the
	// same pair isn't blocked by E_CONFLICT.
	if _, err := root.GrantsRevoke(f.person, f.machineID); err != nil {
		t.Fatalf("test setup error: revoke fixture's timed grant %s -> %s: %v", f.person, f.machineID, err)
	}

	if _, err := root.GrantsGrant(f.person, f.machineID, ""); err != nil {
		t.Fatalf("test setup error: seed indefinite grant %s -> %s: %v", f.person, f.machineID, err)
	}

	evs, _, err := f.log.Read(events.Filter{
		Types: []events.EventType{events.EventAdminOp},
	})
	if err != nil {
		t.Fatalf("test setup error: read journal: %v", err)
	}
	wantObj := f.person + " -> " + f.machineID
	var found bool
	for _, e := range evs {
		if e.Object != wantObj {
			continue
		}
		if !strings.Contains(e.Result, "grants.grant:ok") {
			continue
		}
		// The Details map is untyped: the wire shape we care about is
		// the empty string under the "until" key. If a future patch
		// re-encoded it as the literal word "indefinite" or as nil,
		// the audit grep breaks — and so does this test.
		v, present := e.Details["until"]
		if !present {
			continue
		}
		s, ok := v.(string)
		if !ok || s != "" {
			t.Fatalf("admin.op audit line for an indefinite grants.grant has Details.until = %#v, want the literal empty string the caller sent so a grep over the audit log finds every indefinite issuance; full event: %+v", v, e)
		}
		found = true
		break
	}
	if !found {
		t.Fatalf("test setup error: no admin.op audit line found for the indefinite grants.grant on %s; journal events: %+v", wantObj, evs)
	}
}
