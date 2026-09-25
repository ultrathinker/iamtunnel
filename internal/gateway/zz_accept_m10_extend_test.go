package gateway

import (
	"encoding/json"
	"testing"
	"time"
)

// M-10: extending access without tearing down the session — grants.extend.
//
// Before this verb the only way to push the deadline out was revoke+grant,
// and GrantAccess refuses a pair that already has a grant: a live session
// would have to be torn down to change a single date. grants.extend changes
// the deadline of the existing grant in place. Extending (the deadline
// moves out, or a finite term becomes indefinite) tears nothing down: the
// engine re-checks against the grant at every SweepExpired, and open
// sessions live exactly until the new deadline. Shortening follows the
// revocation rules: live sessions die, as with a narrowing set-caps or a
// revoke.
//
// The machine-side reader sees the deadline the same way grantView does:
// the "until" field is absent when there is no deadline — an empty string
// in place of a date is never issued in a response (SPEC 4.3).
func TestM10_GrantsExtend(t *testing.T) {
	cmd, ok := commandTable["grants.extend"]
	if !ok {
		t.Fatal("the gateway does not know grants.extend: there is no way to extend a grant deadline without tearing down the session, " +
			"and the CLI, the window and PROTOCOL §6 all promise this command")
	}
	if !cmd.adminOnly {
		t.Fatal("grants.extend is not adminOnly: whoever dials in could extend their own access")
	}

	f := newFixture(t, nil)
	type extendResponse struct {
		Until              *string `json:"until,omitempty"`
		Was                *string `json:"was,omitempty"`
		TerminatedSessions int     `json:"terminatedSessions"`
	}
	extend := func(until string) (extendResponse, *cmdError) {
		body, err := json.Marshal(map[string]any{
			"proto": 1, "person": f.person, "machine": f.machineID, "until": until,
		})
		if err != nil {
			t.Fatalf("marshal grants.extend body: %v", err)
		}
		res, cerr := cmd.run(f.gw, "admin", f.clock.Now(), body)
		if cerr != nil {
			return extendResponse{}, cerr
		}
		raw, err := json.Marshal(res)
		if err != nil {
			t.Fatalf("marshal grants.extend result: %v", err)
		}
		var out extendResponse
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("grants.extend result does not decode as its documented shape: %v", err)
		}
		return out, nil
	}
	engineUntil := func() *time.Time {
		for _, g := range f.gw.aclE.GrantsFor(f.person, f.clock.Now()) {
			if g.Machine == f.machineID {
				return g.Until
			}
		}
		return nil
	}
	stateUntil := func() *time.Time {
		st := f.store.Get()
		for _, g := range st.Grants {
			if g.Person == f.person && g.Machine == f.machineID {
				if g.Until == nil {
					return nil
				}
				u := g.Until.Time
				return &u
			}
		}
		return nil
	}
	at := func(d time.Duration) string {
		return f.clock.Now().Add(d).UTC().Format(time.RFC3339)
	}

	t.Run("extension moves the deadline and tears nothing down", func(t *testing.T) {
		res, cerr := extend(at(2 * time.Hour))
		if cerr != nil {
			t.Fatalf("grants.extend +2h: %v", cerr)
		}
		want := f.clock.Now().Add(2 * time.Hour).UTC()
		if res.Until == nil || *res.Until != want.Format(time.RFC3339) {
			t.Fatalf("grants.extend +2h: response until=%v, want %s", res.Until, want.Format(time.RFC3339))
		}
		if res.TerminatedSessions != 0 {
			t.Fatalf("grants.extend +2h: terminatedSessions=%d, want 0 — an extension does not tear down sessions", res.TerminatedSessions)
		}
		if got := stateUntil(); got == nil || !got.Equal(want) {
			t.Fatalf("state until=%v, want %s", got, want)
		}
		if got := engineUntil(); got == nil || !got.Equal(want) {
			t.Fatalf("engine until=%v, want %s", got, want)
		}
	})

	t.Run("finite to indefinite extends too", func(t *testing.T) {
		res, cerr := extend("")
		if cerr != nil {
			t.Fatalf("grants.extend \"\": %v", cerr)
		}
		if res.Until != nil {
			t.Fatalf("grants.extend \"\": response until=%v, want absent", res.Until)
		}
		if got := stateUntil(); got != nil {
			t.Fatalf("state until=%v, want nil (indefinite)", got)
		}
		if got := engineUntil(); got != nil {
			t.Fatalf("engine until=%v, want nil (indefinite)", got)
		}
	})

	t.Run("shortening follows revoke rules", func(t *testing.T) {
		res, cerr := extend(at(30 * time.Minute))
		if cerr != nil {
			t.Fatalf("grants.extend -shorten: %v", cerr)
		}
		want := f.clock.Now().Add(30 * time.Minute).UTC()
		if res.Until == nil || *res.Until != want.Format(time.RFC3339) {
			t.Fatalf("grants.extend -shorten: response until=%v, want %s", res.Until, want.Format(time.RFC3339))
		}
		if got := engineUntil(); got == nil || !got.Equal(want) {
			t.Fatalf("engine until=%v, want %s — a shortened deadline must remain a live grant", got, want)
		}
	})

	t.Run("unknown pair is E_NOT_FOUND", func(t *testing.T) {
		body, err := json.Marshal(map[string]any{
			"proto": 1, "person": f.person, "machine": "no-such-machine", "until": at(time.Hour),
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, cerr := cmd.run(f.gw, "admin", f.clock.Now(), body); cerr == nil || cerr.code != "E_NOT_FOUND" {
			t.Fatalf("grants.extend on unknown pair: %v, want E_NOT_FOUND", cerr)
		}
	})

	t.Run("deadline in the past or unreadable is E_JSON_INVALID", func(t *testing.T) {
		body, err := json.Marshal(map[string]any{
			"proto": 1, "person": f.person, "machine": f.machineID, "until": at(-time.Hour),
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, cerr := cmd.run(f.gw, "admin", f.clock.Now(), body); cerr == nil || cerr.code != "E_JSON_INVALID" {
			t.Fatalf("grants.extend with past until: %v, want E_JSON_INVALID", cerr)
		}
		body, err = json.Marshal(map[string]any{
			"proto": 1, "person": f.person, "machine": f.machineID, "until": "not-a-time",
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if _, cerr := cmd.run(f.gw, "admin", f.clock.Now(), body); cerr == nil || cerr.code != "E_JSON_INVALID" {
			t.Fatalf("grants.extend with unreadable until: %v, want E_JSON_INVALID", cerr)
		}
	})
}
