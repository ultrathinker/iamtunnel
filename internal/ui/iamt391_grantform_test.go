//go:build windows

package ui

// iamt391_grantform_test.go — IAMT-391's own canaries, for the parts a
// screenshot would not show: until and capability now hold a WORD (a
// preset, or empty), not a raw instant, so something has to turn that
// word back into what the gateway reads before it travels, and something
// has to pick a sane default for a box nobody touched.
//
// The maintainer's complaint was about the two fields' shape (a shared row,
// raw RFC 3339, buttons under the box); the actions module (live.go) is
// the layer this test drives, and it did not change shape at all — it
// gained one resolution step (grantAccess) and one flipped default
// (grantCapability).

import (
	"strings"
	"testing"
	"time"
)

func TestGrantCapabilityDefaultsToExec(t *testing.T) {
	f := newBareFrame(t)
	if got := f.grantCapability(); got != "exec" {
		t.Errorf("grantCapability() on an untouched box = %q, want %q (IAMT-391 point 3)", got, "exec")
	}
	f.editor(ctlAdminGrant + "/capability").SetText("shell")
	if got := f.grantCapability(); got != "shell" {
		t.Errorf(`grantCapability() with "shell" typed = %q, want "shell"`, got)
	}
	f.editor(ctlAdminGrant + "/capability").SetText("whatever")
	if got := f.grantCapability(); got != "exec" {
		t.Errorf("grantCapability() with an unrecognised word = %q, want the exec default, not the old shell default", got)
	}
}

func TestGrantAccessResolvesAnUntilPresetBeforeAsking(t *testing.T) {
	f := newBareFrame(t)
	f.editor(ctlAdminGrant + "/person").SetText("alice")
	f.editor(ctlAdminGrant + "/machine").SetText("win-srv01")
	f.editor(ctlAdminGrant + "/until").SetText("1 hour")

	got := make(chan string, 1)
	f.cfg.Actions.AdminGrantWithCaps = func(person, machine, until, capability string) (string, error) {
		got <- until
		return "granted", nil
	}

	before := time.Now()
	f.grantAccess()
	after := time.Now()

	select {
	case until := <-got:
		at, err := time.Parse(time.RFC3339, until)
		if err != nil {
			t.Fatalf("grantAccess asked the gateway for until=%q, which is not RFC 3339: %v", until, err)
		}
		// RFC 3339 has no fractional seconds, so `at` can read up to a
		// second earlier than the nanosecond-precise bounds around it.
		const slack = time.Second
		if at.Before(before.Add(time.Hour-slack)) || at.After(after.Add(time.Hour+slack)) {
			t.Errorf(`grantAccess resolved "1 hour" to %s, want roughly one hour from the press`, at)
		}
	case <-time.After(guardWait):
		t.Fatal("pressing Grant access with \"1 hour\" in the until box asked the gateway nothing")
	}
}

func TestGrantAccessLeavesUntilRevokedAsTheEmptyString(t *testing.T) {
	for _, until := range []string{"", "until revoked"} {
		until := until
		t.Run(until, func(t *testing.T) {
			f := newBareFrame(t)
			f.editor(ctlAdminGrant + "/person").SetText("alice")
			f.editor(ctlAdminGrant + "/machine").SetText("win-srv01")
			f.editor(ctlAdminGrant + "/until").SetText(until)

			got := make(chan string, 1)
			f.cfg.Actions.AdminGrantWithCaps = func(person, machine, until, capability string) (string, error) {
				got <- until
				return "granted", nil
			}

			f.grantAccess()

			select {
			case sent := <-got:
				if sent != "" {
					t.Errorf("grantAccess asked the gateway for until=%q, want the empty string (indefinite)", sent)
				}
			case <-time.After(guardWait):
				t.Fatal("pressing Grant access asked the gateway nothing")
			}
		})
	}
}

func TestGrantAccessPassesAnUnrecognisedUntilThrough(t *testing.T) {
	// The combo does not stop a person pasting their own RFC 3339 instant
	// (IAMT-391's "possibility to set an arbitrary date" is kept this
	// way): anything that is not a known preset word travels verbatim,
	// exactly as a typed box always has.
	f := newBareFrame(t)
	f.editor(ctlAdminGrant + "/person").SetText("alice")
	f.editor(ctlAdminGrant + "/machine").SetText("win-srv01")
	f.editor(ctlAdminGrant + "/until").SetText("2026-09-13T18:00:00Z")

	got := make(chan string, 1)
	f.cfg.Actions.AdminGrantWithCaps = func(person, machine, until, capability string) (string, error) {
		got <- until
		return "granted", nil
	}

	f.grantAccess()

	select {
	case sent := <-got:
		if sent != "2026-09-13T18:00:00Z" {
			t.Errorf("grantAccess rewrote a typed RFC 3339 instant into %q", sent)
		}
	case <-time.After(guardWait):
		t.Fatal("pressing Grant access asked the gateway nothing")
	}
}

func TestGrantUntilHintNamesTheExactInstant(t *testing.T) {
	f := newBareFrame(t)
	if got := f.grantUntilHint(); !strings.Contains(got, "until revoked") {
		t.Errorf(`grantUntilHint() on an untouched box = %q, want it to say the grant stands until revoked`, got)
	}

	f.editor(ctlAdminGrant + "/until").SetText("until revoked")
	if got := f.grantUntilHint(); !strings.Contains(got, "until revoked") {
		t.Errorf(`grantUntilHint() with "until revoked" picked = %q, want the same no-expiry hint`, got)
	}

	f.editor(ctlAdminGrant + "/until").SetText("1 hour")
	if got := f.grantUntilHint(); !strings.HasPrefix(got, "ends ") {
		t.Errorf(`grantUntilHint() with "1 hour" picked = %q, want it to name the exact instant it resolves to`, got)
	}
}
