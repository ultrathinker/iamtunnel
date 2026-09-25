package ui

// iamt330_pairing_expiry_test.go — IAMT-323 review follow-up (IAMT-330):
// the "Pairing window" card must not keep showing a PIN whose window has
// lapsed. The review found layoutPairingCard redrew the saved PIN and
// reference without ever checking the stored expiry, so an operator who
// comes back to the tab minutes later reads a live-looking PIN the
// gateway has been refusing since the window closed itself.
//
// pairingCardFacts is the card's fact arithmetic, extracted as a pure
// function so the expiry behavior is testable on every platform (the
// render itself is windows-only); layoutPairingCard recomputes it on
// every layout pass with the real clock.

import (
	"strings"
	"testing"
	"time"
)

var iamt330Ref = "gw.example.net:2022#" + strings.Repeat("A", 43)

func TestPairingCardFactsShowAnOpenWindowVerbatim(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 30, 0, 0, time.UTC)
	w := &PairingWindow{Pin: "012345", Ref: iamt330Ref, Expires: now.Add(90 * time.Second)}

	pin, ref, closes := pairingCardFacts(w, now)

	if pin != "012345" {
		t.Errorf("pin = %q, want the live PIN verbatim", pin)
	}
	if ref != iamt330Ref {
		t.Errorf("ref = %q, want the reference verbatim", ref)
	}
	// The stamp AND what is left of it (21.09.2026). A two-minute window
	// written only as "2026-09-16 18:31 UTC" is a subtraction nobody
	// performs faster than the window closes.
	if !strings.Contains(closes, "2026-09-16 18:31 UTC") {
		t.Errorf("closes = %q, want the formatted expiry in it", closes)
	}
	if !strings.Contains(closes, "1:30 left") {
		t.Errorf("closes = %q, want the time remaining beside the stamp", closes)
	}
}

func TestPairingCardFactsHideAnExpiredPIN(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 30, 0, 0, time.UTC)
	w := &PairingWindow{Pin: "012345", Ref: iamt330Ref, Expires: now.Add(-time.Second)}

	pin, ref, closes := pairingCardFacts(w, now)

	if pin != "—" {
		t.Errorf("pin = %q for a lapsed window, want it hidden — the gateway refuses it with E_PAIRING_EXPIRED", pin)
	}
	if ref != iamt330Ref {
		t.Errorf("ref = %q, want the reference still shown (it carries no secret)", ref)
	}
	if !strings.Contains(closes, "expired") || !strings.Contains(closes, "18:29") {
		t.Errorf("closes = %q, want the lapse named with its moment", closes)
	}
}

func TestPairingCardFactsCallTheExpiryInstantExpired(t *testing.T) {
	// The gateway grades !Expires.After(now) — the exact instant is
	// already lapsed. The card must use the same boundary, or it would
	// show a live-looking PIN for the one moment both disagree.
	now := time.Date(2026, 9, 16, 18, 30, 0, 0, time.UTC)
	w := &PairingWindow{Pin: "012345", Expires: now}

	pin, _, closes := pairingCardFacts(w, now)

	if pin != "—" {
		t.Errorf("pin = %q at the exact expiry instant, want it hidden (the gateway is already refusing it)", pin)
	}
	if !strings.Contains(closes, "expired") {
		t.Errorf("closes = %q, want the lapse named", closes)
	}
}

func TestPairingCardFactsKeepTheUnaskedDashes(t *testing.T) {
	pin, ref, closes := pairingCardFacts(nil, time.Now())

	if pin != "—" || ref != "—" || closes != "—" {
		t.Errorf("nil window = (%q, %q, %q), want the three dashes every unanswered fact draws", pin, ref, closes)
	}
}

// -------------------------------------------------------------------------
// The wake-up: the card must ASK for the frame that flips it (round 3).
// -------------------------------------------------------------------------

func TestPairingCardWakeUpTicksEverySecondAndLandsOnTheExpiry(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 30, 0, 0, time.UTC)
	w := &PairingWindow{Pin: "012345", Expires: now.Add(90 * time.Second)}

	at, wake := pairingCardWakeUp(w, now)

	if !wake {
		t.Fatal("open window: no redraw requested — an idle Admin tab would keep showing the dead PIN past expiry")
	}
	// Once a second while the window is open: the card draws a countdown
	// now, and a countdown that only redraws at the end is a stopped
	// clock on the most time-critical screen in the product.
	if !at.Equal(now.Add(time.Second)) {
		t.Errorf("redraw requested for %v, want the next second %v", at, now.Add(time.Second))
	}

	// And the LAST tick is clamped to the expiry instant, so the flip to
	// "expired" still lands exactly on the boundary the gateway grades
	// by rather than up to a second late.
	nearly := w.Expires.Add(-300 * time.Millisecond)
	at, wake = pairingCardWakeUp(w, nearly)
	if !wake {
		t.Fatal("a window 300 ms from lapsing asked for no redraw")
	}
	if !at.Equal(w.Expires) {
		t.Errorf("last redraw requested for %v, want exactly the expiry instant %v", at, w.Expires)
	}
}

func TestPairingCardWakeUpGoesQuietAtAndAfterExpiry(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 30, 0, 0, time.UTC)
	lapsed := []struct {
		label string
		w     *PairingWindow
	}{
		{"exact expiry instant", &PairingWindow{Pin: "012345", Expires: now}},
		{"a second past expiry", &PairingWindow{Pin: "012345", Expires: now.Add(-time.Second)}},
		{"zero expiry (defensive)", &PairingWindow{Pin: "012345"}},
		{"no window at all", nil},
	}
	for _, tc := range lapsed {
		if at, wake := pairingCardWakeUp(tc.w, now); wake {
			t.Errorf("%s: another redraw scheduled for %v — after the flip the card must go quiet, not spin", tc.label, at)
		}
	}
}
