//go:build windows

package ui

// IAMT-331: the "Pairing window" card told the truth only about the
// window THIS window minted. A Stop by another client, another
// administrator's successful pair, or a replacement opened from the far
// side ended the window without this window hearing a word — and the
// card went on drawing a live-looking PIN until its own timer ran out.
// The gateway now says what its pairing window is (gateway.status
// "pairing"), and the card believes that answer.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

var iamt331Now = time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)

func iamt331LocalWindow() *PairingWindow {
	return &PairingWindow{
		Pin: "012345", Ref: iamt330Ref,
		Expires: iamt331Now.Add(90 * time.Second),
	}
}

func TestIAMT331_TheCardLearnsTheWindowDiedFromTheGateway(t *testing.T) {
	// The gateway answers "no window is open" while the local clock says
	// the displayed one still has ninety seconds. The far side ended it —
	// a Stop, another admin's pair — and the card must say so, not keep
	// counting down a PIN the gateway is already refusing.
	live := PairingStatus{Active: false}
	got := adminPairingAfterStatus(iamt331LocalWindow(), live, iamt331Now)
	if got == nil {
		t.Fatal("the reconciler lost the window the card was showing")
	}
	if !got.Gone {
		t.Fatalf("the gateway says the window is gone, but the card still shows it open until %s — the one end no timer here can see", got.Expires.Format(time.RFC3339))
	}
	if got.Pin != "012345" || got.Ref != iamt330Ref {
		t.Errorf("marking the window gone disturbed its facts: pin=%q ref=%q", got.Pin, got.Ref)
	}
}

func TestIAMT331_TheCardLearnsTheWindowWasReplacedFromTheFarSide(t *testing.T) {
	// The gateway answers "a window is open" — but until a different
	// instant than the one this window minted. cmdAdminPairingStart
	// replaces an open window in one write, so a different expiry is a
	// different window: the PIN on the card is already dead.
	live := PairingStatus{Active: true, Expires: iamt331Now.Add(45 * time.Second)}
	got := adminPairingAfterStatus(iamt331LocalWindow(), live, iamt331Now)
	if got == nil || !got.Gone {
		t.Fatalf("the gateway says a window with a different expiry is open, but the card kept its own PIN live: %+v", got)
	}
}

func TestIAMT331_TheCardKeepsAWindowTheGatewayConfirms(t *testing.T) {
	w := iamt331LocalWindow()
	live := PairingStatus{Active: true, Expires: w.Expires}
	got := adminPairingAfterStatus(w, live, iamt331Now)
	if got != w {
		t.Fatalf("the gateway confirmed this very window, but the card replaced it: %+v", got)
	}
	if got.Gone {
		t.Errorf("a window the gateway confirms open must not be marked gone")
	}
}

func TestIAMT331_TheCardShowsAWindowAnotherWindowOpened(t *testing.T) {
	// The gateway says a window is open and this window never minted one:
	// somebody else's Start. The card has no PIN to show, but "no window
	// is open" beside another administrator's live window is the lie this
	// card exists not to tell.
	live := PairingStatus{Active: true, Expires: iamt331Now.Add(60 * time.Second)}
	got := adminPairingAfterStatus(nil, live, iamt331Now)
	if got == nil {
		t.Fatal("the gateway says a window is open, the card shows nothing")
	}
	if !got.Elsewhere {
		t.Errorf("a window this window did not mint must be marked as opened elsewhere: %+v", got)
	}
	if got.Pin != "" || got.Ref != "" {
		t.Errorf("an elsewhere window carries no PIN and no reference: pin=%q ref=%q", got.Pin, got.Ref)
	}
	if !got.Expires.After(iamt331Now) {
		t.Errorf("an elsewhere window carries the gateway's expiry: %s", got.Expires)
	}
}

func TestIAMT331_TheCardKeepsAnExpiredWindowExpired(t *testing.T) {
	// A window that ran out on its own and then the gateway confirms it
	// closed: that is "expired", not "closed early" — the reconciler must
	// not rewrite one truth into the other.
	w := &PairingWindow{Pin: "012345", Expires: iamt331Now.Add(-time.Second)}
	live := PairingStatus{Active: false}
	got := adminPairingAfterStatus(w, live, iamt331Now)
	if got != w {
		t.Fatalf("the reconciler moved an already-expired window: %+v", got)
	}
}

func TestIAMT331_TheCardStaysGoneOnceTheGatewayEndedIt(t *testing.T) {
	w := iamt331LocalWindow()
	w.Gone = true
	live := PairingStatus{Active: true, Expires: iamt331Now.Add(30 * time.Second)}
	got := adminPairingAfterStatus(w, live, iamt331Now)
	if got != w || !got.Gone {
		t.Fatalf("a new window from the far side must not resurrect the dead one: %+v", got)
	}
}

func TestIAMT331_TheCardBelievesTheGatewayOverItsOwnTimer(t *testing.T) {
	// An elsewhere window the gateway no longer reports is simply gone
	// from the screen: there was never a PIN here to mourn.
	live := PairingStatus{Active: false}
	got := adminPairingAfterStatus(&PairingWindow{Elsewhere: true, Expires: iamt331Now.Add(time.Minute)}, live, iamt331Now)
	if got != nil {
		t.Fatalf("an elsewhere window the gateway does not report must vanish, got %+v", got)
	}
}

func TestIAMT331_TheStateLineSaysTheWindowWasClosedEarly(t *testing.T) {
	w := iamt331LocalWindow()
	w.Gone = true
	word, key := pairingWindowState(w, iamt331Now)
	if key != design.MutedKey {
		t.Errorf("a gone window's state line is colored %v, want the muted truth", key)
	}
	if word != "the window was closed early — its PIN no longer works" {
		t.Errorf("state line = %q, want the far-side closure, not the timer's verdict", word)
	}
}

func TestIAMT331_TheStateLineSaysAWindowIsOpenElsewhere(t *testing.T) {
	w := &PairingWindow{Elsewhere: true, Expires: iamt331Now.Add(time.Minute)}
	word, key := pairingWindowState(w, iamt331Now)
	if key != design.WarnKey {
		t.Errorf("an open window from another client is colored %v, want the warning", key)
	}
	if word != "a window is OPEN — opened from another window" {
		t.Errorf("state line = %q, want the elsewhere warning", word)
	}
}

func TestIAMT331_TheFactsHideThePinOfADeadWindow(t *testing.T) {
	w := iamt331LocalWindow()
	w.Gone = true
	pin, _, closes := pairingCardFacts(w, iamt331Now)
	if pin != "—" {
		t.Errorf("a gone window's PIN is drawn as %q, want the dash — nobody can join with it", pin)
	}
	if !strings.Contains(closes, "closed early") {
		t.Errorf("a gone window's closes row = %q, want it said the window was closed early", closes)
	}
}

func TestIAMT331_TheFactsShowAnElsewhereWindowWithoutAPin(t *testing.T) {
	w := &PairingWindow{Elsewhere: true, Expires: iamt331Now.Add(time.Minute)}
	pin, ref, closes := pairingCardFacts(w, iamt331Now)
	if pin != "—" || ref != "—" {
		t.Errorf("an elsewhere window shows pin=%q ref=%q, want dashes — those went to whoever opened it", pin, ref)
	}
	if closes == "" || closes == "—" {
		t.Errorf("an elsewhere window's closes row = %q, want when the window closes", closes)
	}
}

func TestIAMT331_TheCountdownStopsWhenTheGatewayEndsTheWindow(t *testing.T) {
	// pairingCardWakeUp ticks once a second toward the expiry and flips
	// the card there. A window the gateway already ended has nothing left
	// to count: the flip happened the moment the answer landed.
	w := iamt331LocalWindow()
	w.Gone = true
	if at, wake := pairingCardWakeUp(w, iamt331Now); wake {
		t.Errorf("a gone window still schedules a wake-up at %v — counting down a PIN the gateway refuses", at)
	}
}

// TestIAMT331_TheAdminRefreshCarriesTheGatewayWord is the redraw itself:
// the lists refresh every admin action and every entry into the tab, and
// its answer — gateway.status riding along since IAMT-451 — is what ends
// another admin's window on THIS screen.
func TestIAMT331_TheAdminRefreshCarriesTheGatewayWord(t *testing.T) {
	f := newBareFrame(t)
	f.reviseSnapshot(func(s *Snapshot) {
		s.Admin.Pairing = &PairingWindow{
			Pin: "012345", Ref: iamt330Ref,
			Expires: time.Now().Add(time.Hour),
		}
	})
	f.cfg.Actions.AdminList = func(context.Context) (AdminLists, error) {
		return AdminLists{Pairing: &PairingStatus{Active: false}}, nil
	}

	f.refreshAdminLists()
	awaitSaid(t, f, ctlAdminRefresh, design.GoodKey)
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render after refresh: %v", err)
	}

	if f.snap.Admin.Pairing == nil {
		t.Fatal("the refresh erased the card entirely — the far-side closure must be shown, not forgotten")
	}
	if !f.snap.Admin.Pairing.Gone {
		t.Fatalf("the gateway said no window is open, the card still draws %+v as open", *f.snap.Admin.Pairing)
	}
}
