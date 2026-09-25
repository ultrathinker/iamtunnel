package ui

// The maintainer's canary: a string of one kind must not go into the
// action of another kind.
//
// Found by the maintainer on 19.09.2026 during the first live
// setup-from-scratch pass. The window DID recognise the bootstrap
// string: above the button it honestly wrote "This will make THIS
// machine the first administrator of ...". And on press it sent it to
// the pair action, which measures the secret against a six-digit PIN,
// and answered "the PIN must be exactly 6 decimal digits". There is
// no PIN field on the form and there must not be one -- a bootstrap
// string has no PIN.
//
// The price of the defect is the highest possible: this is a person's
// FIRST action on a new gateway. While it does not work, nothing at
// all can be done from the window -- and the gateway itself, on
// install, prints "paste this one string into the Admin tab's single
// field". The promise was in the product; the wiring behind it was
// not.
//
// None of the existing tests caught this: they checked empty fields
// and refusals on strings of a FOREIGN kind (a machine invitation, a
// pair string). A string of the right kind going to the wrong action
// was the blind spot between them.

import (
	"os"
	"strings"
	"testing"
	"time"
)

const (
	claimRouteFingerprint = "SHA256:VHcYlXQPy+pny9JSYsyO0OoExJyZfiiWy11VbnWLpLg"
	claimRouteToken       = "LQkhHace2auhVVbtWK29A67IeIr6_MpTKUHmhs2QlwI"
)

// TestCanary_ClaimStringGoesToTheClaimAction.
//
// Canary: restore the unconditional
// `join := f.cfg.Actions.AdminPairClaim` in joinAsAdmin -- the test
// goes red with the very text the maintainer saw.
func TestCanary_ClaimStringGoesToTheClaimAction(t *testing.T) {
	f := newBareFrame(t)

	claimed := make(chan [2]string, 1)
	paired := make(chan struct{}, 1)
	f.cfg.Actions.AdminClaim = func(ref, token string) (string, *AdminIdentity, error) {
		claimed <- [2]string{ref, token}
		return "ok", nil, nil
	}
	f.cfg.Actions.AdminPairClaim = func(ref, pin string) (string, *AdminIdentity, error) {
		paired <- struct{}{}
		return "", nil, nil
	}

	f.editor(ctlAdminPairJoin).SetText(
		"iamtunnel-claim://203.0.113.10:2022#" + claimRouteFingerprint + ":" + claimRouteToken)
	f.joinAsAdmin()

	select {
	case <-paired:
		t.Fatal("the bootstrap string went to the PAIR action: it measures the secret against a six-digit PIN and will refuse -- exactly what the maintainer saw on 19.09.2026 at the very first step of setup")
	case got := <-claimed:
		if want := "203.0.113.10:2022#" + claimRouteFingerprint; got[0] != want {
			t.Errorf("ref = %q, want %q", got[0], want)
		}
		if got[1] != claimRouteToken {
			t.Errorf("token = %q, want %q -- the bootstrap token itself must travel to the action, not a truncation", got[1], claimRouteToken)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no action was called -- the form swallowed the string silently")
	}
}

// TestCanary_PairStringStillGoesToThePairAction: the
// branch must not have broken what worked. The pair string still goes
// to the pair action.
func TestCanary_PairStringStillGoesToThePairAction(t *testing.T) {
	f := newBareFrame(t)

	claimed := make(chan struct{}, 1)
	paired := make(chan [2]string, 1)
	f.cfg.Actions.AdminClaim = func(ref, token string) (string, *AdminIdentity, error) {
		claimed <- struct{}{}
		return "", nil, nil
	}
	f.cfg.Actions.AdminPairClaim = func(ref, pin string) (string, *AdminIdentity, error) {
		paired <- [2]string{ref, pin}
		return "ok", nil, nil
	}

	f.editor(ctlAdminPairJoin).SetText(
		"iamtunnel admin pair gw.example.net:2022#" + claimRouteFingerprint + " 123456")
	f.joinAsAdmin()

	select {
	case <-claimed:
		t.Fatal("the pair string went to the bootstrap action -- the branch broke a working path")
	case got := <-paired:
		if got[1] != "123456" {
			t.Errorf("PIN = %q, want \"123456\"", got[1])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no action was called")
	}
}

// TestCanary_JoiningIsTheFirstAdminSubTab.
//
// The order of sub-tabs is not a matter of taste. On a fresh gateway
// the others cannot answer anything: there is no administrator yet.
// Join used to sit sixth, and the maintainer had to look for it.
//
// Since 21.09.2026 there is no separate Join tab -- it merged with
// People, and People stands first. The requirement did not change,
// the name did: the first sub-tab must be the one where a person
// becomes the administrator.
//
// The canary checks both the name and the substance: if People leaves
// the first place or stops carrying the join card, it goes red.
func TestCanary_JoiningIsTheFirstAdminSubTab(t *testing.T) {
	items := adminSubTabOrder()
	if len(items) == 0 {
		t.Fatal("the Admin sub-tab list is empty")
	}
	if items[0] != "People" {
		t.Errorf("the first Admin sub-tab = %q, want \"People\" (order: %v) -- that is where a person becomes the administrator, and until then none of the others can answer anything",
			items[0], items)
	}
	src, err := os.ReadFile("screens.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "joinCardTitle(nil), f.layoutPairJoinForm") {
		t.Error("the People sub-tab no longer draws the join form for an unbound machine -- on a fresh gateway there is nowhere left to become the administrator")
	}
}
