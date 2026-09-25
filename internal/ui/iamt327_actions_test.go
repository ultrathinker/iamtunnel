//go:build windows

package ui

// iamt327_actions_test.go covers the five IAMT-327 admin-tab actions with
// the same two guards iamt149_actions_test.go and iamt181_actions_test.go
// established — a Frame built without a runtime says so instead of
// silently doing nothing, and an empty required box is refused before
// begin() ever starts a goroutine (closed-channel + bounded-wait, round 3
// pattern) — and adds the one property this round introduces: an action's
// outcome may become STATE (Admin.Pairing), not only a sentence. The
// state move is checked the way iamt151_update_snapshot_test.go checks
// UpdateSnapshot: a revision parks in pending, and a Layout pass is what
// takes it into f.snap. Because begin() writes the outcome sentence
// strictly AFTER its work closure returns — and the revision happens
// inside that closure — a test that waits for the final sentence knows
// the revision is already parked, and one offscreen pass makes it
// readable in f.snap without racing the goroutine.

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// testPairingFingerprint is a well-formed SHA-256 fingerprint body (43
// base64 characters, exactly what a decoded 32-byte digest renders as)
// — the shape of the part after '#' in a pairing reference. Only parse
// guards see it; nothing in this file dials anywhere.
var testPairingFingerprint = strings.Repeat("A", 43)

// awaitSaid waits for a begin() outcome to land under a named control.
// Bounded: a build that never calls the action must fail the test, not
// hang it — the same reasoning as TestRefreshMachinesCallsActionsWithContext.
func awaitSaid(t *testing.T, f *Frame, ctl string, want design.ColorKey) saying {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got := f.saidUnder(ctl)
		if got.key == want {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("saidUnder(%q) never reached %v (last seen: %+v)", ctl, want, got)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// -------------------------------------------------------------------------
// The empty-box guards.
// -------------------------------------------------------------------------

func TestJoinAsAdminRefusesAnEmptyRefOrPin(t *testing.T) {
	for _, tc := range []struct{ label, ref, pin string }{
		{"both empty", "", ""},
		{"ref empty", "", "123456"},
		{"pin empty", "gw.example.net:2022#" + testPairingFingerprint, ""},
	} {
		t.Run(tc.label, func(t *testing.T) {
			f := newBareFrame(t)
			called := make(chan struct{})
			f.cfg.Actions.AdminPairClaim = func(ref, pin string) (string, *AdminIdentity, error) {
				close(called)
				return "", nil, nil
			}
			f.editor(ctlAdminPairJoin + "/ref").SetText(tc.ref)
			f.editor(ctlAdminPairJoin + "/pin").SetText(tc.pin)

			f.joinAsAdmin()

			select {
			case <-called:
				t.Fatalf("joinAsAdmin called Actions.AdminPairClaim with %s — it must refuse before touching the network", tc.label)
			case <-time.After(guardWait):
			}

			got := f.saidUnder(ctlAdminPairJoin)
			if got.key != design.BadKey || got.text == "" {
				t.Errorf("saidUnder(%q) = %+v, want a non-empty BadKey refusal", ctlAdminPairJoin, got)
			}
		})
	}
}

func TestAddPersonRefusesAnEmptyNameOrKey(t *testing.T) {
	// The label is a separate field on purpose: here the name IS one of
	// the guarded inputs, so a label doubling as input would lie.
	for _, tc := range []struct{ label, name, key string }{
		{"both empty", "", ""},
		{"name empty", "", "ssh-ed25519 AAAA test"},
		{"key empty", "bob", ""},
	} {
		t.Run(tc.label, func(t *testing.T) {
			f := newBareFrame(t)
			called := make(chan struct{})
			f.cfg.Actions.AdminPeopleAdd = func(name, role, key string) (string, error) {
				close(called)
				return "", nil
			}
			if tc.name != "" {
				f.editor(ctlAdminPeopleAdd + "/name").SetText(tc.name)
			}
			if tc.key != "" {
				f.editor(ctlAdminPeopleAdd + "/key").SetText(tc.key)
			}

			f.addPerson()

			select {
			case <-called:
				t.Fatalf("addPerson called Actions.AdminPeopleAdd with %s — it must refuse before touching the network", tc.label)
			case <-time.After(guardWait):
			}

			got := f.saidUnder(ctlAdminPeopleAdd)
			if got.key != design.BadKey || got.text == "" {
				t.Errorf("saidUnder(%q) = %+v, want a non-empty BadKey refusal", ctlAdminPeopleAdd, got)
			}
		})
	}
}

// TestMintEnrolCodeAsksWithoutBeingTold is the 1.3 inversion of the test
// that stood here before. That one required a refusal when the machine
// box was empty; the box is gone (SPEC §3.4), and with it the only thing
// the card could have refused. An administrator who presses the button
// having typed nothing — because there is nothing to type — must get an
// invitation, not a lecture.
func TestMintEnrolCodeSendsTheNameTheAdminChose(t *testing.T) {
	f := newBareFrame(t)
	got := make(chan string, 1)
	f.cfg.Actions.AdminMachinesEnrolCode = func(name string) (string, string, error) {
		got <- name
		return "iamtunnel-enrol://gw.example.net:2022#fp:secret", "in 24 hours", nil
	}
	f.editor(ctlAdminEnrolCode + "/name").SetText("  office-pc  ")

	f.mintEnrolCode()

	select {
	case name := <-got:
		if name != "office-pc" {
			t.Errorf("the card asked the gateway for %q, want the trimmed name the administrator typed", name)
		}
	case <-time.After(guardWait):
		t.Fatal("pressing Invite a machine asked the gateway nothing")
	}
}

// TestMintEnrolCodeRefusesAnEmptyName. The name is the whole content of
// an invitation since 1.4 — it is what the administrator will grant
// access against and revoke by — so a press with the box empty has
// nothing to mint and must say so rather than reach the network.
func TestMintEnrolCodeRefusesAnEmptyName(t *testing.T) {
	f := newBareFrame(t)
	called := make(chan struct{})
	f.cfg.Actions.AdminMachinesEnrolCode = func(string) (string, string, error) {
		close(called)
		return "", "", nil
	}

	f.mintEnrolCode()

	select {
	case <-called:
		t.Fatal("mintEnrolCode asked the gateway for an invitation with no name")
	case <-time.After(guardWait):
	}
	if got := f.saidUnder(ctlAdminEnrolCode); got.key != design.BadKey || got.text == "" {
		t.Errorf("saidUnder(%q) = %+v, want a non-empty BadKey refusal", ctlAdminEnrolCode, got)
	}
}

// -------------------------------------------------------------------------
// The no-runtime guard.
// -------------------------------------------------------------------------

func TestJoinAsAdminWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	// One box since 1.3 (SPEC §3.6): reference and PIN arrive together,
	// exactly as the gateway prints them.
	f.editor(ctlAdminPairJoin).SetText("gw.example.net:2022#" + testPairingFingerprint + " 123456")

	f.joinAsAdmin()

	if got := f.saidUnder(ctlAdminPairJoin); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlAdminPairJoin, got, noRuntime)
	}
}

func TestOpenPairingWindowWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)

	f.openPairingWindow()

	if got := f.saidUnder(ctlAdminPairingStart); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlAdminPairingStart, got, noRuntime)
	}
}

func TestClosePairingWindowWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)

	f.closePairingWindow()

	if got := f.saidUnder(ctlAdminPairingStop); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlAdminPairingStop, got, noRuntime)
	}
}

func TestAddPersonWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	f.editor(ctlAdminPeopleAdd + "/name").SetText("bob")
	f.editor(ctlAdminPeopleAdd + "/key").SetText("ssh-ed25519 AAAA test")

	f.addPerson()

	if got := f.saidUnder(ctlAdminPeopleAdd); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlAdminPeopleAdd, got, noRuntime)
	}
}

func TestMintEnrolCodeWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	f.editor(ctlAdminEnrolCode + "/name").SetText("office-pc")

	f.mintEnrolCode()

	if got := f.saidUnder(ctlAdminEnrolCode); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctlAdminEnrolCode, got, noRuntime)
	}
}

// -------------------------------------------------------------------------
// The outcome-becomes-state property: Admin.Pairing.
// -------------------------------------------------------------------------

func TestOpenPairingWindowBecomesState(t *testing.T) {
	f := newBareFrame(t)
	want := PairingWindow{
		Pin:     "012345",
		Ref:     "gw.example.net:2022#" + testPairingFingerprint,
		Expires: time.Date(2026, 9, 16, 18, 30, 0, 0, time.UTC),
	}
	f.cfg.Actions.AdminPairingStart = func() (PairingWindow, error) {
		return want, nil
	}

	f.openPairingWindow()

	got := awaitSaid(t, f, ctlAdminPairingStart, design.GoodKey)
	if !strings.Contains(got.text, "open until") {
		t.Errorf("saidUnder(%q).text = %q, want the open-until sentence", ctlAdminPairingStart, got.text)
	}

	// One render pass takes the parked revision into f.snap.
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render after openPairingWindow: %v", err)
	}
	if f.snap.Admin.Pairing == nil {
		t.Fatalf("openPairingWindow left Admin.Pairing nil — the window's PIN must become state, not only a sentence")
	}
	if *f.snap.Admin.Pairing != want {
		t.Errorf("Admin.Pairing = %+v, want %+v", *f.snap.Admin.Pairing, want)
	}
}

func TestClosePairingWindowClearsAnOpenWindow(t *testing.T) {
	f, err := NewFrame(FrameConfig{
		Enrolled: true,
		Snap: Snapshot{Admin: AdminState{Pairing: &PairingWindow{
			Pin:     "654321",
			Expires: time.Date(2026, 9, 16, 18, 30, 0, 0, time.UTC),
		}}},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	f.cfg.Actions.AdminPairingStop = func() (bool, error) { return true, nil }

	f.closePairingWindow()

	got := awaitSaid(t, f, ctlAdminPairingStop, design.GoodKey)
	if !strings.Contains(got.text, "closed") {
		t.Errorf("saidUnder(%q).text = %q, want the closed sentence", ctlAdminPairingStop, got.text)
	}
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render after closePairingWindow: %v", err)
	}
	if f.snap.Admin.Pairing != nil {
		t.Errorf("Admin.Pairing = %+v after a successful stop, want nil", f.snap.Admin.Pairing)
	}
}

func TestClosePairingWindowSaysWhenNoneWasOpen(t *testing.T) {
	f := newBareFrame(t)
	f.cfg.Actions.AdminPairingStop = func() (bool, error) { return false, nil }

	f.closePairingWindow()

	got := awaitSaid(t, f, ctlAdminPairingStop, design.MutedKey)
	if got.text != "No pairing window was open." {
		t.Errorf("saidUnder(%q).text = %q, want the none-was-open sentence", ctlAdminPairingStop, got.text)
	}
}

func TestPairingRefusalLeavesTheStateAsItWas(t *testing.T) {
	seeded := &PairingWindow{Pin: "111222", Expires: time.Date(2026, 9, 16, 18, 30, 0, 0, time.UTC)}
	f, err := NewFrame(FrameConfig{
		Enrolled: true,
		Snap:     Snapshot{Admin: AdminState{Pairing: seeded}},
	})
	if err != nil {
		t.Fatalf("NewFrame: %v", err)
	}
	f.cfg.Actions.AdminPairingStop = func() (bool, error) {
		return false, errors.New("the gateway refused: you are not an administrator")
	}

	f.closePairingWindow()

	awaitSaid(t, f, ctlAdminPairingStop, design.BadKey)
	if _, err := renderFrameOffscreen(f, shotW, shotH); err != nil {
		t.Fatalf("render after refused closePairingWindow: %v", err)
	}
	if f.snap.Admin.Pairing != seeded {
		t.Errorf("a refused stop moved Admin.Pairing (%+v) — a refusal must leave the state exactly as it was", f.snap.Admin.Pairing)
	}
}

// -------------------------------------------------------------------------
// The admin tab draws the four new cards — both themes, window open.
// -------------------------------------------------------------------------

func TestAdminScreenRendersThePairingCards(t *testing.T) {
	withWindow := exampleSnapshot()
	withWindow.Admin.Pairing = &PairingWindow{
		Pin:     "012345",
		Ref:     "gw.example.net:2022#" + testPairingFingerprint,
		Expires: time.Date(2026, 9, 16, 18, 30, 0, 0, time.UTC),
	}
	for _, dark := range []bool{false, true} {
		renderFrame(t, renderCfg{screen: "admin", dark: dark, rights: true, snap: withWindow})
	}
	renderFrame(t, renderCfg{screen: "admin", rights: true, snap: exampleSnapshot()})
}
