//go:build windows

package ui

// iamt402_goal_test.go — IAMT-402's own canaries.
//
// Point 4 is the one called out by name: the claim box must
// never carry a goal forward from a previous session with the form,
// open or closed -- "the deadline is a guess, and zeroing it out
// guarantees nobody works under yesterday's goal by accident."
// openGoalForm is pulled out
// of the disclose button's own click handler exactly so this is provable
// without a rendered frame: no pixel could tell "empty because nobody
// typed anything yet" apart from "emptied on purpose", so the state
// itself is the only honest thing to assert on here.

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

func TestOpenGoalFormAlwaysStartsEmpty(t *testing.T) {
	f := newBareFrame(t)
	ctl := "admin/goal/alice/win-srv01"

	f.openGoalForm(ctl) // first open: nothing was ever there
	if got := f.editor(ctl + "/box").Text(); got != "" {
		t.Fatalf("box = %q on the very first open, want empty", got)
	}

	f.editor(ctl + "/box").SetText("copy the nightly export directory")
	f.openGoalForm(ctl) // close, form left with typed-but-unsaved text
	f.openGoalForm(ctl) // reopen

	if got := f.editor(ctl + "/box").Text(); got != "" {
		t.Errorf("box = %q after closing and reopening, want empty — a stale goal must never carry forward (IAMT-402 point 4)", got)
	}
}

// TestOpenGoalFormClearsEvenWithAnAlreadyClaimedGoal guards the more
// dangerous half of the same rule: the box must stay empty on open even
// when a REAL, already-saved goal exists for this grant (Grant.Goal
// is never read by openGoalForm at all) — a person choosing "Change
// goal" must retype or repick, never edit yesterday's answer in place.
func TestOpenGoalFormClearsEvenWithAnAlreadyClaimedGoal(t *testing.T) {
	f := newBareFrame(t)
	ctl := "admin/goal/alice/win-srv01"
	f.snap.Admin.Grants = []Grant{{Person: "alice", Machine: "win-srv01", Goal: "reinstall the customer portal site"}}

	f.openGoalForm(ctl)
	if got := f.editor(ctl + "/box").Text(); got != "" {
		t.Errorf("box = %q opening \"Change goal\" on a grant that already has one, want empty", got)
	}
}

func TestClaimGoalRefusesAnEmptyGoal(t *testing.T) {
	f := newBareFrame(t)
	ctl := "admin/goal/alice/win-srv01"
	called := make(chan struct{})
	f.cfg.Actions.AdminGrantGoal = func(person, machine, goal string) (string, error) {
		close(called)
		return "", nil
	}

	f.claimGoal(ctl, "alice", "win-srv01")

	select {
	case <-called:
		t.Fatal("claimGoal asked the gateway to save an empty goal")
	case <-time.After(guardWait):
	}
	if got := f.saidUnder(ctl); got.key != design.BadKey || got.text == "" {
		t.Errorf("saidUnder(%q) = %+v, want a non-empty BadKey refusal", ctl, got)
	}
}

func TestClaimGoalWithoutARuntimeSaysSo(t *testing.T) {
	f := newBareFrame(t)
	ctl := "admin/goal/alice/win-srv01"
	f.editor(ctl + "/box").SetText("copy the nightly export directory")

	f.claimGoal(ctl, "alice", "win-srv01")

	if got := f.saidUnder(ctl); got.text != noRuntime || got.key != design.BadKey {
		t.Errorf("saidUnder(%q) = %+v, want {%q, BadKey}", ctl, got, noRuntime)
	}
}

func TestClaimGoalSendsTheTypedWords(t *testing.T) {
	f := newBareFrame(t)
	ctl := "admin/goal/alice/win-srv01"
	f.editor(ctl + "/box").SetText("  reinstall the customer portal site  ")

	got := make(chan [3]string, 1)
	f.cfg.Actions.AdminGrantGoal = func(person, machine, goal string) (string, error) {
		got <- [3]string{person, machine, goal}
		return "goal claimed", nil
	}

	f.claimGoal(ctl, "alice", "win-srv01")

	select {
	case call := <-got:
		if call != [3]string{"alice", "win-srv01", "reinstall the customer portal site"} {
			t.Errorf("claimGoal sent %v, want the trimmed goal for exactly this pair", call)
		}
	case <-time.After(guardWait):
		t.Fatal("claimGoal asked the gateway nothing")
	}
}

// TestClassifierIgnoresGoal pins the honest-caveat gate (point 6): the
// caveat must show for "rules" AND for anything the gateway has not
// (yet) said, and must hide for exactly "ai" and "both" — the two
// sources that actually read a claimed goal.
func TestClassifierIgnoresGoal(t *testing.T) {
	for _, tc := range []struct {
		classifier string
		want       bool
	}{
		{"", true},
		{"rules", true},
		{"ai", false},
		{"both", false},
		{"something-future-and-unknown", true},
	} {
		f := newBareFrame(t)
		f.snap.Admin.RiskMode.Classifier = tc.classifier
		if got := f.classifierIgnoresGoal(); got != tc.want {
			t.Errorf("classifierIgnoresGoal() with classifier=%q = %v, want %v", tc.classifier, got, tc.want)
		}
	}
}
