package ui

// IAMT-406: the goal of the grant, reachable from the machine row's own
// window rather than only from the Admin tab.
//
// The window itself cannot be entered by a test -- openModeWindow panics
// in a test binary on purpose, because a real operating-system window
// opened by `go test` hangs the package's whole run. What CAN be held is
// the part that decides WHICH grant's goal the window is about, and that
// is the part with a way to be wrong: a fetch answers with every grant on
// the gateway, and picking the wrong row would show one person's goal
// under another's machine and then overwrite it.

import "testing"

func TestGoalOfPicksThisGrantOnly(t *testing.T) {
	lists := AdminLists{
		Grants: []Grant{
			{Person: "alice", Machine: "other-vm", Goal: "wrong machine"},
			{Person: "bob", Machine: "win-test-vm", Goal: "wrong person"},
			{
				Person:      "alice",
				Machine:     "win-test-vm",
				Goal:        "reinstalling this IIS site",
				RecentGoals: []string{"reinstalling this IIS site", "copying a directory"},
			},
		},
		RiskMode: RiskMode{Classifier: "both"},
	}

	got := goalOf(lists, "alice", "win-test-vm")
	if !got.Found {
		t.Fatalf("goalOf: Found = false, want true — the pair is listed")
	}
	if got.Goal != "reinstalling this IIS site" {
		t.Errorf("goalOf: Goal = %q, want the alice/win-test-vm goal", got.Goal)
	}
	if len(got.Recent) != 2 || got.Recent[0] != "reinstalling this IIS site" {
		t.Errorf("goalOf: Recent = %v, want this grant's own two", got.Recent)
	}
	if got.Classifier != "both" {
		t.Errorf("goalOf: Classifier = %q, want both", got.Classifier)
	}
}

// A grant the gateway does not list is not the same as a grant with no
// goal: the window says so in different words, so the two must not
// collapse into one another here.
func TestGoalOfReportsMissingPair(t *testing.T) {
	lists := AdminLists{
		Grants:   []Grant{{Person: "alice", Machine: "other-vm", Goal: "something"}},
		RiskMode: RiskMode{Classifier: "rules"},
	}

	got := goalOf(lists, "alice", "win-test-vm")
	if got.Found {
		t.Errorf("goalOf: Found = true for a pair the gateway did not list")
	}
	if got.Goal != "" {
		t.Errorf("goalOf: Goal = %q, want empty for a pair that is not there", got.Goal)
	}
}

// The window and the Admin tab must answer "does a goal reach the
// classifier at all" the same way, including for a gateway that has not
// said which classifier it runs (SPEC IAMT-402 point 6).
func TestClassifierIgnoresGoalWord(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ignore bool
	}{
		{"ai", false},
		{"both", false},
		{"rules", true},
		{"", true},
		{"something-newer", true},
	} {
		if got := classifierIgnoresGoalWord(tc.name); got != tc.ignore {
			t.Errorf("classifierIgnoresGoalWord(%q) = %v, want %v", tc.name, got, tc.ignore)
		}
	}

	// The Frame's own question is the same question, so it must not
	// grow a second answer.
	f := &Frame{}
	f.snap.Admin.RiskMode.Classifier = "both"
	if f.classifierIgnoresGoal() {
		t.Errorf("classifierIgnoresGoal: true under classifier both")
	}
	f.snap.Admin.RiskMode.Classifier = "rules"
	if !f.classifierIgnoresGoal() {
		t.Errorf("classifierIgnoresGoal: false under classifier rules")
	}
}
