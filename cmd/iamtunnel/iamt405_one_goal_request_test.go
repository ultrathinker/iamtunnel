//go:build (windows || linux || darwin) && !nogui

package main

// IAMT-405 canary: the Access tab fills every grant row's goal fields
// from ONE goal.list request. It used to dial goal.history once per
// grant row — a page of N grants cost N round trips for facts one
// reply carries whole. The fact lives in the shape of guiAdminLists,
// not in the rows it returns (the rows came out right either way —
// gui_admin_lists_goal_test.go holds those), so the canary reads the
// source the way iamt399 does.

import (
	"os"
	"strings"
	"testing"
)

func TestIAMT405_TheAccessTabFillsItsGrantRowsFromOneGoalRequest(t *testing.T) {
	body, err := os.ReadFile("gui_actions.go")
	if err != nil {
		t.Fatalf("read gui_actions.go: %v", err)
	}
	text := string(body)
	start := strings.Index(text, "func guiAdminLists")
	if start == -1 {
		t.Fatalf("gui_actions.go no longer has guiAdminLists — the Access tab's lists do not live where this canary looks")
	}
	end := strings.Index(text[start:], "\n}")
	if end == -1 {
		t.Fatalf("could not find the end of guiAdminLists in gui_actions.go")
	}
	fn := text[start : start+end]

	if strings.Contains(fn, "GoalHistory(") {
		t.Fatalf("guiAdminLists still dials goal.history per grant row — a page of N grants costs N round trips instead of the one goal.list request (IAMT-405)")
	}
	if n := strings.Count(fn, "GoalList("); n != 1 {
		t.Fatalf("guiAdminLists calls goal.list %d times, want exactly one request that fills every grant row (IAMT-405)", n)
	}
}
