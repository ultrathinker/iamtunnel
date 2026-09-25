//go:build windows || linux || darwin

package ui

import (
	"os"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// Canary: the Goal button in the machine row, and the green colour for
// ALLOWED.
//
// Two edits of 21.09.2026, both from a live review with the
// maintainer.
//
//  1. The goal has existed since IAMT-402, but only on Admin ->
//     Access. The maintainer works from the machine list and wants to
//     declare the goal from there: "right now I am putting pictures
//     on the desktop" -- and the classifier stops refusing the
//     obvious. The button in the row opens the same window for the
//     same grant, not a second independent setting.
//
//  2. A command that passed under a permission now answers with the
//     word ALLOWED. The default colouring in the window is RED, on
//     purpose: three times in one day a new gateway outcome fell
//     through into a silent green. So ALLOWED is named explicitly,
//     and this must be guarded: drop the line and a successful run
//     turns red and scares a person who was just asked to press
//     Allow.
func TestCanary_GoalButtonAndAllowedColour(t *testing.T) {
	src, err := os.ReadFile("screens.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)
	// CompactButton, not SecondaryButton: the row is deliberately
	// narrow, and one button from the wide primitive reads as a layout
	// bug.
	if !strings.Contains(text, `design.CompactButton(gtx, f.theme,
							f.btn("client/goal/"+strconv.Itoa(idx)), "Goal")`) {
		t.Error("no Goal button in the machine row -- the goal is set only from Admin -> Access again, " +
			"that is, not where the person works")
	}
	if !strings.Contains(text, "f.openGoalWindow(m.Name)") {
		t.Error("the Goal button is wired to nothing")
	}

	// Colour: ALLOWED must be green, and everything else non-empty red.
	if got := classifyExecStderr("ALLOWED — this command was stopped for review and a person approved it."); got != design.GoodKey {
		t.Errorf("ALLOWED is painted %v, want green -- the person pressed Allow, the command went through, "+
			"and a red answer to that frightens without cause", got)
	}
	if got := classifyExecStderr("STOPPED — this command was not run."); got != design.BadKey {
		t.Errorf("the refusal is painted %v, want red", got)
	}
	if got := classifyExecStderr("E_SOMETHING_NOBODY_HAS_WRITTEN_YET"); got != design.BadKey {
		t.Errorf("an unknown outcome is painted %v, want red: the default must be red, "+
			"or the next new outcome falls through into a quiet green again", got)
	}
}

// Canary: in the goal window everything ABOVE the buttons scrolls, and
// the buttons stay put.
//
// The maintainer asked to check this in advance, while the history is
// a single entry: "the area above the buttons is what scrolls". The
// reason is real -- the gateway remembers up to twenty past goals,
// and as a rigid block under the form they would push Claim and Close
// past the bottom edge of the window. A person with a long history
// would not reach the button the window was opened for.
//
// There is no paging there and none is needed: twenty is the gateway
// ceiling itself (state.MaxGoalHistory); "the rest" does not exist.
func TestCanary_GoalWindowScrollsAboveTheButtons(t *testing.T) {
	src, err := os.ReadFile("goal_window.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(src)

	if !strings.Contains(text, "design.PageScrollbar(theme, &page)") {
		t.Error("the top of the goal window does not scroll -- twenty remembered goals will push the buttons off the edge")
	}
	if !strings.Contains(text, "goalBody(") {
		t.Error("the window contents are not extracted into a scrollable element")
	}
	// The buttons must be OUTSIDE the scroll: Rigid after Flexed(1).
	scroll := strings.Index(text, "design.PageScrollbar(theme, &page)")
	claim := strings.Index(text, "&claimBtn, word")
	if scroll < 0 || claim < 0 || claim < scroll {
		t.Error("the Claim button does not sit AFTER the scrollable area -- it is either inside it or gone")
	}
	if !strings.Contains(text, "layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {\n\t\t\t\t\t\treturn design.PageScrollbar(theme, &page)") {
		t.Error("the scrollable area does not take the remaining height -- the buttons will not be pinned to the bottom")
	}
}
