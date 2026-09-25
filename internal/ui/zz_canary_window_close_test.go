//go:build windows || linux || darwin

package ui

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Canary: a window closes by asking, not by leaving the event loop.
//
// On 21.09.2026 the maintainer pressed Close in the stopped-command
// window and it hung: the title changed to "(Not Responding)", and
// together with it the whole application froze.
//
// The cause is not the button. A gio window is a real operating-system
// window with its own message queue, and the loop goroutine is what
// services it. Leaving the loop on a button press means leaving the
// window on screen with no handler: it will never close and will stop
// responding. Windows reports this in exactly the words the
// maintainer saw.
//
// The right way is w.Perform(system.ActionClose). The window leaves
// on its own, a DestroyEvent arrives, and it is THAT which ends the
// loop: by that moment there is nothing left to ignore.
//
// Checked against the source because a real window cannot be opened
// in tests -- it would hang the whole package. We look for `return`
// inside the FrameEvent branch: it must not contain a single one.
func TestCanary_WindowsCloseByAskingNotByLeaving(t *testing.T) {
	files := []string{
		"gui.go",
		"transcript_window.go",
		"command_window.go",
		"mode_window.go",
		"held_window.go",
		"close_prompt.go",
	}
	// A return indented exactly at the switch-case branch or deeper, but
	// not inside a nested function: such lines are looked at separately
	// below.
	bareReturn := regexp.MustCompile(`^\t{3,4}return\s*$`)

	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		lines := strings.Split(string(src), "\n")
		inFrame := false
		depth := 0
		for i, line := range lines {
			switch {
			case strings.Contains(line, "case app.FrameEvent:"):
				inFrame, depth = true, 0
			case strings.Contains(line, "case app.DestroyEvent:"),
				strings.Contains(line, "case app.ViewEvent:"):
				inFrame = false
			}
			if !inFrame {
				continue
			}
			// Inside nested functions (goroutines, layout closures) a
			// return is an ordinary thing and has nothing to do with the
			// window.
			depth += strings.Count(line, "func(") - strings.Count(line, "}()")
			if depth > 0 {
				continue
			}
			if bareReturn.MatchString(line) {
				t.Errorf("%s:%d leaves the event loop straight from the FrameEvent branch.\n"+
					"The window will stay on screen with no handler and stop responding. "+
					"Use w.Perform(system.ActionClose), and end the loop on DestroyEvent.",
					name, i+1)
			}
		}
	}

	// And the direct half: every window with a close button must know
	// about ActionClose. Its absence is the sign that the button was
	// made a return.
	for _, name := range []string{"mode_window.go", "held_window.go", "close_prompt.go"} {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(src), "system.ActionClose") {
			t.Errorf("%s does not call system.ActionClose -- its close button either does not exist "+
				"or closes the window by leaving the loop", name)
		}
	}
}
