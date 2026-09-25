//go:build windows || linux || darwin

package ui

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Canary: every second window has its own font shaper.
//
// On 21.09.2026 the maintainer caught a crash, and the stack read
// straight out: "index out of range [58] with length 57" inside gio
// text.Shaper.NextGlyph, thrown from the mode window -- and the same
// panic in the main window the same second.
//
// The cause: every window lives in its own goroutine but drew with
// the frame's theme, and the theme holds one *text.Shaper. The shaper
// keeps the run being parsed in its own fields and is not built for
// two goroutines: the second window overwrites the first one's
// position, and somebody indexes past the end of the run. The main
// window always draws, so ANY second window was a coin toss.
//
// The defect lived since the transcript window (IAMT-366) and did not
// surface: that window is opened rarely. Three new windows in two
// days made it a matter of time.
//
// The check goes over the source, not over a run: a real window
// cannot be opened in tests, it would hang the whole package. We look
// in every open*Window for a pass of f.theme -- bringing it back
// means bringing the race back.
func TestCanary_SecondWindowsGetTheirOwnShaper(t *testing.T) {
	files := []string{
		"transcript_window.go",
		"command_window.go",
		"mode_window.go",
		"close_prompt.go",
	}
	// f.theme anywhere in these files' bodies: they are entirely about
	// the second window, and they have no legitimate reason to take the
	// frame's theme.
	bad := regexp.MustCompile(`\bf\.theme\b`)
	found := 0
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		text := string(src)
		if !strings.Contains(text, "f.windowTheme()") {
			t.Errorf("%s does not call f.windowTheme() -- the window draws with somebody else's shaper, "+
				"and that is the very race that crashed on 21.09", name)
		}
		for i, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			if bad.MatchString(line) {
				found++
				t.Errorf("%s:%d passes f.theme to a second window: %s\n"+
					"The frame theme's shaper is busy with the main window; f.windowTheme() is needed",
					name, i+1, strings.TrimSpace(line))
			}
		}
	}
	if testing.Verbose() {
		t.Logf("files checked: %d, violations: %d", len(files), found)
	}
}
