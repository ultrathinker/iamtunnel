package ui

// C5 canary: the SERVER tab carries a standing line saying the
// machine's agent keeps running after the window closes. The
// maintainer agreed it is needed; not a dialog, a line on the tab.
//
// The canary checks the contents of the screens.go source: the short
// string "keeps running after this window" must be in
// layoutServerScreen. This is cheaper than trying to render and count
// pixels (the Server tab in the sample sits on the edge of Gate 17 --
// any extra content overflows), yet it still deterministically catches
// the regression: if somebody removes the line, the file changes and
// the canary goes red.

import (
	"os"
	"strings"
	"testing"
)

func TestCanary_C5_ServerTabNamesTheAgentKeepsRunning(t *testing.T) {
	body, err := os.ReadFile("screens.go")
	if err != nil {
		t.Fatalf("read screens.go: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "keeps running after this window") {
		t.Fatalf("screens.go has no line \"keeps running after this window\" -- the standing line of C5 is missing from the SERVER tab")
	}
	// Anchor: the line lives inside layoutServerScreen, not somewhere
	// else (e.g. a stray comment).
	start := strings.Index(text, "func (f *Frame) layoutServerScreen")
	if start == -1 {
		t.Fatalf("screens.go no longer contains layoutServerScreen -- the standing line is not where the maintainer expects it")
	}
	end := strings.Index(text[start:], "\n}\n")
	if end == -1 {
		t.Fatalf("could not find the end of layoutServerScreen in screens.go")
	}
	serverScreenBody := text[start : start+end]
	if !strings.Contains(serverScreenBody, "keeps running after this window") {
		t.Fatalf("layoutServerScreen has no line \"keeps running after this window\" -- the standing line of C5 is missing from the SERVER tab")
	}
	// Negative check: not a dialog (C5 explicitly: "not a dialog").
	if strings.Contains(serverScreenBody, "f.say") && strings.Contains(serverScreenBody, "keeps running") {
		t.Fatalf("the line was put into f.say -- that is a dialog, while C5 demands: not a dialog, a standing line on the tab")
	}
}
