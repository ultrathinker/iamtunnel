//go:build windows || linux || darwin

package ui

import (
	"os"
	"strings"
	"testing"
)

// Canary: the gateway policy has ONE editing form, not two.
//
// 21.09.2026. The mode (log/warn/ask/block) could be changed in two
// places at once: with the segments on the Admin -> Safety tab and in
// the window opened by the square button from the machine row. The
// check source (rules/ai/both) lived only in the window. The result
// was a form where half of the pair is configured here, the other
// half somewhere else, and the first half there as well.
//
// Why that is bad, given both halves call the same action: the form
// pressed less often falls behind. It is the first to stop showing a
// new field, the first to start lying about the current state, and
// the last to learn of a gateway refusal. A safety setting does not
// forgive that: a person changes the mode in the forgotten form, sees
// the confirmation and leaves -- while next to it sits a second form
// with a different truth.
//
// The window won: it is the only one holding the PAIR whole -- who
// judges the command and what is done with a red answer -- and that
// is exactly what the maintainer asked for: "show all the settings
// for this server there, in a pop-up". The Safety tab kept its own
// job: to say in words what the policy is now and to open the editor
// with one press.
//
// The canary reads the source: segmented choice by riskModeWords()
// or riskSourceWords() lives only in settings_window.go.
func TestCanary_OnePolicyEditor(t *testing.T) {
	const owner = "settings_window.go"

	files, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	seen := false
	for _, e := range files {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		text := string(src)
		if !strings.Contains(text, "design.Segmented(") {
			continue
		}
		for _, list := range []string{"riskModeWords()", "riskSourceWords"} {
			if !strings.Contains(text, list) {
				continue
			}
			if name == owner {
				seen = true
				continue
			}
			t.Errorf("%s chooses %s with segments -- that is a second gateway policy editor. "+
				"The editor is one, it lives in %s; the page shows the state in words and "+
				"opens it with a button", name, list, owner)
		}
	}
	if !seen {
		t.Fatalf("no segmented policy choice found in %s -- "+
			"the canary has gone blind: either the file was renamed or the editor moved away", owner)
	}
}
