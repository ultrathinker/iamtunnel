//go:build windows || linux || darwin

package ui

import (
	"strings"
	"testing"
)

// Canary: the settings window does not let a person lock themselves
// behind the approval queue, and says the settings are shared by the
// whole gateway.
//
// On 21.09.2026 the maintainer asked for a settings button in the
// machine row: "one will be able to choose the internal check, or the
// AI check only, or both".
//
// The trap is that choosing "ai" or "both" on a gateway WITHOUT a
// classifier key is a self-shot, and after IAMT-408 a far worse one
// than before: without the key the external check refuses, the
// refusal counts as settled, and EVERY command starts waiting for a
// person. Whoever pressed the button would have locked themselves
// in. The gateway rejects such a transition, and the window must say
// so BEFORE the press -- otherwise the person presses and gets an
// error instead of an explanation.
//
// The second check is about the caption: the button sits in the row
// of ONE machine, while the settings act on the whole gateway.
// Silence here reads as a lie.
func TestCanary_SettingsWindowGuardsAndSaysItIsGatewayWide(t *testing.T) {
	withKey := settingsFacts{Classifier: "rules", Mode: "ask", ClassifierKey: true}
	noKey := settingsFacts{Classifier: "rules", Mode: "ask", ClassifierKey: false}

	for _, want := range []string{"ai", "both"} {
		if got := settingsRefusal(noKey, want); got == "" {
			t.Errorf("without a key the choice %q was not rejected by the window -- a person will press it and lock themselves in: "+
				"without a key the classifier's refusal is settled, and every command joins the approval queue", want)
		}
		if got := settingsRefusal(withKey, want); got != "" {
			t.Errorf("with a key the choice %q was rejected without cause: %q", want, got)
		}
	}
	if got := settingsRefusal(noKey, "rules"); got != "" {
		t.Errorf("the return to rules was rejected (%q) -- it is the only way out and must work always", got)
	}

	// Every choice must explain itself: three words, all of them
	// sounding reasonable, and without an explanation a person picks
	// at random.
	for _, word := range riskSourceWords {
		if strings.TrimSpace(riskSourceExplained(word)) == "" {
			t.Errorf("the choice %q is not explained", word)
		}
	}
	for _, word := range riskModeWords() {
		if strings.TrimSpace(riskModeExplained(strings.ToLower(word))) == "" {
			t.Errorf("the mode %q is not explained", word)
		}
	}

	// And the value's origin: a live switch outlives a restart, so
	// "both" from the file and "both" from a press are different
	// facts, and the window must tell them apart.
	if originWord("live") == "" || originWord("config") == "" {
		t.Error("the window does not distinguish a config-file setting from one switched live")
	}
	if originWord("live") == originWord("config") {
		t.Error("the origin of a live value and a file value reads the same")
	}
}

// Canary: the mode word list in the settings window is NOT its own.
//
// live_watch.go already has riskModeWords(), and next to it stands
// why there is only one: a separate canary checks it against the
// gateway's constants, and that works only while the list is exactly
// one. A second list would drift from the first silently.
func TestCanary_SettingsWindowReusesTheOneModeList(t *testing.T) {
	src, err := readSourceFile("settings_window.go")
	if err != nil {
		t.Fatalf("settings_window.go: %v", err)
	}
	if strings.Contains(src, `"log", "warn", "ask", "block"`) {
		t.Error("the settings window keeps its own list of modes instead of riskModeWords() -- " +
			"the canary that checks it against the gateway's constants reads only that one")
	}
	if !strings.Contains(src, "riskModeWords()") {
		t.Error("the settings window does not call riskModeWords()")
	}
}
