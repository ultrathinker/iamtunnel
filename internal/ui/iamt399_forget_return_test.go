package ui

// IAMT-399 canary: the hint under the FORGET button must answer the
// question a person actually has after pressing it — "how do I get
// back?" — with the two facts the code guarantees but the hint kept
// quiet about: Forget leaves the machine key on disk (ForgetConnection
// drops only the connection record), and the way back is the gateway's
// connection string on the Client tab, which needs neither a claim
// line nor its PIN (guiSaveConnection parses the string directly).
//
// The canary reads screens.go the way zz_canary_c5serverline
// does: rendering the Admin tab to count pixels of one Hint is dearer
// than reading the source, and gate 17 already measures the tab for
// overflow. Deleting either fact re-reddens this test.

import (
	"os"
	"strings"
	"testing"
)

func TestIAMT399_TheForgetHintTellsHowToComeBack(t *testing.T) {
	body, err := os.ReadFile("screens.go")
	if err != nil {
		t.Fatalf("read screens.go: %v", err)
	}
	text := string(body)
	start := strings.Index(text, "func (f *Frame) layoutAlreadyJoined")
	if start == -1 {
		t.Fatalf("screens.go no longer has layoutAlreadyJoined — the Forget hint does not live where this canary looks")
	}
	end := strings.Index(text[start:], "\n}\n")
	if end == -1 {
		t.Fatalf("could not find the end of layoutAlreadyJoined in screens.go")
	}
	hint := text[start : start+end]

	for _, fact := range []struct {
		needle, why string
	}{
		{"the machine key stays on disk", "Forget must say it does not erase this machine's key (only the connection record goes)"},
		{"connection string", "the hint must name the way back: the gateway's connection string"},
		{"Client tab", "the hint must say where the connection-string form lives"},
		{"no claim line, no PIN", "the hint must say the way back needs neither a claim line nor its PIN"},
	} {
		if !strings.Contains(hint, fact.needle) {
			t.Fatalf("the Forget hint in layoutAlreadyJoined does not say %q — %s (IAMT-399)", fact.needle, fact.why)
		}
	}
}
