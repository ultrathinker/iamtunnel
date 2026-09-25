//go:build windows || linux || darwin

package ui

// iamt336_onefield_test.go — one box, and a sentence saying what pressing
// the button would do (SPEC §3.6, IAMT-336).
//
// The defect, from the maintainer's live run on 17.09.2026: the gateway prints
// a ready command line — "iamtunnel admin pair <ref> <pin>" — and the card
// had two boxes, one for each half. He copied the printed line whole, as
// anyone would, put it in the first box, and got a refusal naming
// "iamtunnel admin pair 203.0.113.10" as a bad hostname. The refusal was
// perfectly clear; the form was wrong. And the pairing window it belonged
// to lives two minutes, so the puzzling cost the window.

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

const (
	// The gateway of the 17.09 live run, its fingerprint, and the PIN it
	// printed (address masked for publication). Fixtures invented by
	// hand were tried first and were not valid strings at all — which
	// the parser said so plainly that the mistake was mine, not its.
	testFP  = "QkNrqPIt6GyyKc3yrD7qEHbAP4IWCHRO36CwW5QSUSo"
	testRef = "203.0.113.10:2022#SHA256:" + testFP
	testPIN = "812495"
)

// TestIAMT336TheLineTheGatewayPrintsGoesStraightIntoTheBox is the live-run
// defect, as a test: what the gateway prints, pasted whole, must work.
func TestIAMT336TheLineTheGatewayPrintsGoesStraightIntoTheBox(t *testing.T) {
	for _, form := range []struct {
		name string
		text string
	}{
		{"the command line the gateway prints", "iamtunnel admin pair " + testRef + " " + testPIN},
		{"the same line indented, as it is printed", "  iamtunnel admin pair " + testRef + " " + testPIN + "\n"},
		{"reference and PIN, no command", testRef + " " + testPIN},
	} {
		t.Run(form.name, func(t *testing.T) {
			f := newBareFrame(t)
			f.editor(ctlAdminPairJoin).SetText(form.text)

			got, err := f.pastedJoin()
			if err != nil {
				t.Fatalf("pasting %q was refused: %v", form.text, err)
			}
			if got.Secret != testPIN {
				t.Errorf("PIN read as %q, want %q", got.Secret, testPIN)
			}
			if got.Addr() != "203.0.113.10:2022" {
				t.Errorf("gateway address read as %q, want 203.0.113.10:2022", got.Addr())
			}
		})
	}
}

// TestIAMT336ThePreviewNamesTheGatewayAndItsFingerprint pins the rule that
// the box does nothing on its own: before the button acts, the card says
// what it would do. This is the only place a person ever sees the
// gateway's fingerprint before trusting it — no role in this product
// accepts a key on first sight (SPEC §6.2) — so a preview that omitted it
// would quietly remove the check.
func TestIAMT336ThePreviewNamesTheGatewayAndItsFingerprint(t *testing.T) {
	f := newBareFrame(t)
	f.editor(ctlAdminPairJoin).SetText("iamtunnel admin pair " + testRef + " " + testPIN)

	text, key := f.joinPreview()
	if text == "" {
		t.Fatal("a well-formed pairing line previewed nothing — the person is asked to press a button that has not said what it does")
	}
	if !strings.Contains(text, "203.0.113.10") {
		t.Errorf("preview %q does not name the gateway it would bind this machine to", text)
	}
	if !strings.Contains(text, "QkNrqPIt6GyyKc3yrD7qEHbAP4IWCHRO36CwW5QSUSo") {
		t.Errorf("preview %q does not show the host key fingerprint in full — that is the one moment it is checked by eye", text)
	}
	if key != design.InkKey {
		t.Errorf("preview key = %v, want InkKey: a valid line is a statement, not a warning", key)
	}
}

// TestIAMT336AnEmptyBoxPreviewsNothing — a box nobody has typed in has
// done nothing wrong, and a card that greets a person with a refusal
// teaches them to ignore refusals.
func TestIAMT336AnEmptyBoxPreviewsNothing(t *testing.T) {
	f := newBareFrame(t)
	if text, _ := f.joinPreview(); text != "" {
		t.Errorf("an untouched box previewed %q — it must say nothing until there is something to say", text)
	}
}

// TestIAMT336AStringOfTheWrongKindIsNamedAsSuch. Three kinds of string
// are now in circulation, and they look alike. "Not a valid reference"
// would leave a person staring at a string that IS valid — just not here.
func TestIAMT336AStringOfTheWrongKindIsNamedAsSuch(t *testing.T) {
	for _, row := range []struct {
		name, text, want string
	}{
		{
			name: "a machine invitation",
			// Byte-for-byte the invitation the gateway minted on 17.09:
			// the fingerprint sits here bare, without the "SHA256:" prefix,
			// because the ':' would collide with the secret after it.
			text: "iamtunnel-enrol://203.0.113.10:2022#" + testFP + ":7LLu8s2gx4ZM3t9Snibnm7MwL2a3cGfmmX63WiK8x98",
			want: "MACHINE",
		},
		{
			name: "a connection string",
			text: "iamtunnel://203.0.113.10:2022/alice#" + testFP,
			want: "connection string",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			f := newBareFrame(t)
			f.editor(ctlAdminPairJoin).SetText(row.text)

			if _, err := f.pastedJoin(); err == nil {
				t.Fatalf("%s was accepted as a pairing line", row.name)
			} else if !strings.Contains(err.Error(), row.want) {
				t.Errorf("refusal for %s = %q, want it to name what the string actually is (%q)", row.name, err, row.want)
			}
		})
	}
}

// TestIAMT336PressingWithAnEmptyBoxSaysSo — the button must answer, not
// sit there. A dead control is how a person concludes the program is
// broken.
func TestIAMT336PressingWithAnEmptyBoxSaysSo(t *testing.T) {
	f := newBareFrame(t)
	f.joinAsAdmin()
	if got := f.saidUnder(ctlAdminPairJoin); got.text == "" {
		t.Error("pressing Join with an empty box said nothing at all")
	}
}
