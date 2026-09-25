package ui

// C3 canaries: the truth of the interface. Each catches its own
// defect at its own assertion line -- no -race, no timing faking, no
// network dependency.

import (
	"os"
	"strings"
	"testing"
	"time"
)

// readSourceFile reads a file under internal/ui for source-level
// assertions. Returns an error on a missing file or read failure.
func readSourceFile(name string) (string, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// TestCanary_C3_JoinFormStaysAfterTheMachineHasJoined.
//
// Canary: restore the early return of f.layoutAlreadyJoined in
// layoutPairJoinForm -- the test goes red: the sub-tab will not draw
// the input field, because the condition hiding the form has BOTH
// "already joined" and "not joined" separated. The existing canary in
// zz_canary_claim_route_test.go calls joinAsAdmin() directly
// and never goes through the layout -- which is why the regression of
// this branching stayed unnoticed (C3).
func TestCanary_C3_JoinFormStaysAfterTheMachineHasJoined(t *testing.T) {
	f := newBareFrame(t)
	f.SelectTab(TabAdmin)
	f.selectSubTab("Join")

	// A machine that has already joined: identity is non-nil.
	id := &AdminIdentity{
		Person:  "alice",
		Gateway: "gw.example.net:2022",
		HostKey: "SHA256:abc",
	}
	f.snap.Admin.ThisMachine = id

	gtx := newTestLayoutContext(900, 800)
	dims := f.layoutAdminScreen(gtx)
	if dims.Size.Y <= 0 {
		t.Fatalf("layoutAdminScreen returned zero height")
	}

	// The pair-join editor must still exist after the form is laid
	// out, because a person who has joined can still be issued a
	// pairing PIN to promote them.
	ed := f.editor(ctlAdminPairJoin)
	if ed == nil {
		t.Fatalf("Join card has no pair-join editor after the machine has joined — field disappeared behind the early return that used to send the owner to layoutAlreadyJoined")
	}
}

// TestCanary_C3_JoinFormHasAdminNameField pins the
// C3 item: the Join card has an OPTIONAL administrator-name field.
// The wire and the gateway are another track's job; this side is just
// the field and its label.
func TestCanary_C3_JoinFormHasAdminNameField(t *testing.T) {
	f := newBareFrame(t)
	f.SelectTab(TabAdmin)
	f.selectSubTab("Join")

	gtx := newTestLayoutContext(900, 800)
	_ = f.layoutAdminScreen(gtx)

	nameEd := f.editor(ctlAdminPairJoin + "/name")
	if nameEd == nil {
		t.Fatal("Join card has no administrator-name field — C3 explicitly asked for it")
	}
}

// TestCanary_C3_ZeroStartedIsDashNotRevoked pins the live
// wording bug: a session with no Started time used to print
// "since revoked", which reads as "the session existed and was taken
// back". A zero Started means it never began — the answer is the same
// em-dash the rest of the window uses for an absent time.
func TestCanary_C3_ZeroStartedIsDashNotRevoked(t *testing.T) {
	// untilText is the function the live panel now uses; grantUntilText
	// was the wrong one.
	if got := untilText(time.Time{}); got != "—" {
		t.Fatalf("untilText(zero time) = %q, want \"—\" (the honest answer for an absent time)", got)
	}
	if got := grantUntilText(time.Time{}); got != "revoked" {
		t.Fatalf("grantUntilText(zero time) = %q, want \"revoked\" (that wording is correct for grant deadlines, NOT for session start times)", got)
	}
}

// TestCanary_C3_TranscriptNoteIsSelectable pins the
// C3 item: every Said line in the standalone transcript window is
// selectable. The note line was the one that wasn't.
func TestCanary_C3_TranscriptNoteIsSelectable(t *testing.T) {
	body, err := readSourceFile("transcript_window.go")
	if err != nil {
		t.Fatalf("read transcript_window.go: %v", err)
	}
	// The note line is the one Said call in layout() that we want to
	// stay selectable. Pin the variable name in the source so a future
	// revert that passes nil there reddens.
	if !strings.Contains(body, "noteSel") {
		t.Fatalf("transcript_window.go no longer passes noteSel to design.Said -- the note line is unselectable again (C3)")
	}
}

// TestCanary_C3_RussianPhraseGoneFromGuide pins C3
// last paragraph: the only Russian phrase in an otherwise English window
// was the "← you are here" line in design/grid.go's step header.
// Replaced with English.
func TestCanary_C3_RussianPhraseGoneFromGuide(t *testing.T) {
	body, err := os.ReadFile("design/grid.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	text := string(body)
	if strings.Contains(text, "\u0432\u044b\u0020\u0437\u0434\u0435\u0441\u044c") {
		t.Fatalf("design/grid.go still carries the old Russian \"you are here\" line -- the only Russian in the otherwise English window (C3)")
	}
	if !strings.Contains(text, "you are here") {
		t.Fatalf("design/grid.go no longer contains the English phrase \"you are here\" -- the replacement was not made")
	}
}

// TestCanary_C3_PeoplePngDeletedFromRepo pins the
// requirement to remove the stray 109 KB PNG in internal/ui/.
// The file must not exist on disk.
func TestCanary_C3_PeoplePngDeletedFromRepo(t *testing.T) {
	for _, name := range []string{"People", "People.png"} {
		if _, err := os.Stat(name); err == nil {
			t.Fatalf("internal/ui/%s exists -- the stray 109 KB PNG that slipped in with 83db894 must not be in the repo", name)
		}
	}
}
