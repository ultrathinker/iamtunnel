//go:build windows || linux || darwin

package ui

// iamt336_pickers_test.go — the parts of the 1.3 "as little typing as
// possible" work that a screenshot cannot check.
//
// Three cards used to ask for values the program already knew. Grant
// access asked for a person's name and a machine's name, both of them
// sitting in a list a finger's width above on the same page, and then
// for an expiry written as RFC 3339 — "2026-09-13T18:00:00Z" — which is
// a machine's way of writing a time and which nobody types right first
// go. The pickers offer those; the boxes stay, because a person added a
// second ago is not in the snapshot yet and no four presets will ever
// hold the one moment somebody genuinely needs.
//
// What is tested here is what a picture would not show: that the value a
// press writes is the value the gateway will accept, that "until
// revoked" writes the empty string the command reads as indefinite
// rather than the words, and that the offset is measured from the moment
// of the press.

import (
	"strings"
	"testing"
	"time"
)

// TestUntilPresetsWriteWhatTheGatewayAccepts. The box's own hint says
// "RFC 3339"; a preset that wrote anything else would be a control that
// fills a box with something the button beside it then refuses.
func TestUntilPresetsWriteWhatTheGatewayAccepts(t *testing.T) {
	now := time.Date(2026, 9, 17, 11, 30, 0, 0, time.UTC)

	for _, row := range []struct {
		word string
		want time.Duration
	}{
		{"1 hour", time.Hour},
		{"8 hours", 8 * time.Hour},
		{"24 hours", 24 * time.Hour},
	} {
		t.Run(row.word, func(t *testing.T) {
			got, ok := untilFromPreset(row.word, now)
			if !ok {
				t.Fatalf("%q is drawn as a preset but is not one", row.word)
			}
			at, err := time.Parse(time.RFC3339, got)
			if err != nil {
				t.Fatalf("preset %q wrote %q, which is not RFC 3339 — the box's own hint promises it is: %v", row.word, got, err)
			}
			if d := at.Sub(now); d != row.want {
				t.Errorf("preset %q is %s from now, want %s", row.word, d, row.want)
			}
		})
	}
}

// TestUntilRevokedWritesTheEmptyBox. "admin grants grant" already reads
// an empty until as indefinite, and the box's hint says so. Writing the
// words "until revoked" instead would send the gateway a value it would
// have to learn, to mean the thing the empty string already means.
func TestUntilRevokedWritesTheEmptyBox(t *testing.T) {
	got, ok := untilFromPreset("until revoked", time.Now())
	if !ok {
		t.Fatal(`"until revoked" is drawn as a preset but is not one`)
	}
	if got != "" {
		t.Errorf(`"until revoked" wrote %q; an indefinite grant is the EMPTY box (see grantAccess and admin grants grant)`, got)
	}
}

// TestAnUnknownPresetWritesNothing — the press handler asks this
// function whether a word was one of its own, and a "yes" for a word it
// does not know would clear the box the person just typed into.
func TestAnUnknownPresetWritesNothing(t *testing.T) {
	if _, ok := untilFromPreset("", time.Now()); ok {
		t.Error("the empty word — what a picker reports when nothing was pressed — was treated as a preset, which would clear the box on every frame")
	}
	if _, ok := untilFromPreset("next tuesday", time.Now()); ok {
		t.Error("a word no preset offers was accepted")
	}
}

// TestUntilPresetsAreMeasuredFromThePress. A card can sit open on screen
// for an hour. If the instant were computed when the card was drawn, the
// grant would be short by however long the person took to decide — and
// "1 hour" would quietly mean "no time at all" on a card left open that
// long.
func TestUntilPresetsAreMeasuredFromThePress(t *testing.T) {
	early := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	late := early.Add(90 * time.Minute)

	a, _ := untilFromPreset("1 hour", early)
	b, _ := untilFromPreset("1 hour", late)
	if a == b {
		t.Fatalf("the same preset pressed 90 minutes apart wrote the same instant %q — it is measured from something other than the press", a)
	}
	at, err := time.Parse(time.RFC3339, b)
	if err != nil {
		t.Fatalf("parse %q: %v", b, err)
	}
	if !at.Equal(late.Add(time.Hour)) {
		t.Errorf("pressed at %s, wrote %s, want %s", late, at, late.Add(time.Hour))
	}
}

// TestThePickersOfferWhatTheGatewayNamed. The lists come from the same
// snapshot the page draws above them; a picker offering a name the
// gateway does not have would fill the box with a refusal waiting to
// happen.
func TestThePickersOfferWhatTheGatewayNamed(t *testing.T) {
	people := peopleNames([]Person{
		{Name: "alice", Admin: true},
		{Name: ""}, // a half-built row must not become a blank choice
		{Name: "bob"},
	})
	if strings.Join(people, ",") != "alice,bob" {
		t.Errorf("peopleNames = %v, want the named people in order and nothing else", people)
	}

	machines := machineNames([]AdminMachine{
		{Name: "win-srv01", State: "verified"},
		{Name: ""},
		{Name: "backup-db02", State: "enrolled"},
	})
	if strings.Join(machines, ",") != "win-srv01,backup-db02" {
		t.Errorf("machineNames = %v, want the named machines in order and nothing else", machines)
	}
}

// TestPickInToEmptyListDrawsNothing is the state a fresh gateway is in:
// no people, no machines. An empty strip would be a line of nothing
// under the box, which reads as a control that broke rather than as one
// with nothing to offer.
func TestPickInToEmptyListDrawsNothing(t *testing.T) {
	if got := peopleNames(nil); len(got) != 0 {
		t.Errorf("peopleNames(nil) = %v, want nothing to offer", got)
	}
	if got := machineNames(nil); len(got) != 0 {
		t.Errorf("machineNames(nil) = %v, want nothing to offer", got)
	}
}

// TestPairingOneLineIsWhatTheOtherMachineParses closes the loop of SPEC
// §3.6: the string the Pairing card prints must be the string the Join
// box on the other machine reads. The two live in different packages and
// nothing but a test makes them agree.
func TestPairingOneLineIsWhatTheOtherMachineParses(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	w := &PairingWindow{
		Pin:     testPIN,
		Ref:     testRef,
		Expires: now.Add(2 * time.Minute),
	}

	line := pairingOneLine(w, now)
	if line == "" {
		t.Fatal("an open pairing window printed no line at all — the card's whole purpose since 1.3 is the one string it hands over")
	}

	f := newBareFrame(t)
	f.editor(ctlAdminPairJoin).SetText(line)
	got, err := f.pastedJoin()
	if err != nil {
		t.Fatalf("the line the Pairing card prints was refused by the Join box that must read it: %q — %v", line, err)
	}
	if got.Secret != testPIN {
		t.Errorf("PIN round-tripped as %q, want %q", got.Secret, testPIN)
	}
	if got.Addr() != "203.0.113.10:2022" {
		t.Errorf("gateway round-tripped as %q, want 203.0.113.10:2022", got.Addr())
	}
}

// TestALapsedPairingWindowPrintsNoLine. The facts below keep showing the
// reference, because it is still true that this gateway was named. The
// one-line form is an instruction to act, and handing somebody an
// instruction that can only fail is worse than handing them nothing.
func TestALapsedPairingWindowPrintsNoLine(t *testing.T) {
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	w := &PairingWindow{Pin: testPIN, Ref: testRef, Expires: now.Add(-time.Second)}
	if got := pairingOneLine(w, now); got != "" {
		t.Errorf("a window that closed a second ago still printed %q to send to somebody", got)
	}
	if got := pairingOneLine(nil, now); got != "" {
		t.Errorf("a card with no window at all printed %q", got)
	}
}
