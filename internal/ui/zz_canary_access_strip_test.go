//go:build windows || linux || darwin

package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

// Canary: the strip above the tabs says what it has checked, and not
// a word more.
//
// 21.09.2026. The strip wrote "Recording -- alice is working on this
// machine until 18:00 UTC". Behind those words stands ONE boolean
// answer of the control port: the door is open. Nobody has to be
// inside.
//
// And the same window, two tabs to the right, said the opposite: the
// Session tab and Admin -> Live ask the gateway about CONNECTED
// terminals and answered "nobody is inside any machine at this
// moment". A person who saw the strip went to look -- and had to
// decide which of the window's own screens not to believe.
//
// Worse: on a live installation the name and the deadline have no
// source. serverStateFromControlReply puts in one nameless session
// with no deadline, and the strip printed "-- is working on this
// machine until --", just to keep the shape of a sentence.
func TestCanary_AccessStripSaysOnlyWhatItChecked(t *testing.T) {
	// 1. The door is open, and who and until when is unknown. This is
	// exactly the case that arrives from a live machine.
	got := accessStripText(ServerState{Sessions: []Session{{}}})
	if strings.Contains(got, "until") {
		t.Errorf("the strip names a deadline it does not know: %q. "+
			"The shape of a sentence is no reason to invent a fact", got)
	}
	// A dash placeholder: "-- is working" or "until --".
	if strings.Contains(got, "— is") || strings.HasSuffix(got, "—") {
		t.Errorf("the strip prints a dash instead of an unknown fact: %q", got)
	}
	if strings.Contains(strings.ToLower(got), "is working") ||
		strings.Contains(strings.ToLower(got), "recording") {
		t.Errorf("the strip claims somebody is working on the machine: %q. "+
			"It checked exactly one thing -- that the door is open; connected "+
			"terminals are answered by Session and Admin -> Live, and that is "+
			"a different question", got)
	}
	if !strings.Contains(strings.ToLower(got), "access is open") {
		t.Errorf("the strip does not name what it really checked: %q", got)
	}

	// 2. The name is known -- we say it. The deadline is known -- we say it.
	until := time.Date(2026, 9, 12, 18, 0, 0, 0, time.UTC)
	got = accessStripText(ServerState{Sessions: []Session{{Person: "alice", Until: until}}})
	if !strings.Contains(got, "alice") {
		t.Errorf("the known name is not named: %q", got)
	}
	if !strings.Contains(got, "2026-09-12 18:00 UTC") {
		t.Errorf("the known deadline is not named: %q", got)
	}
	if strings.Contains(strings.ToLower(got), "is working") {
		t.Errorf("the strip still claims presence: %q", got)
	}

	// 3. There is a name, no deadline -- we stay silent about the
	// deadline instead of drawing a dash.
	got = accessStripText(ServerState{Sessions: []Session{{Person: "alice"}}})
	if strings.Contains(got, "until") || strings.HasSuffix(got, "—") {
		t.Errorf("the deadline is unknown, yet the strip talks about it: %q", got)
	}

	// 4. The others are not lost.
	got = accessStripText(ServerState{Sessions: []Session{{Person: "alice"}, {}, {}}})
	if !strings.Contains(got, "+2 more") {
		t.Errorf("the strip lost the others: %q", got)
	}
}

// Canary: every deadline says how much of it is left.
//
// The maintainer gets "closes itself 2026-09-12 16:42 UTC" on screen --
// about a window that lives TWO MINUTES and hands gateway
// administrator rights to whoever finishes reading the line in time.
// Nobody can subtract in their head faster than the window closes.
//
// The absolute label stays: it is unambiguous, survives a screenshot,
// and is needed by two people comparing records. The remainder goes
// NEXT TO IT.
func TestCanary_DeadlinesSayHowMuchIsLeft(t *testing.T) {
	now := time.Date(2026, 9, 12, 16, 40, 0, 0, time.UTC)
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, "expired"},
		{-time.Second, "expired"},
		// Seconds -- because the pairing window is measured in them.
		{30 * time.Second, "30 s left"},
		{107 * time.Second, "1:47 left"},
		{7 * time.Second, "7 s left"},
		// Up to ten minutes seconds are still visible; past that there
		// is no need.
		{9*time.Minute + 5*time.Second, "9:05 left"},
		{42 * time.Minute, "42 m left"},
		{time.Hour + 19*time.Minute, "1 h 19 m left"},
		// More than a day -- in days: nobody reads "73 h 12 m".
		{73 * time.Hour, "3 d left"},
	}
	for _, c := range cases {
		if got := leftText(now.Add(c.in), now); got != c.want {
			t.Errorf("leftText(+%v) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := leftText(time.Time{}, now); got != "no deadline" {
		t.Errorf("the open-ended case = %q -- a dash here would mean \"unknown\", "+
			"while this is known and means \"never\"", got)
	}
	// And zero seconds does not turn into "1:7 left".
	if got := leftText(now.Add(61*time.Second), now); got != "1:01 left" {
		t.Errorf("leftText(+61s) = %q, want %q", got, "1:01 left")
	}
}

// Canary: the pairing card says whether the window is OPEN and what
// the orange button does while it is open.
//
// The screen had the line, the PIN and the closing time -- and both
// buttons at once, OPEN WINDOW and Close now, without a single word
// about the state of the card. As far as a reader could tell, the
// orange button might open a second window, restart this one, or wipe
// the already-sent PIN. It does a third thing: cmdAdminPairingStart
// replaces the open window with a single record, and the old PIN stops
// working that very moment (PROTOCOL 3.4).
func TestCanary_PairingCardNamesItsState(t *testing.T) {
	now := time.Date(2026, 9, 16, 18, 30, 0, 0, time.UTC)

	word, _ := pairingWindowState(nil, now)
	if !strings.Contains(strings.ToLower(word), "no window") {
		t.Errorf("with no window the card says %q", word)
	}

	open := &PairingWindow{Pin: "012345", Ref: "gw:2022#fp", Expires: now.Add(time.Minute)}
	word, key := pairingWindowState(open, now)
	if !strings.Contains(word, "OPEN") {
		t.Errorf("with the window open the card does not say it is open: %q", word)
	}
	if key != design.WarnKey {
		t.Errorf("the open window is not drawn as a warning -- a line handing out " +
			"administrator rights is not an everyday fact")
	}

	lapsed := &PairingWindow{Pin: "012345", Ref: "gw:2022#fp", Expires: now.Add(-time.Second)}
	word, _ = pairingWindowState(lapsed, now)
	if !strings.Contains(strings.ToLower(word), "closed") {
		t.Errorf("the closed window is described as %q", word)
	}
}
