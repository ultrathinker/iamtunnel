//go:build windows || linux || darwin

package ui

// Canary for IAMT-341 round 2, aimed at the defect itself rather than
// at the shape of the fix.
//
// Round 1 fed older bytes into the SAME emulator that had already
// swallowed newer ones, and a terminal is a sequential machine: the
// screen came out with NEW above OLD, and with a clear or a cursor move
// in the mix it came out as a screen that could never have existed.
// Other tests pin the parts that were built (Reset, the held range, the
// cap). This one pins the OUTCOME a person sees: after scrolling up,
// the older line must appear above the newer one, and it must do so
// because the whole held range was replayed in order - not because the
// prepended bytes were special-cased somewhere.

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// castLineFor builds one asciinema v2 output event carrying text.
func castLineFor(t *testing.T, text string) []byte {
	t.Helper()
	return []byte(`[0.5,"o",` + quoteJSON(text) + "]\n")
}

func quoteJSON(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\r':
			b.WriteString(`\r`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// TestCanary_BackfillPutsOlderTextAboveNewer.
//
// Canary: in extendBackward, replay only `newBytes` into the existing VT
// instead of building a fresh one over the whole held range (that is
// literally the round-1 code). The transcript then reads NEW then OLD
// and this goes red on the ordering assertion.
func TestCanary_BackfillPutsOlderTextAboveNewer(t *testing.T) {
	s := &sessionScreenState{views: map[string]*sessionView{}}

	newer := castLineFor(t, "NEWER-LINE\r\n")
	older := castLineFor(t, "OLDER-LINE\r\n")

	// The viewer opened mid-recording: it holds only the newer bytes,
	// starting at a non-zero offset, exactly as a tail fetch leaves it.
	v := &sessionView{
		id:         "sess-canary",
		vt:         record.NewVT(80, 24),
		live:       true,
		headOffset: uint64(len(older)),
		held:       append([]byte(nil), newer...),
	}
	v.offset = v.headOffset + uint64(len(v.held))
	v.remainder = record.ParseCast(v.held, nil, v.vt)
	s.views[v.id] = v

	if got := v.vt.Transcript(); !strings.Contains(got, "NEWER-LINE") {
		t.Fatalf("baseline: the newer line is not on screen before the backfill: %q", got)
	}

	// The person scrolls up and the older chunk arrives.
	s.extendBackward(v, older, 0)

	got := v.vt.Transcript()
	iOld := strings.Index(got, "OLDER-LINE")
	iNew := strings.Index(got, "NEWER-LINE")
	if iOld < 0 || iNew < 0 {
		t.Fatalf("after the backfill the screen lost a line: %q", got)
	}
	if iOld > iNew {
		t.Fatalf("the backfilled line is BELOW the newer one:\n%q\nolder at %d, newer at %d - older bytes were replayed after newer ones instead of the whole held range being replayed in order", got, iOld, iNew)
	}

	// And the held range still describes itself honestly.
	if v.headOffset != 0 {
		t.Errorf("headOffset = %d, want 0 after replaying from the start of the recording", v.headOffset)
	}
	if v.offset != v.headOffset+uint64(len(v.held)) {
		t.Errorf("offset %d does not equal headOffset %d + len(held) %d", v.offset, v.headOffset, len(v.held))
	}
}
