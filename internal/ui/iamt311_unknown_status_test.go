//go:build windows || linux || darwin

package ui

// iamt311_unknown_status_test.go — IAMT-311: a live run showed an
// unprivileged window reading a permission-denied "server status" as a
// confident "sshd not running" / "tunnel offline", while the same
// machine was, in fact, reachable (systemctl/ss/admin machines list all
// agreed). "Could not find out" and "definitely not" are different
// claims, and ServerState.Unknown exists so the screens draw only the
// one they actually know. These pin the pure derivations screens.go
// draws from — no window, no cgo, no offscreen renderer needed, so they
// run on every platform the package builds for.
//
// Canary: drop any one of the Unknown checks below (serverHeadline,
// recordingFact, doorStateText, ServerState.unknownText's fallback) and
// read the corresponding zero-valued fact as a negative one again. Each
// test reddens on its own assertion line, quoting the false confident
// text that came back.

import (
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/ui/design"
)

func TestIAMT311_ServerHeadlineNeverClaimsAtRestWhenUnknown(t *testing.T) {
	_, word, key := serverHeadline(ServerState{Unknown: true})
	if word != "Unknown" {
		t.Fatalf("headline word = %q, want %q — a status that could not be checked must not read as \"At rest\"", word, "Unknown")
	}
	if key != design.WarnKey {
		t.Fatalf("headline color = %v, want design.WarnKey", key)
	}

	// An ordinary idle machine (rights present, genuinely at rest) is
	// unaffected: the zero-valued ServerState still reads "At rest".
	_, wordIdle, _ := serverHeadline(ServerState{})
	if wordIdle != "At rest" {
		t.Fatalf("an ordinary idle snapshot's headline changed to %q — Unknown must not leak into the normal path", wordIdle)
	}
}

func TestIAMT311_RecordingFactNeverClaimsOffWhenUnknown(t *testing.T) {
	s := ServerState{Unknown: true, UnknownReason: "unknown — root privileges are required to check: run \"sudo iamtunnel server status\" in a terminal"}
	if got := recordingFact(s); got != s.UnknownReason {
		t.Fatalf("recording fact = %q, want the unknown reason verbatim (%q) — an unreadable recording state must never say \"off\"", got, s.UnknownReason)
	}

	// Genuinely idle (rights present): unaffected. The WORDS changed on
	// 21.09.2026 -- recording starts when the door opens, not when a
	// person attaches, and the old phrase said the second -- but the
	// property this test guards is the first branch above: unknown is
	// never rendered as "off".
	if got := recordingFact(ServerState{}); got != "off — starts the moment the door opens" {
		t.Fatalf("an ordinary idle snapshot's recording fact changed to %q", got)
	}
}

func TestIAMT311_DoorStateNeverClaimsClosedWhenUnknown(t *testing.T) {
	if got := doorStateText(ServerState{Unknown: true}); got != "unknown" {
		t.Fatalf("door state = %q, want \"unknown\" — a door that could not be checked must not read as \"closed\"", got)
	}
	if got := doorStateText(ServerState{}); got != "closed" {
		t.Fatalf("an ordinary idle door state changed to %q, want \"closed\"", got)
	}
	if got := doorStateText(ServerState{Door: DoorState{State: "open"}}); got != "open" {
		t.Fatalf("a real door state was overridden: got %q, want \"open\"", got)
	}
}

func TestIAMT311_UnknownTextFallsBackWhenReasonIsUnset(t *testing.T) {
	got := ServerState{Unknown: true}.unknownText()
	if got == "" || got == "not running — the door cannot open" {
		t.Fatalf("unknownText() = %q — an unset reason must still read as an honest \"could not check\", never blank or a negative fact", got)
	}

	const reason = "unknown — administrator privileges are required to check"
	if got := (ServerState{Unknown: true, UnknownReason: reason}).unknownText(); got != reason {
		t.Fatalf("unknownText() = %q, want the runtime's own reason (%q) verbatim", got, reason)
	}
}
