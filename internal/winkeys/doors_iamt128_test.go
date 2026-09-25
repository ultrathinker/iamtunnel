package winkeys

// doors_iamt128_test.go — IAMT-128, a file-level guard at the winkeys level.
//
// **The winkeys contract** this test checks: one `Install` call with
// the same `doorID` already recorded in the file is **idempotent**.
// Collapsing a matching `doorID` via `filterDoorLines`
// (`winkeys/doors.go:294–298`) is the ONLY protection
// `winkeys.Door.Install` is REQUIRED to provide by contract; everything
// else ("do not write a foreign line", "do not sweep") lives above it —
// in the gateway's state machine and in `doorController`.
//
// **Why this test does not close out the whole IAMT-128 rule.** The
// rule "exactly one of our access lines per machine" is NOT held at
// the winkeys level. `winkeys.Door.Install` deliberately does NOT
// collapse lines with a **foreign** doorID (that is IAMT-136: `door.open
// has no right to sweep`). If the gateway's state machine, for
// whatever reason, sent two `door.open` calls with different ids back
// to back, winkeys would honestly write both — that is its contract,
// and `TestInstallDoesNotSweepForeignDoorLines`
// (`winkeys/doors_iamt136_test.go:35–102`) pins exactly that behavior
// as mandatory.
//
// The guard against "do not send a second `door.open`" lives in
// `core/door.go:404` (`openReserve`) and `:377` (`openingReserve`); it
// is covered by `TestIAMT128SecondReservationWaitsNotGeneratesNewDoor`
// (`internal/gateway/core/door_iamt128_test.go`). If rule A is broken —
// a second `door.open` reaches the machine, and the machine itself
// (`server/door.go:118–127`) replies `E_CONTROL_DOOR_CONFLICT`. This
// second `door.open` never reaches winkeys, and the file stays with
// one line.
//
// This test's guard is **belt C**: `winkeys.Door.Install`
// (a) serializes concurrent writes through `d.mu` and
// `AcquireFileLock`, and (b) collapses a repeated Install with the same
// `doorID` even under a goroutine race. If (a) or (b) were
// broken, two simultaneous Installs with one `doorID` would leave
// two of our valid lines in the file.
//
// The test must fail on ITS OWN assertion line, not during setup.
// Setup is an empty `t.TempDir()`; the only nontrivial
// check is `strings.Count` over the file's contents.
//
// CANARY IAMT-128 1 — prediction: if winkeys/doors.go:284-300
// (installLocked) drops **both** branches — the `sameID` collapse and
// the `else` branch that "just appends" — and replaces them with an
// unconditional `appendDoorLine(raw, line)`, this test fails on its
// assertion line:
//
//   after two simultaneous door.open calls with one id, the file ended
//   up with 2 valid lines of ours, not 1 — uniqueness is not held
//   even for its own id: "<file contents>"
//
// In that case, no belt of writer protection holds the invariant even
// at the level of its own id. Setup (an empty t.TempDir()) is not affected.
// CRITICAL: this canary must NOT trip IAMT-136 —
// `TestInstallDoesNotSweepForeignDoorLines` checks that foreign and
// corrupted lines of ours remain. The IAMT-128 canary breaks
// **collapsing one's own id** (the `sameID` branch), not the protection
// of foreign lines. These are different edits.

import (
	"os"
	"strings"
	"sync"
	"testing"
)

// TestTwoConcurrentInstallsWithSameIDKeepOneOurLine pins the idempotence
// of `winkeys.Door.Install` under a goroutine race: even if two `Install`
// calls for one `doorID` arrive in parallel (which in a real system
// means "one `door.open` was sent twice" — for example, a reconnect
// without removing the previous line), the file ends up with **exactly
// one** valid line of ours for that id.
//
// The test does NOT check "exactly one line per machine" — that
// invariant is held above this, in the gateway's state machine
// (`core/door.go:404`, `:377`) and in `doorController`
// (`server/door.go:118–127`). This test checks the bottom belt — that
// the writer does not duplicate the line for its own id under a race.
func TestTwoConcurrentInstallsWithSameIDKeepOneOurLine(t *testing.T) {
	path := tempKeyFile(t)

	d := tempDoorWithPath(t, path)

	id := randomDoorID(t)
	if id == "" {
		t.Fatalf("test setup error: randomDoorID returned an empty string")
	}
	line := FormatLine(id, TestKey)
	// gotID, not id: the short := shadowed the outer id, turning the
	// comparison into id != id — a check that can never fire — and a
	// message that printed the same value twice. Caught by
	// staticcheck SA4000 after acceptance.
	if gotID, _, valid, corrupt := isDoorLine(line); !valid || corrupt || gotID != id {
		t.Fatalf("test setup error: line %q must be our valid line for doorID=%q, got id=%q valid=%v corrupt=%v",
			line, id, gotID, valid, corrupt)
	}

	// Starting point: both goroutines enter Install as close together
	// as possible. Install already serializes writes through d.mu and
	// the cross-process file lock; the test's job is to catch a
	// violation of idempotence even under correct serialization.
	// Placing a cross-goroutine barrier inside Install would be a
	// mistake: the test would end up checking our own barrier, not
	// Install's contract.
	var start sync.WaitGroup
	start.Add(1)
	var done sync.WaitGroup
	done.Add(2)

	go func() {
		defer done.Done()
		start.Wait()
		if err := d.Install(id, TestKey); err != nil {
			t.Errorf("door.open #1 (%s) refused on a valid fixture: %v", id, err)
		}
	}()
	go func() {
		defer done.Done()
		start.Wait()
		if err := d.Install(id, TestKey); err != nil {
			t.Errorf("door.open #2 (%s) refused on a valid fixture: %v", id, err)
		}
	}()
	start.Done()
	done.Wait()

	// Byte-level check: read the file bypassing winkeys (os.ReadFile, not
	// Door.ReadLines) and count valid lines via IsOurs.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file after two Installs: %v", err)
	}

	if n := strings.Count(string(got), line+"\r\n"); n != 1 {
		t.Fatalf("after two simultaneous door.open calls with one id the file ended up with %d instances of line %q, want exactly one — uniqueness is not held even for its own id: %q",
			n, line, string(got))
	}
}

// TestSecondInstallWithDifferentIDAppendsButInstallContractDocumentsIt
// documents **observed** winkeys behavior: a repeated Install with a
// **different** doorID honestly appends a line rather than collapsing
// the previous one. This is contractual behavior of
// `winkeys.Door.Install` (see the comment in `winkeys/doors.go:284–300`
// and `doors_iamt136_test.go`), and it does NOT contradict the
// IAMT-128 rule — because the rule "exactly one line per machine" is
// enforced above this, in the gateway's state machine
// (`core/door.go:404`, `:377`) and in `doorController`
// (`server/door.go:118–127`). This test guards against a future
// rework of `installLocked` accidentally introducing "collapse all of
// our lines" (which would break IAMT-136).
//
// The test is NOT meant to pass under canary 1
// (see the file header): canary 1 removes the collapsing of one's own
// doorID, and then *this* test also fails — but on its own
// assertion, not during setup.
func TestSecondInstallWithDifferentIDAppendsButInstallContractDocumentsIt(t *testing.T) {
	path := tempKeyFile(t)

	d := tempDoorWithPath(t, path)

	idA := randomDoorID(t)
	idB := randomDoorID(t)
	if idA == idB {
		t.Fatalf("test setup error: random idA and idB collided (%q)", idA)
	}
	lineA := FormatLine(idA, TestKey)
	lineB := FormatLine(idB, TestKey)

	if err := d.Install(idA, TestKey); err != nil {
		t.Fatalf("first door.open (%s) refused: %v", idA, err)
	}
	if err := d.Install(idB, TestKey); err != nil {
		t.Fatalf("second door.open (%s) refused: %v (Install with a different id must be accepted per the IAMT-136 contract)", idB, err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}

	// Per contract: both lines are in the file. Install with a
	// different id **appends**, it does not collapse. This is
	// documented behavior that protects IAMT-136. If someone ever adds
	// "collapse all of our lines", this test catches the regression.
	if n := strings.Count(string(got), lineA+"\r\n"); n != 1 {
		t.Fatalf("our first line must stay in the file per the IAMT-136 contract (door.open does not sweep foreign lines), but appeared %d times: %q", n, string(got))
	}
	if n := strings.Count(string(got), lineB+"\r\n"); n != 1 {
		t.Fatalf("our second line with a different id must be appended (Install does not collapse a foreign id), but appeared %d times: %q", n, string(got))
	}
}
