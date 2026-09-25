package winkeys

// doors_iamt136_test.go — IAMT-136. door.open has no right to sweep.
//
// PROTOCOL §5.1 authorizes installLocked (door.open's write path) for
// exactly one deletion: atomically replace the file with the ADDED line,
// collapsing the previous line of the SAME doorID. Cleaning up corrupted
// and foreign lines is door.sanitize's and SweepStale's job (same §5.1
// table, door.sanitize row).
//
// Both guards live here, in package winkeys, not in internal/server:
// the rule is implemented in installLocked, the server's door.open is
// exactly one call to Door.Install, and a repeated door.open with the
// same id never even reaches the file (doorController short-circuits on
// dc.installed). So the assertions read most honestly at the Install
// level, next to TestReinstallSameIDCollapses.
//
// The key file path is always given explicitly via tempKeyFile, i.e.
// always inside t.TempDir(): no fallback mechanism (in particular
// config.DirsFor) is involved in this file — there is no way for the
// test to write to a real administrators_authorized_keys.

import (
	"os"
	"strings"
	"testing"
)

// TestInstallDoesNotSweepForeignDoorLines — assertion 1: the file holds
// a foreign line, our VALID line for a different doorID, and our
// CORRUPTED line (our options prefix, ssh-ed25519, marker — but
// invalid key base64). door.open runs with a NEW doorID. Every
// existing line must stay byte-for-byte (together with its CRLF
// terminator), and the new one must be added exactly once. Line bytes
// are compared, not their count: a line swap would still match on count.
func TestInstallDoesNotSweepForeignDoorLines(t *testing.T) {
	path := tempKeyFile(t)

	thirdParty := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHumanAdminKeyDoNotTouch1111 admin@corp`
	const foreignDoorID = "deadbeefcafebabe1234567890abcdef"
	foreignOurs := FormatLine(foreignDoorID, TestKey)
	damagedOurs := Options + ` ssh-ed25519 damaged-key-not-valid-base64!!! iamtunnel-door=` + foreignDoorID
	fixture := strings.Join([]string{thirdParty, foreignOurs, damagedOurs}, "\r\n") + "\r\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("test setup error: write fixture to %s: %v", path, err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != fixture {
		t.Fatalf("test setup error: fixture at %s did not read back unchanged: %v, %q", path, err, string(b))
	}
	// The fixture's classification must be exactly the one the rule
	// talks about, otherwise a red test proves nothing.
	if id, _, valid, corrupt := isDoorLine(foreignOurs); !valid || corrupt || id != foreignDoorID {
		t.Fatalf("test setup error: line %q must be our valid line for the foreign doorID %q, got id=%q valid=%v corrupt=%v", foreignOurs, foreignDoorID, id, valid, corrupt)
	}
	if id, _, valid, corrupt := isDoorLine(damagedOurs); valid || !corrupt {
		t.Fatalf("test setup error: line %q must be our corrupted line (our prefix and marker, invalid key base64), got id=%q valid=%v corrupt=%v", damagedOurs, id, valid, corrupt)
	}
	if _, _, valid, corrupt := isDoorLine(thirdParty); valid || corrupt {
		t.Fatalf("test setup error: line %q must be foreign (not ours), got valid=%v corrupt=%v", thirdParty, valid, corrupt)
	}

	newID := randomDoorID(t)
	if newID == foreignDoorID {
		t.Fatalf("test setup error: random newID collided with the foreign doorID %q", foreignDoorID)
	}
	newLine := FormatLine(newID, TestKey)
	if id, _, valid, corrupt := isDoorLine(newLine); !valid || corrupt || id != newID {
		t.Fatalf("test setup error: new door line %q is invalid: id=%q valid=%v corrupt=%v", newLine, id, valid, corrupt)
	}

	d := tempDoorWithPath(t, path)
	if err := d.Install(newID, TestKey); err != nil {
		t.Fatalf("door.open (Door.Install) refused on a valid fixture: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key file after door.open: %v", err)
	}
	// Every existing line must stay byte-for-byte: door.open has no
	// right to sweep — neither a foreign line, nor our line for a
	// foreign doorID, nor our corrupted line. The only deletion it is
	// allowed is collapsing the line for its own doorID (PROTOCOL
	// §5.1); corrupted and foreign lines are cleared by
	// door.sanitize and SweepStale.
	for _, c := range []struct{ label, line string }{
		{"our valid line for a different doorID", foreignOurs},
		{"our corrupted line (invalid key base64)", damagedOurs},
		{"a foreign line with no marker", thirdParty},
	} {
		if n := strings.Count(string(got), c.line+"\r\n"); n != 1 {
			t.Fatalf("%s must remain byte-for-byte in exactly one instance, but appeared %d times: door.open is sweeping lines that do not name its own doorID, even though PROTOCOL §5.1 authorizes it only to collapse its own doorID (cleaning up corrupted and foreign lines is door.sanitize/SweepStale's job). File: %q", c.label, n, string(got))
		}
	}
	if n := strings.Count(string(got), newLine+"\r\n"); n != 1 {
		t.Fatalf("new door line %q appears %d times after door.open, file: %q", newLine, n, string(got))
	}
	if want := fixture + newLine + "\r\n"; string(got) != want {
		t.Fatalf("door.open changed bytes in the file beyond adding its own line:\n got:  %q\nwant: %q", string(got), want)
	}
}

// TestReinstallSameIDStillCollapses — assertion 2, the other side of the
// IAMT-136 boundary: a repeated door.open with the SAME doorID must
// collapse the previous line for its own id. Forbidding the collapse
// entirely is not a fix, but a new defect: the door line would breed on
// every repeated open. A foreign line must stay byte-for-byte through
// this rewrite.
func TestReinstallSameIDStillCollapses(t *testing.T) {
	path := tempKeyFile(t)

	thirdParty := `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHumanAdminKeyDoNotTouch2222 ops@corp`
	fixture := thirdParty + "\r\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatalf("test setup error: write fixture to %s: %v", path, err)
	}

	id := randomDoorID(t)
	doorLine := FormatLine(id, TestKey)
	wantAfterFirst := fixture + doorLine + "\r\n"

	d := tempDoorWithPath(t, path)
	if err := d.Install(id, TestKey); err != nil {
		t.Fatalf("first door.open (Door.Install) refused: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file after first door.open: %v", err)
	}
	if string(b) != wantAfterFirst {
		t.Fatalf("first door.open did not write exactly one line of its own after the foreign one:\n got:  %q\nwant: %q", string(b), wantAfterFirst)
	}

	if err := d.Install(id, TestKey); err != nil {
		t.Fatalf("repeated door.open with the same doorID refused: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file after repeated door.open: %v", err)
	}
	// door.open must collapse its own line: exactly one line for this
	// doorID, the foreign line untouched, not a byte changed elsewhere.
	if n := strings.Count(string(got), doorLine+"\r\n"); n != 1 {
		t.Fatalf("repeated door.open with the same doorID left %d door lines, want exactly one — collapsing its own doorID (the only deletion door.open is allowed, PROTOCOL §5.1) is lost. File: %q", n, string(got))
	}
	if string(got) != wantAfterFirst {
		t.Fatalf("repeated door.open with the same doorID changed bytes in the file:\n got:  %q\nwant: %q", string(got), wantAfterFirst)
	}
}
