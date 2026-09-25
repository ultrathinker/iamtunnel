package server

// door_sanitize_count_test.go — IAMT-103. door.sanitize wipes every marked
// line from administrators_authorized_keys without naming one id, so the
// journal at the gateway side must know how many lines were taken. The
// machine returns that count in sanitizeResult.Removed; this test pins
// that contract at the doorController boundary.

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// TestDoorSanitize_ReturnsRemovedCount pins the wire contract: a sanitize
// over a file with two corrupted lines and one foreign line reports
// Removed: 2 (the foreign line is not ours and stays untouched). This
// is the value the gateway will copy into events.jsonl's
// door.sanitize Details["removed"], so the test below checks the
// raw JSON the gateway is going to see — a count field is not enough,
// the gateway deserialises the same struct.
func TestDoorSanitize_ReturnsRemovedCount(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)

	// Two corrupted lines: they own the marker signature but the tail is
	// not a 32-hex id, so they are ours-but-broken. One foreign line that
	// must stay byte-for-byte unchanged.
	corruptA := winkeys.Options + " ssh-ed25519 " + winkeys.TestKey + " iamtunnel-door=not-hex-aaaaaaaaaaaa"
	corruptB := winkeys.Options + " ssh-ed25519 " + winkeys.TestKey + " iamtunnel-door=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
	foreign := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRealForeignKey user@home"
	if err := os.WriteFile(keyFile, []byte(corruptA+"\r\n"+corruptB+"\r\n"+foreign+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	resp := dc.sanitize(controlRequest{ID: "z-count", Op: "door.sanitize", Reason: "corrupted"})
	if !resp.OK {
		t.Fatalf("sanitize refused: %+v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatal("sanitize returned no Result payload")
	}
	var got sanitizeResult
	if err := json.Unmarshal(resp.Result, &got); err != nil {
		t.Fatalf("sanitize Result is not parseable as sanitizeResult: %v / payload=%s", err, resp.Result)
	}
	if !got.Sanitized {
		t.Fatalf("sanitize Result.Sanitized is false on ok:true response: %+v", got)
	}
	if got.Removed != 2 {
		t.Fatalf("sanitize Result.Removed = %d, want 2 (two corrupted door lines)", got.Removed)
	}

	// The foreign line must remain exactly as it was written — the
	// invariant the file-level winkeys tests already cover; pinning it
	// here so a refactor that loses it can be blamed on this commit.
	after, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != foreign+"\r\n" {
		t.Fatalf("sanitize disturbed a foreign line: file now %q", string(after))
	}
}

// TestDoorSanitize_RemovedZeroOnCleanFile: a sanitize over a clean file
// still reports Removed: 0. The journal entry has to record "the gateway
// swept and found nothing" separately from "the gateway never swept" —
// the count makes the difference.
func TestDoorSanitize_RemovedZeroOnCleanFile(t *testing.T) {
	dc, keyFile := newTestDoorController(t, nil)
	if err := os.WriteFile(keyFile, []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRealForeignKey user@home\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	resp := dc.sanitize(controlRequest{ID: "z-zero", Op: "door.sanitize", Reason: "corrupted"})
	if !resp.OK {
		t.Fatalf("sanitize refused: %+v", resp.Error)
	}
	var got sanitizeResult
	if err := json.Unmarshal(resp.Result, &got); err != nil {
		t.Fatalf("decode: %v / payload=%s", err, resp.Result)
	}
	if got.Removed != 0 {
		t.Fatalf("Removed on a clean file = %d, want 0", got.Removed)
	}
}
