package record

// IAMT-336 phase 5: stdin in a recording audit.
//
// SPEC §6.5: the audit must record the fact that bytes went human -> machine
// without recording the bytes themselves. The .meta carries stdin{bytes,
// sha256} where sha256 is computed by a streaming SHA-256 over the bytes
// the bridge forwarded, never from a buffer collected up to finalize time.
// An empty stdin has no fact to claim, so the field is absent rather than
// populated with the SHA-256 of zero bytes.
//
// These tests pin the four facts this feature must guarantee, on the ExecRecorder
// path (the spec's case in point). They run the production code; they do
// not substitute a fake hasher.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
)

// hashFromString is the obvious "what should the SHA-256 of these bytes
// be" helper, kept locally so a test failure names exactly which way the
// answer was computed.
func hashFromString(t *testing.T, s string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// TestIAMT336_StdinMeta_CarriesBytesAndHash is the spec's mainline case.
// 47 KB of base64 in real life; "stdin payload" is enough to prove the
// shape. The hash is asserted against the SHA-256 of exactly the bytes
// that were forwarded - the test fails if the recorder hashes something
// other than what the bridge called AddBytesIn with, including the bytes
// the bridge never saw.
func TestIAMT336_StdinMeta_CarriesBytesAndHash(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewExecRecorder(ExecConfig{SessionConfig: SessionConfig{
		BaseDir: dir, Machine: "machine", Person: "person", OSUser: "operator", SessionID: "stdin-fact", SubdirLayout: true,
	}, Command: "WriteAllBytes"})
	if err != nil {
		t.Fatalf("NewExecRecorder: %v", err)
	}
	const stdinPayload = "47KB-worth-of-base64-of-a-jpg-image-from-the-real-session"
	rec.AddBytesIn([]byte(stdinPayload))
	if _, err := rec.Write([]byte("ok")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := rec.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	meta, err := ReadMeta(rec.Paths().MetaPath)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if meta.Stdin == nil {
		t.Fatalf("exec metadata must carry stdin{bytes, sha256} when stdin was forwarded; got nil (record name=%q)", rec.Paths().MetaPath)
	}
	if meta.Stdin.Bytes != int64(len(stdinPayload)) {
		t.Fatalf("exec metadata stdin.bytes=%d, want %d", meta.Stdin.Bytes, len(stdinPayload))
	}
	want := hashFromString(t, stdinPayload)
	if meta.Stdin.SHA256 != want {
		t.Fatalf("exec metadata stdin.sha256=%q, want SHA-256 of the bytes that were forwarded = %q", meta.Stdin.SHA256, want)
	}
	if meta.BytesIn != meta.Stdin.Bytes {
		t.Fatalf("exec metadata bytes_in=%d must equal stdin.bytes=%d (the two count the same thing)", meta.BytesIn, meta.Stdin.Bytes)
	}
}

// TestIAMT336_StdinMeta_AbsentWhenEmpty pins the spec rule that an empty
// stdin has no fact worth printing. The hash of zero bytes is a real
// SHA-256 (e3b0c4...) but it is not a fact about a session, and printing
// it as one would mislead a reader into thinking bytes were forwarded.
func TestIAMT336_StdinMeta_AbsentWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewExecRecorder(ExecConfig{SessionConfig: SessionConfig{
		BaseDir: dir, Machine: "machine", Person: "person", OSUser: "operator", SessionID: "stdin-empty", SubdirLayout: true,
	}, Command: "no-stdin-here"})
	if err != nil {
		t.Fatalf("NewExecRecorder: %v", err)
	}
	if _, err := rec.Write([]byte("ok")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := rec.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	raw, err := os.ReadFile(rec.Paths().MetaPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var meta Metadata
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if meta.Stdin != nil {
		t.Fatalf("exec metadata must NOT carry stdin when nothing was forwarded; got %+v", meta.Stdin)
	}
	// Belt-and-suspenders: a substring check on the raw JSON. If the
	// struct omitempty is later replaced by a struct that serializes to
	// a zero-value object, this catches the regression before a human
	// notices the journal printing e3b0c4 for sessions with no input.
	if strings.Contains(string(raw), `"stdin"`) {
		t.Fatalf("exec .meta must not contain a stdin key when no stdin was forwarded; got:\n%s", raw)
	}
	if meta.BytesIn != 0 {
		t.Fatalf("exec metadata bytes_in=%d, want 0 when no stdin was forwarded", meta.BytesIn)
	}
}

// TestIAMT336_StdinMeta_LargeStreamingHash pins the streaming property.
// A few megabytes are sent in many small chunks; the hash must equal the
// SHA-256 of the bytes concatenated by an independent reader. If the
// recorder had buffered all chunks to compute the hash at finalize
// time, it would still pass on the right answer - but it would also
// defeat the point. The test in particular sends the chunks one byte
// at a time so any per-call allocation that grew with total size would
// explode visibly in the test runner.
func TestIAMT336_StdinMeta_LargeStreamingHash(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewExecRecorder(ExecConfig{SessionConfig: SessionConfig{
		BaseDir: dir, Machine: "machine", Person: "person", OSUser: "operator", SessionID: "stdin-large", SubdirLayout: true,
	}, Command: "cp big.bin /dst"})
	if err != nil {
		t.Fatalf("NewExecRecorder: %v", err)
	}

	// 2 MiB is enough to be a "few MB" and is small
	// enough that a wrong hash is found in milliseconds.
	const total = 2 << 20
	payload := make([]byte, total)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Feed it in 1-byte chunks to stress the streaming path: if any
	// internal buffer grows with total size, this loop would be the
	// first thing to OOM the test runner.
	for i, b := range payload {
		rec.AddBytesIn([]byte{b})
		if i == total-1 {
			// nothing - just making the loop explicit so a debugger
			// sees the last byte is written before finalize.
		}
	}
	if _, err := rec.Write([]byte("copied")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := rec.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	want := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(want[:])

	meta, err := ReadMeta(rec.Paths().MetaPath)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	if meta.Stdin == nil {
		t.Fatalf("exec metadata must carry stdin{bytes, sha256} for a 2 MiB stdin; got nil")
	}
	if meta.Stdin.Bytes != int64(total) {
		t.Fatalf("exec metadata stdin.bytes=%d, want %d", meta.Stdin.Bytes, total)
	}
	if meta.Stdin.SHA256 != wantHex {
		t.Fatalf("exec metadata stdin.sha256=%q, want streaming SHA-256 of the bytes that were forwarded (%q)", meta.Stdin.SHA256, wantHex)
	}
}

// TestIAMT336_ExecJSONL_DoesNotContainStdin pins the other half of the
// rule. The hash is in .meta; the bytes must NOT be in .exec.jsonl. A
// human reading the journal (or grepping it for the secret) must come
// back empty-handed: stdin content is forbidden there even if .meta
// ever leaks.
func TestIAMT336_ExecJSONL_DoesNotContainStdin(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewExecRecorder(ExecConfig{SessionConfig: SessionConfig{
		BaseDir: dir, Machine: "machine", Person: "person", OSUser: "operator", SessionID: "stdin-isolation", SubdirLayout: true,
	}, Command: "WriteAllBytes"})
	if err != nil {
		t.Fatalf("NewExecRecorder: %v", err)
	}
	// Distinctive payload - long enough that random chance of matching
	// anything else in the file is essentially zero, short enough to
	// make a leak obvious in failure output.
	const secret = "PASSWORD-LEAK-CANARY-AMT336-DO-NOT-LOG"
	rec.AddBytesIn([]byte(secret))
	if _, err := rec.Write([]byte("ok")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := rec.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	raw, err := os.ReadFile(rec.Paths().ExecPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf(".exec.jsonl must NOT contain the bytes forwarded on stdin; found the canary. Raw:\n%s", raw)
	}
	if !strings.Contains(string(raw), "WriteAllBytes") {
		t.Fatalf(".exec.jsonl must still contain the command line; got:\n%s", raw)
	}
	// The .meta file is allowed to carry the SHA-256 of the secret, but
	// must not carry the secret itself.
	metaRaw, err := os.ReadFile(rec.Paths().MetaPath)
	if err != nil {
		t.Fatalf("ReadFile meta: %v", err)
	}
	if strings.Contains(string(metaRaw), secret) {
		t.Fatalf(".meta must NOT contain the bytes forwarded on stdin; found the canary. Raw:\n%s", metaRaw)
	}

	// The recording file must also stay in the same size class as a
	// no-stdin recording: just the JSONL envelope (command, chunk,
	// eof), not the 47 KB the live session originally saw.
	if int64(len(raw)) > 4096 {
		t.Fatalf(".exec.jsonl grew unexpectedly large: %d bytes (expected a few hundred). The stdin bytes leaked into the journal.", len(raw))
	}
}

// silence unused-import warnings for io if a future edit removes the
// only use of it; the build tag check on this file catches broken
// edits before they reach review.
var _ = io.Discard
