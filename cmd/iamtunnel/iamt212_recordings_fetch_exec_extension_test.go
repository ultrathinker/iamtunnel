package main

// iamt212_recordings_fetch_exec_extension_test.go — IAMT-212.
//
// The bug: fetchAndWriteParts named local files as `<id>.<part>`, so an
// exec recording (PROTOCOL §8 part "exec") came down as `<id>.exec`
// instead of `<id>.exec.jsonl` — the gateway's on-disk name, set by
// admin_role.go:1569-1570 (`path = found.base + ".exec.jsonl"`).
// SHA-256 matched (the bytes are fine) but the operator's downloaded
// directory no longer mirrored the gateway's, which is required for
// cross-checking the audit archive.
//
// The fix moves the local-file extension into a single table
// (`partFilenameExt` in admin_exec.go) keyed by gateway part name; the
// table has exactly one entry per part, and exec → `.exec.jsonl` is the
// only behavioural change. The PTY branch and the no-meta legacy
// fallback are untouched.
//
// The canary below drives `fetchRecording` through the existing exec
// fake (the same shape iamt209_recordings_fetch_exec_test.go already
// uses) and asserts the file names that land in the output directory.
// It deliberately does NOT live in iamt209's file: this is its own
// concern (the gateway ↔ local filename mapping), and putting the
// canary here keeps the IAMT-212 canary's diff visible in one place.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestIAMT212_FetchRecording_ExecMode_LocalExtensionIsExecJSONL is the
// primary canary for the filename mapping. An exec recording whose
// `.meta` declares `recording_mode:"exec"` MUST come down as
// `<id>.exec.jsonl` (gateway's on-disk name, PROTOCOL §8) plus
// `<id>.meta`. A `.exec` file in the output is a regression — the
// pre-fix behaviour the live Windows VM surfaced.
//
// Canary: in admin_exec.go, replace the `id+ext` line in
// fetchAndWriteParts with the pre-fix `id+"."+part` (and drop the
// partFilenameExt lookup). Exec recordings come down as `<id>.exec`
// again, matching the live-bug shape, and this test goes red on the
// basename assertion in the second loop below:
//
//	written[i] = %q, want basename %q
//
// plus the explicit "exec file must NOT exist" assertion below.
func TestIAMT212_FetchRecording_ExecMode_LocalExtensionIsExecJSONL(t *testing.T) {
	dir := t.TempDir()
	execBytes := []byte("{\"sequence\":1,\"type\":\"command\",\"command\":\"whoami\"}\n")
	metaBytes := []byte(`{"recording_mode":"exec","person":"alice","machine":"vm1"}`)

	// Same shape as iamt209_recordings_fetch_exec_test.go:132 — the fake
	// serves the parts the real gateway would, and the canary is purely
	// about the local filename the CLI picks, not the wire protocol.
	fake := &fakeRecordingFetcher{
		parts: map[string][]byte{
			"meta": metaBytes,
			"exec": execBytes,
		},
	}

	written, err := fetchRecording(fake, "rec-212", dir)
	if err != nil {
		t.Fatalf("fetchRecording: %v", err)
	}

	wantNames := []string{"rec-212.exec.jsonl", "rec-212.meta"}
	if len(written) != len(wantNames) {
		t.Fatalf("fetchRecording wrote %d files (%v), want exactly %v (IAMT-212: exec part on the gateway is `<id>.exec.jsonl`, the local fetch must keep that name)", len(written), written, wantNames)
	}
	for i, name := range wantNames {
		if filepath.Base(written[i]) != name {
			t.Fatalf("written[%d] = %q, want basename %q", i, written[i], name)
		}
	}

	// Belt-and-braces: the pre-fix filename `.exec` MUST NOT appear.
	// The canary line in admin_exec.go (returning to `id+"."+part`)
	// produces exactly this file, and catching it here pins the
	// regression at the byte level, not just by the absence of
	// `.exec.jsonl` (which a future "rename exec to exec.bin" would
	// silently satisfy).
	if _, err := os.Stat(filepath.Join(dir, "rec-212.exec")); err == nil {
		t.Fatalf("downloaded directory contains rec-212.exec — IAMT-212 regression: the local fetch must name the exec part .exec.jsonl, not .exec")
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat rec-212.exec returned unexpected error (must be IsNotExist for a clean no-file case): %v", err)
	}
}

// TestIAMT212_FetchRecording_TerminalMode_PTYBranchNotRegressed
// pins the PTY branch against the same fix: a recording whose `.meta`
// declares `recording_mode:"terminal"` must STILL come down as
// `<id>.cast` + `<id>.txt` + `<id>.meta`. The change touches only the
// exec part, but a careless rename that touches every entry of
// partFilenameExt would break this — and this is the only test that
// catches that.
//
// Canary: in admin_exec.go's partFilenameExt, rename the "cast"
// entry's value from ".cast" to ".exec.jsonl". Terminal recordings now
// download as exec.jsonl (the gateway answers E_NOT_FOUND, fetch
// fails) and this test goes red on the err != nil assertion in
// fetchRecording.
func TestIAMT212_FetchRecording_TerminalMode_PTYBranchNotRegressed(t *testing.T) {
	dir := t.TempDir()
	castBytes := []byte("{\"version\":2,\"width\":80,\"height\":24}\n[0.5,\"o\",\"hi\"]\n")
	txtBytes := []byte("hi\n")
	metaBytes := []byte(`{"recording_mode":"terminal","person":"alice","machine":"vm1"}`)

	fake := &fakeRecordingFetcher{
		parts: map[string][]byte{
			"meta": metaBytes,
			"cast": castBytes,
			"txt":  txtBytes,
		},
	}

	written, err := fetchRecording(fake, "rec-pty-212", dir)
	if err != nil {
		t.Fatalf("fetchRecording PTY (must not be affected by the IAMT-212 exec-extension fix): %v", err)
	}
	wantNames := []string{"rec-pty-212.cast", "rec-pty-212.txt", "rec-pty-212.meta"}
	if len(written) != len(wantNames) {
		t.Fatalf("written = %v, want %v", written, wantNames)
	}
	for i, n := range wantNames {
		if filepath.Base(written[i]) != n {
			t.Fatalf("written[%d] = %q, want basename %q", i, written[i], n)
		}
	}
}

// TestIAMT212_PartFilenameExt_TableIsComplete is a static canary on
// the table itself: every part name that fetchAndWriteParts can be
// handed MUST be in partFilenameExt with a non-empty extension. The
// table is the single source of truth for the local filename mapping,
// and a future edit that adds a new PROTOCOL §8 part without teaching
// the table would otherwise silently fall back to the pre-fix name.
// fetchAndWriteParts already returns an error for an unknown part
// (admin_exec.go's defensive guard), so this test pins the *set* the
// production loop actually consumes.
//
// Canary: drop the "exec" entry from partFilenameExt. exec recordings
// now hit the defensive error branch and this test goes red on the
// missing-key count.
func TestIAMT212_PartFilenameExt_TableIsComplete(t *testing.T) {
	// The closed set of parts the product loop can be handed. The PTY
	// path hands {cast, txt, meta}; the exec path hands {exec, meta};
	// the legacy-no-meta fallback (no .meta on the gateway) hands
	// {cast, txt}. So the union is exactly {cast, txt, exec, meta}.
	required := []string{"cast", "txt", "exec", "meta"}
	for _, p := range required {
		ext, ok := partFilenameExt[p]
		if !ok {
			t.Fatalf("partFilenameExt missing key %q — fetchAndWriteParts would fail for this part with \"unknown recording part\"", p)
		}
		if ext == "" {
			t.Fatalf("partFilenameExt[%q] = %q (empty); the local filename would collapse to the bare id and lose its extension", p, ext)
		}
		if !strings.HasPrefix(ext, ".") {
			t.Fatalf("partFilenameExt[%q] = %q; local extension must start with \".\" so the downloaded file is recognisable by type", p, ext)
		}
	}
	// And: the exec part MUST map to .exec.jsonl — this is the exact
	// bug IAMT-212 fixes (the live VM produced `<id>.exec`, the
	// gateway writes `<id>.exec.jsonl`). A future "simplify" that
	// reverts this entry to ".exec" passes the completeness check
	// above but breaks the on-disk name contract and fails here.
	if got := partFilenameExt["exec"]; got != ".exec.jsonl" {
		t.Fatalf("partFilenameExt[exec] = %q, want %q (gateway stores the lossless exec stream as `<base>.exec.jsonl`, admin_role.go:1569-1570)", got, ".exec.jsonl")
	}
}
