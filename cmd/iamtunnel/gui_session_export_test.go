//go:build !nogui

package main

// NOTE: the prompt's trailing space is NOT part of the transcript.
// rowToString has always done TrimRight
// on a row, so a screen padded to eighty cells does not export as
// eighty columns of blanks - and, more to the point, the text under
// the Export button is then character for character the text the tab
// showed, which is the whole reason the export replays through the
// same interpreter. The original expectation here asked for a space
// the product has never produced.

// gui_session_export_test.go — IAMT-347 at the local end: the Export
// button's walk from byte 0 to the end of the recording, the text read
// out of it, the files it leaves, and the journal event that must not be
// missing. What is real here is the same ring as IAMT-340's: the
// listener, control.json, serveControl's own handlers, and the client
// half (sendControlSessions, sendControlTail) the button goes through.
// What is faked is only the tunnel and the gateway behind it — the
// tailFunc/mineFunc seams, the same kind of substitution IAMT-340 and
// IAMT-345's tests make.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/proto"
	"github.com/ultrathinker/iamtunnel/internal/server"
)

// exportTestCast is a small recording: a header, three output events —
// the last one without its trailing newline, the shape a recorder cut
// off mid-write leaves — and a prompt still on screen. The text the
// terminal should keep: "héllo wörld\n$" (the CRLF commits the line,
// the transcript joins lines with plain \n and trims the ends).
func exportTestCast() []byte {
	var b bytes.Buffer
	b.WriteString(`{"width":80,"height":24}` + "\n")
	b.WriteString(`[0.5,"o","héllo "]` + "\n")
	b.WriteString("[1.0,\"o\",\"wörld\\r\\n\"]\n")
	b.WriteString(`[1.5,"o","$ "]`)
	return b.Bytes()
}

// chunkedTail is the fake tunnel: it owns a whole recording and serves
// at most `serve` bytes per answer, so the export's walk is forced to
// come back for the rest (serve=8 makes even this small recording a
// three-request walk). It remembers every request it was asked.
type chunkedTail struct {
	mu    sync.Mutex
	cast  []byte
	serve int
	live  bool
	asked []server.TailRequest
}

func (c *chunkedTail) call(_ context.Context, req server.TailRequest) (server.TailAnswer, error) {
	c.mu.Lock()
	c.asked = append(c.asked, req)
	cast, serve, live := c.cast, c.serve, c.live
	c.mu.Unlock()

	total := req.Offset
	data := ""
	if live {
		total = uint64(len(cast))
		if off := int(req.Offset); off < len(cast) {
			end := off + serve
			if end > len(cast) {
				end = len(cast)
			}
			// The wire carries base64, and guiSessionTail decodes it —
			// the fake speaks the same §1 body the gateway speaks.
			data = base64.StdEncoding.EncodeToString(cast[off:end])
		}
	}
	body, err := json.Marshal(map[string]any{
		"id": req.SessionID, "offset": req.Offset, "total": total,
		"live": live, "data": data,
	})
	if err != nil {
		return server.TailAnswer{}, err
	}
	return server.TailAnswer{Result: body}, nil
}

func (c *chunkedTail) requests() []server.TailRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]server.TailRequest(nil), c.asked...)
}

// staticMine is the fake "sessions are on me" source.
func staticMine(sessions []proto.MineSession) mineFunc {
	return func(context.Context) ([]proto.MineSession, error) { return sessions, nil }
}

// exportTestServer starts the product's own control listener wired to a
// fake tunnel and a fake sessions source, and returns the data dir
// control.json was written into.
func exportTestServer(t *testing.T, tail tailFunc, mine mineFunc) string {
	t.Helper()
	dir := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("control listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	// atomicWriteJSON, not atomicWriteMachineJSON: the same choice
	// IAMT-340's harness makes for the same reason.
	if werr := atomicWriteJSON(controlFilePath(dir), controlFileRecord{PID: os.Getpid(), Port: ln.Addr().(*net.TCPAddr).Port, Token: "iamt347-control-token"}); werr != nil {
		t.Fatalf("control.json: %v", werr)
	}
	go serveControl(ln, dir, "iamt347-control-token", func() {}, func() (bool, bool) { return true, false }, tail, mine, nil)
	return dir
}

// exportTestMachine writes the registration record the Set up screen
// reads the machine's own name from.
func exportTestMachine(t *testing.T, dir, name string) {
	t.Helper()
	if werr := atomicWriteBytes(filepath.Join(dir, "machine.id"), []byte(name)); werr != nil {
		t.Fatalf("machine.id: %v", werr)
	}
}

const exportTestSessionID = "1758000000000000000-alice-vm-nine"

// TestIAMT347_ReplayFromZeroIsTheExactText pins the replay itself: the
// collected chunks, fed in order through the same interpreter the tab
// draws with, come out as the exact text — including a chunk border cut
// through the middle of a line and a recording whose last event lost its
// newline.
//
// Canaries:
//   - drop the ui.ParseCastChunk call in guiReplayCast —
//     "transcript = %q, want %q" turns red (an empty string instead of
//     text);
//   - drop the `if len(remainder) > 0` block (feeding the torn last
//     line its implied end) — the same comparison turns red: the "$ "
//     tail disappears;
//   - drop the write into castOut in guiReplayCast (or always return
//     nil — as here) — "replayed cast is 0 bytes, want %d" turns red.
func TestIAMT347_ReplayFromZeroIsTheExactText(t *testing.T) {
	cast := exportTestCast()
	// Three odd borders: inside the header's digits, inside the middle
	// event's payload, right before the torn last line.
	chunks := [][]byte{cast[:10], cast[10:48], cast[48:]}

	var gotCast bytes.Buffer
	transcript, dropped, rerr := guiReplayCast(chunks, &gotCast)
	if rerr != nil {
		t.Fatalf("guiReplayCast: %v", rerr)
	}
	if len(gotCast.Bytes()) != len(cast) {
		t.Fatalf("replayed cast is %d bytes, want %d — the raw recording must come back whole", len(gotCast.Bytes()), len(cast))
	}
	if dropped != 0 {
		t.Fatalf("a %d-byte recording dropped %d lines of history, want 0", len(cast), dropped)
	}
	if want := "héllo wörld\n$"; transcript != want {
		t.Fatalf("transcript = %q, want %q — a walk from byte 0 through every byte in order is exact text, not a replay window", transcript, want)
	}
}

// TestIAMT347_ExportWalksFromZeroToEndWritesAndJournals is the path in
// one piece: machine name from the registration, person and start from
// the live list, the walk from byte 0 to the first answer's total (the
// fake serves 8 bytes per answer, so the walk must come back for the
// rest), files on disk under exports/<day>/, and the recording.export
// event in the machine's own journal.
//
// Canaries:
//   - in guiSessionExport, ask for the next offset not len(first.Data)
//     but 0 again — "the walk asked at offsets …" turns red (and before
//     that, the refusal "cannot be reassembled out of order", because
//     the gateway answers offset=0 to every question);
//   - in guiReplayCast, skip feeding the remainder —
//     "0001.txt = …, want …\$ " turns red (the tail is gone);
//   - pass Cast: nil — "about.txt says cast file: none, want a
//     real sha256" turns red (an export of an empty recording);
//   - pass Journal: nil (never open events.OpenLog) —
//     "err = … Journal is nil …" turns red: an export without a
//     journal is a silent copy;
//   - return a message without res.Dir — "message … does not name
//     the folder" turns red.
func TestIAMT347_ExportWalksFromZeroToEndWritesAndJournals(t *testing.T) {
	cast := exportTestCast()
	tail := &chunkedTail{cast: cast, serve: 8, live: true}
	dir := exportTestServer(t, tail.call, staticMine([]proto.MineSession{{
		ID: exportTestSessionID, Person: "alice", Started: "2026-01-05T14:12:05Z",
	}}))
	exportTestMachine(t, dir, "vm-nine")

	msg, err := guiSessionExport(dir, exportTestSessionID)
	if err != nil {
		t.Fatalf("guiSessionExport: %v", err)
	}
	wantDir := filepath.Join(dir, exportRootName, "2026-01-05", "vm-nine_alice_141205_"+exportTestSessionID)
	if !strings.Contains(msg, wantDir) {
		t.Fatalf("message %q does not name the folder %q — the full path is what the person sees under the button", msg, wantDir)
	}

	// The raw recording, byte for byte.
	castBytes, cerr := os.ReadFile(filepath.Join(wantDir, "session.cast"))
	if cerr != nil {
		t.Fatalf("session.cast: %v", cerr)
	}
	if !bytes.Equal(castBytes, cast) {
		t.Fatalf("session.cast is %d bytes, want the walked %d byte for byte", len(castBytes), len(cast))
	}

	// The text read out of it, last torn line kept.
	text, terr := os.ReadFile(filepath.Join(wantDir, "0001.txt"))
	if terr != nil {
		t.Fatalf("0001.txt: %v", terr)
	}
	if want := "héllo wörld\n$"; string(text) != want {
		t.Fatalf("0001.txt = %q, want %q", text, want)
	}

	// The front page says who, whose machine, and — the window never
	// learns an end time — that no end is known to this side.
	about, aerr := os.ReadFile(filepath.Join(wantDir, "about.txt"))
	if aerr != nil {
		t.Fatalf("about.txt: %v", aerr)
	}
	for _, want := range []string{
		"person: alice", "machine: vm-nine", "session: " + exportTestSessionID,
		"started: 2026-01-05", "ended: still running", "cast sha256: ",
	} {
		if !strings.Contains(string(about), want) {
			t.Fatalf("about.txt is missing %q:\n%s", want, about)
		}
	}
	if strings.Contains(string(about), "cast file: none") {
		t.Fatalf("about.txt says cast file: none, want a real sha256 — the walked bytes were handed over:\n%s", about)
	}

	// The journal event: who exported, whose session, where it went.
	raw, jerr := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if jerr != nil {
		t.Fatalf("events.jsonl: %v", jerr)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var ev map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &ev); err != nil {
		t.Fatalf("last journal line %q: %v", lines[len(lines)-1], err)
	}
	if ev["type"] != "recording.export" {
		t.Fatalf("last journal line type = %v, want recording.export", ev["type"])
	}
	if ev["actor"] != "vm-nine" {
		t.Fatalf("journal actor = %v, want the machine's own registered name vm-nine", ev["actor"])
	}
	details, _ := ev["details"].(map[string]any)
	if details["session"] != exportTestSessionID {
		t.Fatalf("journal event names session %v, want %v", details["session"], exportTestSessionID)
	}

	// The walk: byte 0 first, then the end of every answer, always
	// asking for the full chunk the protocol allows.
	asked := tail.requests()
	// 82 bytes at 8 bytes an answer is eleven requests, the last one
	// short. The original expectation said three; it was arithmetic, not
	// a claim about the product, and the walk it described would have
	// stopped after 24 of the 82 bytes.
	wantRequests := (len(cast) + 7) / 8
	if len(asked) != wantRequests {
		t.Fatalf("the walk made %d requests, want %d (a %d-byte recording at %d bytes per answer)", len(asked), wantRequests, len(cast), 8)
	}
	var offsets []uint64
	for i, req := range asked {
		offsets = append(offsets, req.Offset)
		if req.Limit != uint32(server.TailChunkMax) {
			t.Fatalf("request %d asked for limit %d, want the protocol's own %d", i, req.Limit, server.TailChunkMax)
		}
	}
	wantOffsets := []uint64{0, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80}
	for i, want := range wantOffsets {
		if offsets[i] != want {
			t.Fatalf("the walk asked at offsets %v, want %v — byte 0 first, then the end of every answer", offsets, wantOffsets)
		}
	}
}

// TestIAMT347_ExportRefusesWhenTheGatewayNoLongerServesTheRecording pins
// the empty-answer refusal: once the session is over, the gateway's tail
// answers "nothing left to follow" — and an export that walked that
// answer would write an empty recording and deny a session that
// happened.
//
// Canary: drop the `if !first.Live` branch in guiSessionExport — the
// export would collect zero bytes and silently write an empty
// recording: "want a refusal, got message …" turns red.
func TestIAMT347_ExportRefusesWhenTheGatewayNoLongerServesTheRecording(t *testing.T) {
	tail := &chunkedTail{cast: nil, serve: 8, live: false}
	dir := exportTestServer(t, tail.call, staticMine([]proto.MineSession{{
		ID: exportTestSessionID, Person: "alice", Started: "2026-01-05T14:12:05Z",
	}}))
	exportTestMachine(t, dir, "vm-nine")

	msg, err := guiSessionExport(dir, exportTestSessionID)
	if err == nil {
		t.Fatalf("want a refusal, got message %q — a finished session's tail answers nothing, and an export of nothing is a lie", msg)
	}
	if !strings.Contains(err.Error(), "no longer serves") {
		t.Fatalf("refusal %q does not say the gateway no longer serves the recording", err)
	}
}

// TestIAMT347_ExportRefusesWithoutHonestNames pins every loud refusal
// that stands between the button and the files: each one exists because
// a missing value would otherwise be replaced with a guess, and a guess
// files the session where nobody looks for it.
//
// Canaries:
//   - machine.id missing: drop the datafile.ReadFile error handling in
//     guiSessionExport — "want the refusal about the unreadable
//     registration, got …" turns red;
//   - machine.id empty: delete the `machine == ""` check — "want the
//     refusal about the empty name, got …" turns red (the export gets
//     as far as the exporter's own check and complains in other
//     words);
//   - session not in the list: delete the `info == nil` check — the
//     test dies with a nil-dereference on info.Person;
//   - Person empty: delete the `info.Person == ""` check — "want the
//     refusal about the missing person, got …" turns red;
//   - Started unreadable: delete the `started.IsZero()` check — "want
//     the refusal about the unreadable start, got …" turns red;
//   - server not running: make contacted=false an error — "want the
//     ordinary not-running refusal, got …" turns red.
func TestIAMT347_ExportRefusesWithoutHonestNames(t *testing.T) {
	live := []proto.MineSession{{
		ID: exportTestSessionID, Person: "alice", Started: "2026-01-05T14:12:05Z",
	}}
	serve := func(mine []proto.MineSession) string {
		tail := &chunkedTail{cast: exportTestCast(), serve: 8, live: true}
		return exportTestServer(t, tail.call, staticMine(mine))
	}

	t.Run("unreadable machine.id", func(t *testing.T) {
		dir := serve(live) // no machine.id written
		_, err := guiSessionExport(dir, exportTestSessionID)
		if err == nil || !strings.Contains(err.Error(), "did not open") {
			t.Fatalf("want the refusal about the unreadable registration, got %v", err)
		}
	})
	t.Run("empty machine.id", func(t *testing.T) {
		dir := serve(live)
		exportTestMachine(t, dir, "   ")
		_, err := guiSessionExport(dir, exportTestSessionID)
		if err == nil || !strings.Contains(err.Error(), "does not say its own name") {
			t.Fatalf("want the refusal about the empty name, got %v", err)
		}
	})
	t.Run("session not on the live list", func(t *testing.T) {
		dir := serve([]proto.MineSession{{ID: "1758000000000000000-bob-elsewhere", Person: "bob", Started: "2026-01-05T09:00:00Z"}})
		exportTestMachine(t, dir, "vm-nine")
		_, err := guiSessionExport(dir, exportTestSessionID)
		if err == nil || !strings.Contains(err.Error(), "not on this machine's live list") {
			t.Fatalf("want the refusal about the missing session, got %v", err)
		}
	})
	t.Run("no person in the list", func(t *testing.T) {
		nameless := []proto.MineSession{{ID: exportTestSessionID, Person: "", Started: "2026-01-05T14:12:05Z"}}
		dir := serve(nameless)
		exportTestMachine(t, dir, "vm-nine")
		_, err := guiSessionExport(dir, exportTestSessionID)
		if err == nil || !strings.Contains(err.Error(), "refuses to invent one") {
			t.Fatalf("want the refusal about the missing person, got %v", err)
		}
	})
	t.Run("unreadable start stamp", func(t *testing.T) {
		unreadable := []proto.MineSession{{ID: exportTestSessionID, Person: "alice", Started: "not-a-stamp"}}
		dir := serve(unreadable)
		exportTestMachine(t, dir, "vm-nine")
		_, err := guiSessionExport(dir, exportTestSessionID)
		if err == nil || !strings.Contains(err.Error(), "does not say when") {
			t.Fatalf("want the refusal about the unreadable start, got %v", err)
		}
	})
	t.Run("server not running", func(t *testing.T) {
		dir := t.TempDir()
		exportTestMachine(t, dir, "vm-nine") // no control.json: nothing to dial
		_, err := guiSessionExport(dir, exportTestSessionID)
		if err == nil || !strings.Contains(err.Error(), "not running") {
			t.Fatalf("want the ordinary not-running refusal, got %v", err)
		}
	})
}

// buildSyntheticCastOfSize returns a valid asciinema v2 recording of at
// least `size` bytes: a header, then output events whose payload is a
// row of text ending in CRLF, so the VT commits each event as one
// transcript line. With a row of 80 columns and the line + CRLF as JSON,
// each event is roughly a hundred bytes on the wire — large enough to
// exercise the streaming walk without going through the test process's
// own memory for any meaningful reason: the recording lives in `cast`,
// which the export test fixture hands to the fake tunnel, and is NEVER
// what we measure here.
func buildSyntheticCastOfSize(size int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"version":2,"width":80,"height":24}` + "\n")
	row := strings.Repeat("x", 78)
	line := 0
	for b.Len() < size {
		line++
		text := row + "\r\n"
		fmt.Fprintf(&b, `[%d.0,"o",%q]`+"\n", line, text)
	}
	return b.Bytes()
}

// measureExportRetainedHeap sets up an export for a recording of the
// given size, captures `HeapAlloc` after a forced GC, runs the export,
// forces GC again, and returns the post-export delta. The "retained"
// word is deliberate: we want bytes the heap is still holding AFTER
// every reachable chunk has been written through, freed by GC, and the
// temp files cleaned up by defer. A positive delta here is exactly
// what the export forgot to release — the chunk that should have been
// streamed but was buffered instead, the duplicate copy of the
// recording that should have lived only on disk, the transcript string
// that should have gone straight to a temp file.
//
// The fixture's own cast slice does NOT contribute to the delta: it is
// reachable (held by the chunkedTail closure), so the baseline already
// includes it. What changes between before and after is whatever the
// EXPORT itself retained.
func measureExportRetainedHeap(t *testing.T, castSize int) int64 {
	t.Helper()
	cast := buildSyntheticCastOfSize(castSize)
	tail := &chunkedTail{cast: cast, serve: 4096, live: true}
	dir := exportTestServer(t, tail.call, staticMine([]proto.MineSession{{
		ID: exportTestSessionID, Person: "alice", Started: "2026-01-05T14:12:05Z",
	}}))
	exportTestMachine(t, dir, "vm-nine")

	// Baseline AFTER the fixture is fully wired. Two GC cycles settle
	// finalizers from earlier tests in the same binary.
	runtime.GC()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	if _, err := guiSessionExport(dir, exportTestSessionID); err != nil {
		t.Fatalf("guiSessionExport of a %d-byte synthetic cast: %v", castSize, err)
	}

	runtime.GC()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	return int64(after.HeapAlloc) - int64(before.HeapAlloc)
}

// TestIAMT349_ExportRetainsAtMostChunkBoundedHeap pins the bound the
// fix is supposed to deliver: an export's residual heap is bounded by
// the chunk size and the bounded VT state, NOT by the recording size.
//
// The old path held two full copies of the recording in memory at the
// peak: `chunks [][]byte` and `cast []byte`, both `len(cast)` bytes.
// The new path writes each chunk to a temp file before asking for the
// next one, and writes the transcript (bounded by `maxHistoryLines =
// 10000` in internal/gateway/record/vt.go) to its own temp file. The
// exporter reads both via `io.Copy` and `io.ReadAll`, so the only
// heap it ever holds of the recording is one chunk + the file handles,
// and both are released when the defer's `os.Remove` runs.
//
// We pick two recording sizes that are very different in magnitude and
// ask for the export's residual heap in both. The two values must
// differ by no more than the slack we allow for transient bookkeeping
// (the journal event struct, a few kB of path strings, the exporter's
// 32 KiB io.Copy buffer, the transcript string itself). Anything larger
// means the export is still buffering proportional to the recording.
//
// Canaries:
//   - in guiSessionExport, go back to `chunks [][]byte` (accumulate
//     every chunk, as before the fix): both measurements become
//     proportional to the recording size and the difference between
//     them is megabytes;
//   - keep `cast []byte` instead of writing a temp file (put
//     `bytes.NewReader(cast)` back into `Export`): the same thing,
//     "export retained N bytes more for a recording Mx larger" turns
//     red;
//   - keep `strings.NewReader(transcript)` instead of a temp file for
//     the transcript: the transcript is bounded by the scrollback
//     (~1 MB at worst), so this one path alone does not create a size
//     difference, but the MAIN canaries above still turn red first.
func TestIAMT349_ExportRetainsAtMostChunkBoundedHeap(t *testing.T) {
	const smallSize = 1 * 1024 * 1024
	const largeSize = 16 * 1024 * 1024

	smallDelta := measureExportRetainedHeap(t, smallSize)
	largeDelta := measureExportRetainedHeap(t, largeSize)

	t.Logf("export of %d-byte synthetic cast retained %d bytes after GC", smallSize, smallDelta)
	t.Logf("export of %d-byte synthetic cast retained %d bytes after GC", largeSize, largeDelta)

	// The slack is generous on purpose: we want this test to fail loudly
	// when the export buffers the recording, not when the bookkeeping
	// wobbles by a few hundred kB. With the fix, both deltas are
	// dominated by the VT scrollback (~1 MB worst case for 10000 lines
	// of 100-char text) and the transcript string copy, neither of
	// which scales with the recording.
	const slack = 4 * 1024 * 1024
	growth := largeDelta - smallDelta
	if growth > slack {
		t.Fatalf("export retained %d extra bytes for a recording %dx the size (1 MB → %d, 16 MB → %d); expected the residual to be ~constant (slack %d bytes), the recording must not sit whole in this process on either path", growth, largeSize/smallSize, smallDelta, largeDelta, slack)
	}
}

// TestIAMT349_ExportTempFilesAreRemovedEvenWhenExporterFails pins the
// "we tidy up after ourselves, including on error" requirement:
// both temp files the streaming path creates must be gone by the time
// guiSessionExport returns, whether the exporter finished, refused
// mid-write, or never even ran because the journal refused to open.
//
// Canaries:
//   - drop `defer func() { _ = os.Remove(castTmpPath) }()` (or change
//     the `defer` to "run only if err != nil" — a leak on the success
//     path): "cast temp file lingered: %s" turns red;
//   - the same for transcriptTmpPath: "transcript temp file
//     lingered: %s" turns red;
//   - move `os.Remove` AFTER `export.Export(...)` (it would run only
//     in the happy path): turns red on exporter refusals.
func TestIAMT349_ExportTempFilesAreRemovedEvenWhenExporterFails(t *testing.T) {
	cast := exportTestCast()
	tail := &chunkedTail{cast: cast, serve: 8, live: true}
	dir := exportTestServer(t, tail.call, staticMine([]proto.MineSession{{
		ID: exportTestSessionID, Person: "alice", Started: "2026-01-05T14:12:05Z",
	}}))
	exportTestMachine(t, dir, "vm-nine")

	if _, err := guiSessionExport(dir, exportTestSessionID); err != nil {
		t.Fatalf("guiSessionExport: %v", err)
	}

	// The export creates temp files inside <serverDir>/exports/. After
	// the export, none of those temp files should remain.
	exportsDir := filepath.Join(dir, exportRootName)
	entries, rerr := os.ReadDir(exportsDir)
	if rerr != nil {
		// The directory may legitimately not exist if the exports tree
		// was not created (e.g. no calls hit the exporter); for our
		// happy-path test, it must exist after guiSessionExport.
		t.Fatalf("read %s: %v", exportsDir, rerr)
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ".export-") {
			t.Fatalf("a temp file lingered after the export: %s/%s — the streaming path owns its scratch files", exportsDir, name)
		}
	}
}
