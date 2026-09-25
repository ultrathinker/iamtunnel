package gateway

// zz_accept_m12_fetch_cache_test.go — M-12 (review F-09, review F-17).
//
// recordings.fetch used to redo, for EVERY chunk of a download, the
// work that only needs doing once per recording: the full tree walk
// (parse every .meta on the gateway) to resolve the opaque id, and the
// SHA-256 of the WHOLE part file for the response's sha256 field. A
// 500 MB recording fetched in 256 KiB chunks meant ~2000 walks and
// ~2000 full-file hashes — about a terabyte of hashing for one
// download.
//
// These tests do NOT ask "is the answer right" (it was right before;
// iamt209 pins that byte-for-byte). They ask "how much work did the
// gateway do":
//
//   - the hash must be computed ZERO times when the .meta already
//     carries the finalization hash (the recorder hashes cast/txt/exec
//     exactly once, at finalize, and the gateway serves that fact);
//   - exactly ONCE per download when the .meta predates that rule
//     (computed at the first request, then memoized in gateway memory);
//   - and the id→path tree walk must happen exactly ONCE per download,
//     not once per chunk.
//
// The counters hang on the same seams production calls
// (fileSHA256HexFn / scanRecordingsFn), so a regression — routing the
// work back to per-chunk — turns the counter red, not just slower.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// glmM12Payload is ~270 KiB, so a 128 KiB window makes a three-chunk
// download: enough chunks to prove "once", small enough to stay fast.
var glmM12Payload = bytes.Repeat([]byte("m12 quadratic-work canary\r\n"), 12*1024)

// glmM12TerminalRecording writes one finished terminal recording
// (recorder → .cast + .txt + .meta — the same on-disk shape a real PTY
// session leaves) and answers the id and base path the admin surface
// knows it by.
func glmM12TerminalRecording(t *testing.T, baseDir, sessionID string) (id, base string) {
	t.Helper()
	rec, err := record.NewRecorder(record.SessionConfig{
		BaseDir:      baseDir,
		Machine:      "m12box",
		Person:       "alice",
		SessionID:    sessionID,
		SubdirLayout: true,
	})
	if err != nil {
		t.Fatalf("record.NewRecorder: %v", err)
	}
	if _, err := rec.Write(glmM12Payload); err != nil {
		t.Fatalf("recorder write: %v", err)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder close: %v", err)
	}
	return glmM12FindRecording(t, baseDir, sessionID)
}

// glmM12FindRecording scans baseDir and answers the id and base path of
// the recording whose .meta names sessionID.
func glmM12FindRecording(t *testing.T, baseDir, sessionID string) (id, base string) {
	t.Helper()
	entries, err := scanRecordings(baseDir)
	if err != nil {
		t.Fatalf("scanRecordings: %v", err)
	}
	for _, e := range entries {
		if e.metadata.SessionID == sessionID {
			return e.id, e.base
		}
	}
	t.Fatalf("recording with session id %q not found among %d entries", sessionID, len(entries))
	return "", ""
}

// glmM12StripPartHashes rewrites the .meta the way recordings written
// before the hash-at-finalization rule look: same facts, no sha256 for
// the parts. ReadMeta/WriteMeta — the same atomic rewrite the recorder
// itself uses.
func glmM12StripPartHashes(t *testing.T, base string) {
	t.Helper()
	metaPath := base + ".meta"
	meta, err := record.ReadMeta(metaPath)
	if err != nil {
		t.Fatalf("ReadMeta: %v", err)
	}
	meta.CastFile.SHA256 = ""
	meta.TxtFile.SHA256 = ""
	if err := record.WriteMeta(metaPath, meta, 0); err != nil {
		t.Fatalf("WriteMeta: %v", err)
	}
}

func glmM12Fetch(t *testing.T, g *Gateway, id, part string, offset, limit int64) map[string]any {
	t.Helper()
	body, err := json.Marshal(map[string]any{"proto": 1, "id": id, "part": part, "offset": offset, "limit": limit})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, cerr := cmdRecordingsFetch(g, "admin", g.cfg.Now(), body)
	if cerr != nil {
		t.Fatalf("recordings.fetch %s@%d: %v", part, offset, cerr)
	}
	return res.(map[string]any)
}

// glmM12CountHashes counts how many times the gateway actually streams
// a recording file into its SHA-256 while the test runs.
func glmM12CountHashes(t *testing.T) *int {
	t.Helper()
	calls := 0
	prev := fileSHA256HexFn
	fileSHA256HexFn = func(path string) (string, error) {
		calls++
		return prev(path)
	}
	t.Cleanup(func() { fileSHA256HexFn = prev })
	return &calls
}

// glmM12CountWalks counts how many times the gateway walked the whole
// recordings tree while the test runs.
func glmM12CountWalks(t *testing.T) *int {
	t.Helper()
	calls := 0
	prev := scanRecordingsFn
	scanRecordingsFn = func(baseDir string) ([]recordingEntry, error) {
		calls++
		return prev(baseDir)
	}
	t.Cleanup(func() { scanRecordingsFn = prev })
	return &calls
}

func glmM12FileSHA(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// A finished recording whose .meta carries the finalization hash must be
// served without the gateway hashing ANY bytes: the recorder already did
// that work once, at finalize. Red today: every chunk streams the whole
// file into a fresh SHA-256.
func TestM12_MetaHashServedWithoutRehashing(t *testing.T) {
	f := newFixture(t, nil)
	id, base := glmM12TerminalRecording(t, f.recordingsDir(), "m12-metahash")
	want := glmM12FileSHA(t, base+".cast")

	calls := glmM12CountHashes(t)
	first := glmM12Fetch(t, f.gw, id, "cast", 0, 128<<10)
	if got := *calls; got != 0 {
		t.Fatalf("the FIRST chunk already made the gateway hash the recording (%d time(s)) although the .meta carries the finalization hash — serve that hash, do not compute it", got)
	}
	if first["sha256"] != want {
		t.Fatalf("served sha256 = %v, want the finalization hash %s", first["sha256"], want)
	}
	glmM12Fetch(t, f.gw, id, "cast", 128<<10, 128<<10)
	glmM12Fetch(t, f.gw, id, "cast", 256<<10, 128<<10)
	if got := *calls; got != 0 {
		t.Fatalf("a three-chunk download of a hashed .meta recording made the gateway hash %d time(s) — hash once at finalize, never per chunk", got)
	}
}

// A recording whose .meta predates the hash-at-finalization rule has no
// hash to serve: the gateway must compute it exactly ONCE — at the first
// request — and memoize it for the rest of the download. Red today:
// chunk 3 streams the whole file into SHA-256 for the third time.
func TestM12_LegacyMetaHashComputedOnce(t *testing.T) {
	f := newFixture(t, nil)
	id, base := glmM12TerminalRecording(t, f.recordingsDir(), "m12-legacy")
	glmM12StripPartHashes(t, base)
	want := glmM12FileSHA(t, base+".cast")

	calls := glmM12CountHashes(t)
	first := glmM12Fetch(t, f.gw, id, "cast", 0, 128<<10)
	if got := *calls; got != 1 {
		t.Fatalf("first chunk of a legacy recording must hash exactly once, got %d", got)
	}
	if first["sha256"] != want {
		t.Fatalf("served sha256 = %v, want %s", first["sha256"], want)
	}
	glmM12Fetch(t, f.gw, id, "cast", 128<<10, 128<<10)
	third := glmM12Fetch(t, f.gw, id, "cast", 256<<10, 128<<10)
	if got := *calls; got != 1 {
		t.Fatalf("chunks 2 and 3 must reuse the memoized hash: total hashes = %d, want 1", got)
	}
	if third["sha256"] != want {
		t.Fatalf("memoized sha256 = %v, want %s", third["sha256"], want)
	}
}

// The id→path lookup must not walk the whole recordings tree per chunk.
// Red today: three chunks, three walks.
func TestM12_DownloadWalksTreeOnce(t *testing.T) {
	f := newFixture(t, nil)
	id, _ := glmM12TerminalRecording(t, f.recordingsDir(), "m12-walkonce")

	walks := glmM12CountWalks(t)
	for _, off := range []int64{0, 128 << 10, 256 << 10} {
		glmM12Fetch(t, f.gw, id, "cast", off, 128<<10)
	}
	if got := *walks; got != 1 {
		t.Fatalf("a three-chunk download walked the recordings tree %d time(s) — resolve the id once, cache it, never walk per chunk", got)
	}
}

// A cached id must not outlive its recording: after rotation removed the
// files, the next fetch answers E_NOT_FOUND honestly — not a stale cache
// hit that resolves a dead path.
func TestM12_RotatedRecordingIsNotServedFromCache(t *testing.T) {
	f := newFixture(t, nil)
	id, base := glmM12TerminalRecording(t, f.recordingsDir(), "m12-rotated")
	glmM12Fetch(t, f.gw, id, "cast", 0, 128<<10) // populate the cache
	for _, ext := range []string{".cast", ".txt", ".meta"} {
		if err := os.Remove(base + ext); err != nil {
			t.Fatalf("remove %s: %v", base+ext, err)
		}
	}
	body, err := json.Marshal(map[string]any{"proto": 1, "id": id, "part": "cast", "offset": 0, "limit": 128 << 10})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_, cerr := cmdRecordingsFetch(f.gw, "admin", f.gw.cfg.Now(), body)
	if cerr == nil || cerr.code != "E_NOT_FOUND" {
		t.Fatalf("fetch of a rotated-away recording must be E_NOT_FOUND, got %v", cerr)
	}
}

// A recording still being written is not fetched at all (R1-CX F-13,
// 24.09.2026 — the live-serving this test used to pin down was the
// defect): its total and sha256 are facts of different moments of a
// growing file. The refusal must also do no hashing work. After finalize
// lands the hash in the .meta, the same id serves the finalization hash
// without hashing anything.
func TestM12_LiveRecordingHashNeverMemoized(t *testing.T) {
	f := newFixture(t, nil)
	baseDir := f.recordingsDir()
	rec, err := record.NewRecorder(record.SessionConfig{
		BaseDir:      baseDir,
		Machine:      "m12box",
		Person:       "alice",
		SessionID:    "m12-live",
		SubdirLayout: true,
	})
	if err != nil {
		t.Fatalf("record.NewRecorder: %v", err)
	}
	defer func() { _ = rec.Close() }()
	if _, err := rec.Write(glmM12Payload[:1024]); err != nil {
		t.Fatalf("recorder write: %v", err)
	}
	id, base := glmM12FindRecording(t, baseDir, "m12-live")

	calls := glmM12CountHashes(t)
	body, err := json.Marshal(map[string]any{"proto": 1, "id": id, "part": "cast", "offset": 0, "limit": 1 << 20})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, cerr := cmdRecordingsFetch(f.gw, "admin", f.gw.cfg.Now(), body); cerr == nil || cerr.code != "E_CONFLICT" {
		t.Fatalf("fetch of a live recording answered %v, want E_CONFLICT — a growing file is not fetched, it is watched with sessions.tail (F-13)", cerr)
	}
	if _, err := rec.Write(glmM12Payload[1024:]); err != nil {
		t.Fatalf("recorder write: %v", err)
	}
	if got := *calls; got != 0 {
		t.Fatalf("refusing a live recording made the gateway hash %d time(s) — the refusal reads the status and nothing else", got)
	}
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder close: %v", err)
	}
	final := glmM12Fetch(t, f.gw, id, "cast", 0, 1<<20)
	if final["sha256"] != glmM12FileSHA(t, base+".cast") {
		t.Fatalf("post-finalize sha256 = %v, want the finalization hash", final["sha256"])
	}
	if got := *calls; got != 0 {
		t.Fatalf("after finalize the .meta carries the hash, but the gateway hashed %d time(s)", got)
	}
}
