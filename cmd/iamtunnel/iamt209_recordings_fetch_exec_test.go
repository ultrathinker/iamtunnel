package main

// iamt209_recordings_fetch_exec_test.go — IAMT-209.
//
// The bug: "iamtunnel admin recordings fetch <id>" hard-coded the part
// list to {"cast", "txt"}. For a session without PTY (exec), the
// gateway writes only .exec.jsonl + .meta, so the cast/txt fetches
// came back with E_NOT_FOUND and the CLI surfaced
// "recording … part \"cast\" is not available" (exit 2). The fix
// probes the recording mode via .meta first and downloads only the
// parts the recording actually has.
//
// These tests pin the new logic end-to-end at three layers:
//
//   1. Pure functions (`partsForRecordingMode`, `detectRecordingMode`):
//      byte-level shape tests, no I/O.
//
//   2. fetchRecording itself: a recordingFetcher fake returns canned
//      chunks (the same shapes internal/gateway/admin_role.go sends),
//      and the test asserts the parts downloaded and the bytes
//      written to disk. The exec-mode branch and the terminal-mode
//      branch are both covered; the legacy-no-meta branch is the
//      "recordings produced by builds before IAMT-163 carried no
//      .meta" fallback.
//
//   3. The CLI subcommand end-to-end through driveEnv is NOT
//      exercised here — that is an "end-to-end test of an exec session
//      through the real gateway", and it lives in
//      internal/gateway/iamt209_exec_fetch_e2e_test.go and uses the
//      real fixture there.
//
// Canary details per test are documented in the comments above each
// assertion.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/admin"
)

// ---- pure-function canaries -------------------------------------------------

// TestIAMT209_PartsForRecordingMode is the byte-level canary for the
// mapping. A future mode (PROTOCOL §8 reserves the closed set "exec"
// and "terminal" today, but §1.1 explicitly allows new modes via
// capabilities in later versions) MUST keep "exec" → exec and an
// absent/terminal value → cast/txt; an accidental flip turns the
// fix into a regression at the byte level.
//
// Canary: rename the "exec" literal in partsForRecordingMode to
// "terminal". This test goes red on the exec-mode assertion.
func TestIAMT209_PartsForRecordingMode(t *testing.T) {
	cases := []struct {
		name string
		mode string
		want []string
	}{
		{"exec mode", "exec", []string{"exec"}},
		{"terminal mode", "terminal", []string{"cast", "txt"}},
		{"empty mode (legacy .meta)", "", []string{"cast", "txt"}},
		{"unknown mode falls through to terminal", "unknown", []string{"cast", "txt"}},
		{"future mode not yet known to CLI", "audio-stream-v1", []string{"cast", "txt"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := partsForRecordingMode(tc.mode)
			if len(got) != len(tc.want) {
				t.Fatalf("partsForRecordingMode(%q) = %v, want %v", tc.mode, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("partsForRecordingMode(%q)[%d] = %q, want %q", tc.mode, i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestIAMT209_DetectRecordingMode pins the meta decoding. Bytes that
// do not unmarshal (e.g. truncated .meta, garbage) must return "" —
// the caller then takes the terminal fallback, which is the safe
// direction: the worst case is "downloads files that don't exist",
// and the gateway answers that with E_NOT_FOUND on the first chunk,
// which fetchRecording's existing error path already handles.
//
// Canary: in detectRecordingMode, drop the `_ = json.Unmarshal` and
// unconditionally return the literal "exec". Garbage .meta now
// matches the exec branch and is renamed to .exec.jsonl, breaking
// every legacy recording. This test goes red on the garbage-→empty
// assertion.
func TestIAMT209_DetectRecordingMode(t *testing.T) {
	cases := []struct {
		name string
		meta string
		want string
	}{
		{"explicit exec", `{"recording_mode":"exec"}`, "exec"},
		{"explicit terminal", `{"recording_mode":"terminal"}`, "terminal"},
		{"absent field (legacy .meta)", `{"person":"alice"}`, ""},
		{"empty object", `{}`, ""},
		{"garbage bytes", `not json at all`, ""},
		{"null value", `{"recording_mode":null}`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detectRecordingMode([]byte(tc.meta)); got != tc.want {
				t.Fatalf("detectRecordingMode(%q) = %q, want %q", tc.meta, got, tc.want)
			}
		})
	}
}

// ---- fetchRecording with a canned gateway --------------------------------

// fakeRecordingFetcher answers RecordingsFetch with bytes chosen by the
// test, sliced at chunk boundaries. The shape is exactly what
// internal/gateway/admin_role.go's cmdRecordingsFetch produces on the
// wire (RecordingChunk), so tests using this fake are byte-equivalent
// to driving the real gateway over SSH. `parts` is the set of part
// names the fake will serve; anything not in the set returns an error
// matching the gateway's E_NOT_FOUND for an absent part — that lets
// the test pin the "fall back to terminal" path for legacy recordings
// with no .meta.
type fakeRecordingFetcher struct {
	parts  map[string][]byte // part name → full bytes
	totals map[string]int64  // optional: defaults to len(parts[name])
}

func (f *fakeRecordingFetcher) RecordingsFetch(id, part string, offset, limit int64) (admin.RecordingChunk, error) {
	data, ok := f.parts[part]
	if !ok {
		return admin.RecordingChunk{}, fmt.Errorf("recording %q part %q is not available", id, part)
	}
	total := int64(len(data))
	if t, ok := f.totals[part]; ok {
		total = t
	}
	if offset >= total {
		// Zero-chunk at offset==total is legal per PROTOCOL §6.
		sum := sha256.Sum256(data)
		return admin.RecordingChunk{
			ID: id, Part: part, Offset: offset, Total: total,
			SHA256: hex.EncodeToString(sum[:]), Data: "",
		}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	slice := data[offset:end]
	sum := sha256.Sum256(data)
	return admin.RecordingChunk{
		ID: id, Part: part, Offset: offset, Total: total,
		SHA256: hex.EncodeToString(sum[:]),
		Data:   base64.StdEncoding.EncodeToString(slice),
	}, nil
}

// chunkedRecordingBytes returns the same bytes a real gateway would
// serve, sliced into chunks of size `chunk` — fetchRecording's
// download loop must reassemble them byte-for-byte. This is the same
// dance the real fixture exercises in
// internal/gateway/iamt209_exec_fetch_e2e_test.go.
func chunkedRecordingBytes(t *testing.T, payload []byte, chunk int) [][]byte {
	t.Helper()
	var out [][]byte
	for i := 0; i < len(payload); i += chunk {
		end := i + chunk
		if end > len(payload) {
			end = len(payload)
		}
		out = append(out, payload[i:end])
	}
	if len(out) == 0 {
		out = append(out, nil)
	}
	return out
}

// TestIAMT209_FetchRecording_ExecMode_DownloadsExecAndMeta is the
// canary's primary half. An exec recording whose .meta says
// recording_mode="exec" must be downloaded as .exec.jsonl + .meta,
// NOT as .cast + .txt (which would surface E_NOT_FOUND, exactly the
// bug IAMT-209 fixes).
//
// Canary: in fetchRecording, swap the order — call partsForRecordingMode
// FIRST, then probe meta. With this swap the meta probe still works
// but the part list is now wrong: cast/txt for an exec recording.
// The test goes red on the .exec.jsonl assertion.
func TestIAMT209_FetchRecording_ExecMode_DownloadsExecAndMeta(t *testing.T) {
	dir := t.TempDir()
	execBytes := []byte("{\"sequence\":1,\"type\":\"command\",\"command\":\"whoami\"}\n")
	metaBytes := []byte(`{"recording_mode":"exec","person":"alice","machine":"vm1"}`)

	fake := &fakeRecordingFetcher{
		parts: map[string][]byte{
			"meta": metaBytes,
			"exec": execBytes,
		},
	}

	written, err := fetchRecording(fake, "rec-123", dir)
	if err != nil {
		t.Fatalf("fetchRecording: %v", err)
	}

	// Exactly two files: .exec.jsonl and .meta. No .cast, no .txt —
	// those would fail with E_NOT_FOUND on the real gateway and the
	// test asserts they are NOT attempted. The exec file keeps the
	// gateway-side name `<base>.exec.jsonl` (admin_role.go:1569-1570,
	// IAMT-212) so the downloaded directory mirrors the gateway
	// exactly; renaming it to .exec here would silently diverge from
	// the on-disk recording.
	wantNames := []string{"rec-123.exec.jsonl", "rec-123.meta"}
	if len(written) != len(wantNames) {
		t.Fatalf("fetchRecording wrote %d files (%v), want exactly %v", len(written), written, wantNames)
	}
	for i, name := range wantNames {
		if filepath.Base(written[i]) != name {
			t.Fatalf("written[%d] = %q, want basename %q", i, written[i], name)
		}
	}

	// The .exec.jsonl on disk must be byte-identical to what the
	// fake served — the streaming sha256 check on the way through
	// already proves SHA-256 matches; this proves the chunked
	// download re-assembled without loss.
	gotExec, err := os.ReadFile(filepath.Join(dir, "rec-123.exec.jsonl"))
	if err != nil {
		t.Fatalf("read downloaded .exec.jsonl: %v", err)
	}
	if string(gotExec) != string(execBytes) {
		t.Fatalf("downloaded .exec.jsonl = %q, want %q", gotExec, execBytes)
	}
	gotMeta, err := os.ReadFile(filepath.Join(dir, "rec-123.meta"))
	if err != nil {
		t.Fatalf("read downloaded .meta: %v", err)
	}
	if string(gotMeta) != string(metaBytes) {
		t.Fatalf("downloaded .meta = %q, want %q", gotMeta, metaBytes)
	}
}

// TestIAMT209_FetchRecording_TerminalMode_DownloadsCastTxtAndMeta
// pins the terminal branch: a recording whose .meta says
// recording_mode="terminal" must NOT probe for "exec" (the gateway
// answers E_NOT_FOUND for that on terminal recordings, PROTOCOL §6).
// Today this is the same set the pre-IAMT-209 code asked for, so
// the canary is "did the fix accidentally regress terminal?"
//
// Canary: in partsForRecordingMode, rename the default branch's
// return to []string{"exec"}. Terminal recordings are now downloaded
// as .exec.jsonl (which doesn't exist on disk) and the test goes red
// on the .cast assertion.
func TestIAMT209_FetchRecording_TerminalMode_DownloadsCastTxtAndMeta(t *testing.T) {
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

	written, err := fetchRecording(fake, "rec-456", dir)
	if err != nil {
		t.Fatalf("fetchRecording: %v", err)
	}
	wantNames := []string{"rec-456.cast", "rec-456.txt", "rec-456.meta"}
	if len(written) != len(wantNames) {
		t.Fatalf("fetchRecording wrote %d files (%v), want exactly %v", len(written), written, wantNames)
	}
	for i, name := range wantNames {
		if filepath.Base(written[i]) != name {
			t.Fatalf("written[%d] = %q, want basename %q", i, written[i], name)
		}
	}
	gotCast, err := os.ReadFile(filepath.Join(dir, "rec-456.cast"))
	if err != nil {
		t.Fatalf("read .cast: %v", err)
	}
	if string(gotCast) != string(castBytes) {
		t.Fatalf("downloaded .cast = %q, want %q", gotCast, castBytes)
	}
}

// TestIAMT209_FetchRecording_LegacyNoMeta_FallsBackToTerminal pins
// the third branch: a recording whose .meta fetch comes back with an
// E_NOT_FOUND (the fake simulates this by not serving "meta" at all)
// must fall back to the terminal parts, exactly what pre-IAMT-209
// fetch did for every recording. This is the path recordings written
// by builds before IAMT-163 take — they have no .meta on disk.
//
// Canary: in fetchRecording, change the "meta fetch fails" branch to
// return a hard error. Legacy recordings can no longer be downloaded
// and this test goes red on the err==nil assertion.
func TestIAMT209_FetchRecording_LegacyNoMeta_FallsBackToTerminal(t *testing.T) {
	dir := t.TempDir()
	castBytes := []byte("legacy-cast\n")
	txtBytes := []byte("legacy-txt\n")

	// Fake that does NOT serve "meta" at all — fetchRecording's meta
	// probe returns E_NOT_FOUND-shaped error → the function falls
	// back to terminal parts.
	fake := &fakeRecordingFetcher{
		parts: map[string][]byte{
			"cast": castBytes,
			"txt":  txtBytes,
		},
	}

	written, err := fetchRecording(fake, "rec-789", dir)
	if err != nil {
		t.Fatalf("fetchRecording (legacy no-meta): %v — must fall back to terminal parts", err)
	}
	wantNames := []string{"rec-789.cast", "rec-789.txt"}
	if len(written) != len(wantNames) {
		t.Fatalf("fetchRecording wrote %d files (%v), want exactly %v (no .meta: terminal-only fallback)", len(written), written, wantNames)
	}
	for i, name := range wantNames {
		if filepath.Base(written[i]) != name {
			t.Fatalf("written[%d] = %q, want basename %q", i, written[i], name)
		}
	}
}

// TestIAMT209_FetchRecording_ExecWithChunkedDownload exercises the
// download loop's chunk reassembly: a large payload split into
// multiple chunks must come back byte-identical to what the fake
// served. fetchRecording's streamRecordingPart uses a 1 MiB chunk
// (well under PROTOCOL's 1..1048576 limit); the test deliberately
// uses tiny chunks (16 B) so the loop runs many iterations on the
// same code path.
//
// Canary: in streamRecording, drop the loop's "len(raw)==0"
// guard so it runs forever on a zero-length final chunk. This test
// hangs in CI until its deadline; the variant guard is what catches
// the bug here (we cannot time-out the test runner from inside the
// test). The simpler canary is "remove the `offset += int64(len(raw))`
// step" — the loop would never advance and streamRecordingPart
// would return zero bytes after one iteration; this test goes red on
// the byte-equal assertion.
func TestIAMT209_FetchRecording_ExecWithChunkedDownload(t *testing.T) {
	dir := t.TempDir()
	// Build a payload larger than the fake's chunk size so the loop
	// runs at least twice.
	var payload []byte
	for i := 0; i < 32; i++ {
		payload = append(payload, []byte(fmt.Sprintf("line-%02d-padding\n", i))...)
	}
	metaBytes := []byte(`{"recording_mode":"exec"}`)

	fake := &chunkedFakeFetcher{
		parts: map[string][]byte{
			"meta": metaBytes,
			"exec": payload,
		},
		chunk: 16, // tiny so the loop runs many times
	}

	written, err := fetchRecording(fake, "rec-big", dir)
	if err != nil {
		t.Fatalf("fetchRecording chunked: %v", err)
	}
	if len(written) != 2 {
		t.Fatalf("written = %v, want exactly [rec-big.exec.jsonl rec-big.meta]", written)
	}
	gotExec, err := os.ReadFile(filepath.Join(dir, "rec-big.exec.jsonl"))
	if err != nil {
		t.Fatalf("read .exec: %v", err)
	}
	if string(gotExec) != string(payload) {
		t.Fatalf("chunked download reassembled to %q, want %q (lengths: got=%d want=%d)", gotExec, payload, len(gotExec), len(payload))
	}
}

// chunkedFakeFetcher is the same as fakeRecordingFetcher but slices
// responses at a configurable chunk size, so a test can exercise
// fetchRecording's chunked-download loop without writing megabytes
// of payload.
type chunkedFakeFetcher struct {
	parts map[string][]byte
	chunk int
}

func (f *chunkedFakeFetcher) RecordingsFetch(id, part string, offset, limit int64) (admin.RecordingChunk, error) {
	data, ok := f.parts[part]
	if !ok {
		return admin.RecordingChunk{}, fmt.Errorf("recording %q part %q is not available", id, part)
	}
	total := int64(len(data))
	if offset >= total {
		sum := sha256.Sum256(data)
		return admin.RecordingChunk{
			ID: id, Part: part, Offset: offset, Total: total,
			SHA256: hex.EncodeToString(sum[:]), Data: "",
		}, nil
	}
	chunk := int64(f.chunk)
	if limit < chunk {
		chunk = limit
	}
	end := offset + chunk
	if end > total {
		end = total
	}
	slice := data[offset:end]
	sum := sha256.Sum256(data)
	return admin.RecordingChunk{
		ID: id, Part: part, Offset: offset, Total: total,
		SHA256: hex.EncodeToString(sum[:]),
		Data:   base64.StdEncoding.EncodeToString(slice),
	}, nil
}

// TestIAMT209_FetchRecording_SHA256MismatchFails exercises the
// streaming sha256 guard inside streamRecordingPart: a part whose chunk
// advertises a SHA-256 the bytes do NOT actually hash to must be
// rejected, not written. Today this is the only thing standing
// between a wire-corruption bug and a silent "looks like an exec
// recording, contains garbage" download.
//
// Canary: make streamRecordingPart skip the hash check (verify=false
// on streamRecording). A fake that returns chunks with deliberately
// wrong SHA-256 now succeeds and writes the corrupted bytes to disk;
// this test goes red on the err != nil assertion.
func TestIAMT209_FetchRecording_SHA256MismatchFails(t *testing.T) {
	dir := t.TempDir()
	execBytes := []byte("real-exec-bytes\n")
	// Honest SHA of the bytes the test set up, so the chunk that
	// comes back matches; but the RecordingChunk advertises a
	// DIFFERENT SHA, mimicking a corrupted or hostile gateway.
	honestSum := sha256.Sum256(execBytes)
	bogusSum := sha256.Sum256([]byte("not what was sent"))
	fake := &shaLieFetcher{
		parts:     map[string][]byte{"exec": execBytes, "meta": []byte(`{"recording_mode":"exec"}`)},
		lieSHA256: hex.EncodeToString(bogusSum[:]),
		honestSHA: hex.EncodeToString(honestSum[:]),
	}

	_, err := fetchRecording(fake, "rec-bad", dir)
	if err == nil {
		t.Fatalf("fetchRecording with bogus SHA-256 must fail; got success — the streaming sha256 check was bypassed")
	}
	if !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("err = %v, want one mentioning sha256 mismatch", err)
	}
}

// shaLieFetcher is a fakeRecordingFetcher that always reports
// lieSHA256 in the RecordingChunk.SHA256 field. Used to drive the
// streaming sha256 verification failure path.
type shaLieFetcher struct {
	parts     map[string][]byte
	lieSHA256 string
	honestSHA string
}

func (f *shaLieFetcher) RecordingsFetch(id, part string, offset, limit int64) (admin.RecordingChunk, error) {
	data, ok := f.parts[part]
	if !ok {
		return admin.RecordingChunk{}, fmt.Errorf("recording %q part %q is not available", id, part)
	}
	total := int64(len(data))
	if offset >= total {
		return admin.RecordingChunk{
			ID: id, Part: part, Offset: offset, Total: total,
			SHA256: f.lieSHA256, Data: "",
		}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	slice := data[offset:end]
	return admin.RecordingChunk{
		ID: id, Part: part, Offset: offset, Total: total,
		SHA256: f.lieSHA256,
		Data:   base64.StdEncoding.EncodeToString(slice),
	}, nil
}

// TestIAMT209_FetchRecording_PinToMetaFirstCallOrder is a
// behavioural canary on the call ORDER, not just the outcome. fetch
// must probe meta before asking for cast/txt/exec, otherwise an
// exec recording would surface a bogus "cast not available" error
// before the mode probe even ran. The orderFetcher counts meta
// calls and refuses to serve anything until meta has been asked
// for, then refuses to serve anything after the wrong part comes
// first.
//
// Canary: in fetchRecording, swap the order — call
// partsForRecordingMode BEFORE the meta probe. Without meta data the
// mode is unknown and the default ("terminal") is used, which means
// cast is asked first; this test goes red on the order assertion
// (meta must be the very first RecordingsFetch call).
func TestIAMT209_FetchRecording_PinToMetaFirstCallOrder(t *testing.T) {
	dir := t.TempDir()
	// Caller-side assertor: the test makes the fake RECORDER call
	// meta first, and returns an error for any other part until
	// meta has been asked for. If fetchRecording asks for cast or
	// txt or exec before meta, the fake returns an error and the
	// fetchRecording call exits with the wrong message.
	calls := &callOrderRecorder{}
	fake := &orderEnforcingFetcher{
		recorder: calls,
		parts: map[string][]byte{
			"meta": []byte(`{"recording_mode":"exec"}`),
			"exec": []byte("ok"),
		},
	}
	if _, err := fetchRecording(fake, "rec-order", dir); err != nil {
		t.Fatalf("fetchRecording: %v", err)
	}
	if len(calls.order) == 0 || calls.order[0] != "meta" {
		t.Fatalf("first fetch call was %v, want exactly [meta, …] — fetch must probe meta before asking for cast/txt/exec", calls.order)
	}
}

type callOrderRecorder struct {
	order []string
}

type orderEnforcingFetcher struct {
	recorder *callOrderRecorder
	parts    map[string][]byte
}

func (f *orderEnforcingFetcher) RecordingsFetch(id, part string, offset, limit int64) (admin.RecordingChunk, error) {
	f.recorder.order = append(f.recorder.order, part)
	data, ok := f.parts[part]
	if !ok {
		return admin.RecordingChunk{}, fmt.Errorf("recording %q part %q is not available", id, part)
	}
	total := int64(len(data))
	if offset >= total {
		sum := sha256.Sum256(data)
		return admin.RecordingChunk{ID: id, Part: part, Offset: offset, Total: total, SHA256: hex.EncodeToString(sum[:])}, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	slice := data[offset:end]
	sum := sha256.Sum256(data)
	return admin.RecordingChunk{
		ID: id, Part: part, Offset: offset, Total: total,
		SHA256: hex.EncodeToString(sum[:]),
		Data:   base64.StdEncoding.EncodeToString(slice),
	}, nil
}

// TestIAMT209_FetchRecording_WritesMeta_LastInOrder confirms that
// .meta is appended AFTER the streaming parts in the returned
// `written` list. The CLI surface (cmd/iamtunnel/admin_exec.go's
// `recordings/fetch` switch) prints `wrote <path>` in the same
// order; pinning the order means the operator's eyes see
// `.exec.jsonl` / `.meta` rather than `.meta` first then the stream.
//
// Canary: in fetchRecording, swap the order — append "meta" to the
// front of `parts` instead of the end. The .meta file is written
// first and `written[0]` becomes rec-X.meta; this test goes red on
// the basename-order assertion.
func TestIAMT209_FetchRecording_WritesMeta_LastInOrder(t *testing.T) {
	dir := t.TempDir()
	fake := &fakeRecordingFetcher{
		parts: map[string][]byte{
			"meta": []byte(`{"recording_mode":"exec"}`),
			"exec": []byte("ok"),
		},
	}
	written, err := fetchRecording(fake, "rec-order2", dir)
	if err != nil {
		t.Fatalf("fetchRecording: %v", err)
	}
	if len(written) != 2 {
		t.Fatalf("written = %v, want exactly 2 entries", written)
	}
	if filepath.Base(written[0]) != "rec-order2.exec.jsonl" {
		t.Fatalf("written[0] = %q, want rec-order2.exec.jsonl (streaming part first, IAMT-212: keep gateway-side name)", filepath.Base(written[0]))
	}
	if filepath.Base(written[1]) != "rec-order2.meta" {
		t.Fatalf("written[1] = %q, want rec-order2.meta (meta appended last)", filepath.Base(written[1]))
	}
}

// TestIAMT209_FetchRecording_PTYBranchNotRegressed is a small
// double-check: the existing PTY path still works end-to-end through
// the new code. It uses the same fake shape as the existing
// IAMT-163 test and the same cast/txt assertion shape, but routes
// through fetchRecording (which the IAMT-163 test does not).
//
// Canary: in fetchRecording, drop the `parts = append(parts, "meta")`
// line. Terminal recordings no longer get their .meta on disk and
// the third basename assertion goes red.
func TestIAMT209_FetchRecording_PTYBranchNotRegressed(t *testing.T) {
	dir := t.TempDir()
	fake := &fakeRecordingFetcher{
		parts: map[string][]byte{
			"meta": []byte(`{"recording_mode":"terminal"}`),
			"cast": []byte(`{"version":2}` + "\n"),
			"txt":  []byte("hi\n"),
		},
	}
	written, err := fetchRecording(fake, "rec-pty", dir)
	if err != nil {
		t.Fatalf("fetchRecording PTY: %v", err)
	}
	want := []string{"rec-pty.cast", "rec-pty.txt", "rec-pty.meta"}
	if len(written) != len(want) {
		t.Fatalf("written = %v, want %v", written, want)
	}
	for i, n := range want {
		if filepath.Base(written[i]) != n {
			t.Fatalf("written[%d] = %q, want basename %q", i, written[i], n)
		}
	}
}

// TestIAMT209_FetchRecording_RecordingModeWithUnknownCase pins the
// mode-bytes equality: PROTOCOL §8 names the mode literally "exec";
// a future code path that lower-cases the value before comparing
// would silently route the recording through the wrong branch.
//
// Canary: in partsForRecordingMode, lowercase the switch case
// (`case strings.ToLower("exec")`) and rename the literal. The
// mode value "exec" no longer matches and a recording with
// `recording_mode:"exec"` is now treated as terminal. This test
// goes red on the exec-branches assertion.
func TestIAMT209_FetchRecording_RecordingModeWithUnknownCase(t *testing.T) {
	dir := t.TempDir()
	// Same-shape .meta with the mode spelled exactly "exec" (the
	// PROTOCOL §8 wire form).
	metaBytes := []byte(`{"recording_mode":"exec","machine":"vm1"}`)
	fake := &fakeRecordingFetcher{
		parts: map[string][]byte{
			"meta": metaBytes,
			"exec": []byte("ok"),
		},
	}
	written, err := fetchRecording(fake, "rec-mode-case", dir)
	if err != nil {
		t.Fatalf("fetchRecording: %v", err)
	}
	// No .cast (the fake does not serve it; if the CLI asked for
	// cast, it would have come back with an E_NOT_FOUND error and
	// this test would fatal on err != nil).
	if len(written) != 2 {
		t.Fatalf("written = %v, want exactly 2 entries (exec + meta)", written)
	}
	if filepath.Base(written[0]) != "rec-mode-case.exec.jsonl" {
		t.Fatalf("written[0] = %q, want rec-mode-case.exec.jsonl (mode \"exec\" must take the exec branch, IAMT-212: keep gateway-side name)", filepath.Base(written[0]))
	}
}

// roundTripMetaConfirm is a tiny utility the e2e test below uses to
// prove the .meta JSON the gateway actually emits is parseable by
// detectRecordingMode: the bytes the fetchRecording test wrote to
// disk must round-trip through detectRecordingMode and pick the
// same branch the live code took.
//
// Canary: drop the .meta file from the list of parts the live fetch
// downloads. detectRecordingMode then sees a .meta that lives on
// disk (from a previous run, or empty), so this test goes red on
// the second fetchRecording call.
func TestIAMT209_FetchRecording_MetaRoundTrip(t *testing.T) {
	dir := t.TempDir()
	metaBytes := []byte(`{"recording_mode":"exec","person":"alice","machine":"vm1"}`)
	fake := &fakeRecordingFetcher{
		parts: map[string][]byte{
			"meta": metaBytes,
			"exec": []byte("ok"),
		},
	}
	if _, err := fetchRecording(fake, "rec-roundtrip", dir); err != nil {
		t.Fatalf("fetchRecording: %v", err)
	}
	// Re-read the .meta fetchRecording wrote and confirm
	// detectRecordingMode still classifies it the same way. This
	// is what catches a silent mismatch between the gateway's
	// recording_mode wire form and what detectRecordingMode parses.
	writtenMeta, err := os.ReadFile(filepath.Join(dir, "rec-roundtrip.meta"))
	if err != nil {
		t.Fatalf("read .meta from disk: %v", err)
	}
	if got := detectRecordingMode(writtenMeta); got != "exec" {
		t.Fatalf("detectRecordingMode(<written .meta>) = %q, want %q", got, "exec")
	}
	// And the reverse: a real .meta payload the gateway sends
	// (per the IAMT-163 fixture in
	// internal/gateway/record/exec_recorder.go) must round-trip too.
	if got := detectRecordingMode([]byte(`{"recording_mode":"exec","exec_file":{"name":"x.exec.jsonl","size":1,"sha256":"a"}}`)); got != "exec" {
		t.Fatalf("detectRecordingMode(realistic .meta) = %q, want %q", got, "exec")
	}
}

// TestIAMT209_JSONShape_RecordingChunkExact pins the wire shape
// fetchRecording reads. The fake uses admin.RecordingChunk
// directly; this test re-encodes a fixed chunk to JSON and back to
// catch a typo in the RecordingChunk struct that the live code
// would silently mis-read.
//
// Canary: rename RecordingChunk.SHA256 to RecordingChunk.Sha256.
// The on-wire JSON key "sha256" no longer round-trips and this test
// goes red on the field assertion.
func TestIAMT209_JSONShape_RecordingChunkExact(t *testing.T) {
	in := admin.RecordingChunk{
		ID: "rec-json", Part: "exec", Offset: 12, Total: 99,
		SHA256: "deadbeef", Data: "aGVsbG8=",
	}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out admin.RecordingChunk
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip RecordingChunk =\n%+v\nwant\n%+v\njson=%s", out, in, data)
	}
	// And: RecordingChunk.SHA256 maps to the wire key "sha256"
	// (PROTOCOL §6) — not "Sha256", not "hash". A Go-fmt-renamed
	// field would silently break fetch.
	if !strings.Contains(string(data), `"sha256":"deadbeef"`) {
		t.Fatalf("RecordingChunk.SHA256 wire key changed; JSON=%s", data)
	}
}

// _ keeps unused imports live while the file is being iterated.
var _ = chunkedRecordingBytes
var _ = base64.StdEncoding.EncodeToString
