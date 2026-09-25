package gateway

// R1-CX F-13 (review of 22-23.09): recordings.fetch served a
// recording whose .meta still says status:"recording" - a file that is
// being written as it is served. The response's "total" is one Stat and
// its "sha256" a separate hashing pass, so the two facts of one answer
// already belong to different moments of a growing file; worse, the file
// keeps growing BETWEEN the chunks of one download, and the client walks
// offset by offset against a moving end - it either stops early on a
// stale total (an incomplete transcript that looks complete) or verifies
// a hash of a prefix against the finished file. PROTOCOL §6 leaves live
// viewing to sessions.tail and describes recordings.fetch as reading a
// finished recording; the check for that was simply missing. The fix
// refuses every part of a still-growing recording (the .meta itself is
// rewritten at finalize, so even part "meta" flips under the reader) and
// serves again once the session has ended.

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

// r1cxF13TryFetch runs one recordings.fetch and hands back whichever of
// the answer or the refusal the gateway produced - neither is a failure
// here; the test below is what judges them.
func r1cxF13TryFetch(t *testing.T, g *Gateway, id, part string, offset, limit int64) (map[string]any, *cmdError) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"proto": 1, "id": id, "part": part, "offset": offset, "limit": limit})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	res, cerr := cmdRecordingsFetch(g, "admin", g.cfg.Now(), body)
	if cerr != nil {
		return nil, cerr
	}
	out, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("recordings.fetch returned %T, want a map", res)
	}
	return out, nil
}

func TestR1CX_F13_FetchRefusesARecordingStillBeingWritten(t *testing.T) {
	f := newFixture(t, nil)
	baseDir := f.recordingsDir()
	rec, err := record.NewRecorder(record.SessionConfig{
		BaseDir:      baseDir,
		Machine:      "m13box",
		Person:       "alice",
		SessionID:    "m13-live",
		SubdirLayout: true,
	})
	if err != nil {
		t.Fatalf("record.NewRecorder: %v", err)
	}
	// A test that aborts before its explicit Close would leave the .cast
	// open and fail t.TempDir's cleanup; finalize is idempotent, so this
	// is safe beside the explicit Close below.
	defer func() { _ = rec.Close() }()
	if _, err := rec.Write(r1cxPayload()); err != nil {
		t.Fatalf("recorder write: %v", err)
	}
	id, base := glmM12FindRecording(t, baseDir, "m13-live")

	// The scenario the finding names: the same live recording, fetched
	// twice, with the file growing between the two requests. Each answer's
	// total and sha256 are facts of the instant that answer was built.
	live1, cerr1 := r1cxF13TryFetch(t, f.gw, id, "cast", 0, 1<<20)
	if _, err := rec.Write(r1cxPayload()); err != nil {
		t.Fatalf("recorder write: %v", err)
	}
	live2, cerr2 := r1cxF13TryFetch(t, f.gw, id, "cast", 0, 1<<20)

	if cerr1 == nil {
		t.Fatalf("recordings.fetch served part %q of a recording whose .meta says status:\"recording\": two fetches of the same live recording answered total=%v sha256=%v and then total=%v sha256=%v - the size and the hash moved between requests, so the client's chunk walk verifies facts of two different moments (F-13)", "cast", live1["total"], live1["sha256"], live2["total"], live2["sha256"])
	}
	if cerr1.code != "E_CONFLICT" {
		t.Fatalf("fetch of a live recording refused with %v, want E_CONFLICT - the recording exists, it is just not finished (F-13)", cerr1)
	}
	if cerr2 == nil || cerr2.code != "E_CONFLICT" {
		t.Fatalf("after the file grew the live recording was still served (cerr=%v), want the same E_CONFLICT refusal (F-13)", cerr2)
	}

	// The .meta part is refused too: the recorder rewrites it at finalize,
	// so even that one stable-looking file flips under the reader.
	if _, cerrMeta := r1cxF13TryFetch(t, f.gw, id, "meta", 0, 1<<20); cerrMeta == nil || cerrMeta.code != "E_CONFLICT" {
		t.Fatalf("fetch of a live recording's .meta part answered %v, want E_CONFLICT (F-13)", cerrMeta)
	}

	// A refusal reads one small .meta and no recording bytes: none of the
	// live fetches may have streamed anything into a hash.
	if got := *glmM12CountHashes(t); got != 0 {
		t.Fatalf("refusing a live recording still hashed a part file %d time(s) - the refusal reads the status and nothing else (F-13)", got)
	}

	// The session ends - the same id becomes fetchable, with the
	// finalization hash the recorder wrote into the .meta.
	if err := rec.Close(); err != nil {
		t.Fatalf("recorder close: %v", err)
	}
	final := glmM12Fetch(t, f.gw, id, "cast", 0, 1<<20)
	if final["sha256"] != glmM12FileSHA(t, base+".cast") {
		t.Fatalf("after the session ended the fetch answered sha256=%v, want the finalization hash %s", final["sha256"], glmM12FileSHA(t, base+".cast"))
	}
}

// r1cxPayload is a fresh block of bytes per call, so the recording
// genuinely grows between the two fetches.
func r1cxPayload() []byte {
	return bytes.Repeat([]byte("r1-cx f13 live-recording canary\r\n"), 8192)
}
