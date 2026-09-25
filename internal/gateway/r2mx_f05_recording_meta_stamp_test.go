package gateway

// R2-MX F-05 of the round-2 review (24.09.2026), low:
// recordingPartSHA256 took the stamp it memozies a hash under by name
// (os.Stat) and then the content by name (record.ReadMeta) - two opens of
// one path. A .meta replaced between them gave the memo a stamp belonging
// to one file and a hash read from another, and the memo then answered for
// a .meta that was never read. The window is one open wide and the
// recordings directory is the gateway's own storage, so nothing here is a
// way in; what it breaks is the one invariant a cache keyed by a stamp has
// to hold - the answer is about the file that was read.
//
// The two opens are the defect, so the test drives the open: the seam
// hands the code a .meta that is NOT the one the path names, and both the
// hash and the stamp have to come from it. Reading by name instead answers
// from a file the caller never opened, which is what the review found.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
)

func r2mxWriteMeta(t *testing.T, path string, meta record.Metadata) int64 {
	t.Helper()
	raw, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		t.Fatalf("marshalling the .meta for %s: %v", path, err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return int64(len(raw))
}

func TestR2MXF05_TheHashAndItsStampComeFromTheSameMeta(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "rec1")
	if err := os.WriteFile(base+".cast", []byte("the cast part, as recorded"), 0o600); err != nil {
		t.Fatalf("writing the cast part: %v", err)
	}
	// The .meta the path names: completed, no finalization hash recorded,
	// so the memo path is the one this call takes.
	r2mxWriteMeta(t, base+".meta", record.Metadata{SessionID: "rec1", Status: "completed", BytesOut: 26})

	// Substitution one: another .meta, which records a hash for the cast
	// part. It is what the code opens, so it is what the answer has to come
	// from.
	const otherHash = "sha256:00000000000000000000000000000000000000000000000000000000deadbeef"
	otherWithHash := filepath.Join(dir, "other-with-hash.meta")
	r2mxWriteMeta(t, otherWithHash, record.Metadata{
		SessionID: "rec1", Status: "completed", BytesOut: 26,
		CastFile: record.FileInfo{SHA256: otherHash},
	})
	recordingOpenMetaFn = func(string) (*os.File, error) { return os.Open(otherWithHash) }
	sum, cerr := recordingPartSHA256(dir, "rec1", base, "cast")
	recordingOpenMetaFn = nil
	if cerr != nil {
		t.Fatalf("recordingPartSHA256: %v", cerr)
	}
	if sum != otherHash {
		t.Errorf("the .meta the code opened records %q for the cast part and the answer is %q: the content was read by name, from a file other than the one the stamp came from, and a recording's reported hash can then belong to another version of it (F-05)", otherHash, sum)
	}

	// Substitution two: a .meta of a different SIZE and with no recorded
	// hash, so the memo is written this time - and it has to be keyed by
	// the stamp of the .meta that was read, not of the one the path names.
	otherBig := filepath.Join(dir, "other-big.meta")
	otherSize := r2mxWriteMeta(t, otherBig, record.Metadata{
		SessionID: "rec2", Status: "completed", BytesOut: 26,
		ExitReason: "the session ended by itself and left this long explanation behind, which is here only to make this .meta a different size from the one the path names",
	})
	recordingOpenMetaFn = func(string) (*os.File, error) { return os.Open(otherBig) }
	_, cerr = recordingPartSHA256(dir, "rec2", base, "cast")
	recordingOpenMetaFn = nil
	if cerr != nil {
		t.Fatalf("recordingPartSHA256 (second call): %v", cerr)
	}
	recordingsHashMu.Lock()
	memo, has := recordingsHashMemo["rec2\x00cast"]
	recordingsHashMu.Unlock()
	if !has {
		t.Fatalf("no hash was memoized for the second call, so this half of the test proves nothing")
	}
	if memo.size != otherSize {
		t.Errorf("the memo is keyed by a %d-byte .meta and the one that was read is %d bytes: the stamp belongs to a different file than the content, so the cache answers for a .meta nobody read (F-05)", memo.size, otherSize)
	}
}
