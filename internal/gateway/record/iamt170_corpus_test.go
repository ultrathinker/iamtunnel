package record

// iamt170_corpus_test.go runs the VT parser over the six real PowerShell
// 5.1 (conhost/ConPTY, OpenSSH_9.5p1 for Windows) sessions captured
// on 2026-09-14 through the real gateway (testdata/corpus/*.cast)
// and byte-compares the resulting transcript against a hand-composed
// reference .txt (testdata/corpus/*.txt) - "what a human watching an 80x24
// terminal would have seen", per SPEC §6.5 — including the spots that were
// disputed during development (post-cls content, the progress-bar
// rendering, the missing checkmark).
//
// Canary: damage any one of the sequences called out for a given
// file (e.g. revert IAMT-215's wrapPending fix in vt.go) and exactly that
// file's subtest fails with a diff pinpointing the first differing byte -
// the other five stay green, since each corpus file exercises a distinct
// set of sequences.
import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestIAMT170_CorpusTranscripts(t *testing.T) {
	const dir = "testdata/corpus"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}

	found := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".cast" {
			continue
		}
		found++
		base := name[:len(name)-len(".cast")]
		t.Run(base, func(t *testing.T) {
			castPath := filepath.Join(dir, name)
			wantPath := filepath.Join(dir, base+".txt")

			got, err := replayCastTranscript(castPath)
			if err != nil {
				t.Fatalf("replay %s: %v", castPath, err)
			}

			wantRaw, err := os.ReadFile(wantPath)
			if err != nil {
				t.Fatalf("read reference %s: %v", wantPath, err)
			}
			want := string(wantRaw)

			if got != want {
				t.Fatalf("IAMT-170 canary (%s): parser transcript does not match the reference transcript.\n--- got ---\n%s\n--- want ---\n%s\n--- first diff ---\n%s",
					base, got, want, firstDiff(got, want))
			}
		})
	}

	if found != 6 {
		t.Fatalf("IAMT-170 canary precondition failed: expected 6 .cast files in %s, found %d", dir, found)
	}
}

// replayCastTranscript replays every "o" (and "r", per PROTOCOL §4.1) event
// of an asciicast v2 file through a fresh VT sized from the file's own
// header, exactly as record.Recorder does for a live session, and returns
// the resulting Transcript().
func replayCastTranscript(castPath string) (string, error) {
	f, err := os.Open(castPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	if !sc.Scan() {
		return "", fmt.Errorf("%s: empty file", castPath)
	}
	var header CastHeader
	if err := json.Unmarshal(sc.Bytes(), &header); err != nil {
		return "", fmt.Errorf("%s: decode header: %w", castPath, err)
	}

	vt := NewVT(header.Width, header.Height)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var ev [3]json.RawMessage
		if err := json.Unmarshal(line, &ev); err != nil {
			return "", fmt.Errorf("%s: decode event: %w", castPath, err)
		}
		var kind, data string
		if err := json.Unmarshal(ev[1], &kind); err != nil {
			return "", fmt.Errorf("%s: decode event type: %w", castPath, err)
		}
		if err := json.Unmarshal(ev[2], &data); err != nil {
			return "", fmt.Errorf("%s: decode event data: %w", castPath, err)
		}
		switch kind {
		case "o":
			if _, err := vt.Write([]byte(data)); err != nil {
				return "", err
			}
		case "r":
			var w, h int
			if _, err := fmt.Sscanf(data, "%dx%d", &w, &h); err == nil && w > 0 && h > 0 {
				vt.Resize(w, h)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("%s: scan: %w", castPath, err)
	}
	vt.Flush()
	return vt.Transcript(), nil
}

// firstDiff returns a short marker of the first byte at which got and want
// diverge, so a failing canary points straight at the broken sequence
// instead of a large opaque blob.
func firstDiff(got, want string) string {
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			lo := i - 20
			if lo < 0 {
				lo = 0
			}
			hi := i + 20
			if hi > n {
				hi = n
			}
			return fmt.Sprintf("byte %d: got ...%s|MISMATCH|%s... vs want ...%s|MISMATCH|%s...",
				i, got[lo:min(i+1, len(got))], got[min(i+1, len(got)):min(hi, len(got))],
				want[lo:min(i+1, len(want))], want[min(i+1, len(want)):min(hi, len(want))])
		}
	}
	if len(got) != len(want) {
		return fmt.Sprintf("lengths differ: got %d want %d (one is a prefix of the other)", len(got), len(want))
	}
	return "(no diff found - should not happen)"
}
