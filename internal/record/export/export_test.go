package export

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

var testZone = time.FixedZone("TEST", 3*3600)

// recordingJournal is the EventSink stand-in: it records what the
// exporter wrote, or fails on demand, so the "journal refused the
// event after the files landed" case is exercisable without a real log.
type recordingJournal struct {
	events []events.Event
	err    error
}

func (j *recordingJournal) Append(e events.Event) error {
	if j.err != nil {
		return j.err
	}
	j.events = append(j.events, e)
	return nil
}

func testRequest(root string, journal EventSink) Request {
	return Request{
		Root:       root,
		Transcript: strings.NewReader("one\n"),
		Cast:       strings.NewReader("cast-bytes-here"),
		Person:     "alice",
		Machine:    "office-pc",
		SessionID:  "1758191525000000000-alice-office-pc",
		StartedAt:  time.Date(2026, 9, 18, 14, 12, 5, 0, testZone),
		EndedAt:    time.Date(2026, 9, 18, 15, 40, 11, 0, testZone),
		Exporter:   "alice",
		PartLimit:  8,
		Version:    "1.4-test",
		Now:        time.Date(2026, 9, 18, 16, 0, 0, 0, testZone),
		Journal:    journal,
	}
}

// mustExport runs Export and fails on any error, message included.
func mustExport(t *testing.T, req Request) Result {
	t.Helper()
	res, err := Export(req)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return res
}

// readAbout parses about.txt into key: value lines.
func readAbout(t *testing.T, dir string) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "about.txt"))
	if err != nil {
		t.Fatalf("read about.txt: %v", err)
	}
	lines := map[string]string{}
	for _, ln := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(ln, ": "); ok {
			lines[k] = v
		}
	}
	return lines
}

// TestExportWritesTheContractLayout checks the folder contract itself:
// the day folder from the session-start date, the session folder named
// machine_person_clock_id, 0001.txt with the first lines, session.cast
// byte for byte as it was handed over.
func TestExportWritesTheContractLayout(t *testing.T) {
	root := t.TempDir()
	journal := &recordingJournal{}
	res := mustExport(t, testRequest(root, journal))

	wantDir := filepath.Join(root, "2026-09-18", "office-pc_alice_141205_1758191525000000000-alice-office-pc")
	if res.Dir != wantDir {
		t.Fatalf("export dir = %s, want %s", res.Dir, wantDir)
	}
	if len(res.Parts) != 1 || res.Parts[0] != "0001.txt" {
		t.Fatalf("parts = %q, want [0001.txt]", res.Parts)
	}
	part, err := os.ReadFile(filepath.Join(res.Dir, "0001.txt"))
	if err != nil {
		t.Fatalf("read 0001.txt: %v", err)
	}
	if string(part) != "one\n" {
		t.Fatalf("0001.txt = %q, want %q", part, "one\n")
	}
	cast, err := os.ReadFile(filepath.Join(res.Dir, "session.cast"))
	if err != nil {
		t.Fatalf("read session.cast: %v", err)
	}
	if string(cast) != "cast-bytes-here" {
		t.Fatalf("session.cast = %q, want the recording byte for byte", cast)
	}
	if res.CastFile != "session.cast" || res.CastBytes != int64(len("cast-bytes-here")) {
		t.Fatalf("cast result = (%q, %d), want (session.cast, 15)", res.CastFile, res.CastBytes)
	}
}

// TestAboutCarriesEverythingPromised checks about.txt against the
// contract list: who, whose machine, which session, when it started,
// when it ended, how many bytes, sha256 of the .cast, product version.
func TestAboutCarriesEverythingPromised(t *testing.T) {
	req := testRequest(t.TempDir(), &recordingJournal{})
	res := mustExport(t, req)
	about := readAbout(t, res.Dir)

	sum := sha256.Sum256([]byte("cast-bytes-here"))
	want := map[string]string{
		"person":           "alice",
		"machine":          "office-pc",
		"session":          "1758191525000000000-alice-office-pc",
		"started":          req.StartedAt.Format(aboutTimeFormat),
		"ended":            req.EndedAt.Format(aboutTimeFormat),
		"transcript bytes": "4",
		"parts":            "1",
		"cast file":        "session.cast",
		"cast bytes":       "15",
		"cast sha256":      hex.EncodeToString(sum[:]),
		"product version":  "1.4-test",
	}
	for k, v := range want {
		if about[k] != v {
			t.Errorf("about.txt: %q = %q, want %q — about must carry everything the contract promises", k, about[k], v)
		}
	}
}

// TestAboutSaysStillRunning checks the "still running" branch: a session
// without an end must say so in words, not show a zero time.
func TestAboutSaysStillRunning(t *testing.T) {
	req := testRequest(t.TempDir(), &recordingJournal{})
	req.EndedAt = time.Time{}
	res := mustExport(t, req)
	about := readAbout(t, res.Dir)
	if about["ended"] != "still running" {
		t.Fatalf("about.txt: ended = %q, want \"still running\"", about["ended"])
	}
}

// TestAboutSaysNoCast checks the no-recording branch: no session.cast
// on disk, "cast file: none" in about.txt, and NO fabricated sha256 —
// an all-zero hash would look like a real one (PROTOCOL §8).
func TestAboutSaysNoCast(t *testing.T) {
	req := testRequest(t.TempDir(), &recordingJournal{})
	req.Cast = nil
	res := mustExport(t, req)
	if _, err := os.Stat(filepath.Join(res.Dir, "session.cast")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session.cast must not exist without a recording, stat err = %v", err)
	}
	about := readAbout(t, res.Dir)
	if about["cast file"] != "none" {
		t.Fatalf("about.txt: cast file = %q, want \"none\"", about["cast file"])
	}
	if sha, ok := about["cast sha256"]; ok {
		t.Fatalf("about.txt must not fabricate a sha256 without a cast, got %q", sha)
	}
}

// TestJournalRecordsWhoExportedWhoseSessionWhere checks the
// recording.export event: exactly one, valid against the event
// dictionary, carrying who, whose session and where.
func TestJournalRecordsWhoExportedWhoseSessionWhere(t *testing.T) {
	journal := &recordingJournal{}
	req := testRequest(t.TempDir(), journal)
	res := mustExport(t, req)

	if len(journal.events) != 1 {
		t.Fatalf("journal got %d events, want exactly 1", len(journal.events))
	}
	ev := journal.events[0]
	if err := ev.Validate(); err != nil {
		t.Fatalf("journal event is not valid: %v", err)
	}
	if ev.Type != events.EventRecordingExport {
		t.Fatalf("event type = %s, want %s", ev.Type, events.EventRecordingExport)
	}
	if ev.Actor != "alice" {
		t.Fatalf("event actor = %q, want the exporter", ev.Actor)
	}
	if ev.Object != "alice -> office-pc" {
		t.Fatalf("event object = %q, want \"alice -> office-pc\"", ev.Object)
	}
	if ev.Result != "ok" {
		t.Fatalf("event result = %q, want \"ok\"", ev.Result)
	}
	if ev.Details["path"] != res.Dir {
		t.Fatalf("event details path = %v, want the export folder", ev.Details["path"])
	}
	if ev.Details["session"] != req.SessionID {
		t.Fatalf("event details session = %v, want the session id", ev.Details["session"])
	}
	if got, ok := ev.Details["bytes"].(int64); !ok || got != 4 {
		t.Fatalf("event details bytes = %v, want 4", ev.Details["bytes"])
	}
	if got, ok := ev.Details["parts"].(int); !ok || got != 1 {
		t.Fatalf("event details parts = %v, want 1", ev.Details["parts"])
	}
}

// TestJournalFailureKeepsBothFacts checks the contract of a refusing
// journal: the files are already on disk, so the caller must get BOTH
// the error AND a Result pointing at the folder — an export whose
// event was lost must not look lost itself.
func TestJournalFailureKeepsBothFacts(t *testing.T) {
	root := t.TempDir()
	journal := &recordingJournal{err: errors.New("log is closed")}
	res, err := Export(testRequest(root, journal))
	if err == nil {
		t.Fatal("a journal refusal must come back as an error")
	}
	if res.Dir == "" {
		t.Fatal("the Result must still name the folder the files are in")
	}
	if _, err := os.Stat(filepath.Join(res.Dir, "about.txt")); err != nil {
		t.Fatalf("the files must be on disk despite the journal refusal: %v", err)
	}
}

// TestTakenFolderNameAdvances checks the take-next-name rule: a
// session folder whose name is already taken must not refuse the human
// their export — the next export lands in name_1 (the same rule
// internal/gateway/record/sessionname.go applies to session names).
func TestTakenFolderNameAdvances(t *testing.T) {
	root := t.TempDir()
	req := testRequest(root, &recordingJournal{})
	taken := filepath.Join(root, "2026-09-18", "office-pc_alice_141205_1758191525000000000-alice-office-pc")
	if err := os.MkdirAll(taken, 0o700); err != nil {
		t.Fatalf("pre-take the folder name: %v", err)
	}
	res := mustExport(t, req)
	if res.Dir != taken+"_1" {
		t.Fatalf("export dir = %s, want the next free name %s_1", res.Dir, taken)
	}
}

// TestExportNumbersPartsSoTheySort checks rule 5 through the real
// writer: twelve parts must be named 0001.txt … 0012.txt, and the
// LEXICOGRAPHIC order of the names must equal the numeric order — the
// point of the zero padding, 0010 after 0009, never 10.txt before 2.txt.
func TestExportNumbersPartsSoTheySort(t *testing.T) {
	root := t.TempDir()
	lines := make([]string, 12)
	for i := range lines {
		// Three characters and a newline: exactly MinPartLimit, so one
		// line fills one part. The first version used a single character
		// and a PartLimit of 2, which is below the rune-safe floor of
		// utf8.UTFMax and was refused outright.
		lines[i] = strings.Repeat(string(rune('a'+i)), 3) + "\n"
	}
	req := testRequest(root, &recordingJournal{})
	req.Transcript = strings.NewReader(strings.Join(lines, ""))
	req.PartLimit = MinPartLimit // one line per part
	res := mustExport(t, req)

	if len(res.Parts) != 12 {
		t.Fatalf("got %d parts, want 12", len(res.Parts))
	}
	for i, name := range res.Parts {
		if want := partName(i + 1); name != want {
			t.Fatalf("part %d is named %q, want %q", i+1, name, want)
		}
	}
	if !sort.StringsAreSorted(res.Parts) {
		t.Fatal("part names do not sort lexicographically")
	}
	independent := append([]string(nil), res.Parts...)
	sort.Strings(independent)
	for i := range independent {
		if independent[i] != res.Parts[i] {
			t.Fatalf("lexicographic order differs from numeric order at %d: %q vs %q", i, independent[i], res.Parts[i])
		}
	}
	if res.Parts[9] != "0010.txt" {
		t.Fatalf("the tenth part must be named 0010.txt, got %q — the classic unpadded failure", res.Parts[9])
	}
	part, err := os.ReadFile(filepath.Join(res.Dir, "0010.txt"))
	if err != nil {
		t.Fatalf("read 0010.txt: %v", err)
	}
	if want := "jjj\n"; string(part) != want {
		t.Fatalf("0010.txt = %q, want %q", part, want)
	}
}

// TestEmptyTranscriptStillWritesOneEmptyPart checks the wiring of the
// documented choice: an empty transcript yields one EMPTY 0001.txt and
// an about.txt that says parts: 1 — not a folder without parts.
func TestEmptyTranscriptStillWritesOneEmptyPart(t *testing.T) {
	req := testRequest(t.TempDir(), &recordingJournal{})
	req.Transcript = strings.NewReader("")
	res := mustExport(t, req)
	if len(res.Parts) != 1 || res.Parts[0] != "0001.txt" {
		t.Fatalf("parts = %q, want exactly [0001.txt]", res.Parts)
	}
	part, err := os.ReadFile(filepath.Join(res.Dir, "0001.txt"))
	if err != nil {
		t.Fatalf("read 0001.txt: %v", err)
	}
	if len(part) != 0 {
		t.Fatalf("0001.txt must be empty, got %q", part)
	}
	about := readAbout(t, res.Dir)
	if about["parts"] != "1" || about["transcript bytes"] != "0" {
		t.Fatalf("about.txt = %v, want parts: 1 and transcript bytes: 0", about)
	}
}

// TestExportRefusesBadRequests walks every required field and every
// grammar rule through the writer: each refusal must happen before
// anything is created — the root stays empty.
func TestExportRefusesBadRequests(t *testing.T) {
	cases := []struct {
		name string
		bend func(*Request)
	}{
		{"empty root", func(r *Request) { r.Root = "" }},
		{"nil transcript", func(r *Request) { r.Transcript = nil }},
		{"empty exporter", func(r *Request) { r.Exporter = "" }},
		{"nil journal", func(r *Request) { r.Journal = nil }},
		{"zero started", func(r *Request) { r.StartedAt = time.Time{} }},
		{"uppercase person", func(r *Request) { r.Person = "Alice" }},
		{"space in machine", func(r *Request) { r.Machine = "pc dana" }},
		{"empty session", func(r *Request) { r.SessionID = "" }},
		{"limit below a rune", func(r *Request) { r.PartLimit = 2 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			req := testRequest(root, &recordingJournal{})
			tc.bend(&req)
			res, err := Export(req)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if res.Dir != "" {
				t.Fatalf("a refused export must not report a folder, got %q", res.Dir)
			}
			entries, rerr := os.ReadDir(root)
			if rerr != nil {
				t.Fatalf("read root: %v", rerr)
			}
			if len(entries) != 0 {
				t.Fatalf("a refused export must create nothing, the root holds %v", entries)
			}
		})
	}
}

// TestCastHashIsOfTheRealBytes pins the streaming hash: about.txt must
// carry the sha256 OF THE BYTES THAT WENT TO DISK, not of nothing —
// dropping the writer from the MultiWriter must fail this test.
func TestCastHashIsOfTheRealBytes(t *testing.T) {
	req := testRequest(t.TempDir(), &recordingJournal{})
	castBytes := bytes.Repeat([]byte("cast payload "), 100)
	req.Cast = bytes.NewReader(castBytes)
	res := mustExport(t, req)
	sum := sha256.Sum256(castBytes)
	about := readAbout(t, res.Dir)
	if about["cast sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("about.txt sha256 = %q, want the hash of the bytes on disk", about["cast sha256"])
	}
}
