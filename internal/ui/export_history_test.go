//go:build windows || linux || darwin

package ui

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The export must contain the TEXT of every session the filter matches,
// not just the page on screen and not just a list of names.
//
// 22.09.2026, the maintainer: they want one person's whole dialogue, and
// everything over a period, so that somebody can afterwards read what
// was done on the server. An export that writes an index and no
// transcripts answers neither.
func TestExportHistory_WritesEveryPageAndEveryTranscript(t *testing.T) {
	const total = 45 // more than one page of exportPageSize? no -- see below

	rows := make([]HistoryRow, 0, total)
	for i := 0; i < total; i++ {
		rows = append(rows, HistoryRow{
			SessionID: "s" + strconv.Itoa(i),
			Person:    "alice",
			Machine:   "win-test-vm",
			Started:   "2026-09-2" + strconv.Itoa(i%9) + "T10:00:00Z",
			Kind:      "exec",
			Outcome:   "ended",
			Command:   "echo " + strconv.Itoa(i),
		})
	}

	pages := 0
	deps := exportDeps{
		History: func(ctx context.Context, person, machine, from, to string, limit, offset int) (HistoryPage, error) {
			pages++
			// Deliberately a SMALLER page than asked for: a gateway is
			// allowed to answer with less, and an exporter that assumed
			// its own page size would stop after the first answer.
			end := offset + 10
			if end > len(rows) {
				end = len(rows)
			}
			if offset >= len(rows) {
				return HistoryPage{Total: len(rows), Offset: offset}, nil
			}
			return HistoryPage{Rows: rows[offset:end], Total: len(rows), Offset: offset, Limit: limit}, nil
		},
		Recordings: func(ctx context.Context, machine, from, to string) ([]RecordingRef, error) {
			var out []RecordingRef
			for i := range rows {
				// The last five have been pruned: their rows survive in
				// the journal and must still be exported, as headers.
				if i >= len(rows)-5 {
					continue
				}
				out = append(out, RecordingRef{
					ID: "rec" + strconv.Itoa(i), SessionID: "s" + strconv.Itoa(i),
					Person: "alice", Machine: "win-test-vm", Mode: "exec",
				})
			}
			return out, nil
		},
		Fetch: func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error) {
			if part != "exec" {
				return nil, 0, 0, errors.New("wrong part for an exec recording: " + part)
			}
			n := strings.TrimPrefix(id, "rec")
			body := execJournal("echo "+n, "output of "+n+"\n")
			if offset >= int64(len(body)) {
				return nil, offset, int64(len(body)), nil
			}
			return body[offset:], int64(len(body)), int64(len(body)), nil
		},
	}

	dir := filepath.Join(t.TempDir(), "out")
	res, err := exportHistory(context.Background(), deps, exportFilter{Person: "alice", Period: "30 days"}, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pages < 2 {
		t.Errorf("the whole history must be walked page by page; the exporter made %d request(s)", pages)
	}
	if res.Sessions != total {
		t.Errorf("exported %d sessions, want %d", res.Sessions, total)
	}
	if res.Transcripts != total-5 {
		t.Errorf("read %d transcripts, want %d", res.Transcripts, total-5)
	}
	if res.MissingBytes != 5 {
		t.Errorf("counted %d pruned recordings, want 5", res.MissingBytes)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// one per session, plus index.txt and all.txt
	if len(entries) != total+2 {
		t.Errorf("the folder holds %d files, want %d (one per session, index.txt, all.txt)", len(entries), total+2)
	}

	all := readFileString(t, filepath.Join(dir, "all.txt"))
	// Every session's OUTPUT, not merely its name: this is the assertion
	// that separates an export from a listing.
	for i := 0; i < total-5; i++ {
		want := "output of " + strconv.Itoa(i)
		if !strings.Contains(all, want) {
			t.Fatalf("all.txt is missing the transcript of session %d (%q)", i, want)
		}
	}
	for i := total - 5; i < total; i++ {
		if !strings.Contains(all, "s"+strconv.Itoa(i)) {
			t.Errorf("all.txt dropped pruned session %d entirely; a row without bytes is still a row", i)
		}
	}
	if !strings.Contains(all, "no recording left") {
		t.Error("all.txt does not say why five sessions have no text")
	}

	index := readFileString(t, filepath.Join(dir, "index.txt"))
	if !strings.Contains(index, "alice") || !strings.Contains(index, "30 days") {
		t.Errorf("index.txt does not say what was exported:\n%s", firstLines(index, 6))
	}
	for i := 1; i <= total; i++ {
		if !strings.Contains(index, strconv.Itoa(i)+". ") {
			t.Fatalf("index.txt is missing row %d", i)
		}
	}
}

// A pruned recording is a normal answer, not a failure of the export.
func TestExportHistory_RefusesOnlyWhenThereIsNothingAtAll(t *testing.T) {
	deps := exportDeps{
		History: func(ctx context.Context, person, machine, from, to string, limit, offset int) (HistoryPage, error) {
			return HistoryPage{}, nil
		},
		Recordings: func(ctx context.Context, machine, from, to string) ([]RecordingRef, error) {
			return nil, nil
		},
		Fetch: func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error) {
			return nil, 0, 0, nil
		},
	}
	dir := filepath.Join(t.TempDir(), "out")
	if _, err := exportHistory(context.Background(), deps, exportFilter{}, dir, nil); err == nil {
		t.Fatal("an export of nothing must say so rather than leave an empty folder behind")
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("the folder was created for an export that had nothing to write")
	}
}

// One unreadable recording must not cost the rest of the export.
func TestExportHistory_OneBadRecordingDoesNotLoseTheOthers(t *testing.T) {
	rows := []HistoryRow{
		{SessionID: "a", Person: "alice", Machine: "m", Started: "2026-09-22T10:00:00Z", Kind: "shell", Outcome: "ended"},
		{SessionID: "b", Person: "bob", Machine: "m", Started: "2026-09-22T11:00:00Z", Kind: "shell", Outcome: "ended"},
	}
	deps := exportDeps{
		History: func(ctx context.Context, person, machine, from, to string, limit, offset int) (HistoryPage, error) {
			if offset > 0 {
				return HistoryPage{Total: 2, Offset: offset}, nil
			}
			return HistoryPage{Rows: rows, Total: 2}, nil
		},
		Recordings: func(ctx context.Context, machine, from, to string) ([]RecordingRef, error) {
			return []RecordingRef{{ID: "ra", SessionID: "a"}, {ID: "rb", SessionID: "b"}}, nil
		},
		Fetch: func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error) {
			if id == "ra" {
				return nil, 0, 0, errors.New("disk went away")
			}
			body := []byte("{\"version\":2,\"width\":80,\"height\":24}\n[0.1,\"o\",\"bob was here\"]\n")
			if offset >= int64(len(body)) {
				return nil, offset, int64(len(body)), nil
			}
			return body[offset:], int64(len(body)), int64(len(body)), nil
		},
	}
	dir := filepath.Join(t.TempDir(), "out")
	res, err := exportHistory(context.Background(), deps, exportFilter{}, dir, nil)
	if err != nil {
		t.Fatalf("one broken recording aborted the whole export: %v", err)
	}
	if res.Sessions != 2 {
		t.Errorf("exported %d sessions, want 2", res.Sessions)
	}
	all := readFileString(t, filepath.Join(dir, "all.txt"))
	if !strings.Contains(all, "bob was here") {
		t.Error("the readable recording did not make it into all.txt")
	}
	if !strings.Contains(all, "disk went away") {
		t.Error("the unreadable recording did not say why it is empty")
	}
}

// M-5a (code review 23.09.2026, review F-18). The history is a list
// that grows at the NEW end, and the export walked it page by page with
// offset/limit and no upper bound: a session that appeared between two
// pages pushed the rows already read further down the list, so the next
// page handed one of them out a second time and the new session was
// never seen at all. The export answered a different question on every
// request, and the folder it wrote was neither the history as it was
// when the person pressed the button nor as it is when the last page
// came back.
//
// One export must ask one question: a snapshot boundary fixed by the
// first request, and no session twice.
func TestM5aExportIsOneSnapshotAndNeverRepeatsASession(t *testing.T) {
	newestFirst := func(id string, at string) HistoryRow {
		return HistoryRow{SessionID: id, Person: "alice", Machine: "win-test-vm", Started: at, Kind: "exec", Outcome: "ended"}
	}
	// The list as the gateway sorts it: newest first.
	live := []HistoryRow{
		newestFirst("s3", "2026-09-22T12:00:00Z"),
		newestFirst("s2", "2026-09-22T11:00:00Z"),
		newestFirst("s1", "2026-09-22T10:00:00Z"),
	}
	var (
		tos     []string
		arrived bool
	)
	deps := exportDeps{
		History: func(ctx context.Context, person, machine, from, to string, limit, offset int) (HistoryPage, error) {
			tos = append(tos, to)
			// A faithful gateway: `to` bounds the answer by event time,
			// and an empty `to` bounds nothing.
			var visible []HistoryRow
			for _, r := range live {
				if to != "" {
					bound, berr := time.Parse(time.RFC3339, to)
					started, serr := time.Parse(time.RFC3339, r.Started)
					if berr == nil && serr == nil && started.After(bound) {
						continue
					}
				}
				visible = append(visible, r)
			}
			// Two rows a page, under the exporter's own page size: the
			// walk costs more than one round trip whatever it asks for.
			var page HistoryPage
			page.Total, page.Offset, page.Limit = len(visible), offset, limit
			if end := offset + 2; offset < len(visible) {
				if end > len(visible) {
					end = len(visible)
				}
				page.Rows = visible[offset:end]
			}
			if !arrived {
				// The new session starts AFTER this page was read. That
				// is the whole of the defect: the row already handed out
				// is pushed one place down the list, and the offset that
				// follows is an offset into a list that has changed. It
				// is stamped a second ahead of the export's own
				// boundary, which is what "it started after the
				// snapshot" means.
				arrived = true
				live = append([]HistoryRow{newestFirst("s4", time.Now().UTC().Add(time.Second).Format(time.RFC3339))}, live...)
			}
			return page, nil
		},
		Recordings: func(ctx context.Context, machine, from, to string) ([]RecordingRef, error) {
			return nil, nil
		},
		Fetch: func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error) {
			return nil, 0, 0, nil
		},
	}

	dir := filepath.Join(t.TempDir(), "out")
	res, err := exportHistory(context.Background(), deps, exportFilter{Person: "alice"}, dir, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(tos) == 0 || tos[0] == "" {
		t.Errorf("the first history request carried no `to` (%v) — without a boundary the export asks a different question on every page and no page can be trusted to join the others (M-5a, review F-18)", tos)
	}
	for i, got := range tos {
		if got != tos[0] {
			t.Errorf("history request %d carried to=%q while the first carried to=%q — every page of one export must be asked against the same snapshot boundary", i, got, tos[0])
		}
	}

	// The three sessions that existed when the export began. The one
	// that started afterwards belongs to no snapshot and is not in it.
	if res.Sessions != 3 {
		t.Errorf("the export wrote %d sessions, want the 3 the snapshot held — a session that appeared while it ran was counted in, or a row was repeated and counted twice", res.Sessions)
	}
	all := readFileString(t, filepath.Join(dir, "all.txt"))
	for _, id := range []string{"s1", "s2", "s3"} {
		if n := strings.Count(all, "session: "+id+"\n"); n != 1 {
			t.Errorf("all.txt mentions session %s %d times, want exactly 1 — a session must be exported once, whatever the history did while the export ran (M-5a, review F-18)", id, n)
		}
	}
	if strings.Contains(all, "session: s4") {
		t.Error("all.txt contains the session that started after the export began — the export must answer the question the snapshot asked, not the one the history asked a minute later")
	}
}

// M-5b (code review 23.09.2026, review F-19). A recording whose
// bytes could not be read was written into the export as an apology line
// and counted NOWHERE: the window went green and said "Wrote N
// sessions", which reads as an archive. A person who never opens every
// text file closes the window believing the history is saved when not
// one transcript made it.
func TestM5bExportOfNothingButFailuresDoesNotReadAsASuccess(t *testing.T) {
	rows := []HistoryRow{
		{SessionID: "a", Person: "alice", Machine: "m", Started: "2026-09-22T10:00:00Z", Kind: "exec", Outcome: "ended"},
		{SessionID: "b", Person: "bob", Machine: "m", Started: "2026-09-22T11:00:00Z", Kind: "shell", Outcome: "ended"},
	}
	deps := exportDeps{
		History: func(ctx context.Context, person, machine, from, to string, limit, offset int) (HistoryPage, error) {
			if offset > 0 {
				return HistoryPage{Total: 2, Offset: offset}, nil
			}
			return HistoryPage{Rows: rows, Total: 2}, nil
		},
		Recordings: func(ctx context.Context, machine, from, to string) ([]RecordingRef, error) {
			return []RecordingRef{{ID: "ra", SessionID: "a"}, {ID: "rb", SessionID: "b"}}, nil
		},
		Fetch: func(ctx context.Context, id, part string, offset int64) ([]byte, int64, int64, error) {
			return nil, 0, 0, errors.New("the gateway stopped answering")
		},
	}
	dir := filepath.Join(t.TempDir(), "out")
	res, err := exportHistory(context.Background(), deps, exportFilter{}, dir, nil)
	if err != nil {
		t.Fatalf("an unreadable recording must not abort the export: %v", err)
	}

	line := exportDoneLine(res)
	if !strings.Contains(line, "could not be read") {
		t.Errorf("the window's summary is %q — with every recording unreadable it still reads as a finished export (M-5b, review F-19)", line)
	}

	index := readFileString(t, filepath.Join(dir, "index.txt"))
	if !strings.Contains(index, "the gateway stopped answering") {
		t.Errorf("index.txt names no failure, so the folder keeps no record of what is missing from it:\n%s", firstLines(index, 12))
	}
	for _, id := range []string{"a", "b"} {
		if !strings.Contains(index, id) {
			t.Errorf("index.txt lost the row of session %s — a session whose bytes are missing is still a visit", id)
		}
	}
}

// execJournal builds the bytes an ExecRecorder writes, without a disk.
func execJournal(command, out string) []byte {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	_ = enc.Encode(map[string]any{"sequence": 0, "type": "command", "command": command})
	_ = enc.Encode(map[string]any{"sequence": 1, "type": "chunk", "stream": "stdout",
		"data": base64.StdEncoding.EncodeToString([]byte(out))})
	return []byte(b.String())
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func firstLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
