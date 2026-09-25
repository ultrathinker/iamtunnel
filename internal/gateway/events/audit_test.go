package events_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// ---------------------------------------------------------------------------
// Audit finding 2. Reading the history must pick up the log and its archives,
// and nothing else that happens to live in the directory.
// ---------------------------------------------------------------------------

func TestAudit2_HistoryOnlyReadsItsOwnFiles(t *testing.T) {
	t.Run("the_pattern_is_exact", func(t *testing.T) {
		accepted := []string{
			"events.jsonl",
			"events-2026-09-12.jsonl",
			"events-archive-2026-09-12.jsonl",
			"events-20260912T101500Z.jsonl",
		}
		for _, name := range accepted {
			if !events.IsLogFileName(name) {
				t.Errorf("%q is a log of this gateway and was not recognised", name)
			}
		}

		rejected := []string{
			"events.jsonl.tmp",
			"events-2026-09-12.jsonl.bak",
			".events.jsonl.swp",
			"events.jsonl.bak.jsonl",                        // ends in .jsonl and starts with events
			"events - \u043a\u043e\u043f\u0438\u044f.jsonl", // what a file manager leaves behind
			"eventsomething.jsonl",                          // no separator: a different file entirely
			"events-.jsonl",                                 // empty label
			"events-2026.09.12.jsonl",                       // dots in the label
			"events_2026.jsonl",                             // wrong separator
			"state.json",
			"events.jsonl.1",
		}
		for _, name := range rejected {
			if events.IsLogFileName(name) {
				t.Errorf("%q is not a log of this gateway but would be read as history", name)
			}
		}
	})

	t.Run("a_stray_file_is_not_read_as_history", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, events.DefaultLogFileName)
		l, err := events.OpenLog(logPath)
		if err != nil {
			t.Fatalf("OpenLog: %v", err)
		}
		defer l.Close()

		now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")
		if err := l.Append(events.Event{
			Time: now, Type: events.EventAdminOp, Actor: "admin", Object: "grant", Result: "ok",
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}

		// Rubbish left by a crash or by another program, shaped to slip through a
		// prefix/suffix filter.
		for _, junk := range []string{"events.jsonl.bak.jsonl", "events - \u043a\u043e\u043f\u0438\u044f.jsonl", "eventsomething.jsonl"} {
			body := `{"time":"2026-09-12T12:00:00Z","type":"admin.op","actor":"GHOST","object":"x","result":"ok"}` + "\n"
			if err := os.WriteFile(filepath.Join(dir, junk), []byte(body), 0600); err != nil {
				t.Fatalf("WriteFile %s: %v", junk, err)
			}
		}

		got, stats, err := events.ReadHistory(dir, events.Filter{})
		if err != nil {
			t.Fatalf("ReadHistory: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("history picked up files that are not its own: %d records instead of 1", len(got))
		}
		if got[0].Actor == "GHOST" {
			t.Fatalf("history answered with somebody else's bytes")
		}
		if stats.Skipped != 0 {
			t.Fatalf("unexpected skipped lines: %+v", stats)
		}
	})

	t.Run("rotation_cannot_write_an_archive_the_history_would_lose", func(t *testing.T) {
		dir := t.TempDir()
		l, err := events.OpenLog(filepath.Join(dir, events.DefaultLogFileName))
		if err != nil {
			t.Fatalf("OpenLog: %v", err)
		}
		defer l.Close()

		bad := filepath.Join(dir, "events.jsonl.2026-09-12")
		if err := l.Rotate(bad); err == nil {
			t.Fatalf("Rotate accepted an archive name that ReadHistory would never find again")
		}
		if _, err := os.Stat(bad); err == nil {
			t.Fatalf("the refused rotation still moved the file")
		}

		good := filepath.Join(dir, events.ArchiveName(time.Date(2026, 9, 12, 10, 15, 0, 0, time.UTC)))
		if !events.IsLogFileName(filepath.Base(good)) {
			t.Fatalf("ArchiveName produced %q, which the history filter rejects", filepath.Base(good))
		}
		if err := l.Rotate(good); err != nil {
			t.Fatalf("Rotate with a canonical archive name failed: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Audit finding 4. The log handle is write-only and append-only, so two handles
// on one file cannot lose or interleave records.
// ---------------------------------------------------------------------------

func TestAudit4_TwoHandlesAppendWithoutLosingRecords(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, events.DefaultLogFileName)

	const perWriter = 200
	writers := 2

	var wg sync.WaitGroup
	wg.Add(writers)
	errCh := make(chan error, writers*perWriter)

	now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")

	for w := 0; w < writers; w++ {
		go func(id int) {
			defer wg.Done()
			// A separate Log over the same file: two handles, as two processes would have.
			l, err := events.OpenLog(path)
			if err != nil {
				errCh <- err
				return
			}
			defer l.Close()
			for i := 0; i < perWriter; i++ {
				if err := l.Append(events.Event{
					Time:   now,
					Type:   events.EventSessionStart,
					Actor:  fmt.Sprintf("writer-%d", id),
					Object: fmt.Sprintf("session-%04d", i),
					Result: "ok",
				}); err != nil {
					errCh <- err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("append from a second handle failed: %v", err)
	}

	got, stats, err := events.ReadFile(path, events.Filter{})
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if stats.Skipped != 0 {
		t.Fatalf("two handles writing at once produced %d unreadable lines %v - records were interleaved",
			stats.Skipped, stats.BadLines)
	}
	if len(got) != writers*perWriter {
		t.Fatalf("expected %d records, got %d - records were lost to the race for the last byte",
			writers*perWriter, len(got))
	}

	// Every line is whole: no record swallowed the newline of another.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile raw: %v", err)
	}
	for i, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if !strings.HasPrefix(line, `{"time"`) || !strings.HasSuffix(line, "}") {
			t.Fatalf("line %d is not a whole record: %q", i+1, line)
		}
	}
}
