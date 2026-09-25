package events_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// ============================================================================
// ROUND 3 INDEPENDENT ACCEPTANCE TESTS (EVENTS PACKAGE)
// ============================================================================

func TestOwnR3_EventLogValidationAndCorruption(t *testing.T) {
	t.Run("invalid_events_fail_with_ErrInvalidEvent_and_are_not_written", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, events.DefaultLogFileName)
		l, err := events.OpenLog(logPath)
		if err != nil {
			t.Fatalf("OpenLog: %v", err)
		}
		defer l.Close()

		now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")

		// 1. Auth without an address and fingerprint
		err = l.Append(events.Event{
			Time: now, Type: events.EventAuthSuccess, Actor: "alice", Result: "ok",
		})
		if err == nil || !errors.Is(err, events.ErrInvalidEvent) {
			t.Fatalf("expected ErrInvalidEvent on auth without addr/fp, got %v", err)
		}

		// 2. Auth with an address only, no fingerprint (in the previous round this wrongly passed!)
		err = l.Append(events.Event{
			Time: now, Type: events.EventAuthSuccess, Actor: "alice", Result: "ok",
			Address: "192.168.1.1:2222",
		})
		if err == nil || !errors.Is(err, events.ErrInvalidEvent) {
			t.Fatalf("expected ErrInvalidEvent on auth without fingerprint, got %v", err)
		}
		if !strings.Contains(err.Error(), "requires a fingerprint") {
			t.Fatalf("error message must specify missing fingerprint, got %v", err)
		}

		// 3. Auth with a fingerprint only, no address
		err = l.Append(events.Event{
			Time: now, Type: events.EventAuthFailure, Actor: "alice", Result: "denied",
			Fingerprint: "SHA256:somefp",
		})
		if err == nil || !errors.Is(err, events.ErrInvalidEvent) {
			t.Fatalf("expected ErrInvalidEvent on auth without address, got %v", err)
		}
		if !strings.Contains(err.Error(), "requires an address") {
			t.Fatalf("error message must specify missing address, got %v", err)
		}

		// 4. Unknown event type
		err = l.Append(events.Event{
			Time: now, Type: "unknown.type", Actor: "alice", Result: "ok",
		})
		if err == nil || !errors.Is(err, events.ErrInvalidEvent) {
			t.Fatalf("expected ErrInvalidEvent on unknown type, got %v", err)
		}

		// 5. Zero time
		err = l.Append(events.Event{
			Type: events.EventAdminOp, Actor: "admin", Object: "person", Result: "ok",
		})
		if err == nil || !errors.Is(err, events.ErrInvalidEvent) {
			t.Fatalf("expected ErrInvalidEvent on zero time, got %v", err)
		}

		// Verify: not a single broken record made it into the file!
		data, err := os.ReadFile(logPath)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		if len(strings.TrimSpace(string(data))) != 0 {
			t.Fatalf("corrupted/invalid events were written to disk: %s", string(data))
		}
	})

	t.Run("corrupted_line_is_reported_in_ReadStats_and_valid_records_are_returned", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, events.DefaultLogFileName)
		l, err := events.OpenLog(logPath)
		if err != nil {
			t.Fatalf("OpenLog: %v", err)
		}

		now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")

		// Append 3 valid events
		for i := 1; i <= 3; i++ {
			err := l.Append(events.Event{
				Time: now, Type: events.EventSessionStart, Actor: "alice", Object: "vm1", Result: "ok",
			})
			if err != nil {
				t.Fatalf("Append %d: %v", i, err)
			}
		}
		_ = l.Close()

		// Corrupt the second line
		content, _ := os.ReadFile(logPath)
		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		if len(lines) != 3 {
			t.Fatalf("expected 3 lines, got %d", len(lines))
		}
		lines[1] = "THIS IS NOT JSON AT ALL"
		_ = os.WriteFile(logPath, []byte(strings.Join(lines, "\n")+"\n"), 0600)

		// Read through ReadFile
		evts, stats, err := events.ReadFile(logPath, events.Filter{})
		if err != nil {
			t.Fatalf("ReadFile failed on file with corrupted line: %v", err)
		}
		if len(evts) != 2 {
			t.Fatalf("expected 2 valid events, got %d", len(evts))
		}
		if stats.Skipped != 1 {
			t.Fatalf("corrupted line disappeared without count! Skipped=%d", stats.Skipped)
		}
		if len(stats.BadLines) != 1 || stats.BadLines[0] != 2 {
			t.Fatalf("expected BadLines=[2], got %+v", stats.BadLines)
		}
	})

	t.Run("rotate_writes_audit_record_with_archive_path", func(t *testing.T) {
		dir := t.TempDir()
		logPath := filepath.Join(dir, events.DefaultLogFileName)
		l, err := events.OpenLog(logPath)
		if err != nil {
			t.Fatalf("OpenLog: %v", err)
		}
		defer l.Close()

		now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")
		_ = l.Append(events.Event{
			Time: now, Type: events.EventAdminOp, Actor: "admin", Result: "ok",
		})

		archive := filepath.Join(dir, events.ArchiveName(time.Now().UTC()))
		if err := l.Rotate(archive); err != nil {
			t.Fatalf("Rotate: %v", err)
		}

		// The new journal must open with a log.rotate record
		evts, _, err := l.Read(events.Filter{})
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(evts) != 1 || evts[0].Type != events.EventLogRotate {
			t.Fatalf("expected 1 log.rotate event in fresh log, got %+v", evts)
		}
		if evts[0].Details["archive"] != archive {
			t.Fatalf("expected archive path in details, got %+v", evts[0].Details)
		}
	})
}
