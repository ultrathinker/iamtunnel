package gateway

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// Canaries for four findings of the History-tab acceptance review
// (21.09.2026). Each is checked on its own property and turns red on
// its own.
func TestCanary_HistoryCodexFindings(t *testing.T) {
	// --- sorting by the moment, not by the string ----------------------
	//
	// RFC 3339 sorts as text only while all stamps share one offset and
	// one shape of the fractional seconds. "12:00:00Z" and "12:00:00.1Z"
	// break that between the two of them, and a journal written by the
	// gateway in another zone breaks it outright.
	t.Run("order", func(t *testing.T) {
		f := newFixture(t, nil)
		rootKey := genSigner(t)
		addPerson(t, f, "root", "admin", rootKey)
		root := dialAdmin(t, f, "root", rootKey)

		// Chosen so that the text and the moment disagree:
		//   sess-late  = 11:00:00Z          -- the moment 11:00 UTC
		//   sess-early = 12:00:00+02:00     -- the moment 10:00 UTC
		// By the moment, early is EARLIER than late. By text, "11..." <
		// "12...", so string sorting puts early first -- that is, declares
		// the older session the newer one.
		day := f.clock.Now().UTC()
		cest := time.FixedZone("CEST", 2*60*60)
		writeStartAt(t, f, "alice", "vm1", "sess-late",
			time.Date(day.Year(), day.Month(), day.Day(), 11, 0, 0, 0, time.UTC))
		writeStartAt(t, f, "alice", "vm1", "sess-early",
			time.Date(day.Year(), day.Month(), day.Day(), 12, 0, 0, 0, cest))

		page, err := root.SessionsHistory("", "", "", "", 50, 0)
		if err != nil {
			t.Fatalf("sessions.history: %v", err)
		}
		var seen []string
		for _, r := range page.Sessions {
			if r.SessionID == "sess-early" || r.SessionID == "sess-late" {
				seen = append(seen, r.SessionID)
			}
		}
		if len(seen) != 2 {
			t.Fatalf("expected both rows, got: %v", seen)
		}
		if seen[0] != "sess-late" {
			t.Errorf("order %v: the newer one must come first. Sorting goes by the stamp text, "+
				"not by the moment in time -- a zone offset reorders the rows", seen)
		}
	})

	// --- a session without a start invents no start time ---------------
	//
	// If session.start stayed outside the answer's boundary (outside the
	// date range or in an archive from before the rotation), the row used
	// to be built from the stop and asserted that the session began at
	// the very moment it ended and was a shell -- even when it was a
	// single exec command.
	t.Run("startless", func(t *testing.T) {
		f := newFixture(t, nil)
		rootKey := genSigner(t)
		addPerson(t, f, "root", "admin", rootKey)
		root := dialAdmin(t, f, "root", rootKey)

		f.gw.appendEvent(events.Event{
			Type: events.EventSessionStop, Actor: "alice", Object: "vm1", Result: "ok",
			Details: map[string]interface{}{"sessionId": "sess-orphan"},
		})

		page, err := root.SessionsHistory("", "", "", "", 50, 0)
		if err != nil {
			t.Fatalf("sessions.history: %v", err)
		}
		for _, r := range page.Sessions {
			if r.SessionID != "sess-orphan" {
				continue
			}
			if r.Kind == "shell" {
				t.Errorf("a startless session declared shell -- the session kind is unknown and must not be invented")
			}
			if r.Kind != "unknown" {
				t.Errorf("kind of a startless session = %q, want unknown", r.Kind)
			}
			return
		}
		t.Fatal("the startless row vanished entirely -- a refusal at the threshold is part of history too")
	})

	// --- journal rotation must not eat the history ---------------------
	//
	// The journal rotates, the old file goes into an archive nearby. Read
	// opens only the current file, ReadHistory -- all of them. History
	// that reads the current one loses everything written before the
	// last rotation: exactly that "a month ago" the tab was created for.
	t.Run("archives", func(t *testing.T) {
		f := newFixture(t, nil)
		rootKey := genSigner(t)
		addPerson(t, f, "root", "admin", rootKey)
		root := dialAdmin(t, f, "root", rootKey)

		f.gw.appendEvent(events.Event{
			Type: events.EventSessionStart, Actor: "alice", Object: "vm1", Result: "ok",
			Details: map[string]interface{}{"sessionId": "sess-archived"},
		})
		archive := filepath.Join(filepath.Dir(f.logPath), events.ArchiveName(f.clock.Now()))
		if err := f.log.Rotate(archive); err != nil {
			t.Fatalf("journal rotation: %v", err)
		}
		f.clock.Advance(time.Minute)
		f.gw.appendEvent(events.Event{
			Type: events.EventSessionStart, Actor: "alice", Object: "vm1", Result: "ok",
			Details: map[string]interface{}{"sessionId": "sess-current"},
		})

		page, err := root.SessionsHistory("", "", "", "", 50, 0)
		if err != nil {
			t.Fatalf("sessions.history: %v", err)
		}
		found := map[string]bool{}
		for _, r := range page.Sessions {
			found[r.SessionID] = true
		}
		if !found["sess-current"] {
			t.Fatalf("a session from the CURRENT journal is not visible -- something else is broken")
		}
		if !found["sess-archived"] {
			t.Errorf("a session from the archive is not visible: history reads only the current journal file " +
				"and loses everything written before the last rotation")
		}
	})

	// --- an identifier collision must not merge two people -------------
	t.Run("collision", func(t *testing.T) {
		f := newFixture(t, nil)
		rootKey := genSigner(t)
		addPerson(t, f, "root", "admin", rootKey)
		root := dialAdmin(t, f, "root", rootKey)

		f.gw.appendEvent(events.Event{
			Type: events.EventSessionStart, Actor: "alice", Object: "vm1", Result: "ok",
			Details: map[string]interface{}{"sessionId": "same-id"},
		})
		f.clock.Advance(time.Minute)
		f.gw.appendEvent(events.Event{
			Type: events.EventSessionStart, Actor: "bob", Object: "vm1", Result: "ok",
			Details: map[string]interface{}{"sessionId": "same-id"},
		})

		page, err := root.SessionsHistory("", "", "", "", 50, 0)
		if err != nil {
			t.Fatalf("sessions.history: %v", err)
		}
		people := map[string]bool{}
		for _, r := range page.Sessions {
			if r.SessionID == "same-id" {
				people[r.Person] = true
			}
		}
		if len(people) != 2 {
			t.Errorf("two people with the same session identifier produced %d row(s) instead of two: %v. "+
				"History that merges other people's sessions into one lies about who did what", len(people), people)
		}
	})
}

// writeStartAt writes a session.start whose stamp carries the zone the
// caller chose. The zone is the point: the journal keeps the text as
// written, and a gateway in another zone writes another offset.
func writeStartAt(t *testing.T, f *fixture, person, machine, id string, at time.Time) {
	t.Helper()
	if err := f.log.Append(events.Event{
		Type: events.EventSessionStart, Actor: person, Object: machine,
		Time: state.NewZonedTime(at), Result: "ok",
		Details: map[string]interface{}{"sessionId": id},
	}); err != nil {
		t.Fatalf("journal: %v", err)
	}
}
