package gateway

// IAMT-452, the gateway's half. The journal is append-only and nothing
// ever rotated it (Log.Rotate had no caller), and every login wrote its
// own auth.success - a window polling every second or two, a script in a
// loop, wrote a line each time. Two things now: the same login, key and
// host within AuthSuccessQuiet is one line, with a count of the rest when
// the quiet ends; and the gateway rotates its own journal by size.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func iamt452Successes(t *testing.T, f *fixture, person string) []events.Event {
	t.Helper()
	evs, _, err := events.ReadHistory(filepath.Dir(f.logPath), events.Filter{Types: []events.EventType{events.EventAuthSuccess}, Actor: person})
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestIAMT452_ALoginRepeatedWithinMinutesIsOneLine(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	for i := 0; i < 3; i++ {
		c := dialAdmin(t, f, "root", rootKey)
		if _, err := c.Whoami(); err != nil {
			t.Fatalf("login %d: %v", i+1, err)
		}
		_ = c.Close()
	}
	if evs := iamt452Successes(t, f, "root"); len(evs) != 1 {
		t.Fatalf("three logins of one key from one host within a minute wrote %d auth.success, want one", len(evs))
	}
}

func TestIAMT452_TheRepeatsAreCountedWhenTheQuietEnds(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.AuthSuccessQuiet = time.Minute })
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	for i := 0; i < 3; i++ {
		c := dialAdmin(t, f, "root", rootKey)
		if _, err := c.Whoami(); err != nil {
			t.Fatalf("login %d: %v", i+1, err)
		}
		_ = c.Close()
	}
	if evs := iamt452Successes(t, f, "root"); len(evs) != 1 {
		t.Fatalf("%d auth.success before the quiet ended, want one", len(evs))
	}

	f.clock.Advance(2 * time.Minute)
	waitUntil(t, "the logins that were not written one by one were never accounted for", func() bool {
		return len(iamt452Successes(t, f, "root")) == 2
	})
	last := iamt452Successes(t, f, "root")[1]
	if n, _ := last.Details["repeats"].(float64); n != 2 {
		t.Errorf("the summary line says repeats=%v, want 2: %+v", last.Details["repeats"], last)
	}
	if last.Address == "" || last.Fingerprint == "" {
		t.Errorf("the summary line lost its address or key: %+v", last)
	}
}

func TestIAMT452_TheGatewayRotatesItsOwnJournalBySize(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.JournalRotateBytes = 4 << 10 })
	dir := filepath.Dir(f.logPath)
	for i := 0; i < 40; i++ {
		f.gw.appendEvent(events.Event{Type: events.EventAdminOp, Actor: "root", Object: "iamt-452", Result: "ok",
			Details: map[string]interface{}{"n": i, "pad": strings.Repeat("x", 100)}})
	}
	waitUntil(t, "the journal grew past its size and was never rotated", func() bool {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return false
		}
		// Done is both halves: the archive is there, and so is the fresh
		// journal Rotate opens right after the rename - between the two
		// there is, for a moment, no events.jsonl at all.
		if _, err := os.Stat(f.logPath); err != nil {
			return false
		}
		for _, e := range entries {
			if e.Name() != "events.jsonl" && events.IsLogFileName(e.Name()) {
				return true
			}
		}
		return false
	})
	st, err := os.Stat(f.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Size() >= 4<<10 {
		t.Errorf("after the rotation the current journal is still %d bytes", st.Size())
	}
	all, _, err := events.ReadHistory(dir, events.Filter{Types: []events.EventType{events.EventAdminOp}, Object: "iamt-452"})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 40 {
		t.Errorf("the history holds %d of the 40 entries after the rotation", len(all))
	}
	rot, _, _ := f.log.Read(events.Filter{Types: []events.EventType{events.EventLogRotate}})
	if len(rot) == 0 {
		t.Errorf("the fresh journal does not begin by saying where the old one went")
	}
}
