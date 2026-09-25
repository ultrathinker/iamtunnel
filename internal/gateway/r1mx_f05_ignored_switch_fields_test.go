package gateway

// F-05 of the round-1 review (24.09.2026): a persisted risk
// switch whose file is malformed is ignored at startup, and the fact IS
// journalled - admin.op, result "risk.mode:startup-ignored" - but
// everything about it sat inside one prose string (details.warning), so
// "logg" was a substring of a sentence rather than a value an operator or
// a parser can take hold of. The same held for risk.source.
//
// The fix keeps the one event for the one fact (a second event would
// double every startup line) and gives the details the pieces: the file,
// what it held, and why it was not used - with the value clipped like
// every other string that came from outside the gateway (IAMT-447). The
// file's content is not the gateway's to trust with the size of a journal
// line: before this, an invalid 4 KiB file put 4 KiB of it in the entry.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

func r1mxF05IgnoredSwitchEvents(t *testing.T, f *fixture, result string) []events.Event {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventAdminOp}, Result: result})
	if err != nil {
		t.Fatalf("read %s: %v", result, err)
	}
	return evs
}

func TestR1MXF05_AnIgnoredRiskModeNamesTheValueAndTheReasonInFields(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.RiskAction = RiskActionLog
		if err := datafile.WriteFileAtomic(filepath.Join(c.DataDir, riskModeFileName), []byte("logg\n"), datafile.WithMode(0o600)); err != nil {
			t.Fatalf("seed the corrupt mode file: %v", err)
		}
	})

	evs := r1mxF05IgnoredSwitchEvents(t, f, "risk.mode:startup-ignored")
	if len(evs) != 1 {
		t.Fatalf("startup-ignored events = %d, want 1", len(evs))
	}
	e := evs[0]
	if v, _ := e.Details["value"].(string); v != "logg\n" {
		t.Errorf("details.value = %q, want the content of the file (%q) as its own field (F-05): the operator has to be able to take hold of what was refused, not read it out of a sentence", v, "logg\n")
	}
	if reason, _ := e.Details["reason"].(string); !strings.Contains(reason, "log, warn, ask") {
		t.Errorf("details.reason = %q, want the reason the value was refused, naming the accepted ones", reason)
	}
	if file, _ := e.Details["file"].(string); !strings.HasSuffix(file, riskModeFileName) {
		t.Errorf("details.file = %q, want the file the value came from", file)
	}
	// The switch did not take effect, and the entry says which one did.
	if e.Details["mode"] != "log" || e.Details["source"] != "config" {
		t.Errorf("the entry names mode=%v source=%v, want the effective log/config", e.Details["mode"], e.Details["source"])
	}
}

func TestR1MXF05_AnIgnoredRiskSourceNamesTheValueAndTheReasonInFields(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		if err := datafile.WriteFileAtomic(filepath.Join(c.DataDir, riskSourceFileName), []byte("neural\n"), datafile.WithMode(0o600)); err != nil {
			t.Fatalf("seed the corrupt source file: %v", err)
		}
	})

	evs := r1mxF05IgnoredSwitchEvents(t, f, "risk.source:startup-ignored")
	if len(evs) != 1 {
		t.Fatalf("startup-ignored events = %d, want 1", len(evs))
	}
	e := evs[0]
	if v, _ := e.Details["value"].(string); v != "neural\n" {
		t.Errorf("details.value = %q, want the content of the file (%q)", v, "neural\n")
	}
	if reason, _ := e.Details["reason"].(string); !strings.Contains(reason, "rules") {
		t.Errorf("details.reason = %q, want the reason the value was refused, naming the accepted ones", reason)
	}
	if e.Details["classifier"] != "rules" || e.Details["source"] != "config" {
		t.Errorf("the entry names classifier=%v source=%v, want the effective rules/config", e.Details["classifier"], e.Details["source"])
	}
}

func TestR1MXF05_AnIgnoredSwitchDoesNotPutTheWholeFileInTheJournal(t *testing.T) {
	big := strings.Repeat("x", 4096) + "\n"
	f := newFixture(t, func(c *Config) {
		if err := datafile.WriteFileAtomic(filepath.Join(c.DataDir, riskModeFileName), []byte(big), datafile.WithMode(0o600)); err != nil {
			t.Fatalf("seed the corrupt mode file: %v", err)
		}
	})

	evs := r1mxF05IgnoredSwitchEvents(t, f, "risk.mode:startup-ignored")
	if len(evs) != 1 {
		t.Fatalf("startup-ignored events = %d, want 1", len(evs))
	}
	v, _ := evs[0].Details["value"].(string)
	if !strings.Contains(v, "bytes)") || len(v) > clipForJournalCap+32 {
		t.Errorf("the entry carries %d bytes of the refused file, want a clipped value (clipForJournal: %d bytes plus the count) - a file the gateway refused must not set the size of a journal line", len(v), clipForJournalCap)
	}
}
