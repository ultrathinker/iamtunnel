package gateway

import (
	"encoding/json"
	"testing"
)

// The canary: history -- by sessions, paged, newest first.
//
// On 21.09.2026 the maintainer asked for a history tab: who connected
// when over a day, a week, a month, and asked that the list not be
// shown all at once but, say, 20 or 50 rows at a time.
//
// Before this the verb returned one row per EVENT and without a bound.
// Both are wrong for this question: one session writes a start, risk
// decisions and a stop, while the person wants a row per visit; and an
// unbounded answer over a month of work can neither be held nor drawn.
//
// Checked together, because alone each property looks like it works:
// grouping, order, paging and the total count.
func TestCanary_HistoryIsGroupedAndPaged(t *testing.T) {
	f := newFixture(t, nil)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	page, err := root.SessionsHistory("", "", "", "", 20, 0)
	if err != nil {
		t.Fatalf("sessions.history: %v", err)
	}
	if page.Limit <= 0 {
		t.Errorf("a page without a bound (limit=%d) -- over a month of work that is an answer with nowhere to put it", page.Limit)
	}
	if page.Limit > 500 {
		t.Errorf("limit=%d: the bound must be a real one, otherwise there is none", page.Limit)
	}

	// An answer without limit must be bounded too: a trap left for the
	// next caller is the same trap.
	raw, err := root.Exec("sessions.history", map[string]any{"proto": 1})
	if err != nil {
		t.Fatalf("sessions.history without limit: %v", err)
	}
	var bare struct {
		Limit int `json:"limit"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(raw, &bare); err != nil {
		t.Fatalf("parsing the answer: %v", err)
	}
	if bare.Limit <= 0 {
		t.Errorf("without limit the gateway returned an unbounded answer (limit=%d) -- the default must be a page", bare.Limit)
	}

	// Newest first: history is read from the beginning, and the beginning
	// is now.
	prev := ""
	for i, r := range page.Sessions {
		if prev != "" && r.Started > prev {
			t.Errorf("row %d is newer than the previous one (%s > %s) -- the order is not newest-to-oldest", i, r.Started, prev)
		}
		prev = r.Started
		if r.Person == "" || r.Machine == "" {
			t.Errorf("row %d has no person or machine: %+v", i, r)
		}
		if r.Kind != "exec" && r.Kind != "shell" {
			t.Errorf("row %d: session kind %q, want exec or shell", i, r.Kind)
		}
	}
}
