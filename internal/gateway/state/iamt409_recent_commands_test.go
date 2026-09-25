package state

// IAMT-409: the buffer of recent exec commands for a person+machine pair.
// Storage mirrors the goals (GoalRecord): in state.json, per pair,
// newest-first, with trimming against both a maximum command count
// (default 10, ceiling 20) and a total character budget (default 2000).
// Scrubbing the command line itself is the caller's (the gateway's) job;
// trimming is the state's job.

import (
	"strings"
	"testing"
	"time"
)

func TestIAMT409_RecordCommandKeepsNewestWithinMaxAndBudget(t *testing.T) {
	st := NewState()
	st.People = append(st.People, Person{Name: "alice"})
	st.Machines = append(st.Machines, Machine{ID: "vm1"})
	now := time.Now()

	// Max 3, budget with headroom: the count is held, the order is newest-first.
	for i := 0; i < 5; i++ {
		if _, err := st.RecordCommand("alice", "vm1", RecentCommand{
			Command: strings.Repeat("a", 10) + string(rune('0'+i)),
			Exit:    "0", At: NewZonedTime(now),
		}, 3, 2000); err != nil {
			t.Fatalf("RecordCommand %d: %v", i, err)
		}
	}
	rec, ok := st.RecentCommandsFor("alice", "vm1")
	if !ok {
		t.Fatal("pair buffer not found")
	}
	if len(rec.Entries) != 3 {
		t.Fatalf("buffer holds %d entries, want 3 (the command maximum)", len(rec.Entries))
	}
	if rec.Entries[0].Command[len(rec.Entries[0].Command)-1] != '4' {
		t.Fatalf("first entry is not the most recent one: %q", rec.Entries[0].Command)
	}
	if rec.Entries[2].Command[len(rec.Entries[2].Command)-1] != '2' {
		t.Fatalf("last entry is not the third from the end: %q", rec.Entries[2].Command)
	}
}

func TestIAMT409_RecordCommandBudgetCutsOldestAndMarksCut(t *testing.T) {
	st := NewState()
	st.People = append(st.People, Person{Name: "alice"})
	st.Machines = append(st.Machines, Machine{ID: "vm1"})
	now := time.Now()

	// Budget 57: three entries of (10 command + 1 code + 8 overhead) = 19 fit
	// (57), the fourth does not.
	mk := func(tag string) RecentCommand {
		return RecentCommand{Command: strings.Repeat(tag, 10), Exit: "0", At: NewZonedTime(now)}
	}
	for _, tag := range []string{"a", "b", "c", "d"} {
		if _, err := st.RecordCommand("alice", "vm1", mk(tag), 20, 57); err != nil {
			t.Fatalf("RecordCommand %q: %v", tag, err)
		}
	}
	rec, _ := st.RecentCommandsFor("alice", "vm1")
	total := 0
	for _, e := range rec.Entries {
		total += len(e.Command) + len(e.Response) + len(e.Exit)
	}
	if total > 57 {
		t.Fatalf("buffer is %d characters against a budget of 57: %v", total, rec.Entries)
	}
	if len(rec.Entries) != 3 || !strings.HasPrefix(rec.Entries[0].Command, "dddddddddd") {
		t.Fatalf("wanted the three most recent entries, newest first, got: %v", rec.Entries)
	}
	for _, e := range rec.Entries {
		if strings.Contains(e.Command, "aaaa") {
			t.Fatalf("the oldest command survived the budget: %q", e.Command)
		}
	}
}

func TestIAMT409_RecordCommandHugeEntryIsTruncatedWithEllipsis(t *testing.T) {
	st := NewState()
	st.People = append(st.People, Person{Name: "alice"})
	st.Machines = append(st.Machines, Machine{ID: "vm1"})
	now := time.Now()

	huge := RecentCommand{Command: strings.Repeat("x", 100), Response: strings.Repeat("y", 100), Exit: "0", At: NewZonedTime(now)}
	rec, err := st.RecordCommand("alice", "vm1", huge, 10, 50)
	if err != nil {
		t.Fatalf("RecordCommand: %v", err)
	}
	e := rec.Entries[0]
	total := len(e.Command) + len(e.Response) + len(e.Exit)
	if total > 50 {
		t.Fatalf("entry is %d characters against a budget of 50", total)
	}
	if !strings.HasSuffix(e.Command, "…") && !strings.HasSuffix(e.Response, "…") {
		t.Fatalf("no ellipsis at the cut point: command=%q response=%q", e.Command, e.Response)
	}
}

func TestIAMT409_RecentCommandsForUnknownPairAndValidation(t *testing.T) {
	st := NewState()
	if _, ok := st.RecentCommandsFor("nobody", "nothing"); ok {
		t.Fatal("a non-existent pair cannot have a buffer")
	}
	if _, err := st.RecordCommand("ghost", "vm1", RecentCommand{Command: "x", At: NewZonedTime(time.Now())}, 10, 100); err == nil {
		t.Fatal("recording for a non-existent person must be refused")
	}
	if _, err := st.RecordCommand("alice", "ghost", RecentCommand{Command: "x", At: NewZonedTime(time.Now())}, 10, 100); err == nil {
		t.Fatal("recording for a non-existent machine must be refused")
	}
	if _, err := st.RecordCommand("alice", "vm1", RecentCommand{Command: "", At: NewZonedTime(time.Now())}, 10, 100); err == nil {
		t.Fatal("an empty command cannot enter the buffer")
	}
}
