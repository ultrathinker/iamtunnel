package events_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func newLog(t *testing.T) (*events.Log, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, events.DefaultLogFileName)
	l, err := events.OpenLog(path)
	if err != nil {
		t.Fatalf("OpenLog: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return 0
	}
	return len(strings.Split(strings.TrimSpace(string(data)), "\n"))
}

// ---------------------------------------------------------------------------
// Fix 7. The journal does not lose records quietly.
// ---------------------------------------------------------------------------

func TestFix7_AppendReportsWhatItRefusedToWrite(t *testing.T) {
	l, path := newLog(t)
	now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")

	rejected := []struct {
		name string
		e    events.Event
	}{
		{"empty event", events.Event{}},
		{"no timestamp", events.Event{Type: events.EventAdminOp, Actor: "admin", Result: "ok"}},
		{"unknown type", events.Event{Time: now, Type: "made.up", Actor: "admin", Result: "ok"}},
		{"auth without address or fingerprint", events.Event{
			Time: now, Type: events.EventAuthSuccess, Actor: "alice", Result: "ok"}},
		{"auth without fingerprint", events.Event{
			Time: now, Type: events.EventAuthSuccess, Actor: "alice", Result: "ok",
			Address: "203.0.113.9:22"}},
		{"auth without address", events.Event{
			Time: now, Type: events.EventAuthFailure, Actor: "alice", Result: "denied",
			Fingerprint: "SHA256:whoever"}},
	}

	for _, tc := range rejected {
		err := l.Append(tc.e)
		if err == nil {
			t.Errorf("%s: Append returned nil - the caller cannot tell 'written' from 'lost'", tc.name)
			continue
		}
		if !errors.Is(err, events.ErrInvalidEvent) {
			t.Errorf("%s: the error must be recognisable as a rejected event, got %v", tc.name, err)
		}
	}

	if n := countLines(t, path); n != 0 {
		t.Fatalf("a rejected event still reached the file: %d lines", n)
	}

	// An auth event carrying both of the things §3.5 names is written.
	ok := events.Event{
		Time: now, Type: events.EventAuthSuccess, Actor: "alice", Object: "gateway", Result: "ok",
		Address: "203.0.113.9:22", Fingerprint: "SHA256:alice",
	}
	if err := l.Append(ok); err != nil {
		t.Fatalf("a complete auth event was refused: %v", err)
	}
	if n := countLines(t, path); n != 1 {
		t.Fatalf("expected exactly the one accepted event in the file, got %d lines", n)
	}
}

func TestFix7_AuthValidationMatchesItsOwnMessage(t *testing.T) {
	now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")

	// The old message promised "address and fingerprint" while the code was content
	// with an actor. An actor is not a fingerprint.
	e := events.Event{Time: now, Type: events.EventAuthSuccess, Actor: "alice", Result: "ok"}
	err := e.Validate()
	if err == nil {
		t.Fatalf("auth.success with neither address nor fingerprint was accepted")
	}
	if !strings.Contains(err.Error(), "both address and fingerprint") {
		t.Fatalf("the message must describe what is actually required, got %q", err)
	}

	// Address and fingerprint may also arrive inside details.
	viaDetails := events.Event{
		Time: now, Type: events.EventAuthFailure, Result: "denied",
		Details: map[string]interface{}{"address": "203.0.113.4:22", "fingerprint": "SHA256:x"},
	}
	if err := viaDetails.Validate(); err != nil {
		t.Fatalf("address and fingerprint supplied in details were not recognised: %v", err)
	}
}

func TestFix7_ReadReportsSkippedLines(t *testing.T) {
	l, path := newLog(t)
	now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")

	for i := 0; i < 3; i++ {
		if err := l.Append(events.Event{
			Time: now, Type: events.EventSessionStart, Actor: "alice", Object: "vm1", Result: "ok",
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	_ = l.Close()

	// Damage a line in the middle of the file: a hole in an audit trail, not a
	// half-written tail.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	lines[1] = `{"time":"2026-09-12T12:00:0`
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, stats, err := events.ReadFile(path, events.Filter{})
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected the 2 readable records, got %d", len(got))
	}
	if stats.Skipped != 1 {
		t.Fatalf("a damaged line disappeared from the history without a count: %+v", stats)
	}
	if len(stats.BadLines) != 1 || stats.BadLines[0] != 2 {
		t.Fatalf("the damaged line must be located, got %+v", stats.BadLines)
	}

	// ReadHistory adds up the statistics of every file it walks.
	_, histStats, err := events.ReadHistory(filepath.Dir(path), events.Filter{})
	if err != nil {
		t.Fatalf("ReadHistory: %v", err)
	}
	if histStats.Skipped != 1 {
		t.Fatalf("ReadHistory lost the count while merging files: %+v", histStats)
	}
}

func TestFix7_RotateRecordsItself(t *testing.T) {
	l, path := newLog(t)
	archive := filepath.Join(filepath.Dir(path), "events-2026-09-12.jsonl")
	now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")

	if err := l.Append(events.Event{
		Time: now, Type: events.EventAdminOp, Actor: "admin", Object: "grant", Result: "ok",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := l.Rotate(archive); err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	got, _, err := l.Read(events.Filter{Types: []events.EventType{events.EventLogRotate}})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("§3.5 counts rotation among the recorded events, and the new log has %d of them", len(got))
	}
	if got[0].Details["archive"] != archive {
		t.Fatalf("the rotation record must say where the old records went, got %+v", got[0].Details)
	}
}

// ---------------------------------------------------------------------------
// Fix 10, held by behaviour. The read loop of the journal has one exit, at end of
// file, and the dead io.EOF branches the fix removed are gone - but counting exit
// operators in the source proves nothing about what a read actually yields: any
// rewrite of the loop breaks the count without touching behaviour, and behaviour
// can break without moving the count. What must hold after reading a journal in
// which a damaged line, a torn trailing line and an empty line occur:
//
//   - every intact record comes back, in order, with its content intact;
//   - the damaged line and the torn tail are reported (count and line numbers),
//     neither silently dropped nor returned as events;
//   - an empty line is neither an event nor damage;
//   - the read is not an error.
// ---------------------------------------------------------------------------

func TestFix10_ReadSurvivesDamagedLinesAndReportsThem(t *testing.T) {
	now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")
	mk := func(actor, object string, typ events.EventType) string {
		raw, err := json.Marshal(events.Event{
			Time: now, Type: typ, Actor: actor, Object: object, Result: "ok",
		})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		return string(raw)
	}

	// Written as raw bytes, behind the Log's back, so the exact damage is under the
	// test's control: the torn tail has no '\n', as a killed process leaves it.
	path := filepath.Join(t.TempDir(), events.DefaultLogFileName)
	content := strings.Join([]string{
		mk("alice", "vm1", events.EventDoorOpen),         // line 1
		"",                                               // line 2: an empty line
		mk("bob", "vm2", events.EventDoorOpen),           // line 3
		`{"time":"2026-09-12T12:00:0`,                    // line 4: damaged mid-file
		mk("alice", "vm1", events.EventDoorClose),        // line 5
		`{"time":"2026-09-12T12:00:00Z","type":"door.cl`, // line 6: torn tail, no '\n'
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, stats, err := events.ReadFile(path, events.Filter{})
	if err != nil {
		t.Fatalf("a journal with a damaged line, a torn tail and an empty line must still be readable, got %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("the three intact records must survive the damaged ones, got %d: %+v", len(got), got)
	}
	want := []struct {
		actor, object string
		typ           events.EventType
	}{
		{"alice", "vm1", events.EventDoorOpen},
		{"bob", "vm2", events.EventDoorOpen},
		{"alice", "vm1", events.EventDoorClose},
	}
	for i, w := range want {
		if got[i].Actor != w.actor || got[i].Object != w.object || got[i].Type != w.typ {
			t.Fatalf("record %d came back wrong: %+v, wanted %s on %s (%s)", i+1, got[i], w.actor, w.object, w.typ)
		}
	}
	if stats.Skipped != 2 {
		t.Fatalf("the damaged line and the torn tail must both be counted as skipped, got Skipped=%d (%+v)", stats.Skipped, stats)
	}
	if len(stats.BadLines) != 2 || stats.BadLines[0] != 4 || stats.BadLines[1] != 6 {
		t.Fatalf("the damaged line (4) and the torn tail (6) must be located, and the empty line (2) "+
			"must appear neither as an event nor among the damaged, got %+v", stats.BadLines)
	}
}

// ---------------------------------------------------------------------------
// Fix 1, journal half: a revocation the store performed reaches events.jsonl.
// ---------------------------------------------------------------------------

func TestFix1_RevocationReachesTheJournal(t *testing.T) {
	dir := t.TempDir()
	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("Open store: %v", err)
	}
	defer s.Close()

	l, _ := newLog(t)
	now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")

	pub := func(tag byte) string {
		// A real ed25519 blob: 11-byte name, then a 32-byte key.
		blob := []byte{0, 0, 0, 11}
		blob = append(blob, []byte("ssh-ed25519")...)
		blob = append(blob, 0, 0, 0, 32)
		for i := 0; i < 32; i++ {
			blob = append(blob, tag*7+byte(i))
		}
		return "ssh-ed25519 " + encodeBase64(blob)
	}

	alicePub, machinePub, newMachinePub := pub(1), pub(2), pub(3)
	aliceFP, _ := state.ComputeFingerprint(alicePub)
	oldFP, _ := state.ComputeFingerprint(machinePub)

	initial := state.NewState()
	initial.People = []state.Person{{Name: "alice", Role: "admin",
		Keys: []state.Key{{Fingerprint: aliceFP, Pub: alicePub, Added: now}}}}
	initial.Machines = []state.Machine{{ID: "vm1", Name: "vm1", State: "verified",
		MachineKey: machinePub, OSUser: `CORP\svc`}}
	if err := initial.GrantAccess("alice", "vm1", nil, "shell"); err != nil {
		t.Fatalf("GrantAccess: %v", err)
	}
	if err := s.Set(*initial); err != nil {
		t.Fatalf("Set: %v", err)
	}
	s.DrainRevocations()

	// The machine comes back with a different key - and access goes away.
	if err := s.Update(func(st *state.State) error {
		st.Machines[0].MachineKey = newMachinePub
		return nil
	}); err != nil {
		t.Fatalf("rekey: %v", err)
	}

	revocations := s.DrainRevocations()
	if len(revocations) != 1 {
		t.Fatalf("expected one revocation to hand to the journal, got %+v", revocations)
	}
	for _, rev := range revocations {
		if err := l.Append(events.NewGrantRevokedEvent(rev, now)); err != nil {
			t.Fatalf("the revocation could not be written to the journal: %v", err)
		}
	}

	written, _, err := l.Read(events.Filter{Types: []events.EventType{events.EventGrantRevoke}})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(written) != 1 {
		t.Fatalf("the journal holds %d revocation records, expected 1", len(written))
	}
	got := written[0]
	if got.Details["reason"] != string(state.RevokedMachineRekeyed) {
		t.Fatalf("the record does not say why access was withdrawn: %+v", got.Details)
	}
	if got.Details["person"] != "alice" || got.Details["machine"] != "vm1" {
		t.Fatalf("the record does not say whose access was withdrawn: %+v", got.Details)
	}
	if got.Details["pinnedKeyFp"] != oldFP {
		t.Fatalf("the record does not name the key the grant was issued against: %+v", got.Details)
	}
}

// encodeBase64 keeps the key builder above readable.
func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
