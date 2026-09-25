package events_test

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// Gate 7: Write 1000 records append-only, read back all 1000 with preserved order.
// Then artificially append an incomplete/truncated line and verify first 1000 still read cleanly.
func TestEvents_Gate7_Append1000AndCrashResilience(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, events.DefaultLogFileName)

	log, err := events.OpenLog(logPath)
	if err != nil {
		t.Fatalf("OpenLog failed: %v", err)
	}
	defer log.Close()

	baseTime, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")
	const totalEvents = 1000

	// 1. Append 1000 records
	for i := 1; i <= totalEvents; i++ {
		eventTime := state.NewZonedTime(baseTime.Add(time.Duration(i) * time.Second))
		err := log.Append(events.Event{
			Time:   eventTime,
			Type:   events.EventSessionStart,
			Actor:  fmt.Sprintf("person:user-%04d", i),
			Object: "machine:target-node",
			Result: "success",
			Details: map[string]interface{}{
				"seq":        i,
				"session_id": fmt.Sprintf("sess-%04d", i),
			},
		})
		if err != nil {
			t.Fatalf("Append record %d failed: %v", i, err)
		}
	}

	// 2. Read back and verify all 1000 records are present and ordered
	records, stats, err := log.Read(events.Filter{})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(records) != totalEvents {
		t.Fatalf("expected %d records, got %d", totalEvents, len(records))
	}
	if stats.Skipped != 0 {
		t.Fatalf("a healthy log reported %d unreadable lines: %v", stats.Skipped, stats.BadLines)
	}

	for i := 0; i < totalEvents; i++ {
		expectedActor := fmt.Sprintf("person:user-%04d", i+1)
		if records[i].Actor != expectedActor {
			t.Fatalf("order mismatch at index %d: expected %s, got %s", i, expectedActor, records[i].Actor)
		}
	}

	// 3. Artificially append an incomplete/truncated line (simulating crash during write of 1001st line)
	// Notice: incomplete JSON without newline or closing brace!
	log.Close()
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatalf("OpenFile failed: %v", err)
	}
	truncatedLine := []byte(`{"time":"2026-09-12T12:16:41Z","type":"session.drop","actor":"person:user-1001","object":"machine:target-node","resul`)
	if _, err := f.Write(truncatedLine); err != nil {
		t.Fatalf("Write truncatedLine failed: %v", err)
	}
	f.Close()

	// 4. Reopen and read: must safely recover and return the 1000 valid preceding records!
	log2, err := events.OpenLog(logPath)
	if err != nil {
		t.Fatalf("OpenLog2 failed: %v", err)
	}
	defer log2.Close()

	recoveredRecords, recoveredStats, err := log2.Read(events.Filter{})

	if err != nil {
		t.Fatalf("expected graceful read recovery, got error: %v", err)
	}
	if len(recoveredRecords) != totalEvents {
		t.Fatalf("Gate 7 failure: expected 1000 recovered records after truncated trailing line, got %d", len(recoveredRecords))
	}
	// Recovery is graceful, not silent: the torn line is counted and located.
	if recoveredStats.Skipped != 1 || len(recoveredStats.BadLines) != 1 {
		t.Fatalf("the torn trailing line was swallowed without a word: stats=%+v", recoveredStats)
	}

	// Verify order and identity of the recovered records
	for i := 0; i < totalEvents; i++ {
		expectedActor := fmt.Sprintf("person:user-%04d", i+1)
		if recoveredRecords[i].Actor != expectedActor {
			t.Fatalf("recovered record mismatch at index %d: expected %s, got %s", i, expectedActor, recoveredRecords[i].Actor)
		}
	}
}

// Gate 8: Rotation by rename: old records remain accessible in archive, new records written to new log.
func TestEvents_Gate8_Rotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, events.DefaultLogFileName)
	archivePath := filepath.Join(dir, "events-archive-2026-09-12.jsonl")

	log, err := events.OpenLog(logPath)
	if err != nil {
		t.Fatalf("OpenLog failed: %v", err)
	}
	defer log.Close()

	baseTime, _ := state.ParseZonedTime("2026-09-12T10:00:00Z")

	// 1. Write 300 records before rotation
	for i := 1; i <= 300; i++ {
		if err := log.Append(authEvent(baseTime, i, fmt.Sprintf("person:old-%d", i))); err != nil {
			t.Fatalf("Append old record %d: %v", i, err)
		}
	}

	// 2. Perform rotation to archivePath
	if err := log.Rotate(archivePath); err != nil {
		t.Fatalf("Rotate failed: %v", err)
	}

	// 3. Write 150 new records after rotation
	for i := 1; i <= 150; i++ {
		if err := log.Append(authEvent(baseTime, 300+i, fmt.Sprintf("person:new-%d", i))); err != nil {
			t.Fatalf("Append new record %d: %v", i, err)
		}
	}

	// 4. Verify current log contains the rotation record and the 150 new ones
	currentRecords, _, err := log.Read(events.Filter{})
	if err != nil {
		t.Fatalf("Read current log failed: %v", err)
	}
	if len(currentRecords) != 151 {
		t.Fatalf("expected 1 rotation record plus 150 new records in current log, got %d", len(currentRecords))
	}
	if currentRecords[0].Type != events.EventLogRotate {
		t.Fatalf("the new log must open with the %s record, got %s", events.EventLogRotate, currentRecords[0].Type)
	}
	if currentRecords[1].Actor != "person:new-1" {
		t.Fatalf("expected first new record 'person:new-1', got %s", currentRecords[1].Actor)
	}

	// 5. Verify archive log contains the 300 old records
	archiveRecords, _, err := events.ReadFile(archivePath, events.Filter{})
	if err != nil {
		t.Fatalf("ReadFile archive failed: %v", err)
	}
	if len(archiveRecords) != 300 {
		t.Fatalf("expected 300 records in archive log, got %d", len(archiveRecords))
	}
	if archiveRecords[0].Actor != "person:old-1" {
		t.Fatalf("expected first archive record 'person:old-1', got %s", archiveRecords[0].Actor)
	}

	// 6. Verify ReadFiles across archive and current returns everything in order
	allRecords, _, err := events.ReadFiles(events.Filter{}, archivePath, logPath)
	if err != nil {
		t.Fatalf("ReadFiles failed: %v", err)
	}
	if len(allRecords) != 451 {
		t.Fatalf("expected 451 combined records, got %d", len(allRecords))
	}
}

// authEvent builds an auth.success event that carries what §3.5 asks of one:
// an address and a fingerprint.
func authEvent(base state.ZonedTime, seq int, actor string) events.Event {
	return events.Event{
		Time:        state.NewZonedTime(base.Add(time.Duration(seq) * time.Second)),
		Type:        events.EventAuthSuccess,
		Actor:       actor,
		Object:      "gateway",
		Result:      "ok",
		Address:     fmt.Sprintf("203.0.113.%d:22", seq%256),
		Fingerprint: fmt.Sprintf("SHA256:fp-%d", seq),
	}
}

// Test filtering by time, event type, actor, and result.
func TestEvents_Filtering(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, events.DefaultLogFileName)

	log, err := events.OpenLog(logPath)
	if err != nil {
		t.Fatalf("OpenLog failed: %v", err)
	}
	defer log.Close()

	t1, _ := state.ParseZonedTime("2026-09-12T10:00:00Z")
	t2, _ := state.ParseZonedTime("2026-09-12T11:00:00Z")
	t3, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")
	t4, _ := state.ParseZonedTime("2026-09-12T13:00:00Z")

	for _, e := range []events.Event{
		{Time: t1, Type: events.EventAuthSuccess, Actor: "alice", Object: "gw", Result: "ok",
			Address: "203.0.113.7:22", Fingerprint: "SHA256:alice"},
		{Time: t2, Type: events.EventAuthFailure, Actor: "bob", Object: "gw", Result: "denied",
			Address: "203.0.113.8:22", Fingerprint: "SHA256:bob"},
		{Time: t3, Type: events.EventSessionStart, Actor: "alice", Object: "vm1", Result: "success"},
		{Time: t4, Type: events.EventSessionStop, Actor: "alice", Object: "vm1", Result: "closed"},
	} {
		if err := log.Append(e); err != nil {
			t.Fatalf("Append %s: %v", e.Type, err)
		}
	}

	// Filter by Actor
	aliceEvents, _, _ := log.Read(events.Filter{Actor: "alice"})
	if len(aliceEvents) != 3 {
		t.Fatalf("expected 3 events for alice, got %d", len(aliceEvents))
	}

	// Filter by Type
	authFails, _, _ := log.Read(events.Filter{Types: []events.EventType{events.EventAuthFailure}})
	if len(authFails) != 1 || authFails[0].Actor != "bob" {
		t.Fatalf("expected 1 auth failure for bob, got %+v", authFails)
	}

	// Filter by Time Window: between t2 and t3 inclusive
	startTime := t2.Time
	endTime := t3.Time
	windowEvents, _, _ := log.Read(events.Filter{Since: &startTime, Until: &endTime})
	if len(windowEvents) != 2 {
		t.Fatalf("expected 2 events in window, got %d", len(windowEvents))
	}
}

// The product source and the document this test reads. The list of event types
// is deliberately NOT written down here: it is taken from the Go AST of
// event.go, the same way scripts/check_eventdict.go takes it, so that declaring
// a new EventType constant is enough to pull it into these checks whether or not
// its author remembers this file.
const (
	eventSourceFile = "event.go"
	eventTypeIdent  = "EventType"
	validatorIdent  = "IsValidEventType"
	specFenceInfo   = "iamtunnel-event-types-v1"
	specDocRelPath  = "docs/PROTOCOL.md"
)

// findRepoFile returns the path of rel. `go test` runs a package's tests with
// the package directory as the working directory, so a plain relative path
// works for event.go; walking up to the module root covers the document too.
func findRepoFile(rel string) (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}
	for i := 0; i < 8; i++ {
		candidate := filepath.Join(dir, rel)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", false
}

// eventTypeConstants parses the product source and returns, in source order, the
// names and the values of every constant declared with an EXPLICIT EventType
// type. A constant without the explicit type is just a string and is skipped,
// exactly as gate 12 skips it: its membership in the dictionary is not provable.
func eventTypeConstants(t *testing.T, path string) ([]string, map[string]string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("cannot parse %s: %v", eventSourceFile, err)
	}

	var names []string
	values := map[string]string{}
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			id, ok := vs.Type.(*ast.Ident)
			if !ok || id.Name != eventTypeIdent {
				continue
			}
			for k, n := range vs.Names {
				if k >= len(vs.Values) {
					t.Fatalf("%s: constant %s has an explicit %s type but no value", eventSourceFile, n.Name, eventTypeIdent)
				}
				lit, ok := vs.Values[k].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s: constant %s has an explicit %s type but is not a string literal, so its membership in the dictionary cannot be compared", eventSourceFile, n.Name, eventTypeIdent)
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: constant %s: %v", eventSourceFile, n.Name, err)
				}
				values[n.Name] = v
				names = append(names, n.Name)
			}
		}
	}
	return names, values
}

// validatorAccepts parses the product source and returns the identifiers the
// IsValidEventType switch accepts. It walks the AST, not the text: comments and
// string literals elsewhere in the file cannot smuggle a name in, and an
// identifier that has no constant behind it shows up here as an extra name.
func validatorAccepts(t *testing.T, path string) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("cannot parse %s: %v", eventSourceFile, err)
	}

	accepted := map[string]bool{}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name == nil || fd.Name.Name != validatorIdent {
			return true
		}
		found = true
		ast.Inspect(fd.Body, func(m ast.Node) bool {
			cc, ok := m.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				if id, ok := e.(*ast.Ident); ok {
					accepted[id.Name] = true
				}
			}
			return true
		})
		return false
	})
	if !found {
		t.Fatalf("%s: no %s function, so the dictionary of accepted event types cannot be read from the AST", eventSourceFile, validatorIdent)
	}
	return accepted
}

// specDictionary reads the single machine-readable SPEC §3.5 dictionary block.
// The scan is line-based and dumb on purpose: only the body of the block whose
// info-string is specFenceInfo is read, and nothing else in the document.
func specDictionary(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read %s: %v", specDocRelPath, err)
	}

	var blocks []string
	lines := strings.Split(string(raw), "\n")
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "```"+specFenceInfo {
			continue
		}
		var body []string
		for i++; i < len(lines); i++ {
			if strings.HasPrefix(strings.TrimLeft(lines[i], " \t"), "```") {
				break
			}
			body = append(body, lines[i])
		}
		blocks = append(blocks, strings.Join(body, "\n"))
	}
	if len(blocks) != 1 {
		t.Fatalf("%s: expected exactly one ```%s block, found %d: the dictionary must be machine-readable, otherwise there is nothing to hold the code against", specDocRelPath, specFenceInfo, len(blocks))
	}

	var names []string
	if err := json.Unmarshal([]byte(blocks[0]), &names); err != nil {
		t.Fatalf("%s: the ```%s block is not a JSON array of strings: %v", specDocRelPath, specFenceInfo, err)
	}
	for _, n := range names {
		if strings.TrimSpace(n) == "" {
			t.Fatalf("%s: the ```%s block contains an empty name", specDocRelPath, specFenceInfo)
		}
	}
	sort.Strings(names)
	return names
}

// sortedValues returns the values of the declared constants, sorted.
func sortedValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// sortedNames returns the keys of a set, sorted.
func sortedNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// missingFrom returns the elements of a that are absent from b, sorted.
func missingFrom(a, b []string) []string {
	in := make(map[string]bool, len(b))
	for _, s := range b {
		in[s] = true
	}
	out := make([]string, 0, len(a))
	for _, s := range a {
		if !in[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// identForValue returns the identifier of the constant that holds value.
func identForValue(values map[string]string, value string) string {
	for name, v := range values {
		if v == value {
			return name
		}
	}
	return "?"
}

// TestEvents_AllSpecEventTypes holds the closed dictionary of SPEC §3.5 event
// types against what event.go declares and what IsValidEventType accepts, and
// checks that every one of those types survives the JSON round trip and the
// journal.
//
// The list of types is not written down here on purpose. It is read from the Go
// AST of event.go - the same way scripts/check_eventdict.go reads it - so a new
// EventType constant is pulled into these checks whether or not its author
// remembers this file. A test that carries its own copy of the list only ever
// proves that the copy equals itself: deleting a name from it leaves the test
// green (IAMT-116).
func TestEvents_AllSpecEventTypes(t *testing.T) {
	srcPath, ok := findRepoFile(eventSourceFile)
	if !ok {
		t.Fatalf("%s not found relative to the working directory: this test reads the product source instead of keeping its own copy of the list, and cannot run without it", eventSourceFile)
	}

	names, values := eventTypeConstants(t, srcPath)
	if len(names) == 0 {
		t.Fatalf("%s declares no constant with an explicit %s type: the completeness guard would be vacuous", eventSourceFile, eventTypeIdent)
	}
	declaredValues := sortedValues(values)
	if len(declaredValues) != len(names) {
		t.Fatalf("%s declares %d %s constant(s) but only %d distinct event name(s): one name is claimed by two constants", eventSourceFile, len(names), eventTypeIdent, len(declaredValues))
	}

	accepted := validatorAccepts(t, srcPath)
	for _, name := range names {
		if !accepted[name] {
			t.Fatalf("%s declares %s = %q with an explicit %s type, but %s does not accept it: such an event can never be written", eventSourceFile, name, values[name], eventTypeIdent, validatorIdent)
		}
	}
	for _, name := range sortedNames(accepted) {
		if _, declared := values[name]; !declared {
			t.Fatalf("%s accepts %s, which is not a constant with an explicit %s type: the validator and the declared dictionary disagree", validatorIdent, name, eventTypeIdent)
		}
	}

	docPath, ok := findRepoFile(specDocRelPath)
	if !ok {
		t.Fatalf("%s not found above the working directory: this test holds the code against the machine-readable SPEC §3.5 dictionary and cannot run without it", specDocRelPath)
	}
	specNames := specDictionary(t, docPath)
	codeOnly := missingFrom(declaredValues, specNames)
	docOnly := missingFrom(specNames, declaredValues)
	if len(codeOnly) > 0 || len(docOnly) > 0 {
		var parts []string
		if len(codeOnly) > 0 {
			listed := make([]string, 0, len(codeOnly))
			for _, v := range codeOnly {
				listed = append(listed, fmt.Sprintf("%s (%s)", v, identForValue(values, v)))
			}
			parts = append(parts, "declared in the code but absent from the dictionary: "+strings.Join(listed, ", "))
		}
		if len(docOnly) > 0 {
			parts = append(parts, "in the dictionary but declared nowhere in the code: "+strings.Join(docOnly, ", "))
		}
		t.Fatalf("SPEC §3.5 event dictionary drift in %s: %d %s constant(s) with an explicit type in the code, %d name(s) in the machine-readable dictionary of %s; %s",
			eventSourceFile, len(declaredValues), eventTypeIdent, len(specNames), specDocRelPath, strings.Join(parts, "; "))
	}

	// Every type must survive the JSON round trip §3.5 describes and the append
	// path of the journal itself.
	dir := t.TempDir()
	logPath := filepath.Join(dir, events.DefaultLogFileName)
	log, err := events.OpenLog(logPath)
	if err != nil {
		t.Fatalf("OpenLog failed: %v", err)
	}
	defer log.Close()

	now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")
	for i, name := range names {
		evt := events.Event{
			Time:        now,
			Type:        events.EventType(values[name]),
			Actor:       "test-actor",
			Object:      fmt.Sprintf("obj-%d", i),
			Result:      "ok",
			Address:     "203.0.113.5:22",
			Fingerprint: "SHA256:test",
		}
		raw, err := json.Marshal(evt)
		if err != nil {
			t.Fatalf("marshalling an event of type %s (%s): %v", values[name], name, err)
		}
		var back events.Event
		if err := json.Unmarshal(raw, &back); err != nil {
			t.Fatalf("unmarshalling an event of type %s (%s): %v", values[name], name, err)
		}
		if back.Type != evt.Type {
			t.Fatalf("the JSON round trip changed the event type %s (%s) into %q", values[name], name, back.Type)
		}
		if !events.IsValidEventType(evt.Type) {
			t.Fatalf("%s (%s) is declared but %s rejects it", values[name], name, validatorIdent)
		}
		if err := log.Append(evt); err != nil {
			t.Fatalf("failed appending event of type %s (%s): %v", values[name], name, err)
		}
	}

	records, _, err := log.Read(events.Filter{})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if len(records) != len(names) {
		t.Fatalf("expected %d records, got %d", len(names), len(records))
	}
	for i, name := range names {
		if records[i].Type != events.EventType(values[name]) {
			t.Fatalf("record %d: expected type %s (%s), got %s", i, values[name], name, records[i].Type)
		}
	}
}

// Test concurrent appending from multiple goroutines under -race.
func TestEvents_ConcurrentAppends(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, events.DefaultLogFileName)
	log, err := events.OpenLog(logPath)
	if err != nil {
		t.Fatalf("OpenLog failed: %v", err)
	}
	defer log.Close()

	now, _ := state.ParseZonedTime("2026-09-12T12:00:00Z")
	const numWorkers = 8
	const eventsPerWorker = 50

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < eventsPerWorker; i++ {
				err := log.Append(events.Event{
					Time:   now,
					Type:   events.EventSessionStart,
					Actor:  fmt.Sprintf("worker-%d", workerID),
					Object: fmt.Sprintf("session-%d", i),
					Result: "ok",
				})
				if err != nil {
					t.Errorf("worker %d append failed: %v", workerID, err)
				}
			}
		}(w)
	}

	wg.Wait()

	allRecords, _, err := log.Read(events.Filter{})
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	expectedTotal := numWorkers * eventsPerWorker
	if len(allRecords) != expectedTotal {
		t.Fatalf("expected %d records, got %d", expectedTotal, len(allRecords))
	}
}
