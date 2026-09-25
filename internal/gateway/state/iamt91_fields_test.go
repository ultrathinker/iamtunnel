package state_test

// IAMT-91, step one: the five §4.3 machine fields and the load of a state.json
// written before they existed.
//
// The point of these tests is MEMORY. The live defence already works: the
// gateway compares the target sshd host key against the pinned one inside the
// handshake and refuses on mismatch. What it cannot do today is remember that
// it happened - state.Machine carries none of the five fields - so an admin
// cannot tell a machine that was never checked from a machine that FAILED the
// check, and the rule "hostKeyStatus mismatch forbids the door" has no state to
// read. Step one is the data model only: the fields, and the guarantee that an
// old file still loads with "never checked" / "not yet proved".

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// spec43Fields are the five machine fields IAMT-91 adds, in the order §4.3
// lists them.
var spec43Fields = []string{
	"observedSSHDHostKey",
	"hostKeyStatus",
	"requestedOsUser",
	// §4.3 and PROTOCOL §1.6 both spell this field with a lowercase "s":
	// verifiedOsUser. The Go identifier is VerifiedOSUser and stays as it is -
	// the JSON name comes from the tag, and the tag on this build says
	// verifiedOsUser. A test list that disagrees with the tag does not fail: it
	// silently stops finding the line (IAMT-91 round 3, four lines instead of
	// five), which is why the list is now also held against the struct tags by
	// TestIamt91_TheFieldListIsTheTagList.
	"verifiedOsUser",
	"osUserStatus",
}

// writeStateThroughProduct installs st through the real store, so that
// state.json in dir is exactly what this build writes: tmp file, fsync, rename,
// marshalState.
func writeStateThroughProduct(t *testing.T, dir string, st state.State) {
	t.Helper()
	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("state.Open(%s): %v", dir, err)
	}
	defer s.Close()
	if err := s.Set(st); err != nil {
		t.Fatalf("state.Set through the product writer: %v", err)
	}
}

// readStateFile returns the bytes of state.json in dir.
func readStateFile(t *testing.T, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, state.StateFileName))
	if err != nil {
		t.Fatalf("reading %s: %v", state.StateFileName, err)
	}
	return raw
}

// stripSpec43Fields removes exactly those lines of a state.json written by this
// build that carry one of the five §4.3 machine fields, and returns the result
// together with the number of lines dropped.
//
// This is how the pre-IAMT-91 format is obtained. The bytes are the product's
// own output - MarshalIndent, two spaces, one field per line - and the only
// operation applied to them is the subtraction of whole field lines. Nothing is
// typed by hand, so a test built on the result is a test against a real old
// file rather than against an approximation of one: if the writer ever stops
// putting a field on its own line, the dropped-line count stops matching and
// the test says so instead of silently testing something else.
func stripSpec43Fields(t *testing.T, raw []byte) ([]byte, int) {
	t.Helper()
	var kept []string
	dropped := 0
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		isField := false
		for _, f := range spec43Fields {
			if strings.HasPrefix(trimmed, `"`+f+`":`) {
				isField = true
				break
			}
		}
		if isField {
			dropped++
			continue
		}
		kept = append(kept, line)
	}
	return []byte(strings.Join(kept, "\n")), dropped
}

// oldFormatState builds a genuine pre-IAMT-91 state.json: the product writes a
// complete state first (all five fields populated, so all five keys are in the
// file), and the five field lines are then subtracted. It fails the test if the
// subtraction is not exactly five lines, or if the result still mentions any of
// the fields, or is not valid JSON.
func oldFormatState(t *testing.T, st state.State) []byte {
	t.Helper()

	newDir := t.TempDir()
	writeStateThroughProduct(t, newDir, st)

	oldRaw, dropped := stripSpec43Fields(t, readStateFile(t, newDir))
	if dropped != len(spec43Fields) {
		t.Fatalf("subtracting the five §4.3 fields from a state.json written by this build dropped %d line(s), want %d: the writer's shape changed, so this test is no longer looking at the pre-IAMT-91 format", dropped, len(spec43Fields))
	}
	for _, f := range spec43Fields {
		if strings.Contains(string(oldRaw), `"`+f+`"`) {
			t.Fatalf("the derived old-format state.json still carries %q: the subtraction did not produce the old format", f)
		}
	}
	if !json.Valid(oldRaw) {
		t.Fatalf("the derived old-format state.json is not valid JSON:\n%s", oldRaw)
	}
	return oldRaw
}

// machineWithAllSpec43Fields returns baseState with every §4.3 field of its
// machine set, so that the product writer emits all five keys.
func machineWithAllSpec43Fields(t *testing.T) state.State {
	t.Helper()
	st := baseState(t)
	observed := edPub(9)
	pinned := observed
	st.Machines[0].SSHDHostKey = &pinned
	verified := `CORP\svc`
	st.Machines[0].ObservedSSHDHostKey = &observed
	st.Machines[0].HostKeyStatus = state.HostKeyStatusMatch
	st.Machines[0].RequestedOSUser = `CORP\svc`
	st.Machines[0].VerifiedOSUser = &verified
	st.Machines[0].OSUserStatus = state.OSUserStatusVerified
	return st
}

// writeRawState puts raw into a fresh directory as state.json.
func writeRawState(t *testing.T, raw []byte) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, state.StateFileName), raw, 0600); err != nil {
		t.Fatalf("writing %s: %v", state.StateFileName, err)
	}
	return dir
}

// TestIamt91_OldStateFileLoadsAsNeverChecked is the central test of step one: a
// state.json written before these fields existed must load, must not be
// read-only, and must read as "never compared" and "never proved" - not as an
// empty string, which is a member of neither closed set.
func TestIamt91_OldStateFileLoadsAsNeverChecked(t *testing.T) {
	want := machineWithAllSpec43Fields(t)
	oldRaw := oldFormatState(t, want)

	oldDir := writeRawState(t, oldRaw)

	s, err := state.Open(oldDir)
	if err != nil {
		t.Fatalf("an old-format state.json must still load, got: %v", err)
	}
	defer s.Close()
	if s.IsReadOnly() {
		t.Fatalf("an old-format state.json was opened read-only: %v", s.CorruptError())
	}
	if cerr := s.CorruptError(); cerr != nil {
		t.Fatalf("an old-format state.json was reported corrupt: %v", cerr)
	}

	got := s.Get()
	if err := got.Validate(); err != nil {
		t.Fatalf("an old-format state.json with defaults must remain valid after loading: %v", err)
	}
	m, ok := got.MachineByID("vm1")
	if !ok {
		t.Fatalf("machine vm1 is missing after loading an old-format state.json")
	}

	if m.HostKeyStatus != state.HostKeyStatusUnverified {
		t.Fatalf("a machine with no recorded host key comparison must read as %q, got %q: an empty status is in neither closed set and makes every later comparison against it false", state.HostKeyStatusUnverified, m.HostKeyStatus)
	}
	if m.OSUserStatus != state.OSUserStatusPending {
		t.Fatalf("a machine with no recorded OS user probe must read as %q, got %q", state.OSUserStatusPending, m.OSUserStatus)
	}
	if m.ObservedSSHDHostKey != nil {
		t.Fatalf("observedSSHDHostKey was invented while loading: got %q, want absent", *m.ObservedSSHDHostKey)
	}
	if m.VerifiedOSUser != nil {
		t.Fatalf("verifiedOsUser was invented while loading: got %q, want absent", *m.VerifiedOSUser)
	}

	// The old format is missing five fields and nothing else: everything the
	// file did carry has to come back unchanged.
	if m.ID != "vm1" || m.Name != "vm1" || m.State != "verified" {
		t.Fatalf("machine identity changed while loading: %+v", m)
	}
	if m.MachineKey != want.Machines[0].MachineKey {
		t.Fatalf("machineKey changed while loading an old-format file")
	}
	if m.OSUser != `CORP\svc` {
		t.Fatalf("osUser changed while loading an old-format file: got %q", m.OSUser)
	}
	if len(got.People) != 1 || got.People[0].Name != "alice" || len(got.Grants) != 1 {
		t.Fatalf("loading an old-format file changed the rest of the state: people=%d grants=%d", len(got.People), len(got.Grants))
	}

	// Reading must not write: IAMT-98's rule, and the reason an old file needs
	// no rewrite to be usable.
	if after := readStateFile(t, oldDir); !bytes.Equal(after, oldRaw) {
		t.Fatalf("state.Open rewrote an old-format state.json; the read path must not write")
	}
}

// TestIamt91_OpenForReadSeesTheSameDefaults covers the other two entry points
// into the shared parse pipeline: OpenForRead without a lock file goes through
// readStateBytesUnlocked, and it has to produce the same defaults.
func TestIamt91_OpenForReadSeesTheSameDefaults(t *testing.T) {
	oldRaw := oldFormatState(t, machineWithAllSpec43Fields(t))
	oldDir := writeRawState(t, oldRaw)

	s, err := state.OpenForRead(oldDir)
	if err != nil {
		t.Fatalf("OpenForRead on an old-format state.json: %v", err)
	}
	defer s.Close()
	if !s.IsReadOnly() {
		t.Fatalf("OpenForRead must return a read-only store")
	}
	read := s.Get()
	m, ok := read.MachineByID("vm1")
	if !ok {
		t.Fatalf("machine vm1 is missing after OpenForRead of an old-format state.json")
	}
	if m.HostKeyStatus != state.HostKeyStatusUnverified || m.OSUserStatus != state.OSUserStatusPending {
		t.Fatalf("OpenForRead read the §4.3 defaults differently from Open: hostKeyStatus=%q osUserStatus=%q", m.HostKeyStatus, m.OSUserStatus)
	}
	if after := readStateFile(t, oldDir); !bytes.Equal(after, oldRaw) {
		t.Fatalf("OpenForRead rewrote the state.json it read")
	}
}

// TestIamt91_WrittenStateCarriesTheClosedSets is the write half: a machine
// created by a transaction that knows nothing about the new fields must still
// reach the disk with a member of each closed set, so that no reader - an older
// build, the admin CLI, an operator with an editor - has to guess what an empty
// status means.
func TestIamt91_WrittenStateCarriesTheClosedSets(t *testing.T) {
	dir := t.TempDir()
	// machineWith() sets none of the five fields: this is the machine the enrol
	// path creates today.
	writeStateThroughProduct(t, dir, baseState(t))

	var doc struct {
		Machines []map[string]json.RawMessage `json:"machines"`
	}
	if err := json.Unmarshal(readStateFile(t, dir), &doc); err != nil {
		t.Fatalf("state.json written by the product is not JSON: %v", err)
	}
	if len(doc.Machines) != 1 {
		t.Fatalf("expected 1 machine in the written state, got %d", len(doc.Machines))
	}
	m := doc.Machines[0]

	if got := jsonString(t, m, "hostKeyStatus"); got != state.HostKeyStatusUnverified {
		t.Fatalf("a machine written without a host key comparison carries hostKeyStatus %q, want %q", got, state.HostKeyStatusUnverified)
	}
	if got := jsonString(t, m, "osUserStatus"); got != state.OSUserStatusPending {
		t.Fatalf("a machine written without an OS user probe carries osUserStatus %q, want %q", got, state.OSUserStatusPending)
	}
	if _, present := m["requestedOsUser"]; !present {
		t.Fatalf("requestedOsUser is a required §4.3 field and must be written even when nothing was requested yet")
	}
	// The two optional fields are different: absent is not the zero value, and
	// "never observed" must stay distinguishable from "observed as <key>".
	if _, present := m["observedSSHDHostKey"]; present {
		t.Fatalf("observedSSHDHostKey was written for a machine whose host key was never observed")
	}
	if _, present := m["verifiedOsUser"]; present {
		t.Fatalf("verifiedOsUser was written for a machine whose OS user was never proved")
	}
}

// TestIamt91_RecordedSuspicionSurvivesAReload proves the defaults do not
// overwrite what is known: the memory of a mismatch is the whole point of the
// task, and a load that filled in "unverified" over it would delete the
// evidence.
func TestIamt91_RecordedSuspicionSurvivesAReload(t *testing.T) {
	pinned := edPub(9)
	foreign := edPub(10)
	st := baseState(t)
	st.Machines[0].SSHDHostKey = &pinned
	st.Machines[0].ObservedSSHDHostKey = &foreign
	st.Machines[0].HostKeyStatus = state.HostKeyStatusMismatch
	st.Machines[0].RequestedOSUser = `CORP\svc`
	st.Machines[0].OSUserStatus = state.OSUserStatusRejected

	dir := t.TempDir()
	writeStateThroughProduct(t, dir, st)

	s, err := state.Open(dir)
	if err != nil {
		t.Fatalf("reopening a state that records a mismatch: %v", err)
	}
	defer s.Close()
	reloaded := s.Get()
	m, ok := reloaded.MachineByID("vm1")
	if !ok {
		t.Fatalf("machine vm1 is missing after a reload")
	}
	if m.HostKeyStatus != state.HostKeyStatusMismatch {
		t.Fatalf("a recorded host key mismatch was overwritten on load: got %q, want %q", m.HostKeyStatus, state.HostKeyStatusMismatch)
	}
	if m.ObservedSSHDHostKey == nil || *m.ObservedSSHDHostKey != foreign {
		t.Fatalf("the foreign host key the machine was seen presenting did not survive the reload")
	}
	if m.OSUserStatus != state.OSUserStatusRejected || m.RequestedOSUser != `CORP\svc` {
		t.Fatalf("recorded OS user facts were overwritten on load: status=%q requested=%q", m.OSUserStatus, m.RequestedOSUser)
	}
}

// TestIamt91_CloneCopiesTheObservedFacts covers the copy the store hands out:
// Get() returns a Clone, and a caller holding one must not be able to rewrite
// what the store remembers.
func TestIamt91_CloneCopiesTheObservedFacts(t *testing.T) {
	pinned := edPub(9)
	observed := edPub(9)
	verified := `CORP\svc`
	st := baseState(t)
	st.Machines[0].SSHDHostKey = &pinned
	st.Machines[0].ObservedSSHDHostKey = &observed
	st.Machines[0].HostKeyStatus = state.HostKeyStatusMismatch
	st.Machines[0].RequestedOSUser = `CORP\svc`
	st.Machines[0].VerifiedOSUser = &verified
	st.Machines[0].OSUserStatus = state.OSUserStatusVerified

	cp := st.Clone()
	if cp.Machines[0].HostKeyStatus != state.HostKeyStatusMismatch ||
		cp.Machines[0].OSUserStatus != state.OSUserStatusVerified ||
		cp.Machines[0].RequestedOSUser != `CORP\svc` {
		t.Fatalf("Clone dropped a §4.3 machine field: %+v", cp.Machines[0])
	}
	if cp.Machines[0].ObservedSSHDHostKey == nil || *cp.Machines[0].ObservedSSHDHostKey != observed {
		t.Fatalf("Clone dropped observedSSHDHostKey")
	}
	if cp.Machines[0].VerifiedOSUser == nil || *cp.Machines[0].VerifiedOSUser != verified {
		t.Fatalf("Clone dropped verifiedOsUser")
	}
	if cp.Machines[0].ObservedSSHDHostKey == st.Machines[0].ObservedSSHDHostKey ||
		cp.Machines[0].VerifiedOSUser == st.Machines[0].VerifiedOSUser {
		t.Fatalf("Clone shares the pointed-to strings with the original: the caller gets a handle on the store's memory")
	}

	// And the copy is deep: writing through the original's pointers must not
	// reach the clone.
	//
	// The expectation is taken from the CLONE's own value, not from the locals
	// (observed, verified): those two variables are exactly what the original's
	// pointers point at, so writing through the original overwrites them and a
	// comparison against them would fail no matter how correct Clone is. (It
	// did: IAMT-91 round 3.)
	cloneObserved := *cp.Machines[0].ObservedSSHDHostKey
	cloneVerified := *cp.Machines[0].VerifiedOSUser

	*st.Machines[0].ObservedSSHDHostKey = edPub(11)
	*st.Machines[0].VerifiedOSUser = `OTHER\user`

	if got := *cp.Machines[0].ObservedSSHDHostKey; got != cloneObserved {
		t.Fatalf("mutating the original through its pointer changed the clone's observedSSHDHostKey: got %q, want %q", got, cloneObserved)
	}
	if got := *cp.Machines[0].VerifiedOSUser; got != cloneVerified {
		t.Fatalf("mutating the original through its pointer changed the clone's verifiedOsUser: got %q, want %q", got, cloneVerified)
	}
	if *st.Machines[0].ObservedSSHDHostKey == cloneObserved || *st.Machines[0].VerifiedOSUser == cloneVerified {
		t.Fatalf("the original was not actually mutated, so this test proved nothing about the depth of the copy")
	}
}

// TestIamt91_TheFieldListIsTheTagList holds the test's own list of §4.3 field
// names against the JSON tags of state.Machine. The failure it prevents is the
// silent one: a name in the list that no longer matches its tag stops matching
// lines in state.json, so the fixture builder counts four fields instead of
// five (or three, or none) and the test keeps passing its way to the wrong
// conclusion. Same rule as IAMT-116: a list written inside a test must be held
// against the source, not against itself.
func TestIamt91_TheFieldListIsTheTagList(t *testing.T) {
	tags := map[string]bool{}
	rt := reflect.TypeOf(state.Machine{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]
		if name != "" && name != "-" {
			tags[name] = true
		}
	}
	for _, f := range spec43Fields {
		if !tags[f] {
			t.Fatalf("the test looks for the JSON field %q, which state.Machine does not have: the struct's tags are %v", f, tagList(rt))
		}
	}
}

// tagList renders the JSON tags of a struct, sorted, for failure messages.
func tagList(rt reflect.Type) []string {
	var out []string
	for i := 0; i < rt.NumField(); i++ {
		if name := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]; name != "" && name != "-" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// TestIamt91_ValueOutsideTheClosedSetIsRefused covers the other direction: a
// status that is not a member of its set must be refused loudly, because the
// door rule and the login rule compare these fields against literals, and a
// typo would disable one of them without a word.
func TestIamt91_ValueOutsideTheClosedSetIsRefused(t *testing.T) {
	cases := []struct {
		field string
		good  string
		bad   string
	}{
		{"hostKeyStatus", state.HostKeyStatusUnverified, "mismatchh"},
		{"osUserStatus", state.OSUserStatusPending, "pendng"},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			good := []byte(`"` + tc.field + `": "` + tc.good + `"`)
			bad := []byte(`"` + tc.field + `": "` + tc.bad + `"`)

			dir := t.TempDir()
			writeStateThroughProduct(t, dir, baseState(t))
			raw := readStateFile(t, dir)
			if !bytes.Contains(raw, good) {
				t.Fatalf("the product did not write %s into state.json, so this test cannot plant the typo", tc.field)
			}
			planted := bytes.Replace(raw, good, bad, 1)

			badDir := writeRawState(t, planted)
			s, err := state.Open(badDir)
			if err == nil {
				s.Close()
				t.Fatalf("a state.json carrying %s %q was accepted: %q is not in the §4.3 closed set, and a reader comparing the field against a literal would silently stop guarding", tc.field, tc.bad, tc.bad)
			}
			defer s.Close()
			var corrupt *state.CorruptStateError
			if !errors.As(err, &corrupt) {
				t.Fatalf("expected *state.CorruptStateError for %s %q, got %T: %v", tc.field, tc.bad, err, err)
			}
			if !s.IsReadOnly() {
				t.Fatalf("a state.json with an out-of-set %s opened as writable", tc.field)
			}
			if after := readStateFile(t, badDir); !bytes.Equal(after, planted) {
				t.Fatalf("the refused state.json was rewritten on disk")
			}
		})
	}
}

// jsonString reads a string field out of a decoded JSON object, failing the test
// if it is absent or not a string.
func jsonString(t *testing.T, obj map[string]json.RawMessage, key string) string {
	t.Helper()
	raw, ok := obj[key]
	if !ok {
		t.Fatalf("state.json does not carry %q", key)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("state.json field %q is not a string: %v", key, err)
	}
	return s
}
