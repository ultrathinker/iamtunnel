package acl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---- test fixtures -------------------------------------------------

// base is the fixed "gateway clock" every test starts from. All times in
// this file are injected; none is read from the wall clock.
var base = time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

type fakeMachine struct {
	verified bool
	online   bool
}

type fakeView struct {
	persons  map[string]bool
	machines map[string]fakeMachine
}

func (v *fakeView) PersonExists(p string) bool    { return v.persons[p] }
func (v *fakeView) MachineExists(m string) bool   { _, ok := v.machines[m]; return ok }
func (v *fakeView) MachineVerified(m string) bool { return v.machines[m].verified }
func (v *fakeView) MachineOnline(m string) bool   { return v.machines[m].online }

// stdView: alice and bob exist; win01 and win02 are verified and online.
func stdView() *fakeView {
	return &fakeView{
		persons: map[string]bool{"alice": true, "bob": true},
		machines: map[string]fakeMachine{
			"win01": {verified: true, online: true},
			"win02": {verified: true, online: true},
		},
	}
}

// newTest returns an engine over stdView with no session limits.
func newTest(t *testing.T) *Engine {
	t.Helper()
	e, err := NewEngine(stdView(), Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func timePtr(t time.Time) *time.Time { return &t }

// grantStd adds the default grant alice -> win01 until base+1h.
func grantStd(t *testing.T, e *Engine) {
	t.Helper()
	g := Grant{Person: "alice", Machine: "win01", Until: timePtr(base.Add(time.Hour)), Caps: []string{"shell"}}
	if err := e.AddGrant(g, base); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
}

// mustOpen opens a session and fails the test on any denial.
func mustOpen(t *testing.T, e *Engine, person, machine string, now time.Time, onRevoke func(DenyReason)) *Session {
	t.Helper()
	s, err := e.OpenSession(person, machine, now, onRevoke)
	if err != nil {
		t.Fatalf("OpenSession(%s, %s): %v", person, machine, err)
	}
	return s
}

// expectDeny asserts that Check refuses with exactly the wanted reason.
func expectDeny(t *testing.T, e *Engine, person, machine string, now time.Time, want DenyReason) {
	t.Helper()
	d := e.Check(person, machine, now)
	if d.Allowed {
		t.Fatalf("Check(%s, %s): allowed, want denial %v", person, machine, want)
	}
	if d.Reason != want {
		t.Fatalf("Check(%s, %s): denial reason = %v (%q), want %v (%q)",
			person, machine, d.Reason, d.Reason, want, want.String())
	}
}

// ---- the nine denial reasons, one test each ------------------------

func TestDenyUnknownPerson(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)
	expectDeny(t, e, "carol", "win01", base, DenyUnknownPerson)
}

func TestDenyUnknownMachine(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)
	expectDeny(t, e, "alice", "win99", base, DenyUnknownMachine)
}

func TestDenyNoGrant(t *testing.T) {
	e := newTest(t)
	// bob exists, win01 exists, but bob has no grant on it.
	expectDeny(t, e, "bob", "win01", base, DenyNoGrant)
}

// TestMachineOnlineIsMemoryFact pins the contract that "online" is an
// in-memory fact: the view object is mutated in place - no file, no
// persistence, nothing written anywhere - and the very next decision
// flips from allowed to "machine is offline". It also shows the view is
// re-read on every decision, not snapshotted when the engine is built.
func TestMachineOnlineIsMemoryFact(t *testing.T) {
	v := stdView()
	e, err := NewEngine(v, Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	grantStd(t, e)

	d := e.Check("alice", "win01", base)
	if !d.Allowed {
		t.Fatalf("check with tunnel up: %+v, want allowed", d)
	}

	// The tunnel dies: an in-memory mutation of the live view, nothing
	// touches any storage.
	v.machines["win01"] = fakeMachine{verified: true, online: false}

	expectDeny(t, e, "alice", "win01", base, DenyMachineOffline)

	// It comes back: same memory, same immediacy.
	v.machines["win01"] = fakeMachine{verified: true, online: true}
	if d := e.Check("alice", "win01", base); !d.Allowed {
		t.Fatalf("check after reconnect: %+v, want allowed", d)
	}
}

// TestGrantScopedToPerson: a grant belongs to its person and machine
// pair. alice holds the only grant on win01; bob, a valid person,
// must be refused with "no grant", not let through because the machine
// has a grant from someone.
func TestGrantScopedToPerson(t *testing.T) {
	e := newTest(t)
	grantStd(t, e) // alice -> win01 only
	expectDeny(t, e, "bob", "win01", base, DenyNoGrant)
}

// TestGrantScopedToMachine: the mirror direction - alice's grant on
// win01 says nothing about win02, even though win02 exists, is verified
// and online.
func TestGrantScopedToMachine(t *testing.T) {
	e := newTest(t)
	grantStd(t, e) // alice -> win01
	expectDeny(t, e, "alice", "win02", base, DenyNoGrant)
}

func TestDenyGrantRevoked(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)
	if _, err := e.Revoke("alice", "win01", base.Add(10*time.Minute)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	expectDeny(t, e, "alice", "win01", base.Add(11*time.Minute), DenyGrantRevoked)
}

func TestDenyGrantExpired(t *testing.T) {
	e := newTest(t)
	grantStd(t, e) // until base+1h
	expectDeny(t, e, "alice", "win01", base.Add(time.Hour), DenyGrantExpired)
}

func TestDenyMachineUnverified(t *testing.T) {
	v := stdView()
	v.machines["win01"] = fakeMachine{verified: false, online: true}
	e, err := NewEngine(v, Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	grantStd(t, e)
	expectDeny(t, e, "alice", "win01", base, DenyMachineUnverified)
}

func TestDenyMachineOffline(t *testing.T) {
	v := stdView()
	v.machines["win01"] = fakeMachine{verified: true, online: false}
	e, err := NewEngine(v, Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	grantStd(t, e)
	expectDeny(t, e, "alice", "win01", base, DenyMachineOffline)
}

func TestDenyPersonSessionLimit(t *testing.T) {
	e, err := NewEngine(stdView(), Limits{PerPerson: 2})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	grantStd(t, e)
	mustOpen(t, e, "alice", "win01", base, nil)
	mustOpen(t, e, "alice", "win01", base, nil)
	expectDeny(t, e, "alice", "win01", base, DenyPersonSessionLimit)
}

func TestDenyMachineSessionLimit(t *testing.T) {
	e, err := NewEngine(stdView(), Limits{PerMachine: 1})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	g := Grant{Person: "alice", Machine: "win01", Until: timePtr(base.Add(time.Hour)), Caps: []string{"shell"}}
	if err := e.AddGrant(g, base); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	g2 := Grant{Person: "bob", Machine: "win01", Until: timePtr(base.Add(time.Hour)), Caps: []string{"shell"}}
	if err := e.AddGrant(g2, base); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	mustOpen(t, e, "alice", "win01", base, nil)
	// alice is at the machine's cap; bob, a different person, hits the
	// machine limit - which proves the reason is the machine's, not
	// the person's.
	expectDeny(t, e, "bob", "win01", base, DenyMachineSessionLimit)
}

// ---- deadline boundary (gate 3) -------------------------------------

func TestExpiryBoundary(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)
	deadline := base.Add(time.Hour)

	for _, tc := range []struct {
		name string
		now  time.Time
		want bool
	}{
		{"second before", deadline.Add(-time.Second), true},
		{"exact instant", deadline, false},
		{"second after", deadline.Add(time.Second), false},
	} {
		d := e.Check("alice", "win01", tc.now)
		if d.Allowed != tc.want {
			t.Errorf("%s (now=%v): allowed = %v, want %v (reason %v)",
				tc.name, tc.now, d.Allowed, tc.want, d.Reason)
		}
		if !tc.want && d.Reason != DenyGrantExpired {
			t.Errorf("%s: reason = %v, want DenyGrantExpired", tc.name, d.Reason)
		}
	}
}

// ---- grant validation happens at write time -------------------------

func TestAddGrantRejectsPastDeadline(t *testing.T) {
	e := newTest(t)
	g := Grant{Person: "alice", Machine: "win01", Until: timePtr(base.Add(-time.Second))}
	if err := e.AddGrant(g, base); err == nil {
		t.Fatal("AddGrant with a deadline in the past: no error")
	}
}

func TestAddGrantRejectsDeadlineBeforeIssue(t *testing.T) {
	e := newTest(t)
	g := Grant{Person: "alice", Machine: "win01", Until: timePtr(base.Add(5 * time.Minute))}
	if err := e.AddGrant(g, base.Add(10*time.Minute)); err == nil {
		t.Fatal("AddGrant with a deadline before the issue time: no error")
	}
}

func TestAddGrantRejectsDeadlineWithoutZone(t *testing.T) {
	e := newTest(t)
	// A deadline parsed into time.Local lost its zone; the gateway runs
	// UTC, so the grant is refused at entry, not at check time.
	g := Grant{Person: "alice", Machine: "win01", Until: timePtr(time.Date(2026, 9, 12, 15, 0, 0, 0, time.Local))}
	if err := e.AddGrant(g, base); err == nil {
		t.Fatal("AddGrant with a zoneless (Local) deadline: no error")
	}
}

func TestAddGrantRejectsZeroDeadline(t *testing.T) {
	e := newTest(t)
	g := Grant{Person: "alice", Machine: "win01", Until: timePtr(time.Time{}), Caps: []string{"shell"}}
	if err := e.AddGrant(g, base); err == nil {
		t.Fatal("AddGrant with a zero deadline: no error")
	}
}

func TestAddGrantRejectsEmptyNames(t *testing.T) {
	e := newTest(t)
	if err := e.AddGrant(Grant{Machine: "win01", Until: timePtr(base.Add(time.Hour))}, base); err == nil {
		t.Fatal("AddGrant without a person: no error")
	}
	if err := e.AddGrant(Grant{Person: "alice", Until: timePtr(base.Add(time.Hour))}, base); err == nil {
		t.Fatal("AddGrant without a machine: no error")
	}
}

func TestNewEngineRejectsNegativeLimits(t *testing.T) {
	if _, err := NewEngine(stdView(), Limits{PerPerson: -1}); err == nil {
		t.Fatal("NewEngine with a negative person limit: no error")
	}
	if _, err := NewEngine(stdView(), Limits{PerMachine: -1}); err == nil {
		t.Fatal("NewEngine with a negative machine limit: no error")
	}
	if _, err := NewEngine(nil, Limits{}); err == nil {
		t.Fatal("NewEngine without a view: no error")
	}
}

// ---- revocation while a session is live (gate 4) ---------------------

func TestRevokeKillsActiveSession(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)

	killed := make(chan DenyReason, 1)
	s := mustOpen(t, e, "alice", "win01", base, func(r DenyReason) { killed <- r })

	n, err := e.Revoke("alice", "win01", base.Add(10*time.Minute))
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if n != 1 {
		t.Fatalf("Revoke killed %d sessions, want 1", n)
	}
	// The notification is delivered in its own goroutine; wait for it
	// deterministically.
	select {
	case r := <-killed:
		if r != DenyGrantRevoked {
			t.Fatalf("owner notified with %v, want DenyGrantRevoked", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owner was not notified in 2s")
	}

	// Counters converge to zero on the revocation path.
	pp, pm := e.SessionCounts()
	if len(pp) != 0 || len(pm) != 0 {
		t.Fatalf("after revoke: perPerson=%v perMachine=%v, want empty", pp, pm)
	}
	// The dead session must not be closeable a second time: the third
	// way out (normal Close) converges on the same zero.
	if e.Close(s.ID, base.Add(11*time.Minute)) {
		t.Fatal("Close after revoke reported true, want false")
	}
	// And the person is refused with the revocation reason.
	expectDeny(t, e, "alice", "win01", base.Add(11*time.Minute), DenyGrantRevoked)
}

func TestRevokeNonexistentGrant(t *testing.T) {
	e := newTest(t)
	if _, err := e.Revoke("alice", "win01", base); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("Revoke of a missing grant: err = %v, want ErrNoGrant", err)
	}
}

func TestReGrantAfterRevocation(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)
	if _, err := e.Revoke("alice", "win01", base.Add(10*time.Minute)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// The admin grants access again (SPEC 3.3): the pair works anew.
	fresh := Grant{Person: "alice", Machine: "win01", Until: timePtr(base.Add(2 * time.Hour)), Caps: []string{"shell"}}
	if err := e.AddGrant(fresh, base.Add(20*time.Minute)); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	mustOpen(t, e, "alice", "win01", base.Add(21*time.Minute), nil)
}

// TestAddGrantRejectsWrongCaps: in 1.0 the capability set is exactly one of
// ["shell"] or ["exec"] (SPEC 4.3), and acl enforces it at write time, the same
// contract the state package enforces.
func TestAddGrantRejectsWrongCaps(t *testing.T) {
	e := newTest(t)
	cases := [][]string{
		nil,               // no caps at all
		{},                // empty set
		{"shell", "exec"}, // more than one capability
		{"shell", "sftp"}, // extra capability
		{"sftp", "shell"}, // right capability, wrong order/extras
	}
	for i, caps := range cases {
		g := Grant{Person: "alice", Machine: "win01", Until: timePtr(base.Add(time.Hour)), Caps: caps}
		if err := e.AddGrant(g, base); err == nil {
			t.Errorf("case %d (caps %v): accepted, want rejection", i, caps)
		}
	}
	// Both legal sets go through.
	for _, caps := range [][]string{{"shell"}, {"exec"}} {
		g := Grant{Person: "alice", Machine: "win01", Until: timePtr(base.Add(time.Hour)), Caps: caps}
		if err := e.AddGrant(g, base); err != nil {
			t.Fatalf("caps %v rejected: %v", caps, err)
		}
	}
}

// ---- expiry sweep of live sessions -----------------------------------

func TestSweepExpiredKillsSessionWithReason(t *testing.T) {
	e := newTest(t)
	grantStd(t, e) // until base+1h

	killed := make(chan DenyReason, 1)
	mustOpen(t, e, "alice", "win01", base, func(r DenyReason) { killed <- r })

	if n := e.SweepExpired(base.Add(30 * time.Minute)); n != 0 {
		t.Fatalf("SweepExpired before the deadline killed %d, want 0", n)
	}
	if n := e.SweepExpired(base.Add(time.Hour)); n != 1 {
		t.Fatalf("SweepExpired at the deadline killed %d, want 1", n)
	}
	select {
	case r := <-killed:
		if r != DenyGrantExpired {
			t.Fatalf("owner notified with %v, want DenyGrantExpired", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owner was not notified in 2s")
	}
	pp, pm := e.SessionCounts()
	if len(pp) != 0 || len(pm) != 0 {
		t.Fatalf("after sweep: perPerson=%v perMachine=%v, want empty", pp, pm)
	}
}

// TestSweepExpiredClosesOnlyDueSessions proves that expiry is selected per
// grant, not per machine or per sweep batch: later grants remain live until
// their own deadline arrives.
func TestSweepExpiredClosesOnlyDueSessions(t *testing.T) {
	e := newTest(t)
	grants := []Grant{
		{Person: "alice", Machine: "win01", Until: timePtr(base.Add(time.Minute)), Caps: []string{"shell"}},
		{Person: "bob", Machine: "win01", Until: timePtr(base.Add(2 * time.Minute)), Caps: []string{"shell"}},
		{Person: "alice", Machine: "win02", Until: timePtr(base.Add(3 * time.Minute)), Caps: []string{"shell"}},
	}
	for _, grant := range grants {
		if err := e.AddGrant(grant, base); err != nil {
			t.Fatalf("AddGrant(%s,%s): %v", grant.Person, grant.Machine, err)
		}
	}
	first := mustOpen(t, e, "alice", "win01", base, nil)
	second := mustOpen(t, e, "bob", "win01", base, nil)
	third := mustOpen(t, e, "alice", "win02", base, nil)

	if n := e.SweepExpired(base.Add(time.Minute)); n != 1 {
		t.Fatalf("first sweep killed %d sessions, want exactly 1", n)
	}
	live := make(map[SessionID]bool)
	for _, session := range e.Sessions() {
		live[session.ID] = true
	}
	if live[first.ID] || !live[second.ID] || !live[third.ID] {
		t.Fatalf("after first deadline live sessions=%v; first=%v second=%v third=%v", live, first.ID, second.ID, third.ID)
	}
	if n := e.SweepExpired(base.Add(2 * time.Minute)); n != 1 {
		t.Fatalf("second sweep killed %d sessions, want exactly 1", n)
	}
	if n := e.SweepExpired(base.Add(3 * time.Minute)); n != 1 {
		t.Fatalf("third sweep killed %d sessions, want exactly 1", n)
	}
	if live := e.Sessions(); len(live) != 0 {
		t.Fatalf("sessions after all deadlines = %v, want none", live)
	}
}

// ---- session accounting: the three ways out converge -----------------

func TestOpenCloseOpenCounters(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)

	s1 := mustOpen(t, e, "alice", "win01", base, nil)
	pp, pm := e.SessionCounts()
	if pp["alice"] != 1 || pm["win01"] != 1 {
		t.Fatalf("after open: perPerson=%v perMachine=%v", pp, pm)
	}
	if !e.Close(s1.ID, base.Add(time.Minute)) {
		t.Fatal("first Close reported false")
	}
	pp, pm = e.SessionCounts()
	if len(pp) != 0 || len(pm) != 0 {
		t.Fatalf("after close: perPerson=%v perMachine=%v, want empty", pp, pm)
	}

	// Open again after a normal close: the grant is untouched.
	mustOpen(t, e, "alice", "win01", base.Add(2*time.Minute), nil)
	pp, _ = e.SessionCounts()
	if pp["alice"] != 1 {
		t.Fatalf("second open: perPerson=%v, want alice=1", pp)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)
	s := mustOpen(t, e, "alice", "win01", base, nil)
	if !e.Close(s.ID, base) {
		t.Fatal("first Close: false")
	}
	for i := 2; i <= 5; i++ {
		if e.Close(s.ID, base) {
			t.Fatalf("Close #%d: true, want false", i)
		}
	}
	pp, pm := e.SessionCounts()
	if len(pp) != 0 || len(pm) != 0 {
		t.Fatalf("counters after repeated closes: %v %v", pp, pm)
	}
}

// TestNotificationsDoNotBlockCaller: the sweep timer runs once a
// second, so a slow subscriber must never stall the caller. The
// callback here blocks until we let it go; Revoke still returns.
func TestNotificationsDoNotBlockCaller(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)

	release := make(chan struct{})
	blocked := make(chan struct{})
	s := mustOpen(t, e, "alice", "win01", base, func(DenyReason) {
		close(blocked)
		<-release
	})

	done := make(chan struct{})
	go func() {
		_, err := e.Revoke("alice", "win01", base.Add(time.Minute))
		if err != nil {
			t.Errorf("Revoke: %v", err)
		}
		close(done)
	}()

	// The subscriber must have been started (not merely queued behind a
	// lock)...
	select {
	case <-blocked:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("callback did not start in 2s")
	}
	// ...and the caller must return while the callback is still parked.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("Revoke blocked on a slow subscriber")
	}
	close(release)
	_ = s
}

// TestSessionIDJournalMarshalling: in the event journal a zero session
// id must not masquerade as session number zero - it marshals to null,
// while issued ids marshal to their number.
func TestSessionIDJournalMarshalling(t *testing.T) {
	zeroJSON, err := json.Marshal(map[string]SessionID{"session": {}})
	if err != nil {
		t.Fatalf("marshal zero id: %v", err)
	}
	if string(zeroJSON) != `{"session":null}` {
		t.Fatalf("zero id marshals as %s, want null", zeroJSON)
	}
	e := newTest(t)
	grantStd(t, e)
	s := mustOpen(t, e, "alice", "win01", base, nil)
	if !s.ID.Valid() {
		t.Fatal("issued id is invalid/zero")
	}
	if s.ID.Uint64() == 0 {
		t.Fatal("issued id is numerically zero")
	}
	if s.ID.String() == (SessionID{}).String() {
		t.Fatal("issued id stringifies like the zero one")
	}
	validJSON, err := json.Marshal(map[string]SessionID{"session": s.ID})
	if err != nil {
		t.Fatalf("marshal valid id: %v", err)
	}
	if string(validJSON) != fmt.Sprintf(`{"session":%d}`, s.ID.Uint64()) {
		t.Fatalf("valid id marshals as %s, want its number", validJSON)
	}
	// And the zero id never closes anything.
	if e.Close(SessionID{}, base.Add(time.Minute)) {
		t.Fatal("zero id closed a session")
	}
}

func TestReasonsAreSingleLineAndDistinct(t *testing.T) {
	seen := make(map[string]bool)
	for r := ReasonNone; r <= DenyAdminKilled; r++ {
		s := r.String()
		if s == "" && r != ReasonNone {
			t.Errorf("%d: empty text", r)
		}
		if strings.ContainsAny(s, "\n\r") {
			t.Errorf("%d: text %q is not a single line", r, s)
		}
		if seen[s] {
			t.Errorf("text %q is used twice", s)
		}
		seen[s] = true
	}
}

// TestEngineKill covers the administrator session kill path (SPEC §3.3, PROTOCOL §6).
// It specifically tests that Engine.Kill terminates the live session, notifies
// the owner callback with DenyAdminKilled, cleans up session counters, and prevents
// subsequent closes or duplicate kills.
func TestEngineKill(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)
	killed := make(chan DenyReason, 1)
	s := mustOpen(t, e, "alice", "win01", base, func(r DenyReason) { killed <- r })

	if !e.Kill(s.ID, base.Add(10*time.Minute), DenyAdminKilled) {
		t.Fatalf("Kill(%s) returned false, want true", s.ID)
	}
	select {
	case r := <-killed:
		if r != DenyAdminKilled {
			t.Fatalf("owner notified with %v, want DenyAdminKilled", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owner was not notified in 2s")
	}

	pp, pm := e.SessionCounts()
	if len(pp) != 0 || len(pm) != 0 {
		t.Fatalf("after Kill: perPerson=%v perMachine=%v, want empty", pp, pm)
	}

	if e.Close(s.ID, base.Add(11*time.Minute)) {
		t.Fatal("Close after Kill reported true, want false")
	}

	if e.Kill(s.ID, base.Add(12*time.Minute), DenyAdminKilled) {
		t.Fatal("duplicate Kill reported true, want false")
	}
	if e.Kill(SessionID{}, base.Add(12*time.Minute), DenyAdminKilled) {
		t.Fatal("Kill with zero SessionID reported true, want false")
	}
}

// TestParseSessionID covers parsing and canonical format validation of session IDs.
func TestParseSessionID(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  uint64
	}{
		{"session:1", 1},
		{"session:42", 42},
		{"session:18446744073709551615", 18446744073709551615},
	} {
		id, err := ParseSessionID(tc.input)
		if err != nil {
			t.Fatalf("ParseSessionID(%q) error = %v, want nil", tc.input, err)
		}
		if id.Uint64() != tc.want {
			t.Fatalf("ParseSessionID(%q) = %d, want %d", tc.input, id.Uint64(), tc.want)
		}
		if id.String() != tc.input {
			t.Fatalf("id.String() = %q, want %q", id.String(), tc.input)
		}
	}

	for _, input := range []string{
		"",
		"1",
		"session:",
		"session:0",
		"session:00",
		"session:01",
		"session:007",
		"session:-1",
		"session:+1",
		"session:abc",
		"session: 1",
		"session:1 ",
		"session:18446744073709551616",
		"session:<invalid>",
		"other:1",
	} {
		if id, err := ParseSessionID(input); err == nil {
			t.Fatalf("ParseSessionID(%q) accepted invalid input; got %v", input, id)
		}
	}
}

// TestDenyErrorFormat tests that DenyError formats as "acl: <reason text>".
func TestDenyErrorFormat(t *testing.T) {
	err := &DenyError{Reason: DenyGrantRevoked}
	want := "acl: access revoked by administrator"
	if got := err.Error(); got != want {
		t.Fatalf("DenyError.Error() = %q, want %q", got, want)
	}
}

// TestDenyReasonOutOfBounds tests fallback for unknown/out-of-bounds DenyReason values.
func TestDenyReasonOutOfBounds(t *testing.T) {
	if got := DenyReason(-1).String(); got != "unknown reason" {
		t.Fatalf("DenyReason(-1).String() = %q, want \"unknown reason\"", got)
	}
	if got := DenyReason(999).String(); got != "unknown reason" {
		t.Fatalf("DenyReason(999).String() = %q, want \"unknown reason\"", got)
	}
}

// TestZeroSessionIDBehavior tests behavior of an uninitialized / zero SessionID value.
func TestZeroSessionIDBehavior(t *testing.T) {
	var zero SessionID
	if zero.Valid() {
		t.Fatalf("zero SessionID.Valid() = true, want false")
	}
	if got := zero.Uint64(); got != 0 {
		t.Fatalf("zero SessionID.Uint64() = %d, want 0", got)
	}
	if got := zero.String(); got != "session:<invalid>" {
		t.Fatalf("zero SessionID.String() = %q, want \"session:<invalid>\"", got)
	}
}

// TestEngineSessionsSnapshotIntegrity tests that Sessions() preserves all fields
// of active sessions in its snapshot.
func TestEngineSessionsSnapshotIntegrity(t *testing.T) {
	e := newTest(t)
	grantStd(t, e)
	t0 := base.Add(5 * time.Minute)
	s := mustOpen(t, e, "alice", "win01", t0, nil)

	sessions := e.Sessions()
	if len(sessions) != 1 {
		t.Fatalf("Sessions() len = %d, want 1", len(sessions))
	}
	snap := sessions[0]
	if snap.ID != s.ID || snap.Person != "alice" || snap.Machine != "win01" || !snap.OpenedAt.Equal(t0) {
		t.Fatalf("Sessions() snapshot mismatch: got %+v, want ID=%v Person=alice Machine=win01 OpenedAt=%v", snap, s.ID, t0)
	}
}

// TestIndefiniteGrant_FullLifecycle tests that an indefinite grant (Until == nil):
// 1. Is accepted by AddGrant.
// 2. Allows Check and OpenSession.
// 3. Is NOT swept as expired by SweepExpired even far into the future.
// 4. Immediately cuts access and kills live sessions upon Revoke.
// 5. Consistently denies subsequent Check and OpenSession after Revoke.
func TestIndefiniteGrant_FullLifecycle(t *testing.T) {
	e := newTest(t)
	// Grant with Until == nil (no deadline):
	g := Grant{Person: "alice", Machine: "win01", Caps: []string{"shell"}}
	if err := e.AddGrant(g, base); err != nil {
		t.Fatalf("AddGrant indefinite grant: %v", err)
	}

	d := e.Check("alice", "win01", base)
	if !d.Allowed {
		t.Fatalf("Check on indefinite grant: allowed = false, reason = %v", d.Reason)
	}

	killed := make(chan DenyReason, 1)
	s, err := e.OpenSession("alice", "win01", base, func(r DenyReason) { killed <- r })
	if err != nil {
		t.Fatalf("OpenSession on indefinite grant: %v", err)
	}
	if !s.ID.Valid() {
		t.Fatalf("session id is invalid: %v", s.ID)
	}

	// Periodic sweeper 100 days later: grant must NOT be swept as expired
	future := base.Add(100 * 24 * time.Hour)
	if n := e.SweepExpired(future); n != 0 {
		t.Fatalf("SweepExpired killed %d session(s) on indefinite grant, want 0", n)
	}

	// Revocation immediately kills the session
	tRevoke := base.Add(10 * time.Minute)
	n, err := e.Revoke("alice", "win01", tRevoke)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if n != 1 {
		t.Fatalf("Revoke returned %d killed sessions, want 1", n)
	}

	select {
	case r := <-killed:
		if r != DenyGrantRevoked {
			t.Fatalf("owner callback got %v, want DenyGrantRevoked", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("owner callback was not notified on Revoke")
	}

	// Post-revoke Check and OpenSession are denied
	dPost := e.Check("alice", "win01", tRevoke.Add(time.Minute))
	if dPost.Allowed || dPost.Reason != DenyGrantRevoked {
		t.Fatalf("post-revoke Check: allowed=%v reason=%v, want false and DenyGrantRevoked", dPost.Allowed, dPost.Reason)
	}
	if _, err := e.OpenSession("alice", "win01", tRevoke.Add(time.Minute), nil); err == nil {
		t.Fatal("post-revoke OpenSession succeeded, want error")
	}
}
