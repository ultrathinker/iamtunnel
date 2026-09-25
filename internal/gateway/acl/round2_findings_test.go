package acl

// round2_findings_test.go — second, independent pass over this package
// (round 1's own findings are regression_findings_test.go's R1-R6;
// this file numbers fresh findings F-01, F-02, ... — F-01 lives in
// internal/gateway/enrol_rekey_acl_desync_test.go because it is a
// gateway<->acl integration defect, not reproducible from this package
// alone).

import (
	"testing"
	"time"
)

// hourLater exists because acl.Grant.Until became *time.Time in
// IAMT-123 (a deadline is now optional: absence differs from zero time).
// base is the package-wide test clock declared in acl_test.go.
var hourLater = base.Add(time.Hour)

// onlinePanicView wraps fakeView and makes MachineOnline panic on demand,
// standing in for any future View implementation (internal/gateway's
// stateView today) that panics instead of returning cleanly - a nil map, a
// closed store, a bug in a future refactor. The engine must survive that,
// because View is a caller-supplied interface the acl package does not
// control (acl.go:35-51 doc comment).
type onlinePanicView struct{ *fakeView }

func (v *onlinePanicView) MachineOnline(m string) bool {
	panic("simulated View panic (e.g. a bug in the gateway's stateView)")
}

// TestFinding_F2_ViewPanicLeaksEngineMutexForever proves that OpenSession,
// Close, Revoke, Kill and SweepExpired (acl.go) take e.mu.Lock() and release
// it with a plain e.mu.Unlock() - never a deferred one. Check and AddGrant
// do defer their unlock (acl.go:169-178, 239-246); the other five do not.
//
// checkLocked (acl.go:250-280), invoked from OpenSession while e.mu is
// held, calls straight into the caller-supplied View (PersonExists,
// MachineExists, MachineVerified, MachineOnline). If any of those panics,
// the panic unwinds OpenSession without ever reaching e.mu.Unlock(): the
// mutex stays locked forever. Every subsequent call to Check, OpenSession,
// Revoke, Kill or SweepExpired then blocks forever too - a single panic
// anywhere in the View wedges the entire ACL engine permanently, silently
// (no crash, no log line, just every future access decision hanging), which
// is worse than the panic itself: nobody can grant, revoke or open a
// session ever again without a gateway restart.
func TestFinding_F2_ViewPanicLeaksEngineMutexForever(t *testing.T) {
	t.Skip("FINDING F-02: OpenSession/Close/Revoke/Kill/SweepExpired (acl.go) take e.mu.Lock() and " +
		"release it with a plain e.mu.Unlock(), not a deferred one (unlike Check and AddGrant). A panic inside " +
		"checkLocked, invoked from a caller-supplied View (acl.go: PersonExists/MachineExists/MachineVerified/MachineOnline), " +
		"unwinds the stack past the Unlock - the mutex stays locked forever, and the whole permission engine " +
		"(Check/OpenSession/Revoke/Kill/SweepExpired) hangs silently until the gateway is restarted.")

	v := &onlinePanicView{fakeView: stdView()}
	e, err := NewEngine(v, Limits{})
	if err != nil {
		t.Fatalf("test setup error: NewEngine: %v", err)
	}
	if err := e.AddGrant(Grant{Person: "alice", Machine: "win01", Until: &hourLater, Caps: []string{"shell"}}, base); err != nil {
		t.Fatalf("test setup error: AddGrant: %v", err)
	}

	panicked := make(chan struct{})
	go func() {
		defer func() {
			recover()
			close(panicked)
		}()
		_, _ = e.OpenSession("alice", "win01", base, nil)
	}()
	select {
	case <-panicked:
	case <-time.After(2 * time.Second):
		t.Fatalf("test setup error: the goroutine calling OpenSession never returned/panicked as expected")
	}

	result := make(chan Decision, 1)
	go func() { result <- e.Check("alice", "win01", base) }()

	select {
	case <-result:
		// e.mu was released; no leak.
	case <-time.After(2 * time.Second):
		t.Fatalf("F-02: e.Check(\"alice\", \"win01\", ...) is still blocked 2s after a panic inside View.MachineOnline " +
			"unwound OpenSession without releasing e.mu (acl.go: OpenSession/Close/Revoke/Kill/SweepExpired do not " +
			"defer e.mu.Unlock()) - the engine's mutex leaked locked forever")
	}
}

// TestConfirm_RevokeTouchesOnlyItsOwnPair is a confirmation, not a finding
// (the review question's second half: "does a revoke kill other sessions along the way").
// Revoke's session-collection loop (acl.go:225-229) filters on an exact
// (person, machine) match; this pins that a revoke of one pair leaves a
// different person on the same machine, and the same person on a different
// machine, completely alone - both their sessions and their grants.
func TestConfirm_RevokeTouchesOnlyItsOwnPair(t *testing.T) {
	e := newTest(t) // stdView: alice, bob; win01, win02 both verified+online

	for _, g := range []Grant{
		{Person: "alice", Machine: "win01", Until: &hourLater, Caps: []string{"shell"}},
		{Person: "bob", Machine: "win01", Until: &hourLater, Caps: []string{"shell"}},
		{Person: "alice", Machine: "win02", Until: &hourLater, Caps: []string{"shell"}},
	} {
		if err := e.AddGrant(g, base); err != nil {
			t.Fatalf("test setup error: AddGrant(%+v): %v", g, err)
		}
	}

	target := mustOpen(t, e, "alice", "win01", base, nil)
	bystanderSameMachine := mustOpen(t, e, "bob", "win01", base, nil)
	bystanderSamePerson := mustOpen(t, e, "alice", "win02", base, nil)

	n, err := e.Revoke("alice", "win01", base.Add(time.Minute))
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if n != 1 {
		t.Fatalf("Revoke killed %d sessions, want exactly 1 (alice->win01 only)", n)
	}

	// killLocked's bookkeeping (map delete, counter decrement) runs
	// synchronously inside Revoke before it returns; only the onRevoke
	// notification is deferred to a goroutine (acl.go: runNotes). So the
	// session set is already final here, no wait needed.
	live := map[SessionID]bool{}
	for _, s := range e.Sessions() {
		live[s.ID] = true
	}
	if live[target.ID] {
		t.Fatalf("Revoke(alice, win01): the revoked session %v is still in Sessions()", target.ID)
	}
	if !live[bystanderSameMachine.ID] {
		t.Fatalf("Revoke(alice, win01) also removed bob's session on the same machine (%v)", bystanderSameMachine.ID)
	}
	if !live[bystanderSamePerson.ID] {
		t.Fatalf("Revoke(alice, win01) also removed alice's session on a different machine (%v)", bystanderSamePerson.ID)
	}

	pp, pm := e.SessionCounts()
	if pp["alice"] != 1 {
		t.Fatalf("perPerson[alice] = %d, want 1 (only the win02 session should remain)", pp["alice"])
	}
	if pp["bob"] != 1 {
		t.Fatalf("perPerson[bob] = %d, want 1", pp["bob"])
	}
	if pm["win01"] != 1 {
		t.Fatalf("perMachine[win01] = %d, want 1 (bob's session)", pm["win01"])
	}
	if pm["win02"] != 1 {
		t.Fatalf("perMachine[win02] = %d, want 1 (alice's session)", pm["win02"])
	}

	expectDeny(t, e, "alice", "win01", base.Add(time.Minute), DenyGrantRevoked)
	if d := e.Check("bob", "win01", base.Add(time.Minute)); !d.Allowed {
		t.Fatalf("bob's grant on win01 was collateral damage: %+v", d)
	}
	if d := e.Check("alice", "win02", base.Add(time.Minute)); !d.Allowed {
		t.Fatalf("alice's grant on win02 was collateral damage: %+v", d)
	}
}
