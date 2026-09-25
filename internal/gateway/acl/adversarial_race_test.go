package acl

// adversarial_race_test.go — review-Phase-5 adversarial probes for the
// grant revocation/session accounting path. Lives in package acl so it
// can touch the engine internals (e.g. RevokedAt) directly.

import (
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type advView struct {
	persons  map[string]bool
	machines map[string]bool
	verified map[string]bool
	online   map[string]bool
}

func (v *advView) PersonExists(p string) bool    { return v.persons[p] }
func (v *advView) MachineExists(m string) bool   { return v.machines[m] }
func (v *advView) MachineVerified(m string) bool { return v.verified[m] }
func (v *advView) MachineOnline(m string) bool   { return v.online[m] }

func advStdView() *advView {
	return &advView{
		persons:  map[string]bool{"alice": true},
		machines: map[string]bool{"win01": true},
		verified: map[string]bool{"win01": true},
		online:   map[string]bool{"win01": true},
	}
}

// TestRevokeAfterSessionOpened: Revoke must kill a session that was
// opened before the revoke and is still live at revoke time.
func TestAdvRevokeAfterSessionOpened(t *testing.T) {
	e, err := NewEngine(advStdView(), Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t0 := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	if err := e.AddGrant(Grant{Person: "alice", Machine: "win01", Until: timePtr(t0.Add(time.Hour)), Caps: []string{"shell"}}, t0); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	killed := make(chan DenyReason, 1)
	if _, err := e.OpenSession("alice", "win01", t0, func(r DenyReason) { killed <- r }); err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	n, err := e.Revoke("alice", "win01", t0.Add(time.Second))
	if err != nil || n != 1 {
		t.Fatalf("Revoke n=%d err=%v", n, err)
	}
	select {
	case r := <-killed:
		if r != DenyGrantRevoked {
			t.Fatalf("callback got %v, want DenyGrantRevoked", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("callback never fired")
	}
	pp, pm := e.SessionCounts()
	if len(pp) != 0 || len(pm) != 0 {
		t.Fatalf("counters not zero after revoke: pp=%v pm=%v", pp, pm)
	}
}

// TestAdvRevokedFutureDeadline: a revoke with the grant's deadline
// still in the future must still deny every subsequent OpenSession.
// This pins that the only thing that matters after Revoke is RevokedAt.
func TestAdvRevokedFutureDeadline(t *testing.T) {
	e, err := NewEngine(advStdView(), Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t0 := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	if err := e.AddGrant(Grant{Person: "alice", Machine: "win01", Until: timePtr(t0.Add(time.Hour)), Caps: []string{"shell"}}, t0); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	if _, err := e.Revoke("alice", "win01", t0.Add(time.Minute)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if d := e.Check("alice", "win01", t0.Add(2*time.Minute)); d.Allowed {
		t.Fatal("Check allowed after Revoke with future deadline")
	}
	_, err = e.OpenSession("alice", "win01", t0.Add(2*time.Minute), nil)
	var de *DenyError
	if !errors.As(err, &de) || de.Reason != DenyGrantRevoked {
		t.Fatalf("OpenSession err = %v, want DenyError{DenyGrantRevoked}", err)
	}
}

// TestAdvRevokeSweepConverge: Revoke and SweepExpired both kill
// sessions, but on different conditions. Make sure both paths produce
// the same end state when a session is open at the boundary.
//
// A session is opened while both Revoke and SweepExpired would fire:
//   - revoke kills via killNote (synchronous)
//   - sweep kills via expiry (now >= Until)
//
// We exercise both: first Revoke, then SweepExpired over a separate
// grant that has expired. In both cases the final counter is zero.
func TestAdvRevokeSweepConverge(t *testing.T) {
	e, err := NewEngine(advStdView(), Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t0 := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	if err := e.AddGrant(Grant{Person: "alice", Machine: "win01", Until: timePtr(t0.Add(time.Hour)), Caps: []string{"shell"}}, t0); err != nil {
		t.Fatalf("AddGrant1: %v", err)
	}
	killedRev := make(chan DenyReason, 1)
	if _, err := e.OpenSession("alice", "win01", t0, func(r DenyReason) { killedRev <- r }); err != nil {
		t.Fatalf("open1: %v", err)
	}
	if _, err := e.Revoke("alice", "win01", t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	<-killedRev

	if err := e.AddGrant(Grant{Person: "alice", Machine: "win01", Until: timePtr(t0.Add(5 * time.Minute)), Caps: []string{"shell"}}, t0.Add(3*time.Minute)); err != nil {
		t.Fatalf("AddGrant2: %v", err)
	}
	killedExp := make(chan DenyReason, 1)
	if _, err := e.OpenSession("alice", "win01", t0.Add(4*time.Minute), func(r DenyReason) { killedExp <- r }); err != nil {
		t.Fatalf("open2: %v", err)
	}
	if n := e.SweepExpired(t0.Add(2 * time.Minute)); n != 0 {
		t.Fatalf("SweepExpired before deadline killed %d, want 0", n)
	}
	if n := e.SweepExpired(t0.Add(5 * time.Minute)); n != 1 {
		t.Fatalf("SweepExpired at deadline killed %d, want 1", n)
	}
	select {
	case r := <-killedExp:
		if r != DenyGrantExpired {
			t.Fatalf("sweep notify got %v, want DenyGrantExpired", r)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("sweep notify never fired")
	}
	pp, pm := e.SessionCounts()
	if len(pp) != 0 || len(pm) != 0 {
		t.Fatalf("final counters: pp=%v pm=%v", pp, pm)
	}
}

// TestAdvMassiveOpenRevoke: drive an engine with many concurrent
// openers plus one revoker/re-granter. Verify final counters are zero,
// no leak, and the openers see a mix of ok / denied across the
// race window. Run under -race.
func TestAdvMassiveOpenRevoke(t *testing.T) {
	e, err := NewEngine(advStdView(), Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	t0 := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	deadline := t0.Add(time.Hour)
	if err := e.AddGrant(Grant{Person: "alice", Machine: "win01", Until: &deadline, Caps: []string{"shell"}}, t0); err != nil {
		t.Fatalf("AddGrant: %v", err)
	}
	const nWorkers = 40
	const nIters = 200
	var wg sync.WaitGroup
	var opened, denied uint64
	for i := 0; i < nWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < nIters; j++ {
				s, err := e.OpenSession("alice", "win01", t0, nil)
				if err != nil {
					var de *DenyError
					if !errors.As(err, &de) {
						t.Errorf("unexpected deny: %v", err)
						return
					}
					atomic.AddUint64(&denied, 1)
					continue
				}
				atomic.AddUint64(&opened, 1)
				e.Close(s.ID, t0)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Wait for one successful open before revoking anything. Otherwise the
		// whole revoke/re-add cycle can finish before a single worker gets in,
		// and "opened > 0" is a hope about the scheduler rather than a fact.
		for atomic.LoadUint64(&opened) == 0 {
			runtime.Gosched()
		}
		for j := 0; j < nIters; j++ {
			_, _ = e.Revoke("alice", "win01", t0)
			// While the grant is gone it MUST deny, and only this goroutine ever
			// adds it back - so asserting the denial from here makes it causal.
			// The old test merely hoped some worker would land inside this
			// window; under a plain (non -race) run it often did not, and three
			// of twelve runs were red with denied=0 (IAMT-93). -race hid it by
			// slowing everything down.
			if _, err := e.OpenSession("alice", "win01", t0, nil); err == nil {
				t.Errorf("iteration %d: open succeeded while the grant was revoked", j)
				return
			} else {
				var de *DenyError
				if !errors.As(err, &de) {
					t.Errorf("iteration %d: unexpected error while revoked: %v", j, err)
					return
				}
				atomic.AddUint64(&denied, 1)
			}
			_ = e.AddGrant(Grant{Person: "alice", Machine: "win01", Until: &deadline, Caps: []string{"shell"}}, t0)
		}
	}()
	wg.Wait()
	pp, pm := e.SessionCounts()
	if len(pp) != 0 || len(pm) != 0 {
		t.Fatalf("final counters not zero: pp=%v pm=%v", pp, pm)
	}
	if opened == 0 || denied == 0 {
		t.Fatalf("opened=%d denied=%d (want both > 0)", opened, denied)
	}
}
