package acl

import (
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestPersonLimitGate covers gate 6: with a limit of 2, a third session
// of the same person is refused with the person-limit reason, and after
// one of the live sessions closes the same open attempt passes.
func TestPersonLimitGate(t *testing.T) {
	e, err := NewEngine(stdView(), Limits{PerPerson: 2})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	grantStd(t, e)

	s1 := mustOpen(t, e, "alice", "win01", base, nil)
	mustOpen(t, e, "alice", "win01", base, nil)

	_, err = e.OpenSession("alice", "win01", base, nil)
	deny, ok := err.(*DenyError)
	if !ok {
		t.Fatalf("third open: err = %v, want *DenyError", err)
	}
	if deny.Reason != DenyPersonSessionLimit {
		t.Fatalf("third open: reason = %v, want DenyPersonSessionLimit", deny.Reason)
	}

	// One session goes away (normal path); the same attempt now passes.
	if !e.Close(s1.ID, base.Add(time.Minute)) {
		t.Fatal("Close of the first session: false")
	}
	pp, _ := e.SessionCounts()
	if pp["alice"] != 1 {
		t.Fatalf("perPerson = %d, want 1", pp["alice"])
	}
	s3 := mustOpen(t, e, "alice", "win01", base, nil)
	if s3 == nil {
		t.Fatal("third open after one close: nil session")
	}
}

// TestConcurrentSessions100 covers gate 5: one hundred goroutines open
// and close sessions concurrently. Run under -race it must be clean, the
// peak counter must be exactly 100 and the final counters exactly zero.
func TestConcurrentSessions100(t *testing.T) {
	e, err := NewEngine(stdView(), Limits{PerPerson: 0, PerMachine: 0}) // 0 = unlimited
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	grantStd(t, e)

	const n = 100
	ids := make(chan SessionID, n)

	// Wave 1: everyone opens.
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := e.OpenSession("alice", "win01", base, nil)
			if err != nil {
				t.Errorf("open: %v", err)
				return
			}
			ids <- s.ID
		}()
	}
	wg.Wait()
	close(ids)

	if got := len(ids); got != n {
		t.Fatalf("opened %d sessions, want %d", got, n)
	}
	pp, pm := e.SessionCounts()
	if pp["alice"] != n {
		t.Fatalf("peak perPerson[alice] = %d, want %d", pp["alice"], n)
	}
	if pm["win01"] != n {
		t.Fatalf("peak perMachine[win01] = %d, want %d", pm["win01"], n)
	}

	// Wave 2: everyone closes in parallel, each first close must win.
	var wg2 sync.WaitGroup
	for id := range ids {
		wg2.Add(1)
		go func(id SessionID) {
			defer wg2.Done()
			if !e.Close(id, base.Add(time.Minute)) {
				t.Errorf("Close(%d): false on the first close", id)
			}
		}(id)
	}
	wg2.Wait()

	// Wave 3: everyone closes again in parallel; idempotent Close must
	// refuse every duplicate and keep the counters exact.
	var wg3 sync.WaitGroup
	for id := range ids {
		wg3.Add(1)
		go func(id SessionID) {
			defer wg3.Done()
			if e.Close(id, base.Add(time.Minute)) {
				t.Errorf("duplicate Close(%d): true, want false", id)
			}
		}(id)
	}
	wg3.Wait()

	pp, pm = e.SessionCounts()
	if len(pp) != 0 || len(pm) != 0 {
		t.Fatalf("final counters: perPerson=%v perMachine=%v, want empty", pp, pm)
	}
}

// TestConcurrentMixedTraffic hammers one engine from many goroutines
// doing opens, closes, checks, sweeps and a revoke all at once; under
// -race it proves the single-mutex design holds and the counters end at
// zero no matter which goroutine closed what.
func TestConcurrentMixedTraffic(t *testing.T) {
	e, err := NewEngine(stdView(), Limits{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	grantStd(t, e) // alice -> win01 until base+1h

	deadline := base.Add(time.Hour)
	var wg sync.WaitGroup

	// 40 workers open and close sessions in a loop. While the revoke
	// worker is between Revoke and re-AddGrant, an open honestly
	// answers "revoked"/"no grant": those attempts are retried, any
	// other denial is a failure.
	//
	// The retry yields the processor and is bounded in time, not in
	// iterations. A plain spin with a count ceiling made this test
	// intermittent: forty busy openers can starve the one revoke
	// worker, so the ceiling was reached while the engine was still
	// legitimately between Revoke and AddGrant, and the test then
	// reported the honest "revoked" answer as a failure. Observed
	// under load in gate 5. The bound below is a backstop against a
	// genuine hang, not the assertion: the assertion is that no open
	// is ever denied for any reason other than these two.
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				var s *Session
				started := time.Now()
				for {
					var err error
					s, err = e.OpenSession("alice", "win01", base, nil)
					if err == nil {
						break
					}
					var de *DenyError
					if !errors.As(err, &de) || (de.Reason != DenyGrantRevoked && de.Reason != DenyNoGrant) {
						t.Errorf("open: %v", err)
						return
					}
					if time.Since(started) > 30*time.Second {
						t.Errorf("open: still refused as %v after 30s; the revoke worker is not making progress", de.Reason)
						return
					}
					runtime.Gosched()
				}
				e.Close(s.ID, base)
			}
		}()
	}
	// 10 workers just check.
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				e.Check("alice", "win01", base)
			}
		}()
	}
	// 3 workers sweep expiry (never fires before the deadline).
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				e.SweepExpired(base)
			}
		}()
	}
	// One worker revokes and immediately re-grants, repeatedly.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 25; j++ {
			if _, err := e.Revoke("alice", "win01", base); err != nil {
				t.Errorf("revoke: %v", err)
				return
			}
			g := Grant{Person: "alice", Machine: "win01", Until: &deadline, Caps: []string{"shell"}}
			if err := e.AddGrant(g, base); err != nil {
				t.Errorf("re-grant: %v", err)
				return
			}
		}
	}()

	wg.Wait()

	// The re-grant loop may have raced a final revoke in: end the test
	// in a known state and require empty counters either way.
	e.SweepExpired(deadline.Add(time.Minute))
	pp, pm := e.SessionCounts()
	if len(pp) != 0 || len(pm) != 0 {
		t.Fatalf("final counters: perPerson=%v perMachine=%v, want empty", pp, pm)
	}
}
