package gateway

// iamt161_close_waits_for_probe_test.go is the IAMT-161 canary: a single
// test that catches BOTH regression modes found in
// the round-1 fix:
//
//   (A) removing the g.probesWG.Wait() in Gateway.Close, OR
//   (B) removing the g.probesWG.Add(1) / defer Done() bookkeeping that
//       handleMachine (and admin cmdMachinesSetUser, and the two
//       machine_conn.go driveRetiredOpen spawns) do around `go
//       g.runSSHDProbe(mc)`.
//
// The canary holds state.Store.mu from a long-running Update so the
// probe's finishSSHDProbe cannot complete (it needs Store.Update). The
// probe is therefore stuck "in flight" reliably: every code path
// before Close.Wait (or, with canary B, the broken Close.Wait that
// returns immediately because probesWG counter is 0) returns while
// probesInFlight.Load() is still > 0.
//
// On a correct fix: Gateway.Close calls probesWG.Wait(), which blocks
// until the probe's deferred Done() runs. With Store.mu held, that
// deferred Done() never runs until we release the lock — but we do,
// via the test, once we've confirmed the bug-detection assertion
// fired (or, with the fix, never fired and we then release the lock
// so Close can return).

import (
	"runtime"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestIAMT161_CloseWaitsForSSHDProbeToFinish(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		// Safety net, not the assertion: if anything else keeps the
		// probe alive past 5s, fail loudly rather than hang the
		// test runner. The canary itself runs in fractions of a
		// second.
		c.SSHDProbeTimeout = 5 * time.Second
	})

	// needsSSHDProbe (sshd_probe.go:26) requires RequestedOSUser != ""
	// AND OSUserStatus != Verified. The harness's default fixture
	// seeds the machine as verified, which is why round-1's canary
	// never even reached the probe — handleMachine saw needsSSHDProbe
	// return false and skipped the launch entirely. prepareSSHDProbe
	// is the same helper the existing sshd_probe_test.go uses.
	prepareSSHDProbe(t, f)

	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// Wait until the probe is actually running before we set the
	// trap. handleMachine launches the probe with `go`; we observe
	// probesInFlight (unexported, accessible from this package)
	// rather than a timing side-channel.
	for f.gw.probesInFlight.Load() == 0 {
		runtime.Gosched()
	}
	if f.gw.probesInFlight.Load() == 0 {
		t.Fatal("IAMT-161 canary precondition failed: sshd probe never started")
	}

	// Hold state.Store.mu via a long-running Update so the probe's
	// finishSSHDProbe cannot complete — it tries to do
	// g.cfg.Store.Update at the very end of its lifetime, and with
	// the lock held by us, that Update blocks. The probe is therefore
	// stuck on the lock for as long as we choose to keep it. This
	// eliminates the "the probe finishes in microseconds after
	// teardown" race that made the round-1 canary non-deterministic
	// for canary A: Close (with or without probesWG.Wait) cannot
	// return with probesInFlight == 0 until we release the lock,
	// because the probe's Done() is unreachable while Store.Update
	// is blocked.
	releaseStoreLock := make(chan struct{})
	holderStarted := make(chan struct{})
	go func() {
		f.store.Update(func(st *state.State) error {
			close(holderStarted)
			<-releaseStoreLock
			return nil
		})
	}()
	<-holderStarted

	// Call Close in a goroutine. The deadline is HANG PROTECTION —
	// waiting with a deadline is acceptable only as protection against
	// a hang, never as part of the assertion itself. With the fix, Close blocks on probesWG.Wait()
	// until we release the lock; without the fix, Close returns
	// while probesInFlight is still > 0.
	closeReturned := make(chan struct{})
	go func() {
		defer close(closeReturned)
		_ = f.gw.Close()
	}()

	hangDeadline := 500 * time.Millisecond
	select {
	case <-closeReturned:
		// Close returned. With the fix, probesWG.Wait() forced
		// Close to block until the probe's Done() ran — but the
		// probe's Done() only runs after the deferred
		// finishSSHDProbe returns, which only runs after its
		// Store.Update returns, which only returns after we
		// release releaseStoreLock. So Close CANNOT have
		// returned while we still hold the lock.
		//
		// That means: if probesInFlight > 0 at this point,
		// Close did not actually wait for the probe — the bug
		// is present, either as canary A (probesWG.Wait
		// removed) or canary B (probesWG.Add/Done removed).
		if got := f.gw.probesInFlight.Load(); got != 0 {
			close(releaseStoreLock) // let the holder exit so the test runner can clean up
			t.Fatalf("CANARY (IAMT-161): gw.Close returned with %d sshd probe(s) still in flight; "+
				"the probe is stuck on state.Store.mu (held by this test) waiting for finishSSHDProbe, "+
				"so probesInFlight > 0 here means Gateway.Close did not wait for its own writer. "+
				"This is exactly the regression that produced 'TempDir RemoveAll: directory is not empty' "+
				"under -race in TestE2E_EnrolSuccessPath, because the probe writes state.json.tmp.<pid>.<nanos> "+
				"after t.Cleanup has already run.",
				got)
		}
	case <-time.After(hangDeadline):
		// Hang protection. With the correct fix, Close is
		// blocked on probesWG.Wait() exactly because the
		// probe is stuck on the lock we hold. This branch
		// therefore fires only when the fix is correct —
		// we release the lock below to let the probe finish
		// and Close return.
		t.Logf("IAMT-161: Close blocked for >%s on probesWG.Wait — exactly the wait the fix requires; releasing the lock", hangDeadline)
	}

	// Whether Close already returned (assertion above fired or
	// passed) or is still blocked (the fix is correct and Close is
	// waiting on probesWG.Wait), release the lock now so the probe
	// can finish. Without this, Close is deadlocked waiting for
	// probesWG.Wait() and the next select would time out as a
	// hang-protection failure, NOT as a canary pass.
	close(releaseStoreLock)

	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("gw.Close deadlocked even after the test released Store.mu; the probe's finishSSHDProbe is unable to complete")
	}

	// Final sanity: with the lock released and Close returned, the
	// probe must be done. This catches any future regression where
	// Close.Wait is added but the deferred Done() is missed.
	if got := f.gw.probesInFlight.Load(); got != 0 {
		t.Fatalf("IAMT-161: probesInFlight = %d after Close returned and lock released; expected 0", got)
	}
}
