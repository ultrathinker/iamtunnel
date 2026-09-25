package gateway

// sshd_probe_test.go exercises the three §7 probe outcomes using the existing
// in-process target and fake machine. newFixture roots its state, journal and
// recordings in t.TempDir(); no test creates a key file or touches a Windows
// SSH configuration path.
//
// IAMT-134 added the three "sticky mismatch" tests at the bottom of this
// file. They reach the probe through the three real call sites (runSSHDProbe
// directly, the reconnect path in machine_role.go, and the set-user path in
// admin_role.go) instead of through pinSSHDHostKey, which hardcodes the
// mayClearMismatch=false argument and so cannot tell whether any of those
// sites still routes through the non-clearing branch.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

const probeUser = `MACHINE\probe`

func prepareSSHDProbe(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID != f.machineID {
				continue
			}
			m := &st.Machines[i]
			m.State = "enrolled"
			m.OSUser = probeUser
			m.RequestedOSUser = probeUser
			m.VerifiedOSUser = nil
			m.OSUserStatus = state.OSUserStatusPending
			m.SSHDHostKey = nil
			m.ObservedSSHDHostKey = nil
			m.HostKeyStatus = state.HostKeyStatusUnverified
			return nil
		}
		return errors.New("probe machine is missing")
	}); err != nil {
		t.Fatalf("prepare probe state: %v", err)
	}
}

func probeMachineConn(t *testing.T, f *fixture) *machineConn {
	t.Helper()
	mc, ok := f.gw.reg.get(f.machineID)
	if !ok {
		t.Fatal("probe machine is not registered")
	}
	return mc
}

func assertProbeDoorClosed(t *testing.T, fm *fakeMachine) {
	t.Helper()
	fm.waitDoorCycleClosed(t)
	if installed, _ := fm.doorInstalled(); installed {
		t.Fatal("temporary probe door remained installed")
	}
}

func assertProbeState(t *testing.T, f *fixture, wantStatus, wantState string, wantVerified bool) {
	t.Helper()
	st := f.store.Get()
	m, ok := st.MachineByID(f.machineID)
	if !ok {
		t.Fatal("probe machine disappeared from state")
	}
	if m.OSUserStatus != wantStatus || m.State != wantState {
		t.Fatalf("probe state = (status=%q state=%q), want (%q %q)", m.OSUserStatus, m.State, wantStatus, wantState)
	}
	if (m.VerifiedOSUser != nil) != wantVerified {
		t.Fatalf("verifiedOsUser presence = %v, want %v", m.VerifiedOSUser != nil, wantVerified)
	}
	if wantVerified && *m.VerifiedOSUser != probeUser {
		t.Fatalf("verifiedOsUser = %q, want %q", *m.VerifiedOSUser, probeUser)
	}
}

func assertProbeEvent(t *testing.T, f *fixture, want events.EventType) {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{want}})
	if err != nil {
		t.Fatalf("read probe events: %v", err)
	}
	matched := 0
	for _, event := range evs {
		if event.Object == f.machineID && event.Details["requestedOsUser"] == probeUser {
			matched++
		}
	}
	if matched != 1 {
		t.Fatalf("journal has %d %q events for sshd probe of %q, want 1: %+v", matched, want, f.machineID, evs)
	}
}

func TestSSHDProbe_SuccessVerifiesRequestedUserAndClosesDoor(t *testing.T) {
	// The budget is shared with phase one, and phase one is allowed to finish
	// after it (observeSSHDHostKey needs only the host key it caught during
	// KEX). This test is not about the deadline, so it must not be decided by
	// how long a handshake took under -race: with a tight budget the probe
	// would correctly refuse to install a door and the probe could not verify
	// anyone. IAMT-304 round 3 — see TestSSHDProbe_TimedOutOpenLateSuccess-
	// ClosesDoor for the flake this avoids.
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = probeTestBudget })
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	prepareSSHDProbe(t, f)

	if err := f.gw.runSSHDProbe(probeMachineConn(t, f)); err != nil {
		t.Fatalf("sshd probe: %v", err)
	}
	assertProbeState(t, f, state.OSUserStatusVerified, "verified", true)
	if got := f.sshd.userAuthenticatedByPublicKey(); got != probeUser {
		t.Fatalf("probe public-key auth user = %q, want requestedOsUser %q", got, probeUser)
	}
	assertProbeDoorClosed(t, fm)
	assertProbeEvent(t, f, events.EventEnrolVerified)
}

func TestSSHDProbe_RejectedUserClosesDoor(t *testing.T) {
	// Same budget reasoning as the success test above: the door has to open
	// for phase two to be reached at all, so the shared budget must outlast
	// phase one by a margin a slow host cannot eat.
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = probeTestBudget })
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	prepareSSHDProbe(t, f)

	// The first (host-key) phase needs no public key and still observes the
	// host key. Refusing the door key makes only phase two fail.
	f.sshd.setKeyAllowed(func([]byte) bool { return false })
	if err := f.gw.runSSHDProbe(probeMachineConn(t, f)); err == nil {
		t.Fatal("sshd probe unexpectedly accepted a rejected OS user")
	}
	assertProbeState(t, f, state.OSUserStatusRejected, "enrolled", false)
	assertProbeDoorClosed(t, fm)
	assertProbeEvent(t, f, events.EventEnrolFailed)
}

func TestSSHDProbe_DeadlineClosesDoor(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = probeTestBudget })
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	prepareSSHDProbe(t, f)

	// Phase two is where this test wants the budget to run out, and only the
	// test can put it there: the shared budget covers phase one too, and how
	// long phase one takes is a property of the machine and of the race
	// detector (under -race on an M1 it ran past the 25ms the first version of
	// this test allowed for everything, so the deadline used to fire inside
	// phase one and the door was never even opened).
	//
	// probeDeadlineFn is consulted once per bounded wait, and this is the
	// reason it is: the reservation's door.open round trip and phase two
	// need different ceilings, and a single deadline captured before phase
	// one could not be both — the reservation must not expire while phase
	// one legitimately still runs, while phase two's must expire inside the
	// public-key callback, which is the moment the deferred release has to
	// close the door. IAMT-320 reworked what each call returns; see the
	// comment at the seam below.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.sshd.setKeyAllowed(func([]byte) bool {
		<-release
		return false
	})
	// IAMT-320: the seam used to hand BOTH bounded waits a flat 150ms
	// ceiling — "ample for a fake machine that answers immediately" — and
	// each ceiling was a guess about the scheduler that a stalled run could
	// turn into a false red: a door.open round trip that missed 150ms fails
	// the reservation before any door exists (waitDoorCycleClosed below then
	// times out on a cycle that never began), and a phase-two channel open
	// that missed it dies inside openProbeTarget's own timeout branch, which
	// tears the machine conn down and breaks the same cycle from the other
	// side. The ceiling is now measured, per bounded wait:
	//
	//   - the reservation's round trip gets NO test ceiling: the seam
	//     returns the probe's own shared budget (probeDeadline ignores a
	//     later deadline, so this is exactly "do not shorten"). A healthy
	//     run behaves as before — the fake machine answers immediately —
	//     and a stalled one cannot miss a ceiling the test invented. A
	//     regression that hangs the reservation still gives up at the
	//     shared budget and still fails the cycle assertion below;
	//   - phase two keeps a short ceiling that expires inside the blocked
	//     public-key callback — that deadline verdict is what this test
	//     asserts — but its floor is scaled by what the same wire path has
	//     just demonstrably cost: probeDeadlineFn's first call happens
	//     after phase one returned, so the time since the probe started
	//     measures this machine's current handshake cost under the current
	//     load, and the ceiling is four times that measurement, never
	//     below the old 150ms.
	start := time.Now()
	calls := 0
	var phaseOneCost time.Duration
	f.gw.probeDeadlineFn = func(shared time.Time) time.Time {
		calls++
		if calls == 1 {
			phaseOneCost = time.Since(start)
			return shared
		}
		ceiling := 150 * time.Millisecond
		if scaled := 4 * phaseOneCost; scaled > ceiling {
			ceiling = scaled
		}
		return time.Now().Add(ceiling)
	}

	err := f.gw.runSSHDProbe(probeMachineConn(t, f))
	if err == nil {
		t.Fatal("sshd probe unexpectedly exceeded its deadline without failing")
	}
	if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("sshd probe error = %v, want deadline exceeded", err)
	}
	assertProbeState(t, f, state.OSUserStatusRejected, "enrolled", false)
	assertProbeDoorClosed(t, fm)
	assertProbeEvent(t, f, events.EventEnrolFailed)
}

// TestIAMT304_SpentBudgetSendsNoDoorOpen pins the first half of the round-2
// review's finding, in the shape round 9 demanded: the budget check has to
// bind the wire write itself. reserve used to apply core.Reservation and drive
// door.open even when the caller's context was already done, and the first fix
// for that put the check at reserve's entry - which still left a window,
// because sendCommand registers its pending entry and writes the request
// BEFORE it starts waiting for the reply, so a deadline that passed between
// the check and the send still installed a temporary door for a caller that
// had already given up.
//
// Deterministic by construction: the seam hands the reservation a deadline in
// the past, so the deadline is spent exactly when driveOneUntil decides
// whether to send. That is the state a phase one running past the budget
// leaves behind; reaching it by shrinking SSHDProbeTimeout would make the test
// race phase one, which is the flake IAMT-304 started from.
//
// Three assertions, one per property of the fix:
//
//   - nothing was written: the fake machine never installed a line, and
//     everOpened (sticky) proves it was not installed and closed again;
//   - the automaton still ran its reconciliation: a door.open that is not
//     written is fed to the Opening row as core.Timeout, and that cell's whole
//     action is the mandatory §5.2 door.status - so the machine must have been
//     asked. A fix that returns before the automaton (the entry check this
//     replaces) leaves the count unchanged;
//   - the reservation is resolved as the budget's verdict, not as a wire
//     outcome.
//
// Canary: pass a zero/negative timeout to sendCommand instead of refusing the
// write (the round-9 shape - "time.Until(deadline) <= 0" still reaching the
// wire). door.open goes out, the fake machine installs the line, and this test
// fails with "a probe whose budget was already spent still installed a
// temporary door". Moving the refusal back to reserve's entry instead fails
// with "door.status requests went N -> N across a probe whose budget was
// spent": nothing is written either way, but the automaton never hears the
// timeout, so the reconciliation §5.2 owes after an incomplete opening is
// skipped.
func TestIAMT304_SpentBudgetSendsNoDoorOpen(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = probeTestBudget })
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	prepareSSHDProbe(t, f)
	f.gw.probeDeadlineFn = func(time.Time) time.Time { return time.Now().Add(-time.Second) }
	statusesBefore := fm.doorStatusRequests()

	err := f.gw.runSSHDProbe(probeMachineConn(t, f))
	if err == nil {
		t.Fatal("sshd probe with an already spent budget reported success")
	}
	if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("sshd probe error = %v, want the deadline named (sshd_probe.go's spent-budget branch), not an ordinary door-open failure", err)
	}
	if fm.doorEverOpened() {
		t.Fatal("a probe whose budget was already spent still installed a temporary door: door.open reached the wire after the reservation deadline (IAMT-304)")
	}
	if got := fm.doorStatusRequests(); got <= statusesBefore {
		t.Fatalf("door.status requests went %d -> %d across a probe whose budget was spent: the refused door.open must still be fed to the automaton as core.Timeout, because the Opening row's timeout cell is the §5.2 reconciliation the machine needs to hear (IAMT-304)", statusesBefore, got)
	}
	assertProbeState(t, f, state.OSUserStatusRejected, "enrolled", false)
	assertProbeEvent(t, f, events.EventEnrolFailed)
}

// TestIAMT304_OpenWaitIsBoundedByTheProbeBudget pins the second half: with
// door.open in flight the probe must stop waiting at its own deadline, not at
// DoorOpenTimeout. This test never touches DoorOpenTimeout, so the ceiling in
// force is the fixture's 2s against a budget of 60ms — far enough apart for
// the assertions to tell which one ended the wait.
//
// The machine's install lands after the probe has given up. That is the
// interleaving that leaves a real line behind if the runtime merely stops
// waiting: the late reply must reach the automaton's closed+late-reply cell,
// which emits door.close, and the machine must report the installed-to-removed
// cycle. Two independent assertions cover the two halves of the defect:
//
//   - the door was still absent when the probe returned: the probe gave up
//     while the reply was outstanding. An unbounded wait would instead have
//     collected the reply at 500ms and carried on to phase two with a spent
//     budget — which is what the canary below produces;
//   - the OPEN WAIT ITSELF finished well inside DoorOpenTimeout, which is
//     what "the wait is bounded by the remaining budget" has to mean when the
//     reply never arrives at all (the fake machine's hangOpen behaviour).
//
// IAMT-304 round 5: this used to measure elapsed from before calling
// runSSHDProbe at all, i.e. including phase one (observeSSHDHostKey) — a
// real handshake against the fake target sshd that g.probeDeadlineFn is not
// even consulted for (sshd_probe.go calls it only once reserve's wait is
// about to start, AFTER phase one already returned). On the reporting Linux
// VM under -race that measurement showed 1.42s against a 60ms budget and a
// 1s (DoorOpenTimeout/2) ceiling — not 2s (DoorOpenTimeout itself), which is
// what the wait actually being unbounded would produce, and not anywhere near
// 60ms either. That third value is exactly what phase one's own real, if
// slow, duration plus a correctly-bounded ~60ms open wait adds up to; it is
// not evidence the open wait was unbounded, only that the TEST was timing an
// interval phase one's variable cost was smuggled into. openWaitStart is
// captured inside the seam itself, at the exact instant sshd_probe.go computes
// the open wait's deadline (probeDeadline's only call before mc.reserve), so
// elapsed now measures only the interval the assertion is actually about,
// deterministically excluding phase one regardless of how long it legitimately
// runs under load.
//
// Canary: drop the `time.Until(deadline)` ceiling from driveOneUntil, so the
// wait is bounded by DoorOpenTimeout alone. door.open then waits out the
// 500ms install, reserve reports the door open, phase two runs with the
// deadline the seam hands it, and the probe returns success — the test fails
// with "sshd probe unexpectedly succeeded after its door.open budget expired".
func TestIAMT304_OpenWaitIsBoundedByTheProbeBudget(t *testing.T) {
	const budget = 60 * time.Millisecond
	// The machine installs this long after decoding door.open — named
	// because the not-installed-at-return canary below is defined against
	// it: the install cannot land before seam+installDelay, and the canary
	// is decisive only while the check itself happens before that instant.
	const installDelay = 500 * time.Millisecond
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = probeTestBudget })
	fm := f.connectMachine(fakeMachineBehavior{delayOpenInstall: installDelay})
	f.waitMachineOnline(t)
	prepareSSHDProbe(t, f)
	// The reservation is the wait under test; phase two's budget is the same
	// seam's business in the deadline test above, and giving it room here
	// keeps the canary's verdict about the reservation alone. The seam runs on
	// the probe goroutine, so the counter and openWaitStart need no locking:
	// runSSHDProbe has not returned yet when the assertions below read them.
	calls := 0
	var openWaitStart time.Time
	f.gw.probeDeadlineFn = func(time.Time) time.Time {
		calls++
		if calls == 1 {
			openWaitStart = time.Now()
			return openWaitStart.Add(budget)
		}
		return time.Now().Add(2 * time.Second)
	}

	// IAMT-320: a witness for how much wall-clock this process actually
	// kept while the probe ran. The elapsed bound below has no airtight
	// threshold: every wait between the ctx timer's firing and the probe's
	// return (the deferred release, the journal append) is itself scheduler
	// work a starved run can stretch, so a correct build can post a large
	// elapsed purely by being descheduled. What IS observable is whether
	// this process was descheduled at all: a 25ms step overrun by 500ms or
	// more is 20x the ask and by itself accounts for the whole ceiling —
	// that is the drainStarvedGap argument from the IAMT-316 fix, scaled to
	// this test's numbers. The witness never decides a pass; it only turns
	// "fail on a lie" into "record undecided and let the event-based
	// assertions below carry the verdict".
	witnessStop := make(chan struct{})
	witnessGaps := make(chan time.Duration, 1)
	// IAMT-320 review fix (third round): the baseline is taken HERE, in
	// the parent, before the go statement — not inside the goroutine. A
	// `go` statement only guarantees that the closure will eventually
	// start running: a run stalled right after issuing it would take a
	// goroutine-side last AFTER the stall had already happened, report a
	// near-zero maxGap, and hand the elapsed bound below a clean-looking
	// witness on a genuinely starved run — the exact lie this witness
	// exists to catch, relocated into its own setup. Per the Go memory
	// model, parent writes before `go f()` happen-before any code in
	// f's body, so this goroutine can never observe a last later than
	// the instant the parent decided to start watching, and a stall
	// landing before the goroutine's first scheduling slice is still
	// captured by its first time.Since(last). The baseline can only sit
	// a few instructions early: a wider window only widens maxGap, and
	// a wider maxGap can only turn a failure into UNDECIDED, never the
	// reverse. After the go statement the parent never touches last
	// again — the goroutine is its only writer, so no lock is needed.
	last := time.Now()
	go func() {
		const step = 25 * time.Millisecond
		var maxGap time.Duration
		for {
			select {
			case <-witnessStop:
				// IAMT-320 review fix: the last interval is measured
				// HERE, not left to the timer case. On a stalled run the
				// overdue timer case is ready at the very select that
				// also sees the closed witnessStop, and Go's select picks
				// at random between ready cases — so the pre-fix
				// goroutine could take the stop case, drop the stall (the
				// single largest gap: the very one this witness exists to
				// report) from maxGap, and hand the elapsed bound below a
				// clean-looking witness. Every wakeup now records the
				// interval since the previous wakeup — timer case and
				// stop case alike — so the chain of gaps is complete no
				// matter which ready case each select lands on, and a
				// stall landing in the last mile before stopWitness is
				// called can no longer be silently dropped. last is
				// written only by this goroutine — the parent set it
				// once, before the go statement — so the final read
				// needs no lock, and
				// time.Since(last) is a lower bound on the true gap: it
				// can only widen the starvation evidence, never shrink
				// it.
				if gap := time.Since(last); gap > maxGap {
					maxGap = gap
				}
				witnessGaps <- maxGap
				return
			case <-time.After(step):
				now := time.Now()
				if gap := now.Sub(last); gap > maxGap {
					maxGap = gap
				}
				last = now
			}
		}
	}()
	var witnessOnce sync.Once
	var witnessMax time.Duration
	stopWitness := func() time.Duration {
		witnessOnce.Do(func() {
			close(witnessStop)
			witnessMax = <-witnessGaps
		})
		return witnessMax
	}
	t.Cleanup(func() { stopWitness() })

	err := f.gw.runSSHDProbe(probeMachineConn(t, f))
	if openWaitStart.IsZero() {
		t.Fatal("IAMT-304 canary precondition failed: probeDeadlineFn was never called before the probe returned — the open wait this test measures was never reached")
	}
	// IAMT-320 review fix (third round): elapsed is captured BEFORE the
	// witness is stopped, so the judged window [openWaitStart, here]
	// lies inside the witness window [baseline, final stop measurement].
	// With the reads in the other order, a stall in the sliver between
	// stopWitness and time.Since inflated the very number being judged
	// while the only thing that could excuse it was already stopped.
	// The verdicts below judge this captured value, so no later stall
	// can touch it.
	elapsed := time.Since(openWaitStart)
	maxGap := stopWitness()
	if err == nil {
		t.Fatal("sshd probe unexpectedly succeeded after its door.open budget expired")
	}
	if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("sshd probe error = %v, want the probe deadline named, not an ordinary door-open failure", err)
	}
	// IAMT-320: "the door is absent when the probe returns" is only
	// decidable against a MEASURED check instant. The install cannot land
	// before openWaitStart+installDelay (door.open is written after the
	// seam records openWaitStart, and the machine sleeps installDelay from
	// decoding it), so while the check itself happens before
	// openWaitStart+installDelay-budget, an install seen here is a genuine
	// regression — the probe must have been waiting for the reply. But a
	// run descheduled for hundreds of milliseconds between the probe's
	// return and this check can legitimately find the door already
	// installed; failing on that reads the machine's load as a product
	// defect. On such a run the canary is undecided rather than failed —
	// the deadline verdict above and the measured elapsed bound below still
	// pin the wait, and the cycle assertion below still proves the late
	// install is reconciled to a closed door.
	if installed, _ := fm.doorInstalled(); installed {
		if sinceSeam := time.Since(openWaitStart); sinceSeam < installDelay-budget {
			t.Fatalf("the machine installed the temporary door before the probe returned (check %v after the open-wait seam began, before the earliest possible install at %v): the wait was not bounded by the probe budget, so the late-install reconciliation below was not exercised", sinceSeam, installDelay)
		}
		t.Logf("IAMT-320: the door was already installed when this test looked (%v after the open-wait seam began; the earliest possible install is %v) — the not-installed-at-return canary is undecided on this starved run, not passed; the wait is still bounded by the deadline verdict and the elapsed bound, and the cycle below must still complete", time.Since(openWaitStart), installDelay)
	}
	if half := f.gw.cfg.DoorOpenTimeout / 2; elapsed > half {
		if maxGap >= 500*time.Millisecond {
			t.Logf("IAMT-320: the open wait measured %v (ceiling %v), but this machine cannot keep time: a %v witness step was overrun by %v at worst, which alone accounts for the ceiling. The bound is UNDECIDED on this run, not passed; a healthy run still fails here on a genuine unbounded wait.",
				elapsed, half, 25*time.Millisecond, maxGap)
		} else {
			t.Fatalf("sshd probe's open wait took %v (measured from probeDeadlineFn's first call, excluding phase one) to give up on door.open; the wait must be bounded by the probe budget (%v), not by DoorOpenTimeout (%v)", elapsed, budget, f.gw.cfg.DoorOpenTimeout)
		}
	}
	assertProbeDoorClosed(t, fm)
	assertProbeState(t, f, state.OSUserStatusRejected, "enrolled", false)
	assertProbeEvent(t, f, events.EventEnrolFailed)
}

// TestSSHDProbe_TimedOutOpenLateSuccessClosesDoor pins the interleaving that
// used to lose a real door: door.open timed out, the immediate reconciliation
// status saw no line, and only then did the machine install the line and send
// its success reply.  The retired reply must reach core.LateReply, whose
// close is observed as an installed-to-closed event rather than assumed after
// a sleep.
//
// The budget is deliberately far larger than the wait under test
// (probeTestBudget against DoorOpenTimeout's 20ms). IAMT-304 round 3: this test used to run on 500ms,
// which is a budget phase one SHARES — and phase one is allowed to finish
// after it, because observeSSHDHostKey only needs the host key it caught
// during KEX, not a completed handshake. On a slow host under -race phase one
// therefore consumed the budget, and the reservation was correctly refused the
// wire write; the machine never installed anything, so this test's
// installed-to-closed cycle could not happen and it failed on its guard.
// The scenario it means to exercise — "the reply came after we gave up" — needs
// a budget that is still alive when door.open is written, and the timeout that
// ends the wait here is DoorOpenTimeout (20ms) against a machine that installs
// at 100ms. Shrinking the shared budget is what makes this unreachable; the
// refusal itself is pinned by TestIAMT304_SpentBudgetSendsNoDoorOpen.
//
// IAMT-304 round 4 — why this test used to lean on wall-clock waits, and
// why round 6 replaces that entirely (review round13, F-304-1). The
// failure that survived round 3 was not the closure being lost: the
// machine never received door.open at all, because the fixture's own
// keepalive tore the machine down mid-probe. Round 4 widened that window
// and made the test poll a fm.openReqs counter (through an accessor,
// doorOpenRequests, later removed as dead code once round 6's barrier
// replaced every caller - IAMT-304 round 12, staticcheck U1000) with a
// generous guard instead of assuming. Round 5 raised the guards further
// after a slow Linux VM still failed occasionally. review of
// round 5 found the real defect in the TEST, not in either fix:
// observeSSHDHostKey (phase
// one) is a genuine SSH key exchange against the fake target sshd through
// two relays - real network and cryptographic work whose duration nothing
// in this package, least of all a fake clock, bounds or controls. Every
// wall-clock guard rounds 4 and 5 added was a guess at how long that
// unrelated work might legitimately take under load; no guess is
// unconditionally large enough, and a bigger one is not a fix (it is the
// same guess, slower to fail).
//
// Round 6 removes phase one's variance from this test instead of coping
// with it: g.phaseOneObserveFn stubs observeSSHDHostKey to return the fake
// target's real host key synchronously, so nothing before the door.open
// reservation takes unbounded real time. fm.openReceived is a
// deterministic barrier - closed the instant the machine's control loop
// decodes door.open, before any delay - so "door.open reached the wire"
// is an event this test blocks on, not a value a poll loop hopes to
// observe soon enough.
//
// Round 7 (review round13, F-304-1 continued) removes the SECOND
// wall-clock guess round 6 still made: a fixed time.Sleep(DoorOpenTimeout
// + margin) before releasing holdOpenInstall, on the assumption that the
// gateway's own openingTimeout-triggered reconciliation door.status would
// always have reached the fake machine by then. Under sibling load
// (-race, GOMAXPROCS=2, nine sibling tests sharing the scheduler) the
// goroutine driving that reconciliation can be delayed tens of
// milliseconds past the timeout firing, long enough for the fixed sleep
// to win the race and release the install BEFORE the reconciliation
// status reaches the machine. When that happens the machine truthfully
// reports installed:true on that status, and the automaton takes the
// spec'd closedStatus/"reconnect" cell instead of the late-reply cell -
// completeRetiredOpenReconciliation then deliberately discards the
// retired reply rather than double-closing (see its own doc comment).
// That was never a product defect: closedStatus's "reconnect" branch and
// closedLate's "late-reply" branch are both correct for the ordering
// they each assume, and only the test's guessed sleep, not the gateway,
// controlled which ordering actually occurred.
//
// fm.reconcileStatusReplied is the barrier that removes that guess: it
// closes only once the fake machine has WRITTEN the reply to the first
// door.status it receives after door.open, still reporting installed:
// false because the install itself cannot run until holdOpenInstall is
// released. Waiting for that barrier before releasing pins the wire
// ordering the test needs (the reconciliation status's negative reply is
// queued on the same writeMu-guarded stream strictly before the late
// door.open reply can be) instead of hoping a sleep outlasted a
// scheduler delay it never measured.
//
// Canary: drop core's closedLate cell (or the retired-open bookkeeping in
// machine_conn.go) and the late close never lands — the test fails after the
// hung guard with "the gateway never closed the late door: ... reason
// \"late-reply\" ...".
func TestSSHDProbe_TimedOutOpenLateSuccessClosesDoor(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.SSHDProbeTimeout = probeTestBudget
		cfg.DoorOpenTimeout = 20 * time.Millisecond
	})
	release := make(chan struct{})
	fm := f.connectMachine(fakeMachineBehavior{holdOpenInstall: release})
	f.waitMachineOnline(t)
	prepareSSHDProbe(t, f)

	// Phase one stubbed to a synchronous, known-good answer: see the file
	// doc comment above for why its real duration must not be part of
	// this test's timing at all.
	f.gw.phaseOneObserveFn = func(*machineConn, time.Time) (string, error) {
		return authorizedKeyLine(f.sshd.signer.PublicKey()), nil
	}

	mc := probeMachineConn(t, f)
	errCh := make(chan error, 1)
	go func() { errCh <- f.gw.runSSHDProbe(mc) }()

	// (a) The deterministic barrier: block until the machine has actually
	// decoded door.open - not until a poll loop happens to notice it, and
	// not gated on anything phase one does, since phase one no longer does
	// any real work. probeTestBudget is only the hung-test guard here (the
	// same reasoning waitUntilFor's other callers use); a healthy run
	// clears this in well under a millisecond.
	fm.waitDoorOpenReceived(t, probeTestBudget)

	// (b) The second deterministic barrier (round 7): block until the
	// machine has already answered the mandatory post-timeout
	// reconciliation door.status with installed:false, which can only
	// happen before the held install is released. This replaces a fixed
	// sleep that raced the gateway's own scheduling under sibling load -
	// see the file doc comment above for the failure that raced.
	fm.waitReconcileStatusReplied(t, probeTestBudget)
	close(release)

	err := <-errCh
	if err == nil {
		t.Fatal("sshd probe unexpectedly succeeded after temporary door.open timed out")
	}

	// (c) The closure, synchronised on the gateway's own transition.
	// lateReplyHungGuard, not waitUntil's plain 10s: see that constant's
	// own comment for why this specific wait's dependency chain (the
	// automaton's own door.status reconciliation, then a further
	// door.close round trip) is longer than the one 10s was calibrated
	// against.
	// waitUntilEvery, not waitUntilFor: lateReplyHungGuard is 40s, and
	// polling doorCloseWithReason (an events.Log.Read call) every 2ms for
	// that whole window is tens of thousands of lock acquisitions against
	// the same mutex the write this test is waiting for also needs - see
	// waitUntilEvery's own doc comment for why that is self-inflicted
	// contention, not a neutral observer.
	waitUntilEvery(t, lateReplyHungGuard, 25*time.Millisecond,
		fmt.Sprintf("the gateway never closed the late door: no confirmed door.close with reason \"late-reply\" reached the journal for %s; the probe's verdict was %v", f.machineID, err),
		func() bool { return doorCloseWithReason(t, f, "late-reply") })
	// The late close is only half the property: the line must have been
	// installed first (everOpened is sticky: "installed and later closed", not
	// "never touched") and must be gone now.
	if !fm.doorEverOpened() {
		t.Fatal("the gateway closed a late door the machine had never installed: everOpened is false, so this close did not come from a late door.open success")
	}
	if installed, id := fm.doorInstalled(); installed {
		t.Fatalf("the gateway journalled the late-reply close but the machine still holds door %q: the close did not reach it", id)
	}
	assertProbeState(t, f, state.OSUserStatusRejected, "enrolled", false)
	assertProbeEvent(t, f, events.EventEnrolFailed)
}

// doorCloseWithReason reports whether the gateway journalled a confirmed
// door.close with this reason for the fixture's machine. It reads the
// gateway's own transition record (events.jsonl through the store's log), not
// the machine's simulated authorized_keys: a test that synchronises on a door
// it expects the automaton to close should wait for the automaton's verdict,
// which is what the journal holds.
func doorCloseWithReason(t *testing.T, f *fixture, reason string) bool {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventDoorClose}})
	if err != nil {
		return false
	}
	for _, event := range evs {
		if event.Object == f.machineID && event.Result == "ok" && event.Details["reason"] == reason {
			return true
		}
	}
	return false
}

// ---- IAMT-134: the "sticky mismatch" rule must hold through every real
// entry point of the automatic probe, not through pinSSHDHostKey, which
// hardcodes mayClearMismatch=false and so cannot tell whether any real
// caller still passes false.

// seedStickyMismatch puts the machine into the exact precondition that
// makes the sticky branch at sshd_probe.go:253 fire: a recorded mismatch
// (with the foreign key still on record for an administrator to inspect)
// and a pinned key equal to what the fake sshd actually serves. It does
// NOT change OSUserStatus, so each caller controls whether the automatic
// probe will run.
func seedStickyMismatch(t *testing.T, f *fixture, observed, pinned string) {
	t.Helper()
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID != f.machineID {
				continue
			}
			st.Machines[i].SSHDHostKey = &pinned
			st.Machines[i].HostKeyStatus = state.HostKeyStatusMismatch
			v := observed
			st.Machines[i].ObservedSSHDHostKey = &v
			return nil
		}
		return errors.New("seed sticky mismatch: probe machine is missing")
	}); err != nil {
		t.Fatalf("seed sticky mismatch: %v", err)
	}
}

func assertStickyMismatchIntact(t *testing.T, f *fixture, foreign, wantFailureContext string) {
	t.Helper()
	st := f.store.Get()
	m, ok := st.MachineByID(f.machineID)
	if !ok {
		t.Fatalf("%s: probe machine disappeared from state", wantFailureContext)
	}
	if m.HostKeyStatus != state.HostKeyStatusMismatch {
		t.Fatalf("%s: hostKeyStatus was rewritten to %q; hostKeyStatus = mismatch is sticky (SPEC §4.3, §6.2) and only machines.verify / machines.rekey may clear it",
			wantFailureContext, m.HostKeyStatus)
	}
	if m.ObservedSSHDHostKey == nil {
		t.Fatalf("%s: observedSSHDHostKey was cleared; the foreign key that triggered the suspicion must stay on record until an administrator acts",
			wantFailureContext)
	}
	if *m.ObservedSSHDHostKey != foreign {
		t.Fatalf("%s: observedSSHDHostKey was rewritten to %q; the foreign key %q that triggered the suspicion must stay on record until an administrator acts",
			wantFailureContext, *m.ObservedSSHDHostKey, foreign)
	}
}

// TestSSHDProbe_AutomaticProbeDoesNotClearStickyMismatch (IAMT-134, level
// B) goes through runSSHDProbe directly — the same wrapper the reconnect
// (machine_role.go:79) and the set-user path (admin_role.go:760) call.
// Replacing the hardcoded `false` at sshd_probe.go:36 with `true` makes
// this test fail on its own assertion line; the old IAMT-91 test stays
// green because it never went through that wrapper.
func TestSSHDProbe_AutomaticProbeDoesNotClearStickyMismatch(t *testing.T) {
	// IAMT-320: this used to run on a 250ms SSHDProbeTimeout with a real
	// phase-one handshake against the fake target, while the assertion below
	// names the sticky-mismatch branch — which the probe only reaches AFTER
	// that handshake completes. A KEX through two relays under -race on a
	// loaded VM legitimately overshoots 250ms; the probe then fails with the
	// handshake's own deadline error and this test goes red on a fact about
	// the machine's load, not about the sticky rule. The same round-6 remedy
	// TestSSHDProbe_TimedOutOpenLateSuccessClosesDoor took applies: the
	// phaseOneObserveFn seam removes the handshake from the timed path by
	// producing the very key the fake target serves, synchronously. The
	// budget is then unreachable on this path (nothing runs between it and
	// the sticky return), and probeTestBudget is the file's convention for
	// "the deadline is not what this test is about" — the assertion still
	// travels through runSSHDProbe, the real pin comparison, and the real
	// sticky branch at sshd_probe.go:253.
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = probeTestBudget })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	prepareSSHDProbe(t, f)

	// Same host key the fake sshd serves == pinned. The probe will see them
	// agree and reach the sticky branch.
	foreign := authorizedLine(genSigner(t).PublicKey())
	pinned := authorizedLine(f.sshd.signer.PublicKey())
	seedStickyMismatch(t, f, foreign, pinned)

	f.gw.phaseOneObserveFn = func(*machineConn, time.Time) (string, error) {
		return authorizedKeyLine(f.sshd.signer.PublicKey()), nil
	}

	err := f.gw.runSSHDProbe(probeMachineConn(t, f))
	if err == nil {
		t.Fatal("automatic probe accepted a sticky mismatch without error; the next observation equal to the pinned key must leave the recorded suspicion in place (sshd_probe.go:253)")
	}
	if !strings.Contains(err.Error(), "recorded SSHD host-key mismatch") {
		t.Fatalf("automatic probe error %q did not name the sticky-mismatch branch (sshd_probe.go:99-101)", err)
	}
	assertStickyMismatchIntact(t, f, foreign, "F-01B (automatic probe, sshd_probe.go:36)")
}

// TestSSHDProbe_ReconnectDoesNotClearStickyMismatch (IAMT-134, level V)
// reaches the probe through the real reconnect path: connectMachine +
// waitMachineOnline makes machine_role.go:79 fire `go g.runSSHDProbe(mc)`
// when needsSSHDProbe is true. The probe runs in a goroutine, so the
// test waits for the journal's EventEnrolFailed entry instead of using
// time.Sleep. Replacing the call site with runSSHDProbeForAdmin makes
// this test fail on its own assertion line; tests B and V-prime stay
// green because they don't reach this call site.
func TestSSHDProbe_ReconnectDoesNotClearStickyMismatch(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = 250 * time.Millisecond })

	foreign := authorizedLine(genSigner(t).PublicKey())
	pinned := authorizedLine(f.sshd.signer.PublicKey())
	seedStickyMismatch(t, f, foreign, pinned)
	// needsSSHDProbe (sshd_probe.go:26) requires OSUserStatus != Verified;
	// promote to Pending so the reconnect actually fires the automatic probe.
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID != f.machineID {
				continue
			}
			st.Machines[i].State = "enrolled"
			st.Machines[i].OSUser = probeUser
			st.Machines[i].RequestedOSUser = probeUser
			st.Machines[i].VerifiedOSUser = nil
			st.Machines[i].OSUserStatus = state.OSUserStatusPending
			return nil
		}
		return errors.New("set pending: probe machine is missing")
	}); err != nil {
		t.Fatalf("set pending: %v", err)
	}

	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// The probe runs in a goroutine via machine_role.go:79. Wait for it
	// via the journal — never time.Sleep (a flaky wait is a setup
	// failure, not an assertion).
	waitUntil(t, "reconnect probe did not log EventEnrolFailed", func() bool {
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolFailed}})
		if err != nil {
			return false
		}
		for _, event := range evs {
			if event.Object == f.machineID && event.Details["requestedOsUser"] == probeUser {
				return true
			}
		}
		return false
	})
	assertStickyMismatchIntact(t, f, foreign, "F-01R (reconnect probe, machine_role.go:79)")
}

// TestSSHDProbe_SetUserDoesNotClearStickyMismatch (IAMT-134, level
// V-prime) reaches the probe through the machines.set-user path:
// connectMachine + waitMachineOnline first (with OSUserStatus=Verified so
// the reconnect-time probe stays quiet), then a real admin.Conn issues
// machines.set-user, which admin_role.go:760 fires as `go
// g.runSSHDProbe(mc)` after the user change. Replacing the call site with
// runSSHDProbeForAdmin makes this test fail on its own assertion line;
// tests B and V stay green because they don't reach this call site.
func TestSSHDProbe_SetUserDoesNotClearStickyMismatch(t *testing.T) {
	f := newFixture(t, func(cfg *Config) { cfg.SSHDProbeTimeout = 250 * time.Millisecond })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	foreign := authorizedLine(genSigner(t).PublicKey())
	pinned := authorizedLine(f.sshd.signer.PublicKey())
	seedStickyMismatch(t, f, foreign, pinned)

	rootKey := genSigner(t)
	addPerson(t, f, "iamt134-setuser", "admin", rootKey)
	root := dialAdmin(t, f, "iamt134-setuser", rootKey)
	if err := root.MachinesSetUser(f.machineID, probeUser); err != nil {
		t.Fatalf("machines.set-user: %v", err)
	}

	waitUntil(t, "set-user probe did not log EventEnrolFailed", func() bool {
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventEnrolFailed}})
		if err != nil {
			return false
		}
		for _, event := range evs {
			if event.Object == f.machineID && event.Details["requestedOsUser"] == probeUser {
				return true
			}
		}
		return false
	})
	assertStickyMismatchIntact(t, f, foreign, "F-01S (set-user probe, admin_role.go:760)")
}
