package gateway

// closeaftermachinedrain_test.go: IAMT-108, gateway half, second layer.
// bridge_ownership_test.go (internal/gateway/core) proves core.Bridge no
// longer closes human/target on a clean end; this file proves the other
// side of that split - human_role.go's closeAfterMachineDrain - actually
// waits for the machine's last request to drain (bounded by
// sshx.ExitStatusGrace) before closing them itself, and does nothing at all
// on a non-clean end (core.Bridge already closed both streams there).
//
// Every case here drives the "drained" channel directly instead of routing
// a real exit-status through a real mreqs channel and a real
// proxyChannelRequests goroutine, on purpose: that route is exactly the one
// whose timing is a genuine goroutine-scheduling race (gate 5 went red
// about once in six runs under load, green 40/40 in isolation) and no
// single-machine test can turn that race into a reliable canary. Testing
// closeAfterMachineDrain directly, with the channel state fully controlled
// by the test, removes the race instead of trying to win it: what is being
// checked below is the deterministic, testable half of the fix - given a
// known "drained" state, does this function wait, and does it give up when
// it should.
//
// IAMT-316: this file used to measure that wait by sleeping through it -
// time.Sleep(grace - 1s), then "assert not closed yet". That is not a
// measurement, it is a guess about the scheduler. closeAfterMachineDrain
// has no system call and no platform branch in it (human_role.go: a
// time.NewTimer, a select, two Close calls), so it cannot behave
// differently on Linux than on Windows or darwin; what differed was the
// test's own sleep, which on a loaded VM under -race overshoots the 5s
// deadline, after which the observed close is legitimate and the "CANARY"
// line fires on a lie. The rule this file now follows: never infer WHEN a
// close happened from WHEN the test managed to look. fakeCloser timestamps
// the close itself, and every timing verdict below is taken against that
// recorded instant, which no amount of descheduling can move. Descheduling
// can then only cost coverage, never correctness.
//
// There is no skip in this file. Round 4 removed the one it had: it was
// reachable on the "never returns" path, which is the one failure this test
// is here for, so a loaded runner could skip a genuine hang forever. Every
// timing verdict below is now a two-sided bound on a recorded instant -
// never earlier than start+grace, never later than start+grace+
// drainHangBudget - and "nothing was closed at all" is always a failure.

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// drainClockSlack absorbs clock/timer granularity when a recorded close
// instant is compared against sshx.ExitStatusGrace. In principle none is
// needed: Go's timer fires off the same monotonic source time.Now() reads,
// and the timer is armed strictly after the test takes `start`, so a correct
// build can never record a close before start+grace. 50ms is kept as pure
// defensive margin - 1% of the 5s grace, far below every regression class
// this file guards (the wait deleted outright closes at ~0ms; a wait
// rewritten to a wrong constant lands hundreds of ms out at worst), so it
// costs the canary nothing while making a false red impossible on any of the
// three target platforms.
const drainClockSlack = 50 * time.Millisecond

// drainPollEvery is how often the not-yet-closed state is sampled, starting
// at t=0 rather than once near the deadline. The frequency IS the canary: a
// build with the bounded select deleted closes at ~0ms and is caught by the
// first sample, ~25ms in, on every run and on every platform - the property
// the old single midpoint sleep was trying to buy and did not.
const drainPollEvery = 25 * time.Millisecond

// drainHangBudget is how long past sshx.ExitStatusGrace the give-up is still
// allowed to take before the session is called hung. The contract being
// checked is "ends rather than hangs forever", so this bound exists only to
// keep an actual hang from running into go test's own timeout; it is
// deliberately far larger than the old 3s window, which left barely 2s of
// head-room over the deadline and was eaten by the same overshoot that ate
// the canary. It is also the UPPER bound every timing assertion below is
// measured against: start+grace is the floor, start+grace+drainHangBudget
// the ceiling.
//
// There is deliberately no "the machine was starved, so skip" escape from
// that ceiling. An earlier version of this test had one, gated on the worst
// observed poll-loop gap, and it was wrong in the most expensive possible
// way: a regression that waits on a channel which never closes produces no
// close and no return at all, so it reached the timeout branch - and one
// single >=1s scheduling gap anywhere before the deadline was then enough to
// turn "this build hangs forever" into SKIP. On a permanently loaded runner
// that is a permanent skip of the exact failure this test exists to catch.
// Starvation can make a measurement late; it cannot make a Close that never
// happened.
const drainHangBudget = 30 * time.Second

// fakeCloser is a deterministic io.Closer double that records whether, how
// many times, and - the point of IAMT-316 - exactly WHEN Close was called.
type fakeCloser struct {
	mu       sync.Mutex
	closed   bool
	calls    int
	closedAt time.Time
}

func (c *fakeCloser) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.calls++
	// First close only: closedAt answers "when did this stream end", which
	// is a property of the first Close. A later duplicate Close (which on
	// these paths would itself be a bug, and is asserted against below)
	// must not be able to rewrite that instant into a passing one.
	if c.calls == 1 {
		c.closedAt = time.Now()
	}
	return nil
}

// snapshot reports the close state together with the recorded instant of the
// first Close. Callers judge timing against `at`, never against the moment
// they happened to call snapshot: a poller that was descheduled past the
// deadline still reads the true close instant and still reaches the right
// verdict.
func (c *fakeCloser) snapshot() (closed bool, calls int, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed, c.calls, c.closedAt
}

// TestCloseAfterMachineDrainClosesPromptlyWhenAlreadyDrained is the common
// case: the machine's last request had already been forwarded (drained is
// already closed) by the time core.Bridge returned cleanly. Both streams
// must close without waiting out the grace bound.
func TestCloseAfterMachineDrainClosesPromptlyWhenAlreadyDrained(t *testing.T) {
	grace := sshx.ExitStatusGrace
	// Half the grace, not a small fixed number of milliseconds. What this
	// test must prove is "did NOT wait out the grace", and grace/2 proves
	// exactly that - a regression that waits the bound out lands at 5s and
	// is caught - while leaving 2.5s of scheduling head-room instead of the
	// 0.5s the old bound left. IAMT-316: a 500ms window on a loaded VM
	// measures the machine's load, not the product.
	promptBound := grace / 2

	drained := make(chan struct{})
	close(drained)
	human := &fakeCloser{}
	target := &fakeCloser{}

	start := time.Now()
	done := make(chan struct{})
	go func() {
		closeAfterMachineDrain(nil, drained, human, target)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(promptBound):
		t.Fatalf("closeAfterMachineDrain did not return within %v on an already-drained session; it must not wait out sshx.ExitStatusGrace (%v) when drained is already closed", promptBound, grace)
	}

	humanClosed, humanCalls, humanAt := human.snapshot()
	targetClosed, targetCalls, targetAt := target.snapshot()
	if !humanClosed {
		t.Fatal("closeAfterMachineDrain did not close human on a clean, already-drained end")
	}
	if !targetClosed {
		t.Fatal("closeAfterMachineDrain did not close target on a clean, already-drained end")
	}
	// Measured against the recorded close instant, not against "when this
	// goroutine got around to looking".
	if elapsed := humanAt.Sub(start); elapsed >= promptBound {
		t.Fatalf("closeAfterMachineDrain closed human %v after the call began on an already-drained session; want well under sshx.ExitStatusGrace (%v)", elapsed, grace)
	}
	if elapsed := targetAt.Sub(start); elapsed >= promptBound {
		t.Fatalf("closeAfterMachineDrain closed target %v after the call began on an already-drained session; want well under sshx.ExitStatusGrace (%v)", elapsed, grace)
	}
	if humanCalls != 1 || targetCalls != 1 {
		t.Fatalf("closeAfterMachineDrain closed human %d time(s) and target %d time(s); each stream must be closed exactly once", humanCalls, targetCalls)
	}
	// Close ordering is part of the contract human_role.go implements:
	// human first, then target. Both instants come from the same monotonic
	// clock, so equality is possible and allowed - only an inversion is not.
	if targetAt.Before(humanAt) {
		t.Fatalf("closeAfterMachineDrain closed target before human (target at %v, human at %v after the call began); the order is human then target", targetAt.Sub(start), humanAt.Sub(start))
	}
}

// TestCloseAfterMachineDrainWaitsFullGraceThenGivesUp is the deterministic
// stand-in for the silent-machine case: a machine that half-closed
// its data side (so core.Bridge still ends cleanly) and then went silent -
// never sending exit-status, never closing the nested session channel, so
// drained never closes. The session must still end, but only after
// sshx.ExitStatusGrace, not before and not never.
//
// This test genuinely waits out sshx.ExitStatusGrace (about 5s) in real
// time, the same way internal/client/connect_silentpeer_test.go's
// TestConnectSilentPeerStillReturns already does for the client half of
// this same constant - there is no way to prove a real bound is honored
// without letting real time pass, and shortening it here would test a
// different number than production uses. What IAMT-316 changed is not how
// much time passes but how it is read: the test polls the close state from
// t=0 every drainPollEvery and judges every observation against the instant
// fakeCloser recorded, so a run that is descheduled straight past the
// deadline reads "closed at 5.0s" and correctly says nothing is wrong,
// where the old midpoint sleep read "closed by the time I woke up" and
// failed a correct build.
//
// CANARY: delete the bounded select in closeAfterMachineDrain (make it
// close human/target unconditionally, with no wait) and this test fails at
// the first t.Fatalf in the poll loop below, on every run and on every
// platform - not "about one time in six". The regression closes at ~0ms,
// the first sample lands ~25ms in and reads a recorded close instant of
// ~0ms, and "closed before the deadline" is then a plain postcondition, not
// a race: no scheduling delay anywhere can turn a recorded 0ms into 5s.
func TestCloseAfterMachineDrainWaitsFullGraceThenGivesUp(t *testing.T) {
	grace := sshx.ExitStatusGrace
	if grace <= 2*time.Second {
		t.Fatalf("test assumes room for many not-yet-closed samples before the deadline; sshx.ExitStatusGrace = %v", grace)
	}
	drained := make(chan struct{}) // never closed
	human := &fakeCloser{}
	target := &fakeCloser{}

	start := time.Now()
	done := make(chan struct{})
	// returnedAt is written before close(done) and read only after a
	// successful receive from done, so the close/receive pair is the
	// happens-before edge that makes the read race-free.
	var returnedAt time.Time
	go func() {
		closeAfterMachineDrain(nil, drained, human, target)
		returnedAt = time.Now()
		close(done)
	}()

	// Phase 1 - the canary. Sample the close state from t=0 until the
	// deadline. Every sample that finds a stream closed is judged against
	// the recorded close instant: before start+grace it is a real
	// regression (the timer cannot fire early), at or after it the deadline
	// simply arrived while this loop was running and there is nothing left
	// to watch.
	deadline := start.Add(grace)
	var (
		samples  int
		maxGap   time.Duration
		lastOpen time.Duration
		lastPoll = start
	)
	// mustNotBeEarly is the only place in this test where a timing verdict
	// is drawn, and it draws it from the recorded close instant alone - not
	// from "now", not from which sample happened to notice. That is the
	// whole of IAMT-316 in one function.
	mustNotBeEarly := func(name string, closed bool, at time.Time) {
		t.Helper()
		if !closed {
			return
		}
		elapsed := at.Sub(start)
		if elapsed >= grace-drainClockSlack {
			return
		}
		t.Fatalf("CANARY: closeAfterMachineDrain closed %s %v after the wait began, "+
			"before sshx.ExitStatusGrace (%v) elapsed; the bounded wait was skipped "+
			"or shortened. Measured from the close itself, not from when this test "+
			"looked: %d samples every %v since t=0, worst scheduling gap %v, both "+
			"streams last seen open at %v.",
			name, elapsed, grace, samples, drainPollEvery, maxGap, lastOpen)
	}
	// mustNotBeLate is the other half of the same idea, and the half this
	// test used to be missing: the recorded close instant must also be
	// inside the ceiling. Without it, a run descheduled until both done and
	// the timeout were ready could have select pick done and pass on a
	// close that happened far past the budget, since only the floor was
	// ever asserted.
	mustNotBeLate := func(name string, at time.Time) {
		t.Helper()
		elapsed := at.Sub(start)
		if elapsed <= grace+drainHangBudget+drainClockSlack {
			return
		}
		t.Fatalf("closeAfterMachineDrain closed %s %v after the wait began, past the "+
			"%v this test allows (sshx.ExitStatusGrace %v plus %v of head-room for "+
			"scheduling). The contract is the full grace and then a give-up, not an "+
			"open-ended wait. Poll loop: %d samples every %v, worst gap %v.",
			name, elapsed, grace+drainHangBudget, grace, drainHangBudget,
			samples, drainPollEvery, maxGap)
	}
	for {
		now := time.Now()
		if gap := now.Sub(lastPoll); gap > maxGap {
			maxGap = gap
		}
		lastPoll = now

		humanClosed, _, humanAt := human.snapshot()
		targetClosed, _, targetAt := target.snapshot()
		mustNotBeEarly("human", humanClosed, humanAt)
		mustNotBeEarly("target", targetClosed, targetAt)

		if humanClosed || targetClosed {
			// Closed, and legitimately so: the deadline has passed. The
			// remaining assertions live after the wait below.
			break
		}
		samples++
		lastOpen = now.Sub(start)
		if !now.Before(deadline) {
			break
		}
		time.Sleep(drainPollEvery)
	}

	// Phase 2 - the give-up. The bound is absolute (start + grace +
	// drainHangBudget) rather than "3s from wherever phase 1 happened to
	// end", so a slow phase 1 cannot eat the window the way the old
	// sleep-then-3s structure did.
	wait := time.Until(start.Add(grace + drainHangBudget))
	if wait < time.Second {
		// Phase 1 alone overran the whole budget on a badly starved
		// machine. Still give the return a real chance rather than
		// declaring a hang on a timer that had already expired.
		wait = time.Second
	}
	returned := false
	select {
	case <-done:
		returned = true
	case <-time.After(wait):
		// The timer and done can become ready in the same instant and
		// select picks among ready cases at random, so look once more
		// before calling this a hang.
		select {
		case <-done:
			returned = true
		default:
		}
	}
	if !returned {
		// Unconditional. A close that never happened has no timestamp to be
		// late, so there is no scheduling story that turns this into a
		// pass, and no gap measurement that may downgrade it to a skip:
		// this is precisely the "never finishes" regression the test is
		// here for. The measured scheduling numbers go into the message so
		// a reader on a loaded runner can see them - they explain how long
		// the wait took, they do not excuse the result.
		t.Fatalf("closeAfterMachineDrain has still not returned %v after the wait "+
			"began, with the machine's request stream never draining - this is the "+
			"hang that must never happen. The bound is sshx.ExitStatusGrace "+
			"(%v) plus %v of head-room for scheduling. Poll loop: %d samples every "+
			"%v, worst gap %v.",
			time.Since(start), grace, drainHangBudget, samples, drainPollEvery, maxGap)
	}
	// Race-free: close(done) happens-before this read.
	if elapsed := returnedAt.Sub(start); elapsed > grace+drainHangBudget+drainClockSlack {
		t.Fatalf("closeAfterMachineDrain returned %v after the wait began, past the "+
			"%v this test allows (sshx.ExitStatusGrace %v plus %v of head-room). "+
			"Receiving from done is not on its own proof that the budget was kept: "+
			"a goroutine descheduled past the deadline sees it ready too. Poll loop: "+
			"%d samples every %v, worst gap %v.",
			elapsed, grace+drainHangBudget, grace, drainHangBudget,
			samples, drainPollEvery, maxGap)
	}

	humanClosed, humanCalls, humanAt := human.snapshot()
	targetClosed, targetCalls, targetAt := target.snapshot()
	if !humanClosed {
		t.Fatal("closeAfterMachineDrain never closed human even after giving up on the machine's request stream")
	}
	if !targetClosed {
		t.Fatal("closeAfterMachineDrain never closed target even after giving up on the machine's request stream")
	}
	// The full grace really did pass before each close - measured against
	// the recorded instants, so this holds however late this goroutine was
	// scheduled to check it. Repeated here and not only in the poll loop
	// because a run whose loop was descheduled straight past the deadline
	// may have taken no useful sample at all; this pair is what still
	// catches a "no wait" regression on such a run.
	mustNotBeEarly("human", humanClosed, humanAt)
	mustNotBeEarly("target", targetClosed, targetAt)
	mustNotBeLate("human", humanAt)
	mustNotBeLate("target", targetAt)
	if humanCalls != 1 || targetCalls != 1 {
		t.Fatalf("closeAfterMachineDrain closed human %d time(s) and target %d time(s); each stream must be closed exactly once", humanCalls, targetCalls)
	}
	// Same ordering contract as the already-drained case: human, then
	// target.
	if targetAt.Before(humanAt) {
		t.Fatalf("closeAfterMachineDrain closed target before human (target at %v, human at %v after the wait began); the order is human then target", targetAt.Sub(start), humanAt.Sub(start))
	}
}

// TestCloseAfterMachineDrainDoesNothingOnNonCleanEnd: on a non-clean end
// core.Bridge has already closed both streams itself (to unblock a peer -
// see core/bridge.go's doc comment on Bridge and machine_conn.go's comment
// on the ctx field). closeAfterMachineDrain must return immediately without
// closing anything again, on this path, regardless of whether drained ever
// closes.
func TestCloseAfterMachineDrainDoesNothingOnNonCleanEnd(t *testing.T) {
	grace := sshx.ExitStatusGrace
	// grace/2 for the same reason as the already-drained case: the
	// regression this guards (the bridgeErr guard removed, so the function
	// falls into the bounded wait on a never-closing channel) blocks for
	// the whole 5s and is caught at 2.5s just as surely as at 500ms, with
	// five times the head-room for a loaded machine.
	returnBound := grace / 2

	drained := make(chan struct{}) // deliberately never closed: must not matter here
	human := &fakeCloser{}
	target := &fakeCloser{}

	done := make(chan struct{})
	go func() {
		closeAfterMachineDrain(errors.New("bridge error"), drained, human, target)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(returnBound):
		t.Fatalf("closeAfterMachineDrain blocked for %v on a non-clean end; core.Bridge already closed both streams on that path so this call must return immediately", returnBound)
	}
	if closed, calls, _ := human.snapshot(); closed || calls != 0 {
		t.Fatalf("closeAfterMachineDrain closed human on a non-clean end (calls=%d); core.Bridge already did that", calls)
	}
	if closed, calls, _ := target.snapshot(); closed || calls != 0 {
		t.Fatalf("closeAfterMachineDrain closed target on a non-clean end (calls=%d); core.Bridge already did that", calls)
	}
}
