//go:build linux || darwin

package winkeys

// doorwatch_maxwait_test.go — IAMT-305: the maxWait cap, proved exactly.
//
// TestDoorwatch_RunWatchdogHonoursMaxWait runs the real pidfd/kqueue watcher
// and used to fail whenever the machine was busy: it required the call to
// return within 5x maxWait (200ms -> 1s), while the loop's granularity is one
// watchdogPollWindow (500ms) of real polling and a loaded machine stretches
// that window by however long the process waits for a CPU. The observed reds
// were 1.246s and 2.85s — the scheduler, not the cap. (That test now asserts
// only the plumbing and a hung-test guard.)
//
// The cap itself cannot be pinned with a real clock: the poll count a deadline
// produces is a range, not a number, because each poll costs at least
// watchdogPollWindow but can cost arbitrarily more. The previous version of
// this file therefore bounded the count "from above with slack" (+4 polls) —
// and, as review round 11 pointed out, a deadline of maxWait+10ms produces a
// count that fits inside that slack, so the test could not see a changed
// deadline at all. Two changes fix that:
//
//   - runWatchdogUnix reads its clock through watchdogNow (doorwatch.go), so
//     this test can install a virtual clock. The fake watcher advances it by a
//     known pollCost per poll, which makes the loop's deadline arithmetic
//     exact: a loop that gives up after floor(maxWait/pollCost)+1 polls is
//     applying exactly maxWait, and any deadline that differs by one pollCost
//     or more changes the count — in both directions, including the dangerous
//     one (a longer cap: the watcher would outlive the door it guards).
//   - the fake records the wait it is handed, so the loop's cadence
//     (watchdogPollWindow) is pinned too, instead of only the count.

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// virtualClock is the seam value for watchdogNow. Nothing sleeps: the fake
// watcher moves this clock forward by pollCost per poll, so a test that polls
// 138 times finishes in microseconds and its verdict does not depend on the
// machine's load.
type virtualClock struct {
	now time.Time
}

func (c *virtualClock) Now() time.Time { return c.now }

func (c *virtualClock) advance(d time.Duration) { c.now = c.now.Add(d) }

// pollCountingWatcher is a parentWatcher that never reports the parent dead.
// Each poll costs the virtual clock pollCost — the model of a poll that returns
// as soon as it is asked, which the real watchers do on EINTR — so the loop's
// own deadline, not this fake, has to be what ends the wait. It also refuses to
// poll more than limit times, so a loop whose deadline is effectively absent
// (a hard-coded default far longer than the cap, or a deadline read from a
// clock this fake does not move) fails with a named error instead of spinning.
type pollCountingWatcher struct {
	polls    int
	limit    int
	pollCost time.Duration
	clock    *virtualClock
	// waits records every timeout the loop handed over, so a test can assert
	// the cadence the loop asks for and not only how many times it asked.
	waits []time.Duration
}

func (w *pollCountingWatcher) Wait(timeout time.Duration) (bool, error) {
	w.polls++
	w.waits = append(w.waits, timeout)
	if w.polls > w.limit {
		return false, fmt.Errorf("parent watcher polled %d times and the deadline still had not expired", w.polls)
	}
	w.clock.advance(w.pollCost)
	return false, nil
}

func (w *pollCountingWatcher) Close() {}

// TestRunWatchdogUnix_CapIsTheConfiguredMaxWait is the deterministic half of
// TestDoorwatch_RunWatchdogHonoursMaxWait: it asserts the loop stops because
// the maxWait it was given expired — not because some other deadline did (a
// hard-coded default, the dangerous direction: the watcher would outlive the
// door it guards), and not because the watcher's patience ran out.
//
// The count is exact rather than bounded: on a virtual clock that advances
// pollCost per poll, a deadline of exactly maxWait can only end the wait after
// floor(maxWait/pollCost)+1 polls. maxWait is deliberately not a multiple of
// pollCost, so a deadline off by a single pollCost — in either direction —
// produces a different number and this test says so.
//
// Canaries:
//   - change runWatchdogUnix's `deadline := watchdogNow().Add(maxWait)` to any
//     longer constant (a hard-coded default, or maxWait+10ms): the poll count
//     grows and the test fails with "the loop polled N times for a 137ms cap on
//     a clock that advances 1ms per poll: exactly 138 polls fit a deadline of
//     exactly 137ms, so the deadline it applies is not the maxWait it was
//     given" — and, on the same regression, "the loop gave up at 148ms
//     (virtual), want 138ms";
//   - shorten the deadline by one pollCost: the same two messages, with smaller
//     readings — the watcher that gives up early and leaves the line behind;
//   - hand the watcher anything other than watchdogPollWindow: "poll 1 was
//     handed a 137ms wait, want the shared watchdogPollWindow 500ms ...".
func TestRunWatchdogUnix_CapIsTheConfiguredMaxWait(t *testing.T) {
	const (
		maxWait  = 137 * time.Millisecond
		pollCost = 1 * time.Millisecond
		// limit is far above maxWait/pollCost (137) so a correct loop never
		// reaches it, and low enough that a loop on a much longer deadline is
		// caught instead of spinning.
		limit = 5000
	)
	clock := &virtualClock{now: time.Unix(1700000000, 0)}
	start := clock.Now()
	restore := watchdogNow
	watchdogNow = clock.Now
	t.Cleanup(func() { watchdogNow = restore })

	w := &pollCountingWatcher{limit: limit, pollCost: pollCost, clock: clock}
	err := runWatchdogUnix(w, os.Getpid(), strings.Repeat("a", 32), "/nonexistent/authorized_keys", nil, maxWait, "/nonexistent/door.lock", os.Getuid(), os.Getgid())

	if err == nil {
		t.Fatal("runWatchdogUnix must give up on a parent that never exits")
	}
	if !strings.Contains(err.Error(), "still alive after "+maxWait.String()) {
		t.Fatalf("runWatchdogUnix returned %v, want the timeout naming the configured maxWait %s — an error from the watcher means the deadline its loop applied was not this maxWait", err, maxWait)
	}
	if want := int(maxWait/pollCost) + 1; w.polls != want {
		t.Fatalf("the loop polled %d times for a %s cap on a clock that advances %s per poll: a deadline of exactly %s ends the wait after exactly %d polls, so the deadline the loop applies is not the maxWait it was given (IAMT-305 round 4)", w.polls, maxWait, pollCost, maxWait, want)
	}
	// The same fact stated as a moment rather than a count: the loop gave up on
	// the first poll AFTER the cap, and a deadline that moved by one pollCost
	// moves this reading with it.
	if want := start.Add(maxWait + pollCost); !clock.Now().Equal(want) {
		t.Fatalf("the loop gave up at %s (virtual), want %s: a deadline of exactly %s expires at %s, one %s poll after the cap — the deadline the loop applies is not the maxWait it was given (IAMT-305 round 4)", clock.Now().Sub(start), want.Sub(start), maxWait, want.Sub(start), pollCost)
	}
	for i, got := range w.waits {
		if got != watchdogPollWindow {
			t.Fatalf("poll %d was handed a %s wait, want the shared watchdogPollWindow %s: the loop's polling cadence is not the one the package documents", i+1, got, watchdogPollWindow)
		}
	}
}
