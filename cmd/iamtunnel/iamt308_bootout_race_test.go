package main

// iamt308_bootout_race_test.go — IAMT-308 round 4: a live Mac showed
// `launchctl bootout` returning before launchd's own job table had
// actually forgotten the label — the very next call, `launchctl
// bootstrap`, raced that still-settling teardown and answered exit
// status 5, "Bootstrap failed: 5: Input/output error" (confirmed by
// hand: bootstrapping a label that genuinely IS still loaded gives the
// identical error). waitForGone (gateway.go) is the fix's polling half,
// platform-neutral and pure enough to pin directly with a fake check
// function — the darwin production seam (gateway_launchd_darwin.go)
// wires it around a real "launchctl print" query, which these tests
// cannot reach on a non-darwin host.

import (
	"errors"
	"testing"
	"time"
)

// TestWaitForGone_AlreadyGoneSucceedsInOneCall is the base case: the
// label is already gone on the first check — no waiting, no retries.
//
// Canary: break the early `!loaded` check (for example, spin through all
// attempts every time) — the call-count check below turns red.
func TestWaitForGone_AlreadyGoneSucceedsInOneCall(t *testing.T) {
	calls := 0
	err := waitForGone(func() (bool, error) {
		calls++
		return false, nil
	})
	if err != nil {
		t.Fatalf("waitForGone must succeed when the first check already says gone: %v", err)
	}
	if calls != 1 {
		t.Fatalf("waitForGone must not poll again once the label is already gone: got %d calls", calls)
	}
}

// TestWaitForGone_RetriesUntilGone models the exact live-Mac race:
// bootout accepted, but launchd still reports the label loaded for a
// couple of polls before it actually clears.
//
// Canary: remove the retry loop in waitForGone (check only once) —
// "waitForGone must succeed once the label clears" turns red.
func TestWaitForGone_RetriesUntilGone(t *testing.T) {
	prevSleep := installLivenessSleep
	installLivenessSleep = func(time.Duration) {}
	t.Cleanup(func() { installLivenessSleep = prevSleep })

	calls := 0
	err := waitForGone(func() (bool, error) {
		calls++
		return calls < 3, nil // "loaded" twice, then "gone"
	})
	if err != nil {
		t.Fatalf("waitForGone must succeed once the label clears: %v", err)
	}
	if calls != 3 {
		t.Fatalf("waitForGone must stop polling the instant the label clears: got %d calls, want 3", calls)
	}
}

// TestWaitForGone_FailsWhenNeverGone is the timeout path: the label
// stays loaded for every attempt — waitForGone must give up and report
// it, not hang or silently claim success.
//
// Canary: make waitForGone return nil while still loaded —
// "waitForGone must fail" below turns red.
func TestWaitForGone_FailsWhenNeverGone(t *testing.T) {
	prevSleep := installLivenessSleep
	installLivenessSleep = func(time.Duration) {}
	t.Cleanup(func() { installLivenessSleep = prevSleep })

	calls := 0
	err := waitForGone(func() (bool, error) {
		calls++
		return true, nil // still loaded, every time
	})
	if err == nil {
		t.Fatal("waitForGone must fail when the label never clears")
	}
	if calls != installLivenessAttempts {
		t.Fatalf("waitForGone must use every attempt before giving up: got %d calls, want %d", calls, installLivenessAttempts)
	}
}

// TestWaitForGone_PropagatesQueryError: a query that cannot even answer
// must surface its own error, not a generic "still loaded" — the
// operator needs to know launchctl itself is failing, not just that the
// label looks stuck.
//
// Canary: replace the returned error with a generic "still loaded" —
// the errors.Is below turns red.
func TestWaitForGone_PropagatesQueryError(t *testing.T) {
	prevSleep := installLivenessSleep
	installLivenessSleep = func(time.Duration) {}
	t.Cleanup(func() { installLivenessSleep = prevSleep })

	wantErr := errors.New("launchctl print: permission denied")
	err := waitForGone(func() (bool, error) {
		return false, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("waitForGone must propagate the query's own error: got %v, want %v", err, wantErr)
	}
}
