package gateway

// iamt314_rate_sweeper_lifecycle_test.go: Gateway.Close must stop the rate
// limiter's sweeper, and this file is the named canary for that.
//
// gateway.New builds an auth.RateLimiter, and NewRateLimiter starts the A-3
// sweeper goroutine. Until IAMT-314 round 4, Gateway.Close stopped its own
// sweepers and waited on its own WaitGroups but never called g.rate.Close(),
// so every gateway in a process left one sweeper behind. In production that
// is one goroutine for the lifetime of a process that has exactly one
// gateway - benign, and the comment on RateLimiter.Close said so. In tests
// it is one per gateway, and it is the exact goroutine class this ticket
// exists to catch.
//
// Why a named test and not only the package-level goleak check:
//
//   - a goleak failure at the end of the package names the goroutine but not
//     the lifecycle rule it broke, and it lands on whichever test happened to
//     run last. This one says "Gateway.Close did not stop the sweeper" on its
//     own line;
//   - the pre-existing broad leak check, iamt175_goroutine_leak_test.go, is
//     deliberately scoped to frames of package github.com/ultrathinker/iamtunnel/internal/gateway
//     itself ("gateway." and not "gateway/"), so a goroutine owned by
//     internal/gateway/auth never matched it. That is precisely why this leak
//     survived a package that already had a leak test.
//
// It is a diff against a baseline taken before the fixture is built, not an
// absolute count, so leftovers from any earlier test cannot make it fire and
// cannot make it pass either. The tests in this package do not run in
// parallel (no t.Parallel anywhere), so the snapshot is stable.
//
// CANARY: delete the g.rate.Close() call from Gateway.Close in gateway.go and
// this test fails on every run, naming the sweeper, before the package-level
// goleak check gets a word in.

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// rateSweeperFrame is the frame that identifies the sweeper goroutine in a
// runtime stack dump. It is the function itself, not NewRateLimiter: the
// "created by" line names the constructor, the frame list names the loop, and
// nothing calls sweepLoop synchronously, so one match means one live sweeper.
const rateSweeperFrame = "github.com/ultrathinker/iamtunnel/internal/gateway/auth.(*RateLimiter).sweepLoop"

// liveSweepers counts the goroutines whose stack contains rateSweeperFrame.
func liveSweepers() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	n := 0
	for _, block := range strings.Split(string(buf), "\n\ngoroutine ") {
		if strings.Contains(block, rateSweeperFrame) {
			n++
		}
	}
	return n
}

func TestIAMT314_GatewayCloseStopsTheRateLimiterSweeper(t *testing.T) {
	before := liveSweepers()

	f := newFixture(t, nil)

	// First half of the contract: the sweeper really is running while the
	// gateway is alive. Without this the test would also pass on a build
	// where NewRateLimiter stopped starting it at all, and would then be
	// guarding nothing. The goroutine is created inside New, so this is a
	// scheduling wait, not a timing assumption.
	deadline := time.Now().Add(5 * time.Second)
	for liveSweepers() <= before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := liveSweepers(); got <= before {
		t.Fatalf("no new %s goroutine appeared after gateway.New (before=%d, now=%d); "+
			"this test cannot prove Close stops a sweeper that never started",
			rateSweeperFrame, before, got)
	}

	if err := f.gw.Close(); err != nil {
		t.Fatalf("Gateway.Close: %v", err)
	}

	// Second half: after Close the count is back to the baseline.
	// auth.RateLimiter.Close closes sweepStop and then waits on sweepDone,
	// which sweepLoop closes on its way out, so by the time Gateway.Close
	// has returned the loop has already run its last statement - the only
	// thing left is the runtime reaping the goroutine, which is what this
	// short bounded poll absorbs. It is decay protection, not the assertion.
	deadline = time.Now().Add(5 * time.Second)
	for {
		got := liveSweepers()
		if got <= before {
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatalf("CANARY: %d %s goroutine(s) still running 5s after Gateway.Close "+
				"returned (baseline before this test: %d). Gateway.Close owns the "+
				"limiter it built in New and must call g.rate.Close(); nothing else "+
				"in the process will.",
				got-before, rateSweeperFrame, before)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
