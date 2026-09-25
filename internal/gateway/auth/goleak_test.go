package auth

// goleak_test.go: IAMT-314. See internal/sshx/goleak_test.go for why the
// check is wired per package rather than once over ./....
//
// This is the package that proves the point. auth owns the RateLimiter
// whose A-3 sweeper (ratelimit.go, sweepLoop) is started by
// NewRateLimiter and stopped only by Close - the goroutine class that
// leaked unnoticed until a human found it, with -race green the whole
// time because nothing was racing, something was simply never ending.
//
// Wiring it here found that the tests themselves were leaking it: four
// RateLimiters were built and never closed (the auditRate helper in
// ratelimit_test.go, the world fixture in auth_test.go, and two cases in
// regression_findings_test.go). Those now close their limiters. That is a
// fix, not a workaround: Close exists precisely for this, and a test
// that never calls it cannot notice if Close stops working.
//
// A second run caught the last one, and it is worth recording because it
// is a shape rather than an oversight: TestNewRateLimiterRejectsBadConfig
// ends by proving a VALID config is accepted, and threw that limiter away
// into "_". A valid config means the sweeper had already started, so that
// one discarded return value was enough to fail the package on its own.
// The six invalid configs in the same test are harmless for the mirror
// reason: validation runs before the goroutine does.
//
// The sweeper is never ignored and must never be. It is a product
// goroutine that is required to finish; an ignore for it would make this
// whole file decorative. The same goes for any other gateway sweeper,
// the machine serve loop, and doorwatch.
//
// No ignores in this package.
//
// Round 4 closed the loop on the caller. gateway.New builds one of these
// limiters (gateway.go:186) and Gateway.Close used not to close it, so
// the sweeper outlived the gateway that owned it - a product leak, and
// the reason internal/gateway itself went unwired for three rounds.
// Gateway.Close now calls g.rate.Close() after g.wg.Wait(), once no
// handshake handler can still be consulting the limiter, and
// internal/gateway has its own TestMain and its own named canary
// (iamt314_rate_sweeper_lifecycle_test.go). internal/client is still
// out, for its own reason: its goroutines are bounded by a single
// Connect call.
//
// LEAK CANARY (make the edit, run, revert): delete the
//
//	t.Cleanup(l.Close)
//
// line from auditRate in ratelimit_test.go. Every test built on that
// helper then leaves its sweeper running and this package goes red on
//
//	github.com/ultrathinker/iamtunnel/internal/gateway/auth.(*RateLimiter).sweepLoop
//
// - the exact stack of the goroutine that was leaked, which is the whole
// point of doing this per package.

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
