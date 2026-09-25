package gateway

// goleak_test.go: IAMT-314, the root package, wired last. See
// internal/sshx/goleak_test.go for why the check is per package and never
// ./... at once.
//
// WHY THIS PACKAGE WAS NOT WIRED EARLIER, AND WHY IT IS NOW
//
// Earlier rounds of this ticket left internal/gateway out and said so in
// internal/gateway/auth/goleak_test.go: gateway.New built an
// auth.RateLimiter, NewRateLimiter started its sweeper, and Gateway.Close
// never called g.rate.Close(), so every gateway in the process left one
// sweeper behind. Documenting a leak and then declining to check the package
// because of it is backwards - it is the package where IAMT-304 found that
// goroutine class by hand, so it is the package that most needs the check.
// Round 4 fixes the product instead: Gateway.Close now stops the limiter, at
// the point in its ordering where no handler can still be consulting it, and
// this file is the check that keeps it stopped. The lifecycle also has its
// own named canary in iamt314_rate_sweeper_lifecycle_test.go, which fails
// with a sentence rather than a stack dump.
//
// The goroutines this package owns, and what ends each of them:
//
//   - the expiry and recording sweepers, and every connection handler and
//     proxy writer: counted in g.wg, ended by Close (sweepStop, the listener,
//     the machine teardowns and the raw transports), waited for by g.wg.Wait;
//   - the sshd-probe goroutines (IAMT-161): counted in g.probesWG, waited for
//     after g.wg;
//   - the rate limiter's sweeper: stopped by g.rate.Close(), which itself
//     waits on sweepDone;
//   - core.Bridge's two copy goroutines: joined inside Bridge before it
//     returns.
//
// Every one of them is a product goroutine that is required to finish. None
// of them may ever be ignored here. No ignores in this package, and an
// IgnoreCurrent or a broad IgnoreTopFunction would defeat the entire ticket
// in the one package it was filed about.
//
// The fixtures were brought up to the same standard as the ones in
// internal/sshx and internal/server in the same round: fakeTargetSSHD (with
// its serveEchoSession, which had the same "<-started" wait with no other
// exit that goleak caught in sshx), fakeMachine and spyMachine now each count
// their goroutines in a WaitGroup, keep what they dial or accept in a
// connSet, and tear down in the only order that cannot hang - cut the
// transports first, wait second.
//
// WHAT WIRING IT CAUGHT ON THE FIRST RUN
//
// A second leak, unrelated to the first, which is the whole argument for
// wiring the package rather than reasoning about it. Three fixtures built
// an ssh.Client by hand - dialHumanClient here, newFakeHuman in
// iamt126_human_keepalive_test.go, dialFailureReplyingHuman in
// iamt220_human_keepalive_policy_test.go - and handed ssh.NewClient a
// fresh chan *ssh.Request so that x/crypto's default "reply false to
// everything" handler would not eat the real global requests. Two of them
// carried a comment saying the goroutine would "park there harmlessly".
// It parks there permanently: handleGlobalRequests ranges over exactly
// that channel and has no other exit, so nothing - not closing the
// client, not closing the connection, not ending the test - could ever
// release it. Every fixture human leaked one.
//
// All three now close that channel from the goroutine that drains the
// real request stream, so the fake channel's lifetime is the transport's
// lifetime and no new ownership rule has to be remembered. The pattern is
// not invented here: internal/admin/client.go does the same thing in
// production, holding its noopReqs on the Conn and closing it in
// Conn.Close. internal/client/dial.go needs nothing at all - it passes
// the real reqs channel, which x/crypto's own mux closes on teardown.
//
// And a third, on the next run: two tests in dormant_f2_3_test.go called
// New(cfg) for the sole purpose of reading the admin.op line New writes
// when it drops an expired grant, and threw the *Gateway into "_". By the
// time New returns it has already started the expiry sweeper, the
// recording sweeper and the rate limiter's sweeper, and Close is the only
// thing that stops any of them - so discarding the handle discards the
// only way to stop them. That is the shape this whole ticket opened with
// (a valid auth.RateLimiter dropped into "_") one layer up. Both now keep
// the gateway and close it from t.Cleanup. Every other New/gateway.New in
// the repository - eleven of them, in this package, in internal/client, in
// test/e2e and in cmd/iamtunnel - already binds and closes.
//
// LEAK CANARY, third one (make the edit, run, revert): change
//
//	gw, err := New(cfg)
//
// back to "if _, err := New(cfg); err != nil {" in either test in
// dormant_f2_3_test.go and drop the matching t.Cleanup. The package goes
// red on three stacks at once - sweepExpired and sweepRecordings at
// gateway.go:263 and :337, and auth.(*RateLimiter).sweepLoop - and on
// -count=2 it goes red on twice as many.
//
// LEAK CANARY, second one (make the edit, run, revert): delete the
//
//	defer close(noopReqs)
//
// line from dialHumanClient in harness_test.go. Every fixture human then
// leaks its handler again and this package goes red on
//
//	golang.org/x/crypto/ssh.(*Client).handleGlobalRequests
//
// in state "chan receive", created by ssh.NewClient - byte for byte the
// failure that rejected round 4.
//
// LEAK CANARY (make the edit, run, revert): delete the
//
//	g.rate.Close()
//
// call from Gateway.Close in gateway.go. Every test that builds a gateway
// then leaves a sweeper behind and this package goes red on
//
//	github.com/ultrathinker/iamtunnel/internal/gateway/auth.(*RateLimiter).sweepLoop
//
// created by auth.NewRateLimiter at ratelimit.go:102 - and
// TestIAMT314_GatewayCloseStopsTheRateLimiterSweeper fails first, saying why
// in words.

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
