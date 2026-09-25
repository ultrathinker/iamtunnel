package server

// goleak_test.go: IAMT-314. See internal/sshx/goleak_test.go for why the
// check is wired per package rather than once over ./....
//
// server is the busiest package wired in this round. Machine.Serve runs
// three long-lived goroutines - the conn.Wait watcher, the keepalive
// responder over m.reqs, and the keepalive prober - plus one pair of
// copy goroutines per spliced target channel. Every one of them is tied
// to the transport: they end when the SSH connection dies, and the tests
// end it (cancel the context, then wait for Serve to return). That is
// the contract this file now enforces rather than assumes. The machine
// serve loop is a product goroutine that is required to finish and must
// never be ignored here.
//
// FIXTURE SHUTDOWN (IAMT-314, round 2)
//
// goleak's first run against internal/sshx failed on a fixture, not on
// product code: a fake sshd session handler waiting on a "started"
// channel that only a shell or exec request could close, with no exit
// for the case where neither ever arrives. serveEchoSession in
// testhelpers_test.go had the identical shape. Here it never actually
// fired - the one test in this package that opens a nested session does
// send shell - so it was a booby trap rather than a live leak, and it is
// fixed the same way: leave on the closed request stream and on the
// fixture's own shutdown, not on "started" alone.
//
// The three fixtures in this package (fakeSSHD, fakeGateway,
// reviewGateway) now each count their goroutines in a WaitGroup, keep
// the connections they accept in a connSet, and tear down from
// t.Cleanup in the only order that cannot hang: close the listener and
// the accepted connections first - that is what ends every "range
// chans" and "range reqs" - and only then wait. Closing the listener
// alone was not enough; it does not touch a connection already accepted.
// The accept goroutine that tests used to start themselves with
// "go gw.acceptOne()" is now started by gw.startAccept(), so the
// fixture owns it and can join it.
//
// Round 3 added the other half of the same idea. Five tests launched
// "go m.Serve(ctx)" and never waited for it: cancelling the context only
// starts the unwind, and Serve still has to stop the prober (which waits
// for the probe loop) and clean the door before it returns. That is the
// same discard shape as a RateLimiter built into "_", one layer up. They
// all go through serveInBackground now, which joins Serve on cleanup with
// a bounded wait, so a Serve that does not return reports it instead of
// stalling the suite.
//
// What is deliberately NOT joined: the "go ssh.DiscardRequests(...)"
// calls inside individual tests, over channels and connections those
// tests close themselves. Those goroutines always have an exit - the
// request stream closes with its transport - so they are a question of
// promptness, not of a goroutine with nowhere to go. If one ever shows
// up, it names the test that owns it.
//
// No ignores in this package.
//
// LEAK CANARY (make the edit, run, revert): in machine.go, add one line
// as the first statement of Machine.Serve
//
//	go func() { select {} }() // IAMT-314 canary
//
// Every test that serves a machine then leaves a goroutine behind and
// this package goes red on
//
//	github.com/ultrathinker/iamtunnel/internal/server.(*Machine).Serve.func1
//
// - the serve loop's own stack, which is exactly the kind of goroutine
// that must never be ignored away.

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
