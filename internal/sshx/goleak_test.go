package sshx

// goleak_test.go: IAMT-314, leaf package, first of the chain.
//
// Gate 5 runs -race, which catches memory that two goroutines touch at
// once. Nothing in this repository catches a goroutine that was started
// and never returned: the rate-limiter sweeper leak (auth's A-3) lived
// unnoticed until a human read the code. goleak closes that hole by
// photographing the process's goroutines after the last test in this
// package has finished and failing if any of them is still there.
//
// Wired per package, from the leaves toward the root, never as ./... at
// once: a single global check would report a leak against whichever
// package happened to run last, and the whole value of this is that the
// red lands on the package that owns the goroutine.
//
// WHAT IT FOUND HERE, ON THE FIRST RUN
//
// Every test passed and the package still failed, on
// (*fakeSSHD).session parked in a channel receive. That was not a
// flake and not a race: the fixture's session handler waited on a
// "started" channel that only a shell or exec request ever closed, and
// the gateway stand-in opens the nested session as soon as the human
// opens his channel - before any shell, and in
// TestEnvForbiddenAnswersFailure instead of any shell, since that test
// only exercises env. Nothing else could ever close "started", so the
// goroutine stood there until the process exited. Every run of that
// test leaked one.
//
// The product's own version of that wait - awaitSessionStart in
// internal/gateway/human_role.go - exits on three conditions, not one:
// the start request, a closed request stream, and a timeout. The
// fixture had only the first. It now also leaves on the closed request
// stream and on its own shutdown, and all three fixtures in
// endtoend_helpers_test.go (fake sshd, gateway, machine) count their
// goroutines in a WaitGroup, tear their accepted connections down from
// t.Cleanup, and wait. Nothing here is ignored away.
//
// No ignores at all in this package, by design: an ignore that is not
// needed is an ignore nobody will question later. Every ignore anywhere
// in this repository must name the one goroutine it allows and say why
// that goroutine is permitted to outlive the tests; a bare
// goleak.IgnoreCurrent or a broad IgnoreTopFunction turns the check
// green and worthless. That goes double here: this is the package the
// check was wired into first, and an exception for the very leak it
// caught would have made the whole exercise decorative.
//
// LEAK CANARY (make the edit, run, revert): in
// endtoend_helpers_test.go, in (*fakeSSHD).session, replace the whole
// IAMT-314 block - both selects, from "select {" through the closing
// brace of the one with the default - with the single line it replaced:
//
//	<-started
//
// TestEnvForbiddenAnswersFailure then leaks its session handler again
// and this package goes red on
//
//	github.com/ultrathinker/iamtunnel/internal/sshx.(*fakeSSHD).session
//
// with "chan receive" as the state - byte for byte the failure that
// rejected the first round of this ticket, which is the strongest
// evidence a canary can have: it is not hypothetical, it already
// happened.

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
