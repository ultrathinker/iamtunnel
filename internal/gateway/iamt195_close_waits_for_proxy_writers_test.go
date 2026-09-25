package gateway

// iamt195_close_waits_for_proxy_writers_test.go isolates the two IAMT-172
// proxy-writer canaries that TestIAMT172_CloseWaitsForProxyChannelRequests
// (iamt172_close_waits_for_writers_test.go) cannot tell apart, and cannot
// reliably tell apart from "the transport died first":
//
//   - that test's block is entirely on request-stream I/O (fwdTo.SendRequest,
//     for r := range src). Gateway.Close tears down every machine and human
//     transport (mc.teardown -> mc.sconn.Close(), then closing every raw
//     net.Conn in g.conns) BEFORE g.wg.Wait, so a writer blocked only on that
//     transport unblocks on its own the moment Close starts tearing it down -
//     a race Close wins in practice, per the canary run:
//     removing g.wg.Add/Done around go proxyChannelRequests left the test
//     green, because the goroutine exits before the 500ms assertion even
//     though nothing waited for it.
//
// The two tests below block each writer on a resource Close never touches:
// a fake core.Recording whose Resize/ExitStatus method parks on a channel
// only the test controls. Neither method is reachable from outside the
// package as a product "test hook" - Config.NewRecording is the existing,
// already-reviewed injection seam (see config.go's own comment: "a test
// replaces this to observe recorder failures... exactly the constructor
// seam"), and blockingResizeRecording/
// blockingExitStatusRecording are ordinary core.Recording implementations
// defined in this test file, not new product surface.
//
// Round 2 fixed two bugs the canary run caught:
//
//  1. TestIAMT195_CloseWaitsForProxyChannelRequests_Resize sent
//     "window-change" with wantReply=false, so it never reached Resize at
//     all (canary precondition failure, not the intended assertion). The
//     reason: sshx.ApplyDisposition's Forward case treats the *forwarded*
//     call's own return value as the verdict - forward := func() (bool,
//     error) { return fwdTo.SendRequest(r.Type, r.WantReply, r.Payload) }
//     (human_role.go's proxyChannelRequests) - and golang.org/x/crypto/ssh's
//     channel.SendRequest ALWAYS returns ok=false when wantReply is false
//     (it does not wait for a reply, so it has nothing to report as ok=true;
//     see ssh/channel.go's SendRequest). ApplyDisposition then sees ok=false
//     and returns Reject, so proxyChannelRequests's `if applied !=
//     sshx.Forward { continue }` skips the resizeRecording switch entirely -
//     for ANY request forwarded with wantReply=false, not just this test's.
//     Every other test in this package that exercises window-change
//     (accept_independent_test.go, adversarial_gateway_test.go,
//     scenarios_test.go, shutdown_test.go) already sends it with
//     wantReply=true for exactly this reason; this file now matches that
//     convention.
//
//  2. TestIAMT195_CloseWaitsForProxyMachineRequests_ExitStatus's first
//     500ms window could never observe the canary, in either build: the
//     human session's own goroutine (wrapped in g.wg one level up, in
//     handleHuman) calls closeAfterMachineDrain, which waits on
//     mreqsDrained for up to sshx.ExitStatusGrace (5s) before forcing
//     human/target closed regardless (human_role.go's own doc comment on
//     closeAfterMachineDrain explains the bound). mreqsDrained only closes
//     once proxyMachineRequests returns - which, with our fake still
//     parked in ExitStatus, it cannot do until the test releases it. So
//     with the g.wg wrapper REMOVED from proxyMachineRequests, Close's
//     g.wg.Wait still has that outer, correctly-wrapped goroutine to wait
//     for, and that goroutine's own wait is bounded by the SAME 5 seconds -
//     Close does not return within 500ms in the buggy build either, purely
//     because of this unrelated timer, masking the missing wrapper
//     entirely. The fix: wait past sshx.ExitStatusGrace (with margin)
//     before treating "Close has not returned" as inconclusive. Past that
//     point the outer goroutine has forced human/target closed and
//     finished on its own regardless of our target's wrapper, so if Close
//     still has not returned, the fix is genuinely holding it (the fake is
//     still parked and nothing else could still be counted); if Close HAS
//     returned by then, the wrapper is missing, and the counter check below
//     catches it deterministically (the fake cannot have unparked itself -
//     only this test's release does that, and it has not run yet).
//
// Each test drives ONLY the one goroutine it names into the fake's blocking
// method; the other proxy writer is left free to exit however it likes
// (transport teardown or a natural drain) because g.wg.Wait must still wait
// for whichever writer is genuinely parked, regardless of what happens to
// its sibling.

import (
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// blockingResizeRecording is a minimal core.Recording plus the duck-typed
// Resize(int, int) error method resizeRecording (human_role.go) looks for.
// Resize parks on release so proxyChannelRequests cannot return while a
// pty-req/window-change is in flight, independent of transport state.
type blockingResizeRecording struct {
	started chan struct{}
	release <-chan struct{}
}

func (r *blockingResizeRecording) Write(p []byte) (int, error) { return len(p), nil }
func (r *blockingResizeRecording) Close() error                { return nil }
func (r *blockingResizeRecording) Abort(string) error          { return nil }
func (r *blockingResizeRecording) AddBytesIn([]byte)           {}
func (r *blockingResizeRecording) Resize(cols, rows int) error {
	close(r.started)
	<-r.release
	return nil
}

// blockingExitStatusRecording is a minimal core.Recording plus the
// duck-typed ExitStatus(uint32) error / ExitSignal(string) error pair
// (execExitRecorder in human_role.go). ExitStatus parks on release so
// proxyMachineRequests cannot return while the machine's exit-status is in
// flight, independent of transport state.
type blockingExitStatusRecording struct {
	started chan struct{}
	release <-chan struct{}
}

func (r *blockingExitStatusRecording) Write(p []byte) (int, error) { return len(p), nil }
func (r *blockingExitStatusRecording) Close() error                { return nil }
func (r *blockingExitStatusRecording) Abort(string) error          { return nil }
func (r *blockingExitStatusRecording) AddBytesIn([]byte)           {}
func (r *blockingExitStatusRecording) ExitStatus(status uint32) error {
	close(r.started)
	<-r.release
	return nil
}
func (r *blockingExitStatusRecording) ExitSignal(string) error { return nil }

// TestIAMT195_CloseWaitsForProxyChannelRequests_Resize is canary A. A
// window-change forces proxyChannelRequests into resizeRecording -> our
// fake's Resize, which parks on a channel the test owns. Close cuts every
// transport first, so the sibling writer (proxyMachineRequests) is free to
// drain on its own; only the parked Resize call can still be holding
// proxyReqsInFlight non-zero when Close reaches g.wg.Wait.
//
// Removing g.wg.Add(1)/defer g.wg.Done() around the go proxyChannelRequests
// launch in human_role.go (counter left in place) reddens this test:
// Close returns almost immediately (nothing counts the parked goroutine any
// more) while our Resize call is still blocked on <-release, so
// proxyReqsInFlight is provably non-zero at that instant.
func TestIAMT195_CloseWaitsForProxyChannelRequests_Resize(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	f := newFixture(t, func(c *Config) {
		c.NewRecording = func(SessionInfo) (core.Recording, error) {
			return &blockingResizeRecording{started: started, release: release}, nil
		}
	})

	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	humanClient, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	hs := openHumanSession(t, humanClient, f)
	hs.shell(t)

	waitForInFlight(t, &f.gw.proxyReqsInFlight, 2, 3*time.Second,
		"IAMT-195 canary precondition failed: the human session never reached proxyChannelRequests")

	// window-change MUST carry wantReply=true here: proxyChannelRequests's
	// forward() reports success (sshx.ApplyDisposition's Forward case)
	// using fwdTo.SendRequest's own return value, and golang.org/x/crypto/
	// ssh's SendRequest always returns ok=false when wantReply is false (it
	// is not waiting for a reply, so it has nothing to report) - which
	// ApplyDisposition would then read as a failed forward and skip the
	// resizeRecording switch entirely, without ever entering Resize. Every
	// other window-change send in this package already uses wantReply=true
	// for the same reason (see the file doc comment).
	w := sshx.WindowChange{Columns: 100, Rows: 40}
	if ok, err := hs.ch.SendRequest("window-change", true, sshx.MarshalWindow(w)); err != nil || !ok {
		t.Fatalf("send window-change: ok=%v err=%v", ok, err)
	}

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("IAMT-195 canary precondition failed: Resize was never entered after window-change")
	}

	closeReturned := make(chan struct{})
	go func() {
		defer close(closeReturned)
		_ = f.gw.Close()
	}()

	select {
	case <-closeReturned:
		if got := f.gw.proxyReqsInFlight.Load(); got != 0 {
			t.Fatalf("CANARY (IAMT-195): gw.Close returned with %d proxy writer(s) still in flight while "+
				"proxyChannelRequests was parked inside Resize (released only by this test) - "+
				"g.wg.Add/Done around the go proxyChannelRequests launch in human_role.go was removed", got)
		}
	case <-time.After(500 * time.Millisecond):
		// Hang protection, not the assertion: with the fix, Close is
		// parked on g.wg.Wait because Resize cannot return on its own.
		// Nothing else in this session (proxyMachineRequests included)
		// depends on our fake, so there is no confounding wait here -
		// unlike canary B below, this 500ms window is already conclusive.
		t.Logf("IAMT-195: Close still waiting for proxyChannelRequests's Resize call under g.wg.Wait")
	}

	close(release)

	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("gw.Close deadlocked even after the test released Resize")
	}

	if got := f.gw.proxyReqsInFlight.Load(); got != 0 {
		t.Fatalf("IAMT-195: proxyReqsInFlight = %d after Close returned and Resize was released; expected 0", got)
	}

	_ = humanClient.Close()
}

// TestIAMT195_CloseWaitsForProxyMachineRequests_ExitStatus is canary B.
// Closing the human channel's write side lets Bridge close the nested
// channel's write side in turn (core/bridge.go: "err == nil ... CloseWrite"),
// which is exactly what makes the fake target sshd's echo loop
// (harness_test.go's serveEchoSession) see EOF and send a real
// "exit-status" back - the same request proxyMachineRequests always forwards
// (human_role.go). Our fake Recording's ExitStatus parks on that request,
// on a channel only the test owns, before Close ever runs.
//
// The first wait window is sshx.ExitStatusGrace (+ margin), not 500ms: see
// the file doc comment for why 500ms cannot distinguish the two builds here
// - the session's own goroutine (correctly g.wg-wrapped one level up) waits
// on the SAME grace period for mreqsDrained via closeAfterMachineDrain
// before forcing the session closed regardless, so Close does not return
// within 500ms in either build. Past ExitStatusGrace, that confound is
// gone: if the wrapper around proxyMachineRequests is missing, Close
// returns once that outer goroutine's own timer fires; if the wrapper is
// present, Close is still held by g.wg.Wait on our still-parked ExitStatus
// call, which nothing but this test's release can end.
//
// Removing g.wg.Add(1)/defer g.wg.Done() around the go proxyMachineRequests
// launch in human_role.go (counter left in place) reddens this test: Close
// returns at the ExitStatusGrace boundary while ExitStatus is still blocked
// on <-release, so proxyReqsInFlight is provably non-zero at that instant.
func TestIAMT195_CloseWaitsForProxyMachineRequests_ExitStatus(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	f := newFixture(t, func(c *Config) {
		c.NewRecording = func(SessionInfo) (core.Recording, error) {
			return &blockingExitStatusRecording{started: started, release: release}, nil
		}
	})

	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	humanClient, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	hs := openHumanSession(t, humanClient, f)
	hs.shell(t)

	waitForInFlight(t, &f.gw.proxyReqsInFlight, 2, 3*time.Second,
		"IAMT-195 canary precondition failed: the human session never reached proxyMachineRequests")

	if err := hs.ch.CloseWrite(); err != nil {
		t.Fatalf("human CloseWrite: %v", err)
	}

	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("IAMT-195 canary precondition failed: ExitStatus was never entered after human CloseWrite")
	}

	closeReturned := make(chan struct{})
	go func() {
		defer close(closeReturned)
		_ = f.gw.Close()
	}()

	select {
	case <-closeReturned:
		if got := f.gw.proxyReqsInFlight.Load(); got != 0 {
			t.Fatalf("CANARY (IAMT-195): gw.Close returned with %d proxy writer(s) still in flight while "+
				"proxyMachineRequests was parked inside ExitStatus (released only by this test) - "+
				"g.wg.Add/Done around the go proxyMachineRequests launch in human_role.go was removed", got)
		}
	case <-time.After(sshx.ExitStatusGrace + 2*time.Second):
		// Hang protection, not the assertion - see the file doc comment on
		// why this window must clear sshx.ExitStatusGrace, not just be a
		// short constant like canary A's 500ms.
		t.Logf("IAMT-195: Close still waiting for proxyMachineRequests's ExitStatus call under g.wg.Wait")
	}

	close(release)

	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("gw.Close deadlocked even after the test released ExitStatus")
	}

	if got := f.gw.proxyReqsInFlight.Load(); got != 0 {
		t.Fatalf("IAMT-195: proxyReqsInFlight = %d after Close returned and ExitStatus was released; expected 0", got)
	}

	_ = humanClient.Close()
}
