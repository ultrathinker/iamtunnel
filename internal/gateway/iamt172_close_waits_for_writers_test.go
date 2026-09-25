package gateway

// iamt172_close_waits_for_writers_test.go is the IAMT-172 canary suite.
//
// IAMT-172 closes the gap IAMT-161 left open: the sshd probe was the
// only fire-and-forget writer accounted for. serveCommandSession
// (admin_role.go) and proxyChannelRequests (human_role.go) also write
// events.jsonl and the recording, and they were fire-and-forget `go`
// launches too. IAMT-172 wraps each of those launches with
// `g.wg.Add(1)` / `defer g.wg.Done()` so Gateway.Close blocks until
// every connection-scoped writer has finished.
//
// Round 4: the round-3 canaries counted goroutines by scraping
// runtime.Stack with a "production-only" filter. That is
// nondeterministic by construction — the filter counted the test's own
// goroutine (its top-frame file line ends in ":<line> +0x<offset>", so
// the "_test.go" suffix check never matched), and in a full package run
// it sees the fixtures and leftovers of neighbouring tests. The
// canaries now read the same unexported
// in-flight counters the IAMT-161 canary reads for the probe:
// serveCmdInFlight and proxyReqsInFlight on Gateway. Both are set
// synchronously at the launch site (before the `go`), so "counter == 1"
// does not depend on scheduler timing at all, and the goroutine
// decrements its counter before its g.wg.Done, so on a fixed build
// "Close returned" implies "counter == 0".
//
// The assertion pair:
//   - while the writer cannot finish (Store.mu held, transport alive),
//     Close does NOT return;
//   - at the moment Close returns, the counter is 0.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// waitForInFlight polls counter until it reaches want. The deadline is
// hang protection, not an assertion: the counters are set synchronously
// at the launch site, so reaching `want` only proves the writer was
// launched — if it never is, the test fails loudly instead of hanging.
func waitForInFlight(t *testing.T, counter *atomic.Int64, want int64, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if got := counter.Load(); got >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s (in-flight counter never reached %d in %s; last value %d)",
				msg, want, timeout, counter.Load())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// TestIAMT172_CloseWaitsForServeCommandSession is canary A for the
// serveCommandSession rule. It opens a command-login SSH connection and
// sends a valid people.add exec. With Store.mu held by the test, the
// handler parks at its first Store access (runCommand's role check →
// cmdPeopleAdd's Store.Update) and cannot return. With the fix
// (g.wg.Add/Done around go g.serveCommandSession), Close blocks on
// g.wg.Wait() until the test releases the lock. Without the fix, Close
// returns while serveCmdInFlight is still 1 — that non-zero counter at
// Close return is the assertion.
func TestIAMT172_CloseWaitsForServeCommandSession(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		// Safety net, not the assertion (same shape as the IAMT-161
		// canary): if anything keeps the command alive past 5s, fail
		// loudly rather than hang the runner.
		c.SSHDProbeTimeout = 5 * time.Second
	})

	// Seed an admin "root" directly via the store so people.add is
	// authorized (the fixture seeds only "alice"/"bob", role user).
	rootKey := genSigner(t)
	if err := f.store.Update(func(st *state.State) error {
		st.People = append(st.People, state.Person{
			Name: "root", Role: "admin",
			Keys: []state.Key{{
				Fingerprint: fingerprintOf(t, rootKey.PublicKey()),
				Pub:         authorizedLine(rootKey.PublicKey()),
				Added:       state.NewZonedTime(f.clock.Now()),
			}},
		})
		return nil
	}); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	root := dialAdmin(t, f, "root", rootKey)

	// Hold Store.mu from a long-running Update BEFORE the command is
	// sent, so the command's first Store access (and with it the whole
	// handler) parks deterministically.
	holderStarted := make(chan struct{})
	releaseStoreLock := make(chan struct{})
	go func() {
		f.store.Update(func(st *state.State) error {
			close(holderStarted)
			<-releaseStoreLock
			return nil
		})
	}()
	<-holderStarted
	// Round-4 rule: a lock the test took is released before the
	// fixture's Close cleanup can run. runtime.Goexit (t.Fatalf) runs
	// defers, and defers run before t.Cleanup — so every exit path
	// below, including the canary failure itself, lets the holder exit
	// and can never leave the parked writer blocking the cleanup Close.
	// Once guards the double close: the green path releases explicitly
	// below, the failure paths via the defer.
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseStoreLock) })
	}
	defer release()

	// Trigger a state-writing command. The key line must be REAL so the
	// command actually reaches cmdPeopleAdd's Store.Update — the write
	// IAMT-172 guards — instead of dying in argument validation. (The
	// handler parks even earlier: runCommand's admin role check does
	// Store.Get, whose RLock blocks while the holder owns the write
	// lock. Round 3 passed nil keys AND the command errored out before
	// any park, which is part of why the canary went red on a healthy
	// product.)
	cmdDone := make(chan struct{})
	go func() {
		defer close(cmdDone)
		_, _ = root.PeopleAdd("iamt172-probe", "user", []string{authorizedLine(genSigner(t).PublicKey())})
	}()

	// Deterministic: serveCmdInFlight is set synchronously inside
	// handleCommand, before the `go`. Counter == 1 means the writer
	// exists; it cannot finish while we hold Store.mu.
	waitForInFlight(t, &f.gw.serveCmdInFlight, 1, 3*time.Second,
		"IAMT-172 canary precondition failed: the people.add writer never started")

	// Call Close in a goroutine.
	closeReturned := make(chan struct{})
	go func() {
		defer close(closeReturned)
		_ = f.gw.Close()
	}()

	select {
	case <-closeReturned:
		// Close returned while we still hold Store.mu. The parked
		// writer cannot have finished — its decrement is unreachable
		// until we release — so a non-zero counter here means Close
		// did not wait for its own writer. That is exactly the
		// regression that lets a last events.jsonl write land after
		// t.TempDir cleanup has begun.
		if got := f.gw.serveCmdInFlight.Load(); got != 0 {
			t.Fatalf("CANARY (IAMT-172): gw.Close returned with %d serveCommandSession goroutine(s) still in flight; "+
				"the writer is parked on state.Store.mu (held by this test), so a non-zero counter here means "+
				"Gateway.Close did not wait for its own writer (g.wg.Add/Done around go g.serveCommandSession "+
				"in admin_role.go removed). A last events.jsonl write can land after every cleanup has run.",
				got)
		}
	case <-time.After(500 * time.Millisecond):
		// Hang protection, not an assertion (IAMT-161 shape). With the
		// fix, Close is parked on g.wg.Wait() exactly because the
		// writer is stuck on the lock we hold.
		t.Logf("IAMT-172: Close blocked on g.wg.Wait while serveCommandSession is parked on Store.mu — the wait the fix requires")
	}

	// Release the lock so the parked command can finish and Close can
	// return. (On the canary-failure path above, the deferred release
	// does this before the fixture cleanups run.)
	release()

	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("gw.Close deadlocked even after the test released Store.mu")
	}

	// The writer's decrement runs before its g.wg.Done (LIFO defers), so
	// the moment Close's g.wg.Wait returns the counter must be 0.
	if got := f.gw.serveCmdInFlight.Load(); got != 0 {
		t.Fatalf("IAMT-172: serveCmdInFlight = %d after Close returned and Store.mu was released; expected 0", got)
	}

	// Let the client side settle (the response was already written by
	// the time serveCommandSession returned, so this is bounded
	// hygiene, not the assertion).
	select {
	case <-cmdDone:
	case <-time.After(2 * time.Second):
		t.Fatal("people.add client call did not return after Close and lock release")
	}
}

// TestIAMT172_CloseWaitsForProxyChannelRequests is canary B for the
// proxyChannelRequests rule. It opens a human session on the fixture's
// default verified machine and drives it through the session start
// (pty-req + shell); serveHumanSession then launches the two proxy
// writers with the counter set synchronously and parks in core.Bridge.
// The writers stay parked on their request streams for as long as the
// transports live, so without the g.wg bookkeeping Close can return
// while proxyReqsInFlight is still non-zero.
//
// Round 5 (IAMT-163/166): the session start is awaited before the
// recording is even opened — awaitSessionStart blocks until the first
// pty-req/shell/exec arrives, and only then are the two proxy
// goroutines launched. A test that opens the channel and sends nothing
// would therefore assert against writers that do not exist yet (and
// the session would die on the SessionSetupTimeout instead). The
// canary sends pty-req + shell, exactly the flow that makes the
// round-3 version red during preparation: that version had first run
// prepareSSHDProbe, flipping the machine record to OSUserStatusPending,
// so serveHumanSession denied the session (SPEC §5.1 requires a
// verified machine) and pty-req died with EOF. Here the fixture
// machine stays verified, so the same requests carry the session into
// the state the canary needs. It still holds no lock of its own —
// nothing in the proxy writers takes Store.mu, and an unlockable lock
// held across a failed preparation is what deadlocked the round-3
// cleanup.
func TestIAMT172_CloseWaitsForProxyChannelRequests(t *testing.T) {
	f := newFixture(t, nil)

	// Default fixture machine (verified) must be connected and online
	// before the human session: the door needs a registered, online
	// machine, and the session needs the verified OS user.
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// Open the human session channel. serveHumanSession runs
	// asynchronously on the connection's handler goroutine: door open,
	// nested handshake to the fake sshd — then awaitSessionStart blocks
	// until the first pty-req/shell/exec. The shell below unblocks it:
	// the recording is opened, forwardSessionStart answers the client,
	// and the two proxy writers are launched right before core.Bridge.
	humanClient, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	hs := openHumanSession(t, humanClient, f)
	hs.shell(t)

	// Deterministic: proxyReqsInFlight is set synchronously inside
	// serveHumanSession before the `go` statements. Reaching 2 proves
	// the session got through ACL, door, nested handshake AND the
	// session start, and that both writers exist; if it never does, the
	// test fails loudly here instead of asserting against a session
	// that was refused or is still waiting for its start request.
	waitForInFlight(t, &f.gw.proxyReqsInFlight, 2, 3*time.Second,
		"IAMT-172 canary precondition failed: the human session never reached proxyChannelRequests")

	// Call Close in a goroutine. Close cuts the transports itself, and
	// the proxy writers can only exit after that cut — so on a fixed
	// build Close's g.wg.Wait() cannot return before both decrements
	// have run.
	closeReturned := make(chan struct{})
	go func() {
		defer close(closeReturned)
		_ = f.gw.Close()
	}()

	select {
	case <-closeReturned:
		if got := f.gw.proxyReqsInFlight.Load(); got != 0 {
			t.Fatalf("CANARY (IAMT-172): gw.Close returned with %d proxyChannelRequests goroutine(s) still in flight; "+
				"the writers were not waited for under g.wg (g.wg.Add/Done around the proxyChannelRequests "+
				"launches in human_role.go removed). A last events.jsonl write or recording resize can land "+
				"after every cleanup has run.",
				got)
		}
	case <-time.After(500 * time.Millisecond):
		// Hang protection. The writers are parked on their request
		// streams; with the fix Close waits for them under g.wg.
		t.Logf("IAMT-172: Close still waiting for proxyChannelRequests under g.wg.Wait")
	}

	select {
	case <-closeReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("gw.Close deadlocked with the human session's proxy writers alive")
	}

	// LIFO defers: each writer decremented the counter before its
	// g.wg.Done, so Close's return implies 0.
	if got := f.gw.proxyReqsInFlight.Load(); got != 0 {
		t.Fatalf("IAMT-172: proxyReqsInFlight = %d after Close returned; expected 0", got)
	}

	// The transport is already cut by Close; drop the client side so no
	// harness goroutine outlives the test into the next one.
	_ = humanClient.Close()
}
