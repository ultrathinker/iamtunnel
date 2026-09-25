package gateway

// iamt126_human_keepalive_test.go: IAMT-126 — gateway must actively probe
// the human end of an SSH connection, not only passively answer its
// incoming keepalives. Without this probe, a human peer that
// holds its transport and stops sending — disconnected cable, laptop lid
// shut, peer never opens its keepalive responder — sits in ESTABLISHED
// forever (sessions>0), io.Copy in core.Bridge stays blocked in a read,
// and the door's idle-close path is held out for the full hard ceiling
// (8 hours).
//
// The fix is in human_role.go (handleHuman starts an sshx.Keepalive.Probe
// at connection entry). These tests pin the two sides of that contract:
// the silent peer is detected and torn down (positive), and the live
// peer that just happens to be reading is left alone (the second side of
// the boundary — without it "the fix" becomes a new defect: it kicks an
// operator out of the session for thinking). Both numbers come from
// Config.HumanKeepalive; nothing in product code uses wall-clock values.
//
// Test-construction rules honoured:
//   * tests fail on the line that asserts the finding, not on setup;
//     every setup step that touches harness, dial or dial is checked
//     with t.Fatalf("test setup error: ...") so a harness failure
//     cannot be misread as a defect;
//   * no real-time waits (Interval=80 ms, MaxMisses=3 ⇒ worst case 240 ms);
//   * only t.TempDir() for any filesystem state — config paths are
//     passed explicitly via Config, never resolved through defaults
//     inside config.DirsFor that have a known history of leaking into
//     C:\ProgramData;
//   * the rule is two-sided, so AT LEAST two canaries are needed;
//     the two canaries here are the two test functions
//     below, each regressed by a different one-knob tweak applied
//     in isolation, and both regressions are named on the file:line
//     where they would first be observed.

import (
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// fakeHuman is the IAMT-126 counterpart of fakeMachine: a single SSH
// peer that the gateway sees as a real person (handshake goes through,
// username "<person>:<machine>", public-key auth succeeds, a session
// channel can be opened) but whose global-request response is under
// test control. The default behaviour mirrors a "well-behaved" client:
// incoming keepalives (and any other global request on the table) are
// answered through sshx.Keepalive.Respond. The goSilent() flag then
// changes the answer to "drop the request without replying" — exactly
// what a peer that is still TCP-alive but no longer listening looks
// like on the wire, and the case PROTOCOL §5 already calls out as the
// main one Probe must catch.
//
// The client side of x/crypto/ssh has its own default
// handleGlobalRequests that replies false to every global request,
// which is the silent case from the gateway's perspective. To stay
// honest about what the production code does, this fake does not use
// ssh.Dial (which would silently wire in that default responder);
// instead it goes through ssh.NewClientConn, throws away the reqs
// channel that NewClient would have fed into that default, and runs
// its own responder goroutine against the real one. The product
// client side may need a parallel fix in internal/client/connect.go
// — that is out of scope for IAMT-126, but it is why this fake
// exists: it lets the gateway-side test be specific about what the
// human side is and is not doing.
type fakeHuman struct {
	t      *testing.T
	addr   string
	person string
	mach   string
	signer ssh.Signer

	client *ssh.Client
	raw    net.Conn

	mu     sync.Mutex
	silent bool
}

func newFakeHuman(t *testing.T, addr, person, machine string, signer ssh.Signer) *fakeHuman {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("test setup error: human dial %s: %v", addr, err)
	}
	cfg := &ssh.ClientConfig{
		User:            person + ":" + machine,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		_ = raw.Close()
		t.Fatalf("test setup error: human handshake %s: %v", addr, err)
	}
	// NewClient would start x/crypto/ssh's default handleGlobalRequests
	// (which answers every global request with false — that IS the
	// silent case). Pass a never-closed channel instead so that
	// goroutine blocks harmlessly; the real reqs are handled by us.
	// IAMT-314: closed below, not never. handleGlobalRequests ranges over
	// exactly this channel and has no other exit, so a channel nobody can
	// close is a goroutine that outlives the client, the connection and
	// the test - goleak found one per fake human once internal/gateway was
	// wired. The close rides on the real request stream's teardown, so it
	// needs no new ownership rule: see the long comment in harness_test.go's
	// dialHumanClient.
	noopReqs := make(chan *ssh.Request)
	client := ssh.NewClient(conn, chans, noopReqs)

	fh := &fakeHuman{
		t: t, addr: addr, person: person, mach: machine,
		signer: signer, client: client, raw: raw,
	}
	go func() {
		defer close(noopReqs)
		fh.respondGlobalRequests(reqs)
	}()
	t.Cleanup(fh.close)
	return fh
}

// respondGlobalRequests is the human-side mirror of fakeMachine.pipeKeepalive:
// while silent is false, every global request is forwarded to
// sshx.Keepalive.Respond so the gateway's probe gets a real success
// reply (Interval × MaxMisses never trips). Once silent flips, the
// channel just drops the request without a Reply, simulating a peer
// whose TCP is up but whose SSH responder has stopped listening —
// the shape §5 calls the main one Probe must catch.
func (fh *fakeHuman) respondGlobalRequests(reqs <-chan *ssh.Request) {
	forward := make(chan *ssh.Request)
	go func() {
		sshx.Keepalive{}.Respond(forward)
	}()
	// IAMT-314: without this the responder above outlives the loop below,
	// which ends when the transport dies. fakeMachine.pipeKeepalive in
	// harness_test.go and the e2e harness both already had it; this copy
	// did not.
	defer close(forward)
	for r := range reqs {
		fh.mu.Lock()
		silent := fh.silent
		fh.mu.Unlock()
		if silent {
			// Drop without Reply: PROBE counts this as a miss
			// (PROTOCOL §5: "error/failure/missing answer").
			continue
		}
		forward <- r
	}
}

func (fh *fakeHuman) goSilent() {
	fh.mu.Lock()
	fh.silent = true
	fh.mu.Unlock()
}

func (fh *fakeHuman) close() {
	if fh.client != nil {
		_ = fh.client.Close()
	}
	if fh.raw != nil {
		_ = fh.raw.Close()
	}
}

// TestIAMT126_SilentHumanIsDetectedAndSessionTornDown is the positive
// half of the contract. After the session is up and the fake human
// goes silent, the gateway's probe (PROTOCOL §4.2) must reach
// MaxMisses misses, the callback must close sconn, the Bridge's
// io.Copy on the human side must fail, and the session/door must
// wind down the same way any transport loss does (PROTOCOL §5.2).
//
// The assertion fires on the SendRequest probe — sending any channel
// request on a closed transport returns an error — and that is the
// first observable effect of sconn.Close(). Everything that follows
// (session.drop event, mc.finishSession, door close) is the existing
// teardown path; it is not asserted here because it is covered by the
// scenario tests and adding more assertions here would only obscure
// which line is the actual canary for the IAMT-126 finding.
//
// CANARY 1: in the test fixture's cfgMod, replace the
// HumanKeepalive line with
//
//	HumanKeepalive: sshx.Keepalive{Interval: time.Hour, MaxMisses: 3, Name: "keepalive@openssh.com"},
//
// The probe will never declare dead inside this test's lifetime, so
// the assertion at human_role.go:... fails on the very first run with
// "CANARY 1: silent human transport was not torn down" — the exact
// finding this test must turn red on.
func TestIAMT126_SilentHumanIsDetectedAndSessionTornDown(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.HumanKeepalive = sshx.Keepalive{
			Interval:  80 * time.Millisecond,
			MaxMisses: 3,
			Name:      "keepalive@openssh.com",
		}
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	fh := newFakeHuman(t, f.addr, f.person, f.machineID, f.personKey)
	hs := openHumanSession(t, fh.client, nil)
	hs.shell(t)

	waitUntil(t, "setup error: session did not become active before silence", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	fh.goSilent()

	// This is the IAMT-126 line: the gateway must have closed the
	// human's transport by now (Interval × MaxMisses = 240 ms worst
	// case). Any SendRequest on a closed transport returns an error;
	// that error is the canary's exact signal.
	waitUntil(t, "CANARY 1: silent human transport was not torn down within Interval × MaxMisses; gateway did not detect the silent peer (PROTOCOL §4.2 / iamt126_human_keepalive_test.go:TestIAMT126_SilentHumanIsDetectedAndSessionTornDown)", func() bool {
		_, err := hs.ch.SendRequest("window-change", true, sshx0())
		return err != nil
	})
}

// TestIAMT126_LiveQuietHumanIsNotKilled is the second side of the
// boundary. An operator reading the output of a long command sends
// no bytes for many keepalive intervals; the gateway must NOT kill
// the session on that account. The probe fires every Interval and
// the fake answers every one with success — there are no misses,
// MaxMisses is never reached, and the session must still be alive
// several intervals later.
//
// The assertion is symmetric to the silent case: SendRequest must
// still succeed (the channel is open). The wait underneath that
// assertion is several intervals' worth of wall time (5 × 80 ms =
// 400 ms), not a real-time wait; the test is short enough to never
// trip the "test must not sleep minutes" rule.
//
// CANARY 2: in the test fixture's cfgMod, replace the
// HumanKeepalive line with
//
//	HumanKeepalive: sshx.Keepalive{Interval: time.Millisecond, MaxMisses: 1, Name: "keepalive@openssh.com"},
//
// The probe demands a reply inside 1 ms; even a well-behaved fake
// occasionally misses once under load, MaxMisses=1 then trips, and
// the session is torn down for an operator who is doing nothing
// wrong. The assertion at human_role.go:... fails on the very first
// run with "CANARY 2: live, quiet human was killed by the probe" —
// the second finding this test must turn red on.
func TestIAMT126_LiveQuietHumanIsNotKilled(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.HumanKeepalive = sshx.Keepalive{
			Interval:  80 * time.Millisecond,
			MaxMisses: 3,
			Name:      "keepalive@openssh.com",
		}
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	fh := newFakeHuman(t, f.addr, f.person, f.machineID, f.personKey)
	hs := openHumanSession(t, fh.client, nil)
	hs.shell(t)

	waitUntil(t, "setup error: session did not become active before the quiet window", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	// Several keepalive intervals pass. The fake responds to every
	// probe with success, so no miss is ever counted.
	time.Sleep(5 * 80 * time.Millisecond)

	// This is the IAMT-126 line: the operator is alive; they were
	// merely quiet. SendRequest on a live channel succeeds.
	if _, err := hs.ch.SendRequest("window-change", true, sshx0()); err != nil {
		t.Fatalf("CANARY 2: live, quiet human was killed by the probe (SendRequest on the human channel returned %v); Interval/MaxMisses are too aggressive — adjust Config.HumanKeepalive or the default in setDefaults (PROTOCOL §4.2 / iamt126_human_keepalive_test.go:TestIAMT126_LiveQuietHumanIsNotKilled)", err)
	}
}
