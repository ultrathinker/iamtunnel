package gateway

// iamt218_silent_human_survives_test.go — a deterministic check of the
// IAMT-218 fix (round 1): the fixture's person, connected through the
// regular dialHuman, stays silent AT THE DATA LEVEL noticeably longer
// than the gateway's full probe budget (HumanKeepalive.Interval ×
// MaxMisses; here 150 ms × 3 = 450 ms) -- and stays alive: the
// protocol-compatible transport (dialHumanClient +
// sshx.Keepalive{}.Respond) answers request success to
// keepalive@openssh.com (PROTOCOL §4.2), there are no misses, and the
// gateway has no reason to tear down the transport of an idle session.
// Then a marker is written into the channel and the echo is read --
// the session is alive.
//
// Before the fix dialHuman was a bare ssh.Dial, x/crypto answered
// failure to every incoming global request (the probe included),
// failure counted as a miss (PROTOCOL §4.2), and the gateway killed
// the person's transport at about the 450th ms: after the silence
// window below, writing to the channel failed with EOF.
//
// There is no contradiction with the iamt126 tests about the "silent"
// person: there the transport SPECIFICALLY does not answer probes (a
// fakeHuman with manually controlled silence and a shortened
// HumanKeepalive) and MUST be killed -- a dead-person check; here the
// transport answers probes and is silent only on data -- an idle-alive
// check. Different transports, different assertions.

import (
	"strings"
	"testing"
	"time"
)

func TestIAMT218_SilentHumanWithCompliantTransportSurvivesKeepalive(t *testing.T) {
	// The silence window is computed from the very numbers the gateway is
	// actually started with, not from literals: cfgMod receives Config
	// after all fixture values (HumanKeepalive is already set in
	// newFixture).
	var cfg Config
	f := newFixture(t, func(c *Config) { cfg = *c })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)

	silent := 3 * cfg.HumanKeepalive.Interval * time.Duration(cfg.HumanKeepalive.MaxMisses)
	if silent <= 0 {
		t.Fatalf("fixture HumanKeepalive is not configured: %+v", cfg.HumanKeepalive)
	}
	time.Sleep(silent)

	// The canary (maintainer's): in dialHumanClient (harness_test.go)
	// replace `go sshx.Keepalive{}.Respond(reqs)` with
	// `go func() { for range reqs {} }()` -- the person's transport
	// stops answering probes altogether. The gateway then kills it after
	// Interval × MaxMisses (~450 ms), the silence window above overlaps
	// that with a 3× margin, and the test fails on the assertion below
	// with the words "IAMT-218 canary: the keepalive fix was reverted".
	// The older canary (dialHuman → a bare ssh.Dial) no longer turns
	// things red after IAMT-220: a failure reply to a person's probe is
	// no longer a miss (PROTOCOL §4.2), and that is pinned by the test
	// TestIAMT220_HumanFailureReplyIsNotAMiss.
	const marker = "alive-after-silence"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("IAMT-218 canary: the keepalive fix was reverted: a fixture human silent for %v (3 x HumanKeepalive.Interval x MaxMisses) lost its transport: write: %v", silent, err)
	}
	got := readUntil(t, hs.ch, marker)
	if !strings.Contains(got, marker) {
		t.Fatalf("IAMT-218 canary: the keepalive fix was reverted: a fixture human silent for %v got no echo back, want %q in the reply, got %q", silent, marker, got)
	}
}
