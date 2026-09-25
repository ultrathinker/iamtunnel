package gateway

// iamt220_human_keepalive_policy_test.go: PROTOCOL §4.2 (IAMT-220).
//
// The live incident (14.09): a real OpenSSH_10.3p1 client went through the
// gateway to a real machine, ran one command, and then just sat there. 39
// seconds later the gateway closed the connection, and events.jsonl recorded
// it as session.stop "ok" — indistinguishable from the human closing their
// own session. The cause: x/crypto/ssh's own client-side default global
// request handler — the same one ssh.Dial wires in, and the one whose doc
// comment says "matches the behaviour of OpenSSH" (client.go's
// handleGlobalRequests) — answers every unknown global request, including
// the gateway's keepalive@openssh.com probe, with request failure. The old
// rule treated that failure as a miss; three of them (well under a minute)
// killed a peer that was, provably, still there to answer.
//
// Three tests pin the fixed rule:
//
//   - (a) TestIAMT220_HumanFailureReplyIsNotAMiss: a human whose transport
//     answers every probe with an explicit request failure — exactly what
//     OpenSSH and x/crypto's default handler do (dialFailureReplyingHuman,
//     deliberately NOT dialHuman, which since IAMT-218 answers success) —
//     must survive past Interval x MaxMisses, and the channel must still
//     carry real bytes afterward, not just answer SendRequest.
//   - (b) TestIAMT220_HumanTrueSilenceStillDropsAsKeepalive: a peer that
//     answers nothing at all (fakeHuman.goSilent, unchanged from IAMT-126)
//     is still torn down, and the journal must name the keepalive loss —
//     session.drop, not session.stop, with a result that says so.
//   - (c) TestIAMT220_MachineFailureReplyStillCountsAsMiss: PROTOCOL §5 is
//     untouched by this fix. A machine that answers keepalive@iamtunnel
//     with explicit failure is still declared dead within the same budget.
import (
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// dialFailureReplyingHuman connects a human whose transport answers every
// global request — keepalive@openssh.com included — with an explicit
// request failure, the way OpenSSH's client and x/crypto's own
// handleGlobalRequests do. It does not go through dialHuman on purpose:
// since IAMT-218 dialHuman answers the probe with success, which would
// make test (a) pass whether or not the §4.2 fix is in place.
func dialFailureReplyingHuman(t *testing.T, addr, person, machine string, signer ssh.Signer) *ssh.Client {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("setup error: human dial %s: %v", addr, err)
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
		t.Fatalf("setup error: human handshake %s: %v", addr, err)
	}
	// IAMT-314: this channel used to be created inline, so nothing could
	// ever close it and the goroutine ssh.NewClient starts on it
	// (handleGlobalRequests) had no exit at all. It is bound and closed
	// from the goroutine that drains the real request stream, so it dies
	// with the transport - same shape as dialHumanClient in harness_test.go
	// and as Conn.Close in internal/admin/client.go.
	noopReqs := make(chan *ssh.Request)
	client := ssh.NewClient(conn, chans, noopReqs)
	go func() {
		defer close(noopReqs)
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestIAMT220_HumanFailureReplyIsNotAMiss is canary (a).
//
// CANARY: in internal/sshx/keepalive.go's Probe, delete the
// `|| k.FailureIsAlive` disjunct from the `alive` expression (restoring
// "failure = miss" for every caller) — this test fails at the waitUntil
// below with "CANARY (a): an OpenSSH-like human answering every keepalive
// with failure was killed anyway", because this fixture's HumanKeepalive
// (60ms x 3 = 180ms worst case) trips many times over inside the sleep
// this test waits out.
func TestIAMT220_HumanFailureReplyIsNotAMiss(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.HumanKeepalive = sshx.Keepalive{Interval: 60 * time.Millisecond, MaxMisses: 3, Name: "keepalive@openssh.com"}
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// Every probe gets request failure — the reply shape OpenSSH and
	// x/crypto's default handler send, the exact thing the live incident hit.
	client := dialFailureReplyingHuman(t, f.addr, f.person, f.machineID, f.personKey)
	hs := openHumanSession(t, client, f)
	hs.shell(t)

	waitUntil(t, "setup error: session did not become active", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	acc := drain(hs.ch)

	// Well past Interval x MaxMisses (60ms x 3 = 180ms), several times
	// over: every probe in this window gets an explicit failure reply
	// from x/crypto/ssh's default handler, never silence and never a
	// transport error.
	time.Sleep(10 * 60 * time.Millisecond)

	if _, err := hs.ch.SendRequest("window-change", true, sshx0()); err != nil {
		t.Fatalf("CANARY (a): an OpenSSH-like human answering every keepalive with failure was killed anyway (SendRequest: %v)", err)
	}

	// Not just SendRequest: prove the byte pipe is still live end to end
	// through the recording and the echoing fake sshd (PROTOCOL §4.2's
	// whole point is that this session keeps working).
	const marker = "iamt220-failure-is-not-a-miss"
	if _, err := hs.ch.Write([]byte(marker + "\n")); err != nil {
		t.Fatalf("write after the failure-reply window: %v", err)
	}
	if !waitContains(t, acc, marker, 3*time.Second) {
		t.Fatalf("CANARY (a): input after the failure-reply window produced no echo — session is not actually alive (got %q)", acc.get())
	}
}

// TestIAMT220_HumanTrueSilenceStillDropsAsKeepalive is canary (b).
//
// CANARY: in human_role.go's serveHumanSession, delete the
// `case probeKilled != nil && probeKilled.Load():` branch (or make it fall
// through to the default) — this test fails at the events.Read assertion
// with "CANARY (b): keepalive teardown was journaled as session.stop \"ok\",
// not session.drop", because bridgeErr stays nil on this path (sconn.Close()
// surfaces as a plain clean-end EOF) and the switch's default branch writes
// session.stop unconditionally.
func TestIAMT220_HumanTrueSilenceStillDropsAsKeepalive(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.HumanKeepalive = sshx.Keepalive{Interval: 60 * time.Millisecond, MaxMisses: 3, Name: "keepalive@openssh.com"}
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	fh := newFakeHuman(t, f.addr, f.person, f.machineID, f.personKey)
	hs := openHumanSession(t, fh.client, f)
	hs.shell(t)

	waitUntil(t, "setup error: session did not become active before silence", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	fh.goSilent()

	waitUntil(t, "true silence (no reply at all) was not torn down within Interval x MaxMisses", func() bool {
		_, err := hs.ch.SendRequest("window-change", true, sshx0())
		return err != nil
	})

	waitUntil(t, "CANARY (b): keepalive teardown never reached events.jsonl", func() bool {
		evs, _, err := f.log.Read(events.Filter{
			Types:  []events.EventType{events.EventSessionDrop, events.EventSessionStop},
			Actor:  f.person,
			Object: f.machineID,
		})
		if err != nil || len(evs) == 0 {
			return false
		}
		last := evs[len(evs)-1]
		if last.Type != events.EventSessionDrop {
			t.Fatalf("CANARY (b): keepalive teardown was journaled as session.stop %q, not session.drop — indistinguishable from a clean human exit (PROTOCOL §4.2, IAMT-220)", last.Result)
		}
		return true
	})
}

// TestIAMT220_MachineFailureReplyStillCountsAsMiss is canary (c): PROTOCOL
// §5 (the machine's own keepalive@iamtunnel) is untouched by the §4.2 fix.
//
// CANARY: in gateway.Config.setDefaults, change the machine-side default to
// also force FailureIsAlive: true on c.Keepalive (copy-pasting the human
// fix onto the wrong field) — this test fails at the second waitUntil with
// "keepalive failure did not remove the machine from the registry", because
// the machine's explicit failure replies would then be read as proof of
// life forever.
func TestIAMT220_MachineFailureReplyStillCountsAsMiss(t *testing.T) {
	f := newFixture(t, func(cfg *Config) {
		cfg.Keepalive = sshx.Keepalive{Interval: 60 * time.Millisecond, MaxMisses: 2}
	})
	fm := f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("setup error: human dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)

	waitUntil(t, "setup error: session did not become active before the machine starts nacking keepalive", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	// The machine now answers every keepalive@iamtunnel probe with an
	// explicit request failure — exactly the reply shape (a) proved is
	// NOT a miss for the human side. §5 must still call it one.
	fm.goNack()

	waitUntil(t, "keepalive failure did not tear the session down", func() bool {
		_, err := hs.ch.SendRequest("window-change", true, sshx0())
		return err != nil
	})
	waitUntil(t, "keepalive failure did not remove the machine from the registry", func() bool {
		_, ok := f.gw.reg.get(f.machineID)
		return !ok
	})
}
