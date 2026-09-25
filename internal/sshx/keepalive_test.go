package sshx

// keepalive_test.go: tests for Keepalive.Probe and Keepalive.Respond.
//
// The tests use a real ssh.Conn over TCP, to observe the wire. The
// main one is TestKeepaliveProbe_DetectsSilentPeer: the peer accepts
// a global request and never answers. This is PROTOCOL §5's third
// case ("a missing answer") and the whole reason keepalive was
// written in the first place.

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// keepaliveMode — how the fake server answers keepalive.
type keepaliveMode int

const (
	keepaliveAck    keepaliveMode = iota // answer with success
	keepaliveNack                        // answer with failure
	keepaliveSilent                      // accept the request and never answer
)

// fakeKeepaliveServer — a minimal SSH server with controllable
// behavior for keepalive@iamtunnel.
type fakeKeepaliveServer struct {
	listener net.Listener
	cfg      *ssh.ServerConfig
	mode     atomic.Int32
	probes   atomic.Int32
	names    chan string
}

func newFakeKeepaliveServer(t *testing.T, mode keepaliveMode) *fakeKeepaliveServer {
	t.Helper()
	s := &fakeKeepaliveServer{names: make(chan string, 64)}
	s.mode.Store(int32(mode))
	s.cfg = &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-fk"}
	s.cfg.AddHostKey(mustSigner(t))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	go s.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return s
}

func (s *fakeKeepaliveServer) serve() {
	for {
		raw, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(raw)
	}
}

func (s *fakeKeepaliveServer) handle(raw net.Conn) {
	defer raw.Close()
	conn, _, reqs, err := ssh.NewServerConn(raw, s.cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	for r := range reqs {
		s.probes.Add(1)
		select {
		case s.names <- r.Type:
		default:
		}
		switch keepaliveMode(s.mode.Load()) {
		case keepaliveAck:
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
		case keepaliveNack:
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		case keepaliveSilent:
			// Stay silent. The transport is alive, there is no answer — PROTOCOL §5.
		}
	}
}

func dialKeepalive(t *testing.T, addr string) ssh.Conn {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            "u",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// --- detecting a silent peer --------------------------------------------------

// TestKeepaliveProbe_DetectsSilentPeer — a silent peer. The peer
// accepts the request and does not answer: onDead must fire within
// Interval × MaxMisses plus slack, and stop() must return control.
//
// Before the fix, the loop was blocked inside conn.SendRequest: the
// miss counter never grew, onDead was never called, and stop() hung forever.
func TestKeepaliveProbe_DetectsSilentPeer(t *testing.T) {
	const interval = 20 * time.Millisecond
	const misses = 3
	srv := newFakeKeepaliveServer(t, keepaliveSilent)
	conn := dialKeepalive(t, srv.listener.Addr().String())

	dead := make(chan time.Time, 1)
	start := time.Now()
	stop := Keepalive{Interval: interval, MaxMisses: misses}.Probe(conn, func() {
		dead <- time.Now()
	})

	// Requirement: detection no later than Interval × MaxMisses. The
	// slack accounts for the scheduler and the TCP handshake.
	budget := interval*misses + 2*time.Second
	select {
	case at := <-dead:
		if elapsed := at.Sub(start); elapsed < interval*misses {
			t.Fatalf("onDead fired after %v, sooner than Interval×MaxMisses = %v", elapsed, interval*misses)
		}
	case <-time.After(budget):
		t.Fatalf("silent peer NOT declared dead within %v (interval=%v, misses=%d)", budget, interval, misses)
	}

	// stop() must return control: an ordinary gateway shutdown must not hang.
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop() hung after detecting a silent peer")
	}

	// The wire will show exactly one probe to the silent peer: x/crypto
	// holds globalSentMu for the whole duration of a global request
	// with want-reply, so subsequent probes wait for the first to
	// return. That does not matter for detection — a miss is counted
	// on interval expiry, not on an answer — but checking "at least
	// misses probes" would be meaningless.
	if got := srv.probes.Load(); got < 1 {
		t.Fatalf("the peer received no probes at all")
	}
}

// TestKeepaliveProbe_StopReturnsWhileSilent — stop() during an
// unanswered probe must also return control, without waiting for an answer.
func TestKeepaliveProbe_StopReturnsWhileSilent(t *testing.T) {
	srv := newFakeKeepaliveServer(t, keepaliveSilent)
	conn := dialKeepalive(t, srv.listener.Addr().String())
	stop := Keepalive{Interval: time.Hour, MaxMisses: 3}.Probe(conn, func() {})
	// Let the loop enter SendRequest.
	waitForCond(t, "probe was not sent", func() bool { return srv.probes.Load() > 0 })
	stopped := make(chan struct{})
	go func() { stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop() hung on an unanswered probe")
	}
}

// TestKeepaliveProbe_OnDeadMayCallStop — the natural pattern of
// "connection died → wind everything down, including keepalive". This
// used to be a self-deadlock: onDead ran inside the goroutine whose
// exit stop() was waiting for.
func TestKeepaliveProbe_OnDeadMayCallStop(t *testing.T) {
	srv := newFakeKeepaliveServer(t, keepaliveNack)
	conn := dialKeepalive(t, srv.listener.Addr().String())
	returned := make(chan struct{})
	// Handing stop off into onDead through a buffered channel: this
	// gives the read a happens-before with the write, so -race does
	// not flag a race in the test itself.
	handoff := make(chan func(), 1)
	stop := Keepalive{Interval: 5 * time.Millisecond, MaxMisses: 1}.Probe(conn, func() {
		(<-handoff)() // must not block itself
		close(returned)
	})
	handoff <- stop
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("onDead, having called stop(), is blocked forever (self-deadlock)")
	}
	stop() // idempotence after the self-call
}

// waitForCond polls cond for up to two seconds.
func waitForCond(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal(msg)
}

// --- miss counter --------------------------------------------------------------

// TestKeepaliveProbe_HealthyNoDeadCallback — the server always
// answers with success; onDead never fires, and probes genuinely go out.
func TestKeepaliveProbe_HealthyNoDeadCallback(t *testing.T) {
	srv := newFakeKeepaliveServer(t, keepaliveAck)
	conn := dialKeepalive(t, srv.listener.Addr().String())
	dead := atomic.Bool{}
	stop := Keepalive{Interval: 5 * time.Millisecond, MaxMisses: 3}.Probe(conn, func() {
		dead.Store(true)
	})
	waitForCond(t, "healthy probes are not going out", func() bool { return srv.probes.Load() >= 5 })
	stop()
	if dead.Load() {
		t.Fatal("a live connection was declared dead")
	}
}

// TestKeepaliveProbe_MissCounterResets — a successful answer resets
// the counter: two consecutive failures at a threshold of 3 must not
// accumulate toward death if there was a success between the runs.
func TestKeepaliveProbe_MissCounterResets(t *testing.T) {
	srv := newFakeKeepaliveServer(t, keepaliveNack)
	conn := dialKeepalive(t, srv.listener.Addr().String())
	dead := atomic.Bool{}
	stop := Keepalive{Interval: 10 * time.Millisecond, MaxMisses: 3}.Probe(conn, func() {
		dead.Store(true)
	})
	defer stop()
	// Two failures, then it heals.
	waitForCond(t, "no probes went out", func() bool { return srv.probes.Load() >= 2 })
	srv.mode.Store(int32(keepaliveAck))
	base := srv.probes.Load()
	waitForCond(t, "no probes went out after healing", func() bool { return srv.probes.Load() >= base+6 })
	if dead.Load() {
		t.Fatal("successful answers did not reset the miss counter")
	}
}

// TestKeepaliveProbe_DeadConnectionFiresCallback — the server answers
// with failure; onDead fires exactly once.
func TestKeepaliveProbe_DeadConnectionFiresCallback(t *testing.T) {
	srv := newFakeKeepaliveServer(t, keepaliveNack)
	conn := dialKeepalive(t, srv.listener.Addr().String())
	count := atomic.Int32{}
	stop := Keepalive{Interval: 5 * time.Millisecond, MaxMisses: 3}.Probe(conn, func() {
		count.Add(1)
	})
	defer stop()
	waitForCond(t, "failures did not lead to onDead", func() bool { return count.Load() > 0 })
	// Give the loop a chance to call onDead again, if it could.
	time.Sleep(50 * time.Millisecond)
	if c := count.Load(); c != 1 {
		t.Fatalf("onDead called %d times, want 1", c)
	}
}

// TestKeepaliveProbe_FailureIsAliveSurvivesNack — PROTOCOL §4.2 (IAMT-220):
// with FailureIsAlive == true, a request failure is not a miss. A
// peer that answers with failure for longer than Interval×MaxMisses
// (like OpenSSH on a keepalive@openssh.com it does not know) stays alive.
//
// CANARY: remove `|| k.FailureIsAlive` from the `alive` expression in
// Probe (internal/sshx/keepalive.go) — the test fails with
// "FailureIsAlive did not save a live peer that answers with failure:
// onDead fired after ...".
func TestKeepaliveProbe_FailureIsAliveSurvivesNack(t *testing.T) {
	const interval = 10 * time.Millisecond
	const misses = 3
	srv := newFakeKeepaliveServer(t, keepaliveNack)
	conn := dialKeepalive(t, srv.listener.Addr().String())
	dead := atomic.Bool{}
	stop := Keepalive{Interval: interval, MaxMisses: misses, FailureIsAlive: true}.Probe(conn, func() {
		dead.Store(true)
	})
	// Longer than Interval×MaxMisses with a generous margin: under the
	// old rule ("failure = a miss") onDead would have fired long before this.
	waitForCond(t, "a peer answering with failure received no probes", func() bool {
		return srv.probes.Load() >= int32(misses)*4
	})
	stop()
	if dead.Load() {
		t.Fatal("FailureIsAlive did not save a live peer answering with failure: onDead fired sooner than a reasonable margin")
	}
}

// TestKeepaliveProbe_FailureIsAliveStillDiesOnSilence — FailureIsAlive
// only changes the interpretation of an explicit failure answer. A
// missing answer (the peer is silent, the transport is alive) remains
// a miss regardless of this field.
//
// CANARY: replace `gotReply && rep.err == nil && (...)` with just
// `!gotReply || rep.err == nil && (...)`, i.e. make "no answer" also
// a non-miss under FailureIsAlive — the test fails on the budget
// timeout: "silent peer with FailureIsAlive NOT declared dead".
func TestKeepaliveProbe_FailureIsAliveStillDiesOnSilence(t *testing.T) {
	const interval = 20 * time.Millisecond
	const misses = 3
	srv := newFakeKeepaliveServer(t, keepaliveSilent)
	conn := dialKeepalive(t, srv.listener.Addr().String())
	dead := make(chan struct{})
	stop := Keepalive{Interval: interval, MaxMisses: misses, FailureIsAlive: true}.Probe(conn, func() {
		close(dead)
	})
	defer stop()
	budget := interval*misses + 2*time.Second
	select {
	case <-dead:
	case <-time.After(budget):
		t.Fatalf("silent peer with FailureIsAlive NOT declared dead within %v", budget)
	}
}

// TestKeepaliveProbe_DefaultsApply — SPEC §3.2/§5.2: 20 seconds,
// 3 misses, the name keepalive@iamtunnel. The previous test did not
// check this at all: corrupting all three constants left it green.
func TestKeepaliveProbe_DefaultsApply(t *testing.T) {
	interval, misses, name := Keepalive{}.resolve()
	if interval != 20*time.Second {
		t.Errorf("default interval %v, SPEC §3.2 requires 20s", interval)
	}
	if misses != 3 {
		t.Errorf("default threshold %d, SPEC §3.2 requires 3", misses)
	}
	if name != "keepalive@iamtunnel" {
		t.Errorf("default name %q, PROTOCOL §5 requires keepalive@iamtunnel", name)
	}
	if DefaultKeepaliveInterval != 20*time.Second || DefaultKeepaliveMisses != 3 ||
		DefaultKeepaliveName != "keepalive@iamtunnel" {
		t.Fatalf("default constants drifted apart: %v/%d/%q",
			DefaultKeepaliveInterval, DefaultKeepaliveMisses, DefaultKeepaliveName)
	}
	// Not just the constants: the name must appear exactly like this on the wire.
	srv := newFakeKeepaliveServer(t, keepaliveAck)
	conn := dialKeepalive(t, srv.listener.Addr().String())
	stop := Keepalive{Interval: 5 * time.Millisecond}.Probe(conn, func() {})
	defer stop()
	select {
	case got := <-srv.names:
		if got != DefaultKeepaliveName {
			t.Fatalf("name on the wire %q, want %q", got, DefaultKeepaliveName)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a probe with the default name never reached the peer")
	}
	// resolve must not override explicitly given values.
	ci, cm, cn := Keepalive{Interval: time.Second, MaxMisses: 7, Name: "x@y"}.resolve()
	if ci != time.Second || cm != 7 || cn != "x@y" {
		t.Fatalf("resolve overrode the given values: %v/%d/%q", ci, cm, cn)
	}
}

// TestKeepaliveProbe_StopIsIdempotent — a repeated stop does not
// panic and does not hang.
func TestKeepaliveProbe_StopIsIdempotent(t *testing.T) {
	srv := newFakeKeepaliveServer(t, keepaliveAck)
	conn := dialKeepalive(t, srv.listener.Addr().String())
	stop := Keepalive{Interval: 5 * time.Millisecond, MaxMisses: 3}.Probe(conn, func() {})
	waitForCond(t, "no probes went out", func() bool { return srv.probes.Load() > 0 })
	done := make(chan struct{})
	go func() {
		stop()
		stop()
		stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a repeated stop() hung")
	}
}

// TestKeepaliveProbe_NilConnPanics — contract: a nil conn triggers a panic.
func TestKeepaliveProbe_NilConnPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("nil conn did not trigger a panic")
		}
	}()
	_ = Keepalive{Interval: time.Millisecond}.Probe(nil, func() {})
}

// --- Respond ----------------------------------------------------------------

// respondServer starts a server whose global requests are served by
// Keepalive.Respond, and returns the client connection.
func respondServer(t *testing.T, k Keepalive) ssh.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	cfg := &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-rsp"}
	cfg.AddHostKey(mustSigner(t))
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		conn, _, reqs, err := ssh.NewServerConn(raw, cfg)
		if err != nil {
			return
		}
		defer conn.Close()
		k.Respond(reqs)
	}()
	return dialKeepalive(t, ln.Addr().String())
}

// sendGlobal sends a global request and keeps the test from hanging
// if Respond stays silent: a gutted Respond used to go unnoticed before.
func sendGlobal(t *testing.T, conn ssh.Conn, name string, wantReply bool) bool {
	t.Helper()
	type res struct {
		ok  bool
		err error
	}
	ch := make(chan res, 1)
	go func() {
		ok, _, err := conn.SendRequest(name, wantReply, nil)
		ch <- res{ok, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("%s: %v", name, r.err)
		}
		return r.ok
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: Respond did not answer (the request hung)", name)
		return false
	}
}

// TestKeepaliveRespond_AnswersByTable — Respond answers by the same
// globalRequestTable as the gateway. There must not be two different
// global-request policies in the package.
func TestKeepaliveRespond_AnswersByTable(t *testing.T) {
	conn := respondServer(t, Keepalive{})
	cases := []struct {
		name string
		want bool
	}{
		{DefaultKeepaliveName, true},            // PROTOCOL §5
		{"keepalive@openssh.com", true},         // §4.1: request success, do not forward
		{"hostkeys-00@openssh.com", false},      // §4.1: violates direction → failure
		{"tcpip-forward", false},                // §4.1: E_SSH_FORWARD_FORBIDDEN
		{"cancel-tcpip-forward", false},         //
		{"no-more-sessions@openssh.com", false}, // Drop, but the spec requires an answer on want-reply
		{"totally-not-keepalive", false},        // default-deny
	}
	for _, c := range cases {
		if got := sendGlobal(t, conn, c.name, true); got != c.want {
			t.Errorf("%s: answer %v, want %v", c.name, got, c.want)
		}
	}
}

// TestKeepaliveRespond_CustomNameIsAnswered — if Name is set
// explicitly, it must be answered, not only the default constant.
func TestKeepaliveRespond_CustomNameIsAnswered(t *testing.T) {
	conn := respondServer(t, Keepalive{Name: "probe@test"})
	if !sendGlobal(t, conn, "probe@test", true) {
		t.Fatal("the keepalive's own name did not get a success")
	}
	if sendGlobal(t, conn, "unknown@test", true) {
		t.Fatal("a foreign name got a success")
	}
}

// TestKeepaliveRespond_NameCannotOverrideTable — the Keepalive.Name
// field is set from outside, and it must not be usable to turn a
// table prohibition into a success: otherwise it would be exactly
// that switch, just through a struct value.
func TestKeepaliveRespond_NameCannotOverrideTable(t *testing.T) {
	for _, name := range []string{"tcpip-forward", "cancel-tcpip-forward", "hostkeys-00@openssh.com"} {
		conn := respondServer(t, Keepalive{Name: name})
		if sendGlobal(t, conn, name, true) {
			t.Errorf("Keepalive{Name: %q} turned a table prohibition into a success", name)
		}
	}
	// A Drop row must also not turn into a success.
	conn := respondServer(t, Keepalive{Name: "no-more-sessions@openssh.com"})
	if sendGlobal(t, conn, "no-more-sessions@openssh.com", true) {
		t.Error("Keepalive.Name turned a Drop into a success")
	}
}

// TestKeepaliveRespond_NoWantReplyThenStillAlive — a request without
// want-reply must neither crash Respond nor stop it. The previous
// test discarded the result entirely and stayed green on a bare `for
// range reqs {}`; here, after a "mute" request, we check that Respond
// keeps answering per the spec.
func TestKeepaliveRespond_NoWantReplyThenStillAlive(t *testing.T) {
	conn := respondServer(t, Keepalive{})
	for i := 0; i < 3; i++ {
		if got := sendGlobal(t, conn, DefaultKeepaliveName, false); got {
			t.Fatal("SendRequest with no want-reply returned ok=true")
		}
	}
	if !sendGlobal(t, conn, DefaultKeepaliveName, true) {
		t.Fatal("Respond stopped answering after mute requests")
	}
	if sendGlobal(t, conn, "subsystem", true) {
		t.Fatal("Respond started answering success to a foreign request after mute requests")
	}
}

// TestKeepaliveRespond_StopsWhenChannelCloses — Respond exits along
// with the request channel and survives a nil element.
func TestKeepaliveRespond_StopsWhenChannelCloses(t *testing.T) {
	reqs := make(chan *ssh.Request, 3)
	reqs <- nil
	// WantReply=false: ssh.Request.Reply sends nothing and does not
	// touch the mux in that case, so a hand-assembled request is safe.
	reqs <- &ssh.Request{Type: DefaultKeepaliveName, WantReply: false}
	reqs <- &ssh.Request{Type: "subsystem", WantReply: false}
	close(reqs)
	done := make(chan struct{})
	go func() {
		Keepalive{}.Respond(reqs)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Respond did not exit after the request channel closed")
	}
}

// --- bidirectional keepalive ---------------------------------------------------

// TestKeepaliveBidirectional proves both sides run a probe against
// each other for at least five intervals, and neither one triggers a
// break.
//
// This exact scenario used to be fundamentally broken:
// keepalive@iamtunnel sat in the table as Forward, there was nowhere
// to forward a global request to, and the receiver answered with
// failure — meaning each side racked up misses on a live connection.
func TestKeepaliveBidirectional(t *testing.T) {
	const interval = 20 * time.Millisecond
	const misses = 3

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-bidi"}
	cfg.AddHostKey(mustSigner(t))

	serverDead := atomic.Bool{}
	serverUp := make(chan func(), 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		defer raw.Close()
		conn, _, reqs, err := ssh.NewServerConn(raw, cfg)
		if err != nil {
			return
		}
		defer conn.Close()
		// The server is simultaneously passive (Respond) and active (Probe).
		stop := Keepalive{Interval: interval, MaxMisses: misses}.Probe(conn, func() {
			serverDead.Store(true)
		})
		serverUp <- stop
		Keepalive{Interval: interval, MaxMisses: misses}.Respond(reqs)
		stop()
	}()

	clientCfg := &ssh.ClientConfig{
		User:            "u",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	raw, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn, _, reqs, err := ssh.NewClientConn(raw, ln.Addr().String(), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	clientDead := atomic.Bool{}
	go Keepalive{Interval: interval, MaxMisses: misses}.Respond(reqs)
	clientStop := Keepalive{Interval: interval, MaxMisses: misses}.Probe(conn, func() {
		clientDead.Store(true)
	})

	var serverStop func()
	select {
	case serverStop = <-serverUp:
	case <-time.After(5 * time.Second):
		t.Fatal("the server side never came up")
	}

	// At least five intervals in both directions.
	time.Sleep(interval * 8)

	clientStop()
	serverStop()
	_ = conn.Close()

	if clientDead.Load() {
		t.Error("the client side declared a live peer dead")
	}
	if serverDead.Load() {
		t.Error("the server side declared a live peer dead")
	}
}
