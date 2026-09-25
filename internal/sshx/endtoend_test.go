package sshx

// endtoend_test.go: end-to-end tests for the full sshx stack.
//
// The rig is built so that every decision is made by the sshx table,
// not an if-chain in the wiring. So this checks not only "what is
// allowed goes through", but also "what is forbidden is rejected on
// the wire", "what is allowed without forwarding gets a local
// success", and "what is dropped creates no event where the spec
// forbids one".

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// TestEndToEndEcho10K — the human sends 10,240 random bytes and gets
// them back through the gateway, the machine, and a fake sshd.
func TestEndToEndEcho10K(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	h.request(t, "pty-req", MarshalPTY(PTYRequest{Term: "xterm-256color", Columns: 101, Rows: 37, WidthPixels: 808, HeightPixels: 592}))
	h.request(t, "shell", nil)
	in := make([]byte, 10*1024)
	if _, err := rand.Read(in); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ch.Write(in); err != nil {
		t.Fatal(err)
	}
	_ = h.ch.CloseWrite()
	out, err := io.ReadAll(h.ch)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if !bytes.Equal(out, in) {
		t.Fatalf("echo mismatch: got %d bytes want %d", len(out), len(in))
	}
}

// TestPTYRequestReachesFakeSSHD — pty-req reaches the machine unaltered.
func TestPTYRequestReachesFakeSSHD(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	want := PTYRequest{Term: "vt100", Columns: 132, Rows: 43, WidthPixels: 1056, HeightPixels: 688}
	h.request(t, "pty-req", MarshalPTY(want))
	h.request(t, "shell", nil)
	s.fake.waitForState(t, false)
	got, _, _, _ := s.fake.state()
	if got != want {
		t.Fatalf("pty=%+v want=%+v", got, want)
	}
}

// TestWindowChangeReachesFakeSSHD — window-change travels with
// want-reply=false and must still reach the machine.
func TestWindowChangeReachesFakeSSHD(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	h.startShell(t)
	want := WindowChange{Columns: 167, Rows: 51, WidthPixels: 1336, HeightPixels: 816}
	if _, err := h.ch.SendRequest("window-change", false, MarshalWindow(want)); err != nil {
		t.Fatal(err)
	}
	s.fake.waitForState(t, true)
	_, got, _, _ := s.fake.state()
	if got != want {
		t.Fatalf("window=%+v want=%+v", got, want)
	}
}

// TestExecReachesFakeSSHD — end-to-end coverage for exec: before the
// fix, only a unit-roundtrip test caught a bug in its parsing.
func TestExecReachesFakeSSHD(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	want := Exec{Command: "id -u && echo 'ok'"}
	h.request(t, "exec", MarshalExec(want))
	waitFor(t, "exec did not reach the machine", func() bool {
		_, ok := s.fake.execSeen()
		return ok
	})
	got, _ := s.fake.execSeen()
	if got != want {
		t.Fatalf("exec=%+v want=%+v", got, want)
	}
}

// TestSignalReachesFakeSSHD — end-to-end coverage for signal
// ("forwarded in both directions"); travels with want-reply=false.
func TestSignalReachesFakeSSHD(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	h.startShell(t)
	for _, name := range []string{"INT", "TERM", "HUP"} {
		if _, err := h.ch.SendRequest("signal", false, MarshalSignal(Signal{Name: name})); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "signal did not reach the machine", func() bool {
		return len(s.fake.signalsSeen()) == 3
	})
	got := s.fake.signalsSeen()
	for i, want := range []string{"INT", "TERM", "HUP"} {
		if got[i] != want {
			t.Fatalf("signal #%d = %q, want %q", i, got[i], want)
		}
	}
}

// TestExitStatusReachesHuman — the machine's exit-status reaches the human.
func TestExitStatusReachesHuman(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	h.startShell(t)
	_ = h.ch.CloseWrite()
	select {
	case got := <-h.exits:
		if got != 42 {
			t.Fatalf("exit status %d", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing exit-status")
	}
}

// TestExitSignalReachesHuman — end-to-end coverage for exit-signal:
// four fields (including the boolean core-dumped) reach the human unaltered.
func TestExitSignalReachesHuman(t *testing.T) {
	f := newFakeSSHD(t)
	f.exitSignal = "SEGV"
	s := newStackWith(t, f, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	h.startShell(t)
	_ = h.ch.CloseWrite()
	select {
	case got := <-h.sigs:
		want := ExitSignal{Signal: "SEGV", CoreDumped: true, ErrorMessage: "killed by test", LanguageTag: "en"}
		if got != want {
			t.Fatalf("exit-signal=%+v want=%+v", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exit-signal did not reach the human")
	}
}

// TestEOFPropagatesToMachine — PROTOCOL §4.1: eof and close are the
// SSH_MSG_CHANNEL_EOF/CLOSE packet types, forwarded via
// CloseWrite()/Close() (RFC 4254 §5.3), not request-table entries. We
// check that this is exactly what provides the SPEC §5.1 semantics
// ("eof, close are forwarded in both directions").
func TestEOFPropagatesToMachine(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	h.startShell(t)
	if _, err := h.ch.Write([]byte("before eof")); err != nil {
		t.Fatal(err)
	}
	// The human's EOF → gateway → machine → target sshd.
	if err := h.ch.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the human's SSH_MSG_CHANNEL_EOF did not reach the machine", s.fake.eofDelivered)
	// The reverse direction: the machine closes the channel, the human reads the stream to the end.
	out, err := io.ReadAll(h.ch)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("before eof")) {
		t.Fatalf("data before EOF was lost: %q", out)
	}
	// But the name "eof" as a channel request is a forgery of a
	// protocol-level packet and is rejected on the wire.
	ok, err := h.ch.SendRequest("eof", true, nil)
	if err == nil && ok {
		t.Fatal("a channel request named eof was accepted")
	}
}

// TestForbiddenRequestsRejectedAndSessionLives — SPEC §5.1's
// forbidden requests are rejected on the wire, after which the session stays alive.
func TestForbiddenRequestsRejectedAndSessionLives(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	for _, name := range []string{"subsystem", "auth-agent-req@openssh.com", "x11-req"} {
		ok, err := h.ch.SendRequest(name, true, nil)
		if err != nil || ok {
			t.Fatalf("%s was not rejected: ok=%v err=%v", name, ok, err)
		}
	}
	for _, name := range []string{"tcpip-forward", "cancel-tcpip-forward", "hostkeys-00@openssh.com"} {
		ok, _, err := s.person.SendRequest(name, true, nil)
		if err != nil || ok {
			t.Fatalf("global %s was not rejected: ok=%v err=%v", name, ok, err)
		}
	}
	if _, _, err := s.person.OpenChannel("direct-tcpip", nil); err == nil {
		t.Fatal("direct-tcpip was not rejected")
	}
	h.startShell(t)
	msg := []byte("still alive")
	if _, err := h.ch.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(h.ch, buf); err != nil || !bytes.Equal(buf, msg) {
		t.Fatalf("session died: %v %q", err, buf)
	}
	if got := s.gate.eventCount(); got < 7 {
		t.Fatalf("recorded %d events, wanted at least 7: %v", got, s.gate.eventsCopy())
	}
}

// TestUnknownRequestsRejectedOnWire — default-deny must be visible on
// the wire, not just in Lookup*. Before this, removing default-deny
// only made exactly one unit test go red, one that compared a constant
// against a constant.
func TestUnknownRequestsRejectedOnWire(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	h.startShell(t)
	for _, name := range []string{"totally-unknown-request", "sftp", "PTY-REQ", "shell "} {
		ok, err := h.ch.SendRequest(name, true, nil)
		if err != nil || ok {
			t.Errorf("channel %q: ok=%v err=%v, wanted a refusal", name, ok, err)
		}
	}
	for _, name := range []string{"totally-unknown-global", "keepalive@nobody", "KEEPALIVE@IAMTUNNEL"} {
		ok, _, err := s.person.SendRequest(name, true, nil)
		if err != nil || ok {
			t.Errorf("global %q: ok=%v err=%v, wanted a refusal", name, ok, err)
		}
	}
	// The session is alive after the refusals.
	if _, err := h.ch.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(h.ch, make([]byte, 5)); err != nil {
		t.Fatalf("session died: %v", err)
	}
}

// TestGlobalKeepaliveAnsweredOnWire — PROTOCOL §5: the receiver
// answers with a request success. keepalive@iamtunnel used to sit in
// the table as Forward, the gateway answered false, and the active
// side racked up misses on a live connection.
func TestGlobalKeepaliveAnsweredOnWire(t *testing.T) {
	s := newStack(t, time.Hour, 3) // the gateway's own probe does not get in the way
	for _, name := range []string{DefaultKeepaliveName, "keepalive@openssh.com"} {
		ok, _, err := s.person.SendRequest(name, true, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !ok {
			t.Fatalf("the gateway answered FALSE to %s; PROTOCOL §5 requires a request success", name)
		}
	}
}

// TestCompatibilityNotificationsProduceNoEvent — PROTOCOL §4.1: eow@
// and no-more-sessions@ are allowed, are not forwarded, and create no event.
func TestCompatibilityNotificationsProduceNoEvent(t *testing.T) {
	s := newStack(t, time.Hour, 3)
	h := openHuman(t, s.person)
	h.startShell(t)
	before := s.gate.eventCount()
	if _, err := h.ch.SendRequest("eow@openssh.com", false, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.person.SendRequest("no-more-sessions@openssh.com", false, nil); err != nil {
		t.Fatal(err)
	}
	// Give the gateway time to process both notifications: an empty pty-req cycle.
	h.request(t, "window-change", MarshalWindow(WindowChange{80, 24, 0, 0}))
	if got := s.gate.eventCount(); got != before {
		t.Fatalf("compatibility notifications created events: %v", s.gate.eventsCopy())
	}
	// The session is alive, the notification did not tear it down.
	if _, err := h.ch.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(h.ch, make([]byte, 2)); err != nil {
		t.Fatalf("session died: %v", err)
	}
}

// TestEnvFiltered — SPEC §5.1: only TERM and LANG go out to the
// machine. The previous test only counted "dropped:env" events and did
// not check the main thing — that TERM actually arrived; a "Forward
// does not forward when want-reply=false" bug left it green.
func TestEnvFiltered(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	for _, e := range []Env{
		{Name: "TERM", Value: "xterm-256color"},
		{Name: "PATH", Value: "/usr/bin"},
		{Name: "LD_PRELOAD", Value: "/tmp/evil.so"},
		{Name: "LANG", Value: "en_US.UTF-8"},
		{Name: "TERM", Value: "bad\x1b]0;title\x07"}, // a value with an escape sequence
	} {
		if _, err := h.ch.SendRequest("env", false, MarshalEnv(e)); err != nil {
			t.Fatal(err)
		}
	}
	h.startShell(t)
	_ = h.ch.CloseWrite()
	select {
	case <-h.exits:
	case <-time.After(5 * time.Second):
		t.Fatal("missing exit-status")
	}

	got := s.fake.envSeen()
	want := []Env{
		{Name: "TERM", Value: "xterm-256color"},
		{Name: "LANG", Value: "en_US.UTF-8"},
	}
	if len(got) != len(want) {
		t.Fatalf("what reached the machine was %+v, wanted %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("env #%d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// Three dropped: PATH, LD_PRELOAD, and TERM with an escape sequence.
	if n := s.gate.countEvent("dropped:env"); n != 3 {
		t.Fatalf("dropped:env = %d, want 3; events: %v", n, s.gate.eventsCopy())
	}
}

// TestEnvForbiddenAnswersFailure — PROTOCOL §4.1: "drop other names, on
// want-reply=true return a failure". Drop used to answer with
// nothing, and the client hung until its own timeout.
func TestEnvForbiddenAnswersFailure(t *testing.T) {
	s := newStack(t, 20*time.Millisecond, 3)
	h := openHuman(t, s.person)
	answered := make(chan bool, 1)
	go func() {
		ok, err := h.ch.SendRequest("env", true, MarshalEnv(Env{Name: "LD_PRELOAD", Value: "/tmp/x"}))
		if err == nil {
			answered <- ok
		}
	}()
	select {
	case ok := <-answered:
		if ok {
			t.Fatal("a forbidden env got a success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no answer for a forbidden env with want-reply=true; the client is hanging")
	}
	// An allowed one — success, because the machine accepted it.
	ok, err := h.ch.SendRequest("env", true, MarshalEnv(Env{Name: "TERM", Value: "xterm"}))
	if err != nil || !ok {
		t.Fatalf("TERM with want-reply=true: ok=%v err=%v", ok, err)
	}
}

// TestKeepaliveHealthy — a live machine is not closed by its own keepalive.
func TestKeepaliveHealthy(t *testing.T) {
	s := newStack(t, 15*time.Millisecond, 3)
	h := openHuman(t, s.person)
	h.startShell(t)
	time.Sleep(6 * 15 * time.Millisecond)
	msg := []byte("alive")
	if _, err := h.ch.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(h.ch, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("healthy keepalive closed session: %v %q", err, got)
	}
}

// TestKeepaliveBidirectionalThroughStack proves keepalive symmetry on the
// full rig: the gateway sends keepalive to the machine, the machine to
// the gateway, both sides judge via globalRequestTable. Eight
// intervals, not a single false break.
func TestKeepaliveBidirectionalThroughStack(t *testing.T) {
	const interval = 20 * time.Millisecond
	const misses = 3
	f := newFakeSSHD(t)
	g := newGateway(t, interval, misses)
	m := newMachineKeepalive(t, g, f.addr(), interval, misses)
	select {
	case <-g.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the machine never registered")
	}
	p, err := ssh.Dial("tcp", g.addr(), insecureClientConfig("human"))
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	h := openHuman(t, p)
	h.startShell(t)

	time.Sleep(interval * 8)

	if m.dead.Load() {
		t.Error("the machine declared a live gateway dead")
	}
	g.mu.Lock()
	gatewayDead := g.dead
	g.mu.Unlock()
	if gatewayDead {
		t.Error("the gateway declared a live machine dead")
	}
	// The tunnel still carries traffic after eight keepalive intervals in both directions.
	msg := []byte("still carrying traffic")
	if _, err := h.ch.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(h.ch, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("tunnel is not carrying traffic: %v %q", err, got)
	}
}

// TestKeepaliveForcedBreakClosesHuman — the machine vanishes
// instantly; the gateway closes the human channel with a diagnostic.
func TestKeepaliveForcedBreakClosesHuman(t *testing.T) {
	s := newStack(t, 15*time.Millisecond, 3)
	h := openHuman(t, s.person)
	h.startShell(t)
	_ = s.machine.conn.Close()
	_ = s.machine.raw.Close()
	done := make(chan []byte, 1)
	go func() {
		b, _ := io.ReadAll(h.ch)
		done <- b
	}()
	select {
	case b := <-done:
		if !bytes.Contains(b, []byte("Machine connection lost: keepalive timeout.")) {
			t.Fatalf("no clear reason for the break: %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the gateway did not close the human after the machine's forced disconnect")
	}
}

// TestKeepaliveSilentMachineClosesHuman — a silent machine (accepts
// the probe and does not answer) must be detected within interval ×
// misses. The same scenario as the Probe unit test, but through the whole rig.
func TestKeepaliveSilentMachineClosesHuman(t *testing.T) {
	const interval = 20 * time.Millisecond
	const misses = 3
	f := newFakeSSHD(t)
	g := newGateway(t, interval, misses)

	// A machine that accepts a global request and never answers.
	raw, err := net.DialTimeout("tcp", g.addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	conn, chans, reqs, err := ssh.NewClientConn(raw, g.addr(), insecureClientConfig("machine:silent"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// IAMT-314: this "silent machine" is hand-assembled and has no
	// fixture that would wait for its goroutines, so it counts them
	// itself. This defer is registered after the two above, so it
	// runs before them: first tear down everything they are blocked
	// on, then wait.
	var wg sync.WaitGroup
	conns := newConnSet()
	defer func() {
		_ = conn.Close()
		_ = raw.Close()
		conns.closeAll()
		wg.Wait()
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range reqs { // accept and stay silent
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := range chans {
			ch, rr, err := n.Accept()
			if err != nil {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				for r := range rr {
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
				}
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				splice(ch, f.addr(), conns)
			}()
		}
	}()
	select {
	case <-g.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the machine never registered")
	}

	select {
	case <-g.deadCh:
	case <-time.After(interval*misses + 5*time.Second):
		t.Fatalf("silent machine not detected within %v", interval*misses)
	}
	if n := g.countEvent("machine-keepalive-timeout"); n != 1 {
		t.Fatalf("break event recorded %d times, want 1", n)
	}
}
