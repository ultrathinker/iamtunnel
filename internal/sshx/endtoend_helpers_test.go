package sshx

// endtoend_helpers_test.go: shared helpers for the e2e and keepalive tests.
//
// The stack: the human (ssh.Client) → the gateway (accepts SSH, proxies
// through iamtunnel-target) → the machine (ssh.Client to the gateway)
// → a fake sshd (accepts session and echoes). The helpers carry no
// policy of their own: every per-request decision is a call into sshx
// (LookupChannelRequest / LookupGlobalRequest / EnvBudget.Decide +
// ApplyDisposition). So weakening any table entry shows up in the
// end-to-end tests, not just the table's own unit tests.

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// helpers --------------------------------------------------------------------

func mustSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func insecureClientConfig(user string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
}

// fakeSSHD — a minimal sshd: accepts "session", echoes the stream, and
// records everything that reached it. The recordings are needed by the
// end-to-end tests: without them there is no way to tell "the request
// reached the machine" from "the request was swallowed along the way".
// connSet -- the set of live connections for one fixture (IAMT-314).
// Closing the set tears all of them down and forbids registering new
// ones, so the fixture's cleanup unblocks its own goroutines itself,
// rather than waiting for the other side to do it. Without it,
// "waiting for your own goroutines" turns into "hanging on them": the
// loop over chans or reqs lives exactly as long as the transport
// under it does.
type connSet struct {
	mu     sync.Mutex
	closed bool
	conns  map[io.Closer]struct{}
}

func newConnSet() *connSet { return &connSet{conns: map[io.Closer]struct{}{}} }

// add registers c and returns false if the set is already closed: in
// that case c is closed right here, and the calling goroutine must
// exit immediately -- otherwise it would go uncounted after closeAll.
func (s *connSet) add(c io.Closer) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = c.Close()
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *connSet) remove(c io.Closer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, c)
}

func (s *connSet) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for c := range s.conns {
		_ = c.Close()
	}
	s.conns = map[io.Closer]struct{}{}
}

type fakeSSHD struct {
	listener net.Listener
	signer   ssh.Signer

	// Teardown (IAMT-314). quit tells the fixture's goroutines there
	// is nothing left to wait for; conns tears down the accepted
	// connections so the loops over chans/reqs finish; wg counts ALL
	// of the fixture's goroutines, and close() waits on exactly that.
	quit     chan struct{}
	quitOnce sync.Once
	wg       sync.WaitGroup
	conns    *connSet

	// rejectOnKeepalive: if true, keepalive@iamtunnel answers false.
	rejectOnKeepalive bool
	// exitSignal: if not empty, an exit-signal with this name is sent
	// instead of exit-status when the session ends.
	exitSignal string

	// observed state
	mu      sync.Mutex
	pty     PTYRequest
	window  WindowChange
	gotPTY  bool
	gotWin  bool
	env     []Env
	exec    Exec
	gotExec bool
	signals []string
	eofSeen bool
}

func newFakeSSHD(t *testing.T) *fakeSSHD {
	t.Helper()
	s := &fakeSSHD{signer: mustSigner(t), quit: make(chan struct{}), conns: newConnSet()}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s.listener = ln
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.accept()
	}()
	t.Cleanup(s.close)
	return s
}

func (f *fakeSSHD) addr() string { return f.listener.Addr().String() }

// close -- deterministic fixture teardown (IAMT-314). All blocking
// points are released first: quit wakes up session, closing the
// listener stops accept, tearing down accepted connections finishes
// the loops over chans and reqs. Only after that do we wait for the
// goroutines. The reverse order -- wg.Wait() before tearing down --
// would hang on exactly the loops it is waiting for.
func (f *fakeSSHD) close() {
	f.quitOnce.Do(func() { close(f.quit) })
	_ = f.listener.Close()
	f.conns.closeAll()
	f.wg.Wait()
}

func (f *fakeSSHD) accept() {
	for {
		raw, err := f.listener.Accept()
		if err != nil {
			return
		}
		if !f.conns.add(raw) {
			continue
		}
		// wg.Add is called from a goroutine already counted in wg, so
		// the counter cannot drop to zero between Add and Wait: there
		// is no forbidden Add/Wait race here.
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.conn(raw)
		}()
	}
}

func (f *fakeSSHD) conn(raw net.Conn) {
	defer raw.Close()
	defer f.conns.remove(raw)
	cfg := &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-fake"}
	cfg.AddHostKey(f.signer)
	conn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for r := range reqs {
			if r.Type == DefaultKeepaliveName {
				ok := !f.rejectOnKeepalive
				if r.WantReply {
					_ = r.Reply(ok, nil)
				}
			} else if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, rr, err := n.Accept()
		if err != nil {
			continue
		}
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.session(ch, rr)
		}()
	}
}

func (f *fakeSSHD) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	started := make(chan struct{})
	reqsDone := make(chan struct{})
	var once sync.Once
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		defer close(reqsDone)
		for r := range reqs {
			switch r.Type {
			case "pty-req":
				p, err := ParsePTY(r.Payload)
				if err != nil {
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
					continue
				}
				f.mu.Lock()
				f.pty = p
				f.gotPTY = true
				f.mu.Unlock()
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
			case "window-change":
				w, err := ParseWindow(r.Payload)
				if err != nil {
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
					continue
				}
				f.mu.Lock()
				f.window = w
				f.gotWin = true
				f.mu.Unlock()
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
			case "signal":
				s, err := ParseSignal(r.Payload)
				if err == nil {
					f.mu.Lock()
					f.signals = append(f.signals, s.Name)
					f.mu.Unlock()
				}
				if r.WantReply {
					_ = r.Reply(err == nil, nil)
				}
			case "exec":
				e, err := ParseExec(r.Payload)
				if err != nil {
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
					continue
				}
				f.mu.Lock()
				f.exec = e
				f.gotExec = true
				f.mu.Unlock()
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
				once.Do(func() { close(started) })
			case "shell":
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
				once.Do(func() { close(started) })
			case "env":
				// Record what actually reached the machine: the env
				// filter test must see not just what was dropped, but
				// also what was let through.
				e, err := ParseEnv(r.Payload)
				if err == nil {
					f.mu.Lock()
					f.env = append(f.env, e)
					f.mu.Unlock()
				}
				if r.WantReply {
					_ = r.Reply(err == nil, nil)
				}
			default:
				if r.WantReply {
					_ = r.Reply(false, nil)
				}
			}
		}
	}()

	// IAMT-314. This used to be a bare "<-started", and it was a real
	// leak, not a race: shell and exec do not always arrive. The
	// gateway opens the nested session immediately once the human
	// opens their channel, before any shell (gateway.proxy below),
	// and the TestEnvForbiddenAnswersFailure test only exercises env
	// and never sends shell at all. started was never closed, and the
	// goroutine stayed blocked reading from the channel until the
	// process ended -- goleak is what caught it.
	//
	// The product's counterpart of this spot -- awaitSessionStart in
	// internal/gateway/human_role.go -- exits on two additional
	// conditions: a closed request stream and a timeout. The fixture
	// repeats the first of these (reqsDone closes strictly AFTER the
	// loop above has processed every request that arrived, so an
	// arriving shell always manages to close started first) and adds
	// its own termination.
	select {
	case <-started:
	case <-reqsDone:
	case <-f.quit:
	}
	// select picks randomly among ready branches, so that alone is
	// not enough: the decision is made on started, and only on started.
	select {
	case <-started:
	default:
		// Neither shell nor exec arrived: there was no session, so
		// there will be no echo loop and no exit-status.
		return
	}

	buf := make([]byte, 32*1024)
	for {
		n, err := ch.Read(buf)
		if n > 0 {
			_, _ = ch.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	// Read to the end of the stream — meaning the human's
	// SSH_MSG_CHANNEL_EOF reached us through the gateway and the machine (RFC 4254 §5.3).
	f.mu.Lock()
	f.eofSeen = true
	sig := f.exitSignal
	f.mu.Unlock()
	if sig != "" {
		_, _ = ch.SendRequest("exit-signal", false, MarshalExitSignal(ExitSignal{
			Signal:       sig,
			CoreDumped:   true,
			ErrorMessage: "killed by test",
			LanguageTag:  "en",
		}))
	} else {
		_, _ = ch.SendRequest("exit-status", false, MarshalExitStatus(ExitStatus{42}))
	}
}

func (f *fakeSSHD) state() (PTYRequest, WindowChange, bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pty, f.window, f.gotPTY, f.gotWin
}

func (f *fakeSSHD) envSeen() []Env {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Env(nil), f.env...)
}

func (f *fakeSSHD) signalsSeen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.signals...)
}

func (f *fakeSSHD) execSeen() (Exec, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.exec, f.gotExec
}

func (f *fakeSSHD) eofDelivered() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.eofSeen
}

func (f *fakeSSHD) waitForState(t *testing.T, wantWindow bool) {
	t.Helper()
	waitFor(t, "fake sshd did not observe pty-req", func() bool {
		_, _, p, w := f.state()
		return p && (!wantWindow || w)
	})
}

// waitFor polls cond for up to two seconds and fails the test with message msg.
func waitFor(t *testing.T, msg string, cond func() bool) {
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

// machine — the machine's connection to the gateway as an SSH client.
// Accepts iamtunnel-target channels, dials the target, and splices the
// stream. Keepalive runs in both directions: Respond to the gateway's
// incoming probes, and (optionally) Probe for its own.
type machine struct {
	conn ssh.Conn
	raw  net.Conn
	done chan struct{}
	g    *gateway

	dead      atomic.Bool
	stopProbe func()

	// Teardown (IAMT-314), set up the same way as fakeSSHD. conns here
	// holds the TCP splice connections to the target: without tearing
	// them down, io.Copy(ch, d) waits for the target to close on its
	// own, and the machine's cleanup would hang on its own wg.Wait().
	wg    sync.WaitGroup
	conns *connSet
}

func newMachine(t *testing.T, g *gateway, target string) *machine {
	return newMachineKeepalive(t, g, target, 0, 0)
}

// newMachineKeepalive starts a machine that also sends
// keepalive@iamtunnel to the gateway itself — the spec §5.2's bidirectional keepalive.
func newMachineKeepalive(t *testing.T, g *gateway, target string, interval time.Duration, misses int) *machine {
	t.Helper()
	raw, err := net.DialTimeout("tcp", g.addr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, g.addr(), insecureClientConfig("machine:m"))
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	m := &machine{conn: conn, raw: raw, done: make(chan struct{}), g: g, conns: newConnSet()}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		Keepalive{}.Respond(reqs)
	}()
	if interval > 0 {
		m.stopProbe = Keepalive{Interval: interval, MaxMisses: misses}.Probe(conn, func() {
			m.dead.Store(true)
		})
	}
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer close(m.done)
		for n := range chans {
			if n.ChannelType() != "iamtunnel-target" || len(n.ExtraData()) != 0 {
				_ = n.Reject(ssh.Prohibited, "bad target")
				continue
			}
			ch, rr, err := n.Accept()
			if err != nil {
				continue
			}
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				for r := range rr {
					if r.WantReply {
						_ = r.Reply(false, nil)
					}
				}
			}()
			m.wg.Add(1)
			go func() {
				defer m.wg.Done()
				splice(ch, target, m.conns)
			}()
		}
	}()
	t.Cleanup(func() {
		// Tear down everything holding goroutines first, then wait
		// for them (IAMT-314).
		_ = conn.Close()
		_ = raw.Close()
		m.conns.closeAll()
		if m.stopProbe != nil {
			// Strictly AFTER conn.Close(): stop() does not wait for
			// the goroutine of the last unanswered probe (this is
			// documented in Keepalive.Probe), and it exits precisely
			// when conn closes.
			m.stopProbe()
		}
		<-m.done
		m.wg.Wait()
	})
	return m
}

// splice -- a bidirectional proxy between an ssh.Channel and a TCP
// target. conns is the owner's set (IAMT-314): without registering
// the TCP connection to the target, io.Copy(ch, d) below waits for
// the target to close on its own, and the owner's cleanup would hang
// on its own wg.Wait().
func splice(ch ssh.Channel, target string, conns *connSet) {
	defer ch.Close()
	d, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return
	}
	defer d.Close()
	if !conns.add(d) {
		return
	}
	defer conns.remove(d)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(d, ch)
		if x, ok := d.(*net.TCPConn); ok {
			_ = x.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ch, d)
		_ = ch.CloseWrite()
	}()
	wg.Wait()
}

// gateway — the actual iamtunnel gateway. Carries no business logic:
// per-request decisions are made by sshx.
type gateway struct {
	listener net.Listener
	signer   ssh.Signer

	// the machine and its channel
	mu        sync.Mutex
	machine   ssh.Conn
	dead      bool
	deadCh    chan struct{}
	deadOnce  sync.Once
	ready     chan struct{}
	readyOnce sync.Once

	// active human channels
	active map[ssh.Channel]struct{}

	// events for the tests
	events []string

	// keepalive settings for gateway → machine
	keepaliveInterval time.Duration
	keepaliveMisses   int
	stopProbe         func()

	// Teardown (IAMT-314), set up the same way as fakeSSHD.
	quit     chan struct{}
	quitOnce sync.Once
	wg       sync.WaitGroup
	conns    *connSet
}

func newGateway(t *testing.T, interval time.Duration, misses int) *gateway {
	t.Helper()
	g := &gateway{
		signer:            mustSigner(t),
		active:            map[ssh.Channel]struct{}{},
		deadCh:            make(chan struct{}),
		ready:             make(chan struct{}),
		keepaliveInterval: interval,
		keepaliveMisses:   misses,
		quit:              make(chan struct{}),
		conns:             newConnSet(),
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g.listener = ln
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		g.accept()
	}()
	t.Cleanup(func() { g.close() })
	return g
}

func (g *gateway) addr() string { return g.listener.Addr().String() }

// close -- deterministic teardown (IAMT-314), the same order as
// fakeSSHD.close: release the blocking points, then wait.
func (g *gateway) close() {
	g.quitOnce.Do(func() { close(g.quit) })
	_ = g.listener.Close()
	g.mu.Lock()
	stop := g.stopProbe
	if g.machine != nil {
		_ = g.machine.Close()
	}
	for c := range g.active {
		_ = c.Close()
	}
	g.mu.Unlock()
	// Without this, "for n := range chans" on g.conn and the loops
	// over reqs wait for the other side to close.
	g.conns.closeAll()
	if stop != nil {
		// After closing the machine's connection: see the same
		// comment in the machine's cleanup about the goroutine for
		// the last unanswered probe.
		stop()
	}
	g.wg.Wait()
}

func (g *gateway) event(s string) {
	g.mu.Lock()
	g.events = append(g.events, s)
	g.mu.Unlock()
}

func (g *gateway) eventCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.events)
}

func (g *gateway) eventsCopy() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.events...)
}

func (g *gateway) countEvent(name string) int {
	n := 0
	for _, e := range g.eventsCopy() {
		if e == name {
			n++
		}
	}
	return n
}

// note records an event for the applied disposition. PROTOCOL §4.1
// requires that compatible OpenSSH notifications (eow@,
// no-more-sessions@) create NO event.
func (g *gateway) note(prefix string, name string, d Disposition) {
	switch d {
	case Reject:
		g.event(prefix + "forbidden:" + name)
	case Drop:
		if !IsCompatibilityNotification(name) {
			g.event(prefix + "dropped:" + name)
		}
	}
}

func (g *gateway) accept() {
	for {
		raw, err := g.listener.Accept()
		if err != nil {
			return
		}
		if !g.conns.add(raw) {
			continue
		}
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			g.conn(raw)
		}()
	}
}

// globalLoop — the gateway's only global-request policy: the sshx table.
func (g *gateway) globalLoop(prefix string, reqs <-chan *ssh.Request) {
	for r := range reqs {
		d := LookupGlobalRequest(r.Type)
		g.note(prefix, r.Type, d)
		// There is nowhere to forward a global request to: forward == nil.
		_ = ApplyDisposition(r.Type, r.WantReply, r.Reply, d, nil)
	}
}

func (g *gateway) conn(raw net.Conn) {
	defer raw.Close()
	defer g.conns.remove(raw)
	cfg := &ssh.ServerConfig{NoClientAuth: true, ServerVersion: "SSH-2.0-gateway"}
	cfg.AddHostKey(g.signer)
	sc, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer sc.Close()

	if strings.HasPrefix(sc.User(), "machine:") {
		g.mu.Lock()
		select {
		case <-g.quit:
			// The gateway is already shutting down: a probe started
			// now would have nobody to stop it -- close() has already
			// captured its own stopProbe.
			g.mu.Unlock()
			return
		default:
		}
		g.machine = sc
		g.stopProbe = Keepalive{Interval: g.keepaliveInterval, MaxMisses: g.keepaliveMisses}.Probe(sc, g.failMachine)
		g.mu.Unlock()
		g.readyOnce.Do(func() { close(g.ready) })
		g.globalLoop("machine-global-", reqs)
		return
	}

	// The human
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		g.globalLoop("human-global-", reqs)
	}()
	for n := range chans {
		if n.ChannelType() == "session" {
			ch, rr, err := n.Accept()
			if err != nil {
				continue
			}
			g.wg.Add(1)
			go func() {
				defer g.wg.Done()
				g.proxy(ch, rr)
			}()
		} else {
			// channel-open direct-tcpip and others: SPEC §5.1
			// allows only one session channel.
			g.event("human-channel-reject:" + n.ChannelType())
			_ = n.Reject(ssh.Prohibited, "forbidden")
		}
	}
}

// machineConn returns the machine's ssh.Conn, if it has not been marked dead yet.
func (g *gateway) machineConn() (ssh.Conn, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.machine, g.machine != nil && !g.dead
}

func (g *gateway) failMachine() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.dead {
		return
	}
	g.dead = true
	g.deadOnce.Do(func() { close(g.deadCh) })
	for c := range g.active {
		_, _ = c.Write([]byte("\r\nMachine connection lost: keepalive timeout.\r\n"))
		_ = c.Close()
	}
	g.events = append(g.events, "machine-keepalive-timeout")
}

// proxy — the main proxy loop for one human channel.
func (g *gateway) proxy(human ssh.Channel, hreqs <-chan *ssh.Request) {
	machineConn, ok := g.machineConn()
	if !ok {
		_, _ = human.Write([]byte("Machine is offline.\r\n"))
		_ = human.Close()
		return
	}
	target, targetReqs, err := machineConn.OpenChannel("iamtunnel-target", nil)
	if err != nil {
		_, _ = human.Write([]byte("Cannot open target channel.\r\n"))
		_ = human.Close()
		return
	}
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for r := range targetReqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	tc := NewChannelConn(target)
	nested, chans, reqs, err := ssh.NewClientConn(tc, "fake-target", insecureClientConfig("administrator"))
	if err != nil {
		_ = target.Close()
		_ = human.Close()
		return
	}
	defer nested.Close()
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for r := range reqs {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for n := range chans {
			_ = n.Reject(ssh.UnknownChannelType, "no reverse channels")
		}
	}()
	session, mreqs, err := nested.OpenChannel("session", nil)
	if err != nil {
		_ = human.Close()
		return
	}
	defer session.Close()

	g.mu.Lock()
	if g.dead {
		g.mu.Unlock()
		_ = human.Close()
		return
	}
	g.active[human] = struct{}{}
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		delete(g.active, human)
		g.mu.Unlock()
	}()

	// The human's channel requests: sshx is the single decision point.
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		budget := NewEnvBudget()
		for r := range hreqs {
			var d Disposition
			if r.Type == "env" {
				d = budget.Decide(r.Payload)
			} else {
				d = LookupChannelRequest(r.Type, r.Payload)
			}
			g.note("", r.Type, d)
			forward := func() (bool, error) {
				return session.SendRequest(r.Type, r.WantReply, r.Payload)
			}
			_ = ApplyDisposition(r.Type, r.WantReply, r.Reply, d, forward)
		}
	}()

	// Requests going from the machine back to the human use the same table.
	normalExit := make(chan struct{})
	var exitOnce sync.Once
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		for r := range mreqs {
			d := LookupChannelRequest(r.Type, r.Payload)
			g.note("machine-", r.Type, d)
			forward := func() (bool, error) {
				return human.SendRequest(r.Type, r.WantReply, r.Payload)
			}
			_ = ApplyDisposition(r.Type, r.WantReply, r.Reply, d, forward)
			if r.Type == "exit-status" || r.Type == "exit-signal" {
				exitOnce.Do(func() { close(normalExit) })
			}
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(session, human)
		// The human's SSH_MSG_CHANNEL_EOF → the machine (RFC 4254 §5.3, PROTOCOL §4.1).
		_ = session.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(human, session)
	}()
	wg.Wait()
	select {
	case <-normalExit:
		_ = human.CloseWrite()
	case <-g.deadCh:
		// The diagnostic has already been sent from failMachine.
	case <-g.quit:
		// IAMT-314: without this branch, the gateway's cleanup would
		// wait here for up to two seconds on every test where
		// exit-status never arrived -- i.e. precisely where the
		// session never started.
	case <-time.After(2 * time.Second):
		_ = human.CloseWrite()
	}
}

// stack — the assembled rig of four participants.
type stack struct {
	fake    *fakeSSHD
	gate    *gateway
	machine *machine
	person  *ssh.Client
}

func newStack(t *testing.T, interval time.Duration, misses int) *stack {
	t.Helper()
	f := newFakeSSHD(t)
	return newStackWith(t, f, interval, misses)
}

func newStackWith(t *testing.T, f *fakeSSHD, interval time.Duration, misses int) *stack {
	t.Helper()
	g := newGateway(t, interval, misses)
	m := newMachine(t, g, f.addr())
	select {
	case <-g.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("machine did not register")
	}
	p, err := ssh.Dial("tcp", g.addr(), insecureClientConfig("human"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.Close()
	})
	return &stack{f, g, m, p}
}

// humanSession — a wrapper over the human's open session channel.
type humanSession struct {
	ch    ssh.Channel
	reqs  <-chan *ssh.Request
	exits chan uint32
	sigs  chan ExitSignal
	done  chan struct{}
}

func openHuman(t *testing.T, p *ssh.Client) *humanSession {
	ch, r, err := p.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &humanSession{ch: ch, reqs: r, exits: make(chan uint32, 1), sigs: make(chan ExitSignal, 1), done: make(chan struct{})}
	// IAMT-314: t.Cleanup runs in reverse order, so this cleanup runs
	// BEFORE the one that closes p in newStackWith: waiting for r to
	// close on its own is not possible here, so we close the human
	// ourselves. The later, redundant close of p down the chain is harmless.
	t.Cleanup(func() {
		_ = ch.Close()
		_ = p.Close()
		<-h.done
	})
	go func() {
		defer close(h.done)
		for q := range r {
			switch q.Type {
			case "exit-status":
				if e, err := ParseExitStatus(q.Payload); err == nil {
					select {
					case h.exits <- e.Status:
					default:
					}
				}
			case "exit-signal":
				if e, err := ParseExitSignal(q.Payload); err == nil {
					select {
					case h.sigs <- e:
					default:
					}
				}
			}
			if q.WantReply {
				_ = q.Reply(false, nil)
			}
		}
	}()
	return h
}

func (h *humanSession) request(t *testing.T, name string, payload []byte) {
	t.Helper()
	ok, err := h.ch.SendRequest(name, true, payload)
	if err != nil || !ok {
		t.Fatalf("%s rejected: ok=%v err=%v", name, ok, err)
	}
}

// startShell — the standard session preamble: pty-req + shell.
func (h *humanSession) startShell(t *testing.T) {
	t.Helper()
	h.request(t, "pty-req", MarshalPTY(PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	h.request(t, "shell", nil)
}
