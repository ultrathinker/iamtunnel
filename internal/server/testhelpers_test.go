package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/winkeys"
)

// testUIDForDoor and testGIDForDoor return the owner winkeys should treat
// the door line as having for unit tests. The winkeys strict-mode preflight
// accepts owner == opts.OwnerUID OR owner == 0, so a concrete non-root
// owner keeps the t.TempDir()-rooted tree valid in both runner shapes
// tests run in:
//
//   - non-root runner: the temp tree is owned by this very process, which
//     is exactly what comes back here — the "owner matches" branch passes,
//     and fchownIfRoot skips the chown (owner already right, non-root
//     cannot chown anyway);
//
//   - root runner (the docker root lane): os.Getuid() would be 0, and
//     DoorOptions{0, 0} is the winkeys unset-owner sentinel —
//     validateOptionsPlatform refuses it outright and fchownIfRoot refuses
//     it too, so passing 0 through would fail every door test before any
//     filesystem work. Under root both helpers return the fixed 1000
//     instead: the temp tree is still root-owned and passes through the
//     preflight's "or root" branch, and the door layer's chown step is a
//     recording seam in this test binary (seams_unix_test.go), so nothing
//     is really chowned to 1000.
//
// IAMT-284: these were one function whose value was used for both fields,
// which silently asserted uid == gid. That holds in the Linux container
// this suite grew up in (first user, private group) and nowhere else: on a
// real macOS account uid=501 but gid=20 (staff). The strict-mode preflight
// then compared the temp tree's real owner (501) with the fixture's 1000
// ("is owned by uid 501, expected uid 1000"), and fchownIfRoot refused
// "501:501" because the user is not in group 501. The ids of an account are
// two independent facts; the fixtures now say so.
func testUIDForDoor() int {
	if uid := os.Getuid(); uid > 0 {
		return uid
	}
	return 1000
}

func testGIDForDoor() int {
	if gid := os.Getgid(); gid > 0 {
		return gid
	}
	return 1000
}

// testhelpers_test.go: key generation and small fake peers shared by this
// package's tests. Nothing here touches a real filesystem path outside
// t.TempDir(), a real sshd, or a real network interface other than
// 127.0.0.1 — the same discipline internal/gateway/harness_test.go
// documents for its own fakes.

func mustEd25519(t *testing.T) any {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return priv
}

func mustRSA(t *testing.T) any {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return priv
}

// fakeGateway is a minimal SSH server standing in for internal/gateway
// from the machine's point of view: it accepts the machine's login and
// lets the test open channels toward it exactly as the real gateway would
// (PROTOCOL §5: only the gateway ever opens iamtunnel-control /
// iamtunnel-target). Unlike internal/gateway/harness_test.go's fakeMachine
// (the mirror image, used from the gateway's own tests), this fake plays
// the gateway's role so internal/server can be tested without importing
// internal/gateway at all.
//
// connSet -- the set of live connections for one fixture (IAMT-314).
// Closing the set tears all of them down and forbids registering new
// ones, so the fixture's cleanup unblocks its own goroutines itself,
// rather than waiting for the other side to do it: the loop over chans
// or reqs lives exactly as long as the transport under it does. A copy
// of the same helper from internal/sshx/endtoend_helpers_test.go: test
// files in one package are not visible to another.
type connSet struct {
	mu     sync.Mutex
	closed bool
	conns  map[io.Closer]struct{}
}

func newConnSet() *connSet { return &connSet{conns: map[io.Closer]struct{}{}} }

// add registers c and returns false if the set is already closed: in
// that case c is closed right here, and the calling goroutine must
// exit immediately.
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

// conn/chans are written exactly once, by acceptOne, strictly before
// close(ready); every reader waits on ready first. That ordering — not a
// mutex — is what makes this race-free under -race: a channel close is a
// happens-before edge for every later receive of it (Go memory model), so
// there is no data race even though acceptOne runs in its own goroutine.
type fakeGateway struct {
	ln           net.Listener
	hostKey      ssh.Signer
	machineKeyOK func(ssh.PublicKey) bool
	// cfgMod, if set, is applied to this fake gateway's own ssh.ServerConfig
	// before it starts accepting - IAMT-173's policy tests use it to pin
	// the server side to a single algorithm so the real wire handshake,
	// not just a struct field, proves the machine client's policy.
	cfgMod func(*ssh.ServerConfig)

	ready chan struct{}
	conn  *ssh.ServerConn
	chans <-chan ssh.NewChannel

	// Teardown (IAMT-314): wg counts the fixture's goroutines, conns
	// holds the accepted connection so close() can tear it down.
	wg    sync.WaitGroup
	conns *connSet
}

func newFakeGateway(t *testing.T, machineKeyOK func(ssh.PublicKey) bool) *fakeGateway {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	fg := &fakeGateway{ln: ln, hostKey: mustSigner(t), machineKeyOK: machineKeyOK, ready: make(chan struct{}), conns: newConnSet()}
	t.Cleanup(fg.close)
	return fg
}

// close -- deterministic teardown (IAMT-314): first tear down what the
// goroutines are blocked on (the listener and the accepted connection —
// the latter closes reqs and chans), then wait. Closing just the
// listener is not enough: it does not touch a connection already
// accepted.
func (fg *fakeGateway) close() {
	_ = fg.ln.Close()
	fg.conns.closeAll()
	fg.wg.Wait()
}

// startAccept runs acceptOne in a goroutine the fixture owns
// (IAMT-314). Tests used to write "go fg.acceptOne()" themselves,
// leaving the fixture with a goroutine it had no way to wait for.
func (fg *fakeGateway) startAccept() {
	fg.wg.Add(1)
	go func() {
		defer fg.wg.Done()
		fg.acceptOne()
	}()
}

func (fg *fakeGateway) addr() string { return fg.ln.Addr().String() }

func (fg *fakeGateway) fingerprint() string { return ssh.FingerprintSHA256(fg.hostKey.PublicKey()) }

// acceptOne accepts exactly one incoming connection and completes the SSH
// server handshake. Run it in its own goroutine before dialing.
func (fg *fakeGateway) acceptOne() {
	raw, err := fg.ln.Accept()
	if err != nil {
		close(fg.ready)
		return
	}
	if !fg.conns.add(raw) {
		close(fg.ready)
		return
	}
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if fg.machineKeyOK == nil || fg.machineKeyOK(key) {
				return &ssh.Permissions{}, nil
			}
			return nil, errRejectedKey
		},
	}
	if fg.cfgMod != nil {
		fg.cfgMod(cfg)
	}
	cfg.AddHostKey(fg.hostKey)
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		_ = raw.Close()
		close(fg.ready)
		return
	}
	fg.conn = sconn
	fg.chans = chans
	fg.wg.Add(1)
	go func() {
		defer fg.wg.Done()
		ssh.DiscardRequests(reqs)
	}()
	close(fg.ready)
}

// wait blocks until acceptOne has completed (successfully or not) and
// returns the accepted connection, failing the test on timeout or on a
// failed handshake.
func (fg *fakeGateway) wait(t *testing.T) *ssh.ServerConn {
	t.Helper()
	select {
	case <-fg.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("gateway never observed the machine's connection")
	}
	if fg.conn == nil {
		t.Fatal("machine's connection to the fake gateway failed")
	}
	return fg.conn
}

// openControl opens the one iamtunnel-control channel this fake plays the
// gateway's side of.
func (fg *fakeGateway) openControl(t *testing.T) ssh.Channel {
	t.Helper()
	sc := fg.wait(t)
	ch, reqs, err := sc.OpenChannel("iamtunnel-control", nil)
	if err != nil {
		t.Fatalf("open control channel: %v", err)
	}
	fg.wg.Add(1)
	go func() {
		defer fg.wg.Done()
		ssh.DiscardRequests(reqs)
	}()
	return ch
}

// serveInBackground runs m.Serve(ctx) in a goroutine the test owns and joins
// it on cleanup (IAMT-314).
//
// Serve is where a machine's long-lived goroutines live - the conn.Wait
// watcher, the keepalive responder, the keepalive prober, and one splice
// pair per accepted target channel. A bare "go m.Serve(ctx)" whose result
// nobody ever waits for is the same discard shape as a RateLimiter
// constructed into "_": cancelling the context only STARTS the unwind, it
// does not finish it, and Serve still has to stop the prober (which itself
// waits for the probe loop) and clean the door on the way out.
//
// The wait is bounded and reports instead of hanging: a Serve that genuinely
// does not return says so on its own line rather than stalling the suite
// until go test's global timeout.
func serveInBackground(t *testing.T, ctx context.Context, cancel context.CancelFunc, m *Machine) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = m.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("Machine.Serve did not return within 10s of context cancellation")
		}
	})
}

var errRejectedKey = &keyRejected{}

type keyRejected struct{}

func (*keyRejected) Error() string { return "fakeGateway: key rejected" }

// fakeSSHD is a minimal loopback TCP+SSH server standing in for the
// machine's own real sshd on 127.0.0.1:22: the real sshd service of
// this machine is never touched; every fake lives on an ephemeral
// loopback port.
type fakeSSHD struct {
	ln      net.Listener
	signer  ssh.Signer
	allowed func([]byte) bool

	// Teardown (IAMT-314), set up the same way as fakeSSHD in internal/sshx.
	quit     chan struct{}
	quitOnce sync.Once
	wg       sync.WaitGroup
	conns    *connSet
}

func newFakeSSHD(t *testing.T, allowed func([]byte) bool) *fakeSSHD {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeSSHD{ln: ln, signer: mustSigner(t), allowed: allowed, quit: make(chan struct{}), conns: newConnSet()}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.accept()
	}()
	t.Cleanup(s.close)
	return s
}

func (s *fakeSSHD) addr() string { return s.ln.Addr().String() }

// close -- deterministic teardown (IAMT-314): release all blocking
// points first, then wait. The reverse order would hang on the very
// loops it is waiting for.
func (s *fakeSSHD) close() {
	s.quitOnce.Do(func() { close(s.quit) })
	_ = s.ln.Close()
	s.conns.closeAll()
	s.wg.Wait()
}

func (s *fakeSSHD) accept() {
	for {
		raw, err := s.ln.Accept()
		if err != nil {
			return
		}
		if !s.conns.add(raw) {
			continue
		}
		// wg.Add from a goroutine already counted in wg: the counter
		// cannot reach zero between Add and Wait, so there is no
		// Add/Wait race.
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.conn(raw)
		}()
	}
}

func (s *fakeSSHD) conn(raw net.Conn) {
	defer raw.Close()
	defer s.conns.remove(raw)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if s.allowed(key.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errRejectedKey
		},
	}
	cfg.AddHostKey(s.signer)
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ssh.DiscardRequests(reqs)
	}()
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, reqs, err := n.Accept()
		if err != nil {
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveEchoSession(ch, reqs)
		}()
	}
}

// serveEchoSession accepts pty-req/shell/exec/window-change/env like a
// real interactive shell would, then echoes every byte back — mirroring
// internal/gateway/harness_test.go's fakeTargetSSHD so a nested SSH
// session over iamtunnel-target has something real to talk to.
func (s *fakeSSHD) serveEchoSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	started := make(chan struct{})
	reqsDone := make(chan struct{})
	var once sync.Once
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(reqsDone)
		for r := range reqs {
			switch r.Type {
			case "pty-req", "shell", "window-change", "env":
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
				if r.Type == "shell" {
					once.Do(func() { close(started) })
				}
			case "exec":
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
				once.Do(func() { close(started) })
			default:
				if r.WantReply {
					_ = r.Reply(false, nil)
				}
			}
		}
	}()

	// IAMT-314: the same fix as (*fakeSSHD).session in internal/sshx,
	// and for the same reason: a bare "<-started" has no way out at
	// all if shell and exec never arrive. Today the only test in this
	// package that opens a nested session does send shell, so here
	// this was a latent issue rather than an active leak; in sshx such
	// a test exists, and there it was an active one.
	select {
	case <-started:
	case <-reqsDone:
	case <-s.quit:
	}
	// select picks randomly among ready branches: the decision is made
	// on started, and only on started.
	select {
	case <-started:
	default:
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
}

// noopSpawnWatchdog is a SpawnWatchdog-shaped function for unit tests of
// door.go's validation logic, which is orthogonal to the real watchdog
// subprocess: winkeys.Watchdog.Stop() is documented nil-receiver-safe, so
// returning (nil, nil) here is a faithful "a watchdog exists and can be
// stopped" stand-in without spawning anything. The real subprocess
// path — spawn-before-write ordering and actual cleanup-on-crash — is
// covered by machine_integration_test.go using the real
// winkeys.SpawnWatchdog against a built iamtunnel.exe, mirroring how
// internal/winkeys/doorwatch_test.go covers it for the gateway side.
func noopSpawnWatchdog(_, _, _ string, _ int, _ time.Duration, _, _ string, _, _ int) (*winkeys.Watchdog, error) {
	return nil, nil
}
