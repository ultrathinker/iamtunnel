package client_test

// connect_test.go exercises internal/client.Connect against a real
// internal/gateway.Gateway (gatewayfixture_test.go) for the denied-machine
// and recording-banner cases, end to end, plus the ordinary happy path
// with a forwarded exit-status. Mid-session transport loss is proved
// against a smaller, deterministic fake human-login peer instead (see
// fakeHumanPeer below): driving that scenario through the full real
// gateway + fake machine + fake target sshd chain turned out to depend
// on exactly when the gateway's nested handshake to the fake target
// sshd completes relative to the fake machine's own splice goroutines,
// which is not a fact internal/client's contract makes any promise
// about and not something this role's tests should be timing-
// sensitive to. The fake peer below plays only the one part
// internal/client actually needs to get right: a session that was
// genuinely granted a shell, then had its transport die before an
// exit-status arrived.

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

// connectRetrying calls client.Connect repeatedly until it reports a
// granted shell or the deadline passes. A freshly connected fake machine
// needs a real (short) round trip with the gateway — control channel
// accept, initial door.status — before a human session can succeed; this
// absorbs exactly that window instead of the test guessing a sleep.
// newOpts is called fresh for every attempt: reusing one attempt's In/Out
// across a retry would race a leftover background copy goroutine against
// the next attempt's own (bridge.go's keyboard-forwarding goroutine is not
// guaranteed to have stopped just because Connect returned).
func connectRetrying(t *testing.T, newOpts func() client.ConnectOptions) (client.ConnectOutcome, *syncBuffer, error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last client.ConnectOutcome
	var lastErr error
	var lastOut *syncBuffer
	for time.Now().Before(deadline) {
		out := &syncBuffer{}
		opts := newOpts()
		opts.Out = out
		outcome, err := client.Connect(context.Background(), opts)
		if err == nil && outcome.ShellGranted {
			return outcome, out, nil
		}
		last, lastErr, lastOut = outcome, err, out
		time.Sleep(20 * time.Millisecond)
	}
	return last, lastOut, lastErr
}

func TestConnectDeniedWithoutGrant(t *testing.T) {
	gf := newGWFixture(t)
	strangerSigner := testSigner(t)
	gf.addPerson(t, "mallory", strangerSigner, nil) // registered, but never granted
	gf.start(t)
	gf.connectMachine(t)

	dir := t.TempDir()
	out := &syncBuffer{}
	inR, inW := io.Pipe()
	t.Cleanup(func() { _ = inW.Close() })

	outcome, err := client.Connect(context.Background(), client.ConnectOptions{
		Conn:           gf.connString("mallory"),
		Machine:        gf.machineID,
		Signer:         strangerSigner,
		KnownHostsPath: client.KnownHostsPath(dir),
		In:             inR,
		Out:            out,
		DialTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if outcome.ShellGranted {
		t.Fatal("a person with no grant was given a shell")
	}
	if outcome.ExitStatus != nil {
		t.Fatalf("a denied session reported an exit status %d", *outcome.ExitStatus)
	}
	if !strings.Contains(out.String(), "Access to this machine is currently unavailable") {
		t.Fatalf("denial text did not reach Out: %q", out.String())
	}
}

// TestConnectGrantedShowsBannerAndForwardsCleanExit proves the banner
// reaches the screen end to end through the real gateway, and covers
// the ordinary completion case (a clean exit-status, not an
// interruption): stdin is empty, so the client's own EOF drives a full,
// real close -> exit-status(0) -> close round trip identical to a real
// "exit" typed into a granted shell.
func TestConnectGrantedShowsBannerAndForwardsCleanExit(t *testing.T) {
	gf := newGWFixture(t)
	signer := testSigner(t)
	until := time.Now().Add(time.Hour)
	gf.addPerson(t, "alice", signer, &until)
	gf.start(t)
	gf.connectMachine(t)

	dir := t.TempDir()
	outcome, out, err := connectRetrying(t, func() client.ConnectOptions {
		return client.ConnectOptions{
			Conn:           gf.connString("alice"),
			Machine:        gf.machineID,
			Signer:         signer,
			KnownHostsPath: client.KnownHostsPath(dir),
			In:             strings.NewReader(""), // immediate EOF -> CloseWrite -> real exit-status round trip
			DialTimeout:    2 * time.Second,
		}
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !outcome.ShellGranted {
		t.Fatal("a granted person never got a shell")
	}
	if outcome.ExitStatus == nil {
		t.Fatal("clean session ended without an exit-status")
	}
	if *outcome.ExitStatus != 0 {
		t.Fatalf("exit-status = %d, want 0", *outcome.ExitStatus)
	}
	if !strings.Contains(out.String(), "This session is recorded") {
		t.Fatalf("recording banner never reached Out: %q", out.String())
	}
	if !strings.Contains(out.String(), gf.machineID) {
		t.Fatalf("banner did not name the machine: %q", out.String())
	}
}

// ---- fake human peer: a minimal double for mid-session transport loss --

// fakeHumanPeer grants exactly one session a shell and then waits to be
// told to die (drop()), at which point it severs the transport outright
// without ever sending exit-status — reproduced on demand,
// deterministically, instead of racing a real gateway's internal door
// timing.
type fakeHumanPeer struct {
	listener net.Listener
	signer   ssh.Signer
	banner   string
	dropCh   chan struct{}
}

func newFakeHumanPeer(t *testing.T, banner string) *fakeHumanPeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h := &fakeHumanPeer{listener: ln, signer: genEDSigner(t), banner: banner, dropCh: make(chan struct{})}
	go h.serve()
	return h
}

func (h *fakeHumanPeer) addr() string        { return h.listener.Addr().String() }
func (h *fakeHumanPeer) fingerprint() string { return ssh.FingerprintSHA256(h.signer.PublicKey()) }

// drop severs the transport outright, as if the network had died mid
// session: no CloseWrite, no exit-status, just gone. Call it at most once.
func (h *fakeHumanPeer) drop() { close(h.dropCh) }

func (h *fakeHumanPeer) serve() {
	for {
		raw, err := h.listener.Accept()
		if err != nil {
			return
		}
		go h.handle(raw)
	}
}

func (h *fakeHumanPeer) handle(raw net.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(h.signer)
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		_ = raw.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, creqs, err := n.Accept()
		if err != nil {
			continue
		}
		go h.serveSession(sconn, ch, creqs)
		return
	}
}

func (h *fakeHumanPeer) serveSession(sconn *ssh.ServerConn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	for r := range reqs {
		switch r.Type {
		case "pty-req", "shell":
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
			if r.Type == "shell" {
				_, _ = ch.Write([]byte(h.banner))
				go func() {
					<-h.dropCh
					_ = sconn.Close() // abrupt transport loss: no CloseWrite, no exit-status
				}()
			}
		default:
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}
}

// TestConnectMidSessionDropIsReportedAsInterrupted proves the person
// must not mistake a torn-down session for a clean one. The
// keyboard side (In) never reaches EOF on its own, so the only way this
// Connect call can return is through the peer's drop().
func TestConnectMidSessionDropIsReportedAsInterrupted(t *testing.T) {
	const banner = "This session is recorded. Machine win01, until 2026-09-12T18:00:00Z.\r\n"
	peer := newFakeHumanPeer(t, banner)
	host, port := splitAddr(peer.addr())
	cs := config.ConnString{Host: host, Port: port, Person: "alice", Fingerprint: peer.fingerprint()}

	dir := t.TempDir()
	out := &syncBuffer{}
	inR, inW := io.Pipe()
	t.Cleanup(func() { _ = inW.Close() })

	type result struct {
		outcome client.ConnectOutcome
		err     error
	}
	doneCh := make(chan result, 1)
	go func() {
		outcome, err := client.Connect(context.Background(), client.ConnectOptions{
			Conn:           cs,
			Machine:        "win01",
			Signer:         testSigner(t),
			KnownHostsPath: client.KnownHostsPath(dir),
			In:             inR,
			Out:            out,
			DialTimeout:    3 * time.Second,
		})
		doneCh <- result{outcome, err}
	}()

	waitFor(t, "banner never arrived", func() bool {
		return strings.Contains(out.String(), "This session is recorded")
	})

	peer.drop()

	select {
	case r := <-doneCh:
		if r.err != nil {
			t.Fatalf("Connect returned an infrastructure error instead of an outcome: %v", r.err)
		}
		if !r.outcome.ShellGranted {
			t.Fatal("session never actually started, so this did not test a mid-session drop")
		}
		if r.outcome.ExitStatus != nil {
			t.Fatalf("interrupted session reported a clean exit-status %d", *r.outcome.ExitStatus)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Connect did not return after the peer dropped the transport")
	}
}
