package client_test

// connect_silentpeer_test.go proves the second half of the clean-exit
// fix's contract (IAMT-108): waiting for the final exit-status on a clean
// end must not resurrect the deadlock the old "Close, then wait" ordering
// existed to prevent. The peer here grants a shell, then goes silent the
// one way keepalive cannot catch: it half-closes the data side (so the
// bridge ends and the client reaches its request-stream wait) but never
// sends exit-status, never closes the channel, never closes the transport,
// and answers keepalive probes with success — exactly what the real
// gateway's global-request table does for keepalive@openssh.com
// (internal/sshx/requests.go, Answer). Nothing but the client's own bound
// can end this session.

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

// silentPeer is a minimal SSH server with exactly one behaviour: after
// granting pty-req and shell and writing the banner, it sends data EOF and
// then stops participating — the wire equivalent of a gateway that died
// silently inside while its transport layer keeps answering.
type silentPeer struct {
	listener net.Listener
	signer   ssh.Signer
	banner   string
}

func newSilentPeer(t *testing.T, banner string) *silentPeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	p := &silentPeer{listener: ln, signer: genEDSigner(t), banner: banner}
	go p.serve()
	return p
}

func (p *silentPeer) addr() string        { return p.listener.Addr().String() }
func (p *silentPeer) fingerprint() string { return ssh.FingerprintSHA256(p.signer.PublicKey()) }

func (p *silentPeer) serve() {
	for {
		raw, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(raw)
	}
}

func (p *silentPeer) handle(raw net.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(p.signer)
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		_ = raw.Close()
		return
	}
	defer sconn.Close()
	go p.answerGlobalRequests(reqs)
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, creqs, err := n.Accept()
		if err != nil {
			continue
		}
		p.serveSession(ch, creqs)
	}
}

// answerGlobalRequests mirrors the real gateway's disposition for the one
// request that matters here: keepalive@openssh.com gets request success
// (sshx.requests.go globalRequestTable, Answer), so the client's keepalive
// loop sees a healthy peer for as long as the test runs.
func (p *silentPeer) answerGlobalRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		if !r.WantReply {
			continue
		}
		_ = r.Reply(r.Type == "keepalive@openssh.com", nil)
	}
}

// serveSession grants the shell, writes the banner, half-closes the data
// side — and then deliberately does nothing, forever: no exit-status, no
// channel close. The request stream stays open; that is the whole point.
func (p *silentPeer) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for r := range reqs {
		switch r.Type {
		case "pty-req", "shell":
			if r.WantReply {
				_ = r.Reply(true, nil)
			}
			if r.Type == "shell" {
				_, _ = ch.Write([]byte(p.banner))
				_ = ch.CloseWrite() // data EOF: the bridge ends, the hang would begin here
			}
		default:
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}
}

// TestConnectSilentPeerStillReturns: a peer that granted a shell and then
// went silent (data EOF, no exit-status, request stream never closed,
// keepalives answered) must not hang the client. The keyboard side never
// reaches EOF on its own, so nothing in the client can end this call except
// the bounded wait; without the bound this test hangs until its watchdog
// fires.
func TestConnectSilentPeerStillReturns(t *testing.T) {
	const banner = "This session is recorded. Machine win01, until 2026-09-12T18:00:00Z.\r\n"
	peer := newSilentPeer(t, banner)
	host, port := splitAddr(peer.addr())
	cs := config.ConnString{Host: host, Port: port, Person: "alice", Fingerprint: peer.fingerprint()}

	dir := t.TempDir()
	out := &syncBuffer{}
	inR, inW := io.Pipe() // never written, never EOFs: the client has no local reason to end the session
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

	select {
	case r := <-doneCh:
		if r.err != nil {
			t.Fatalf("Connect returned an infrastructure error instead of an outcome: %v", r.err)
		}
		if !r.outcome.ShellGranted {
			t.Fatal("the shell was never granted, so this did not exercise the post-grace wait")
		}
		if r.outcome.ExitStatus != nil {
			t.Fatalf("a session whose peer never sent exit-status reported status %d", *r.outcome.ExitStatus)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Connect hung on a silent peer: the exit-status wait is not bounded")
	}
}
