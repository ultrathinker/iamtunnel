package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

type restoreProbeTerminal struct {
	mu       sync.Mutex
	restores int
}

func (t *restoreProbeTerminal) restore() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.restores++
	return nil
}
func (*restoreProbeTerminal) size() (terminalSize, bool) { return terminalSize{}, false }
func (t *restoreProbeTerminal) restored(tst *testing.T) {
	tst.Helper()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.restores != 1 {
		tst.Fatalf("terminal restored %d times, want exactly once", t.restores)
	}
}

type panicScreen struct{}

func (panicScreen) Write([]byte) (int, error) { panic("screen write panic") }

type sessionPeer struct {
	ln      net.Listener
	hostKey ssh.Signer
	shell   chan struct{}
}

func newSessionPeer(t *testing.T) *sessionPeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &sessionPeer{ln: ln, hostKey: terminalTestSigner(t), shell: make(chan struct{})}
	go p.serve()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func terminalTestSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func (p *sessionPeer) serve() {
	for {
		raw, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(raw)
	}
}

func (p *sessionPeer) handle(raw net.Conn) {
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
		return &ssh.Permissions{}, nil
	}}
	cfg.AddHostKey(p.hostKey)
	conn, channels, requests, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		_ = raw.Close()
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(requests)
	for next := range channels {
		if next.ChannelType() != "session" {
			_ = next.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, reqs, err := next.Accept()
		if err != nil {
			return
		}
		p.handleSession(ch, reqs)
		return
	}
}

func (p *sessionPeer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	pty := false
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			pty = true
			_ = req.Reply(true, nil)
		case "shell":
			if !pty {
				_ = req.Reply(false, nil)
				return
			}
			_ = req.Reply(true, nil)
			select {
			case <-p.shell:
			default:
				close(p.shell)
			}
			_, _ = ch.Write([]byte("This session is recorded.\r\n"))
			go func() {
				_, _ = io.Copy(io.Discard, ch)
				_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
				_ = ch.Close()
			}()
		case "window-change":
			_ = req.Reply(true, nil)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

func (p *sessionPeer) connString(t *testing.T) config.ConnString {
	t.Helper()
	host, portText, err := net.SplitHostPort(p.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	return config.ConnString{Host: host, Port: int(port), Person: "alice", Fingerprint: ssh.FingerprintSHA256(p.hostKey.PublicKey())}
}

func terminalConnectOptions(t *testing.T, peer *sessionPeer, in io.Reader, out io.Writer) ConnectOptions {
	t.Helper()
	return ConnectOptions{
		Conn:           peer.connString(t),
		Machine:        "win01",
		Signer:         terminalTestSigner(t),
		KnownHostsPath: KnownHostsPath(t.TempDir()),
		In:             in,
		Out:            out,
		DialTimeout:    2 * time.Second,
	}
}

// TestConnectRestoresTerminalOnEveryExitPath proves the restoration defer in
// Connect itself (not merely the terminal helper) with a fake terminal. No
// test accesses a real console: every observed restore is the fake token.
func TestConnectRestoresTerminalOnEveryExitPath(t *testing.T) {
	open := func(probe *restoreProbeTerminal) terminalOpener {
		return func(io.Reader, io.Writer) (localTerminal, error) { return probe, nil }
	}

	t.Run("connection error", func(t *testing.T) {
		probe := &restoreProbeTerminal{}
		opts := ConnectOptions{Conn: config.ConnString{Host: "127.0.0.1", Port: 1, Person: "alice", Fingerprint: "SHA256:invalid"}, Signer: terminalTestSigner(t), In: strings.NewReader(""), Out: io.Discard, DialTimeout: time.Second}
		if _, err := connect(context.Background(), opts, open(probe)); err == nil {
			t.Fatal("connect to closed port unexpectedly succeeded")
		}
		probe.restored(t)
	})

	t.Run("normal session", func(t *testing.T) {
		peer := newSessionPeer(t)
		probe := &restoreProbeTerminal{}
		outcome, err := connect(context.Background(), terminalConnectOptions(t, peer, strings.NewReader(""), io.Discard), open(probe))
		if err != nil || !outcome.ShellGranted || outcome.ExitStatus == nil {
			t.Fatalf("normal Connect = %+v, %v", outcome, err)
		}
		probe.restored(t)
	})

	t.Run("panic after shell", func(t *testing.T) {
		peer := newSessionPeer(t)
		probe := &restoreProbeTerminal{}
		defer func() {
			if recover() == nil {
				t.Fatal("Connect did not propagate screen panic")
			}
			probe.restored(t)
		}()
		_, _ = connect(context.Background(), terminalConnectOptions(t, peer, strings.NewReader(""), panicScreen{}), open(probe))
	})

	t.Run("context cancellation", func(t *testing.T) {
		peer := newSessionPeer(t)
		probe := &restoreProbeTerminal{}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		inReader, inWriter := io.Pipe()
		defer inWriter.Close()
		done := make(chan struct{})
		go func() {
			_, _ = connect(ctx, terminalConnectOptions(t, peer, inReader, io.Discard), open(probe))
			close(done)
		}()
		select {
		case <-peer.shell:
		case <-time.After(2 * time.Second):
			t.Fatal("shell was not granted")
		}
		cancel()
		select {
		case <-done:
			probe.restored(t)
		case <-time.After(2 * time.Second):
			t.Fatal("Connect did not return after context cancellation")
		}
	})
}
