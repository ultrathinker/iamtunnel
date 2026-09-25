package client

// R1-CX F-08: sshx.OpenChannelWithDeadline was written for the gateway
// (IAMT-450), and the client's own channel opens - client connect, client
// exec, the machines.mine behind the Client tab - still called
// ssh.Conn.OpenChannel, which waits for the gateway's answer without any
// limit. A gateway that took the connection and answered keepalives, but
// never the channel open, held the command - or the window - for good.

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

// r1cxF08DialTimeout is a second, not less: under -race and a loaded host
// the handshake itself must fit - a dial that times out would pass these
// tests for the wrong reason - and the 5s bound still catches a wait with
// no limit.
const r1cxF08DialTimeout = time.Second

func r1cxF08Conn(t *testing.T, p *testsupport.SilentChannelPeer) config.ConnString {
	t.Helper()
	host, portText, err := net.SplitHostPort(p.Addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return config.ConnString{Host: host, Port: port, Person: "alice", Fingerprint: ssh.FingerprintSHA256(p.HostKey.PublicKey())}
}

// r1cxF08GivesUp runs one call against the silent gateway and wants an
// error from it well within a few dial timeouts.
func r1cxF08GivesUp(t *testing.T, what string, run func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- run() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("%s succeeded against a gateway that never answers a channel open", what)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s is still waiting for a gateway that never answers a channel open, 5s into a %v dial timeout", what, r1cxF08DialTimeout)
	}
}

func TestR1CX_F08_ConnectGivesUpOnAGatewayThatNeverOpensTheChannel(t *testing.T) {
	peer := testsupport.NewSilentChannelPeer(t)
	opts := ConnectOptions{
		Conn: r1cxF08Conn(t, peer), Machine: "win01", Signer: terminalTestSigner(t),
		KnownHostsPath: KnownHostsPath(t.TempDir()), In: strings.NewReader(""), Out: io.Discard,
		DialTimeout: r1cxF08DialTimeout,
	}
	opener := func(io.Reader, io.Writer) (localTerminal, error) { return &restoreProbeTerminal{}, nil }
	r1cxF08GivesUp(t, "client connect", func() error {
		_, err := connect(context.Background(), opts, opener)
		return err
	})
}

func TestR1CX_F08_ExecGivesUpOnAGatewayThatNeverOpensTheChannel(t *testing.T) {
	peer := testsupport.NewSilentChannelPeer(t)
	opts := ExecOptions{
		Conn: r1cxF08Conn(t, peer), Machine: "win01", Command: "hostname", Signer: terminalTestSigner(t),
		KnownHostsPath: KnownHostsPath(t.TempDir()), Stdout: io.Discard, Stderr: io.Discard,
		DialTimeout: r1cxF08DialTimeout,
	}
	r1cxF08GivesUp(t, "client exec", func() error {
		_, err := Exec(context.Background(), opts)
		return err
	})
}

func TestR1CX_F08_MachinesGivesUpOnAGatewayThatNeverOpensTheChannel(t *testing.T) {
	peer := testsupport.NewSilentChannelPeer(t)
	dir := t.TempDir()
	r1cxF08GivesUp(t, "machines.mine", func() error {
		_, err := Machines(context.Background(), dir, r1cxF08Conn(t, peer), terminalTestSigner(t), r1cxF08DialTimeout)
		return err
	})
}
