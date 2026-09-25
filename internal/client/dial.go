package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// DefaultDialTimeout bounds the TCP connect and the SSH handshake
// together, matching the spirit of SPEC's ServerAliveInterval-based
// client (a person waiting at a keyboard should not hang indefinitely on
// a gateway that never answers).
const DefaultDialTimeout = 15 * time.Second

// DialOptions carries everything a dial needs beyond the saved connection:
// the identity to authenticate as, the key to sign with, and the paths
// this package must never guess on its own.
type DialOptions struct {
	Conn           config.ConnString
	User           string // full SSH username: "<person>" or "<person>:<machine>"
	Signer         ssh.Signer
	KnownHostsPath string
	Timeout        time.Duration // 0 -> DefaultDialTimeout
}

// dial opens and authenticates one SSH connection to the pinned gateway.
// The host key is checked strictly against Conn.Fingerprint before any
// other byte of the protocol runs: a mismatch aborts the handshake
// itself, so no channel, no exec and no session is ever attempted with
// an impostor gateway.
func dial(ctx context.Context, opts DialOptions) (*ssh.Client, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	addr := fmt.Sprintf("%s:%d", opts.Conn.Host, opts.Conn.Port)

	dctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("cannot reach gateway %s: %v", addr, err)}
	}

	cfg := &ssh.ClientConfig{
		User:            opts.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(opts.Signer)},
		HostKeyCallback: pinnedHostKeyCallback(opts.Conn.Fingerprint, opts.KnownHostsPath),
	}
	// PROTOCOL §1: ordered KEX/cipher/MAC and host-key algorithm lists,
	// not x/crypto defaults (IAMT-173).
	sshx.ApplyClientConfig(cfg)
	// The timeout covers the handshake too, on the socket itself:
	// ClientConfig.Timeout is read only by ssh.Dial, and NewClientConn on
	// an open socket would wait for a silent gateway's first byte for
	// good (IAMT-450). The deadline comes off once the handshake is done.
	if deadline, ok := dctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	sconn, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		var mismatch *ErrFingerprintMismatch
		if errors.As(err, &mismatch) {
			return nil, &config.Error{Class: config.ClassUser, Msg: mismatch.Error()}
		}
		return nil, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("gateway %s refused the connection: %v", addr, err)}
	}
	_ = raw.SetDeadline(time.Time{})
	return ssh.NewClient(sconn, chans, reqs), nil
}

// openSession opens the "session" channel every call of this package
// starts with, and waits for the gateway's answer no longer than timeout
// (DefaultDialTimeout when zero) or until ctx is done (R1-CX F-08).
// ssh.Conn.OpenChannel has no limit of its own: a gateway that took the
// connection and answered keepalives, but never the channel open, held
// client connect, client exec and the Client tab's machines.mine for good.
// A gateway that did not answer in time is hung up on - whatever it says
// later has nobody to say it to.
func openSession(ctx context.Context, client *ssh.Client, timeout time.Duration) (ssh.Channel, <-chan *ssh.Request, error) {
	if timeout <= 0 {
		timeout = DefaultDialTimeout
	}
	ch, reqs, err := sshx.OpenChannelWithDeadline(client, "session", time.Now().Add(timeout), ctx.Done())
	switch {
	case err == nil:
		return ch, reqs, nil
	case errors.Is(err, sshx.ErrOpenChannelTimeout):
		_ = client.Close()
		return nil, nil, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("the gateway did not answer the request for a session within %s", timeout)}
	case errors.Is(err, sshx.ErrOpenChannelStopped):
		_ = client.Close()
		return nil, nil, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("stopped waiting for the gateway to open a session: %v", ctx.Err())}
	}
	return nil, nil, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("gateway refused to open a session: %v", err)}
}
