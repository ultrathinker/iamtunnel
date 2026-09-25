package client

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// ConnectOptions carries everything one interactive session needs. Every
// path (the key, the isolated known_hosts) is a plain field: this package
// never resolves one from an environment variable or a user profile
// directory on its own — the key file path is always a parameter.
type ConnectOptions struct {
	Conn           config.ConnString
	Machine        string
	Signer         ssh.Signer
	KnownHostsPath string

	In  io.Reader
	Out io.Writer

	Term string // default "xterm"
	Cols uint32 // default 80
	Rows uint32 // default 24

	DialTimeout       time.Duration // 0 -> DefaultDialTimeout
	KeepaliveInterval time.Duration // 0 -> sshx.DefaultKeepaliveInterval
}

// ConnectOutcome is the observable result of a session that reached the
// point of opening a channel to the gateway. It intentionally carries no
// "denied" or "interrupted" boolean of its own: both are one and the
// same fact — a channel that ended without ever seeing "shell" succeed,
// or one that did and then ended without an exit-status — and only the
// person being told, and the exit code differing from a clean run, is
// required; this package does not invent a taxonomy the protocol does
// not have. The caller (cmd/iamtunnel/client.go) derives the exit
// code from these two fields.
type ConnectOutcome struct {
	// ShellGranted reports whether the gateway's "shell" reply ever came
	// back successful. False means the session never really started —
	// a denial, or a channel that died before setup finished.
	ShellGranted bool
	// ExitStatus is the remote shell's own exit code (PROTOCOL §4.1,
	// forwarded byte for byte), present only when the channel closed
	// cleanly after sending one. nil with ShellGranted true means the
	// session was interrupted mid-flight.
	ExitStatus *uint32
}

// exitStatusGrace is sshx.ExitStatusGrace: the client's half of one bound
// shared with the gateway's own wait for the same request on the other end
// of this pipe (internal/gateway/human_role.go's closeAfterMachineDrain).
// See sshx.ExitStatusGrace's comment for why the wait exists at all, why it
// must be bounded, and why keepalive cannot stand in for the bound - the
// three points are the same on both ends and are not repeated here.
const exitStatusGrace = sshx.ExitStatusGrace

// sessionDial opens the authenticated transport one session to Machine
// needs — the dial itself, the context cancellation that closes it
// promptly instead of leaving cleanup waiting on a gateway that will never
// speak again, and the shared keepalive probe (PROTOCOL §1.5) — and hands
// back a single stop func that unwinds all three in the same order a
// caller's own defer chain used to (keepalive prober first, then the
// cancellation watcher, then the transport itself). Connect and Exec both
// build their session on top of it: the wire-level dial is identical for
// an interactive shell and a single command, and only the channel
// requests sent after this point differ — one entry point for both.
func sessionDial(ctx context.Context, conn config.ConnString, machine string, signer ssh.Signer, knownHostsPath string, dialTimeout, keepaliveInterval time.Duration) (client *ssh.Client, stop func(), err error) {
	user := conn.Person + ":" + machine
	client, err = dial(ctx, DialOptions{
		Conn:           conn,
		User:           user,
		Signer:         signer,
		KnownHostsPath: knownHostsPath,
		Timeout:        dialTimeout,
	})
	if err != nil {
		return nil, nil, err
	}

	sessionDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close()
		case <-sessionDone:
		}
	}()

	stopKeepalive := sshx.Keepalive{Interval: keepaliveInterval, Name: "keepalive@openssh.com"}.Probe(client.Conn, func() {
		_ = client.Close()
	})

	stop = func() {
		stopKeepalive()
		close(sessionDone)
		_ = client.Close()
	}
	return client, stop, nil
}

// Connect opens one interactive session to Machine as the pinned
// person (sign-in). The host key is checked strictly against
// Conn.Fingerprint before the SSH handshake completes (dial.go); nothing
// past that point ever runs against an unpinned gateway. Whatever the
// gateway writes to the channel — the recording banner on success, or
// the single denial line on refusal — reaches Out before a single byte
// of In is forwarded (bridge.go), and the isolated KnownHostsPath is the
// only file this call ever touches for host-key bookkeeping: the
// person's real known_hosts is never opened by this package (see
// knownhosts.go).
func Connect(ctx context.Context, opts ConnectOptions) (ConnectOutcome, error) {
	return connect(ctx, opts, openTerminal)
}

// connect owns the terminal token throughout the session. Its opener is an
// unexported parameter solely so package-local tests can prove cleanup against
// a fake console; exported Connect always uses openTerminal.
func connect(ctx context.Context, opts ConnectOptions, open terminalOpener) (outcome ConnectOutcome, err error) {
	var zero ConnectOutcome
	terminal, openErr := open(opts.In, opts.Out)
	if openErr != nil {
		return zero, &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("prepare local terminal: %v", openErr)}
	}
	defer func() {
		if restoreErr := terminal.restore(); restoreErr != nil && err == nil {
			outcome = zero
			err = &config.Error{Class: config.ClassEnv, Msg: fmt.Sprintf("restore local terminal: %v", restoreErr)}
		}
	}()

	client, stop, err := sessionDial(ctx, opts.Conn, opts.Machine, opts.Signer, opts.KnownHostsPath, opts.DialTimeout, opts.KeepaliveInterval)
	if err != nil {
		return zero, err
	}
	defer stop()

	ch, reqs, err := openSession(ctx, client, opts.DialTimeout)
	if err != nil {
		return zero, err
	}
	defer ch.Close()

	// screen serializes writes to opts.Out between the ordinary bridge
	// below and the stderr drain started here: two goroutines that could
	// otherwise interleave bytes onto the same person's terminal.
	screen := &syncWriter{w: opts.Out}

	// The gateway's own words — as opposed to the target's — travel on
	// extended data (stream 1), the same separation Exec uses for a
	// command's stdout/stderr. Interactively this used to go unread: a
	// gateway line written before pty-req/shell ever succeeds (A2's
	// E_SSH_SHELL_FORBIDDEN, sent the instant an exec-only grant's
	// pty-req is rejected, well before any exit-status) reached nobody,
	// because the only reader here was the regular stream bridging keeps
	// below. Started before pty-req so it can catch exactly that message.
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		_, _ = io.Copy(screen, ch.Stderr())
	}()

	exitCh := make(chan uint32, 1)
	// reqsDone closes when the request stream is over. It replaces a
	// sync.WaitGroup solely so the clean-path wait below can select on it:
	// the wait must be bounded, and a WaitGroup cannot take part in a
	// select.
	reqsDone := make(chan struct{})
	go func() {
		defer close(reqsDone)
		for r := range reqs {
			if r.Type == "exit-status" {
				if e, perr := sshx.ParseExitStatus(r.Payload); perr == nil {
					select {
					case exitCh <- e.Status:
					default:
					}
				}
			}
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}
	}()

	term := opts.Term
	if term == "" {
		term = "xterm"
	}
	cols, rows := opts.Cols, opts.Rows
	if size, ok := terminal.size(); ok {
		if cols == 0 {
			cols = size.cols
		}
		if rows == 0 {
			rows = size.rows
		}
	}
	if cols == 0 {
		cols = 80
	}
	if rows == 0 {
		rows = 24
	}

	shellGranted := false
	if ptyOK, ptyErr := ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: term, Columns: cols, Rows: rows})); ptyErr == nil && ptyOK {
		if shOK, shErr := ch.SendRequest("shell", true, nil); shErr == nil && shOK {
			shellGranted = true
		}
	}

	// The monitor starts strictly after a successful pty-req and shell reply,
	// and is joined before Close. Therefore it can neither precede pty-req nor
	// write to an already closed session channel.
	resizeDone := make(chan struct{})
	var resizeWG sync.WaitGroup
	if shellGranted {
		monitorInitial := terminalSize{cols: cols, rows: rows}
		if observed, ok := terminal.size(); ok {
			monitorInitial = observed
		}
		resizeWG.Add(1)
		go func() {
			defer resizeWG.Done()
			watchWindowChanges(resizeDone, terminal, monitorInitial, func(size sshx.WindowChange) error {
				_, err := ch.SendRequest("window-change", false, sshx.MarshalWindow(size))
				return err
			})
		}()
	}

	bridgeErr := bridgeFirstThenForward(screen, ch, ch, opts.In)

	// ch.Close before the request-stream join: if bridging ended locally
	// (In hit EOF and the gateway never closes back), the request stream
	// would otherwise never close and this call would hang past the point
	// the session is visibly over.
	close(resizeDone)
	resizeWG.Wait()
	// A clean gateway EOF follows its exit-status request. Do not close the
	// channel first: doing so can discard that final request before the reader
	// above records it. A bridge error is different — actively close to unblock
	// the request stream rather than waiting for a peer that may be gone.
	if bridgeErr != nil {
		_ = ch.Close()
		<-reqsDone
	} else {
		// Wait for the final exit-status, but never past exitStatusGrace:
		// a peer that half-closed and went silent must end this call (with
		// no exit-status — none arrived), not hang it. See the comment on
		// exitStatusGrace for where the number comes from.
		timer := time.NewTimer(exitStatusGrace)
		select {
		case <-reqsDone:
			timer.Stop()
		case <-timer.C:
		}
		_ = ch.Close()
	}
	// ch is closed on every path above, so the stderr drain's Read is
	// about to see EOF too — wait for it so a caller reading Out after
	// this call returns has already seen everything the gateway wrote,
	// not a message still in flight on another goroutine.
	<-stderrDone

	var status *uint32
	select {
	case v := <-exitCh:
		status = &v
	default:
	}

	return ConnectOutcome{ShellGranted: shellGranted, ExitStatus: status}, nil
}

// syncWriter serializes concurrent writers onto one io.Writer. connect's
// stderr drain and its regular-stream bridge both write to the person's
// screen from different goroutines; without this, two lines landing at the
// same instant could interleave byte for byte.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
