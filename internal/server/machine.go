package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// ErrFingerprintMismatch is returned by Dial when the gateway's presented
// host key does not match Config.GatewayFingerprint byte-for-byte.
// This case gets a refusal and a clear message, no trust on first
// contact (SPEC §2), and Run (run.go) never retries a connection
// attempt that failed with this error.
var ErrFingerprintMismatch = errors.New("server: gateway host key fingerprint does not match the pinned fingerprint")

// Machine is one live connection to the gateway: the SSH transport, the
// door controller bound to it, and the accept loop for the two channel
// types the gateway is allowed to open (PROTOCOL §5: "the machine never
// opens a channel itself"). A Machine is used once, for one connection —
// Run (run.go) constructs a fresh one on every reconnect.
type Machine struct {
	cfg   Config
	conn  ssh.Conn
	chans <-chan ssh.NewChannel
	reqs  <-chan *ssh.Request
	door  *doorController

	controlTaken atomic.Bool

	// ctrlMu guards the three fields below. ctrlCh is set the instant
	// the gateway's iamtunnel-control channel is accepted and read by
	// Tail and writeControl (the two places outside the read loop that
	// touch it); ctrlDone is closed when that channel's read loop ends,
	// so a relay waiting on an answer it will never get is released at
	// once instead of sitting out its whole timeout. ctrlCh is nil for
	// as long as no channel is up — that is the honest state Tail
	// reports as ErrNoControlChannel, not an error to invent words for.
	ctrlMu   sync.Mutex
	ctrlCh   ssh.Channel
	ctrlDone chan struct{}

	// ctrlWriteMu serializes whole lines onto ctrlCh. The read loop
	// answers door.* requests while a relay may be writing its own
	// request, and two interleaved writes on one byte stream are one
	// corrupt line — which the peer is right to tear the tunnel down
	// for.
	ctrlWriteMu sync.Mutex

	// tailWait holds the relays waiting for an answer, keyed by the
	// control-request uuid of the question (IAMT-340). The read loop is
	// the only writer of entries it did not create: claimTailReply
	// deletes an entry when it hands the answer over, and Tail deletes
	// its own on every exit path.
	tailMu   sync.Mutex
	tailWait map[string]chan []byte
}

// Dial performs exactly one connection attempt: outbound TCP, then an SSH
// client handshake as "machine:<id>" with the gateway's host key checked
// strictly against Config.GatewayFingerprint. It does not retry and does
// not yet serve anything — call Serve on the result to run the tunnel.
func Dial(ctx context.Context, cfg Config) (*Machine, error) {
	if err := cfg.setDefaults(); err != nil {
		return nil, err
	}

	dialer := net.Dialer{Timeout: cfg.DialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", cfg.GatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("server: dial gateway %s: %w", cfg.GatewayAddr, err)
	}

	// mismatch is set by HostKeyCallback and inspected after NewClientConn
	// returns, rather than relying on errors.Is unwrapping whatever error
	// shape the ssh package chooses to wrap a callback failure in — the
	// callback's own return value is authoritative regardless of how it
	// is reported upward.
	var mismatch error
	clientCfg := &ssh.ClientConfig{
		User: "machine:" + cfg.MachineID,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(cfg.MachineKey)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if got != cfg.GatewayFingerprint {
				mismatch = fmt.Errorf("%w: gateway presented %s, pinned fingerprint is %s", ErrFingerprintMismatch, got, cfg.GatewayFingerprint)
				return mismatch
			}
			return nil
		},
	}
	// PROTOCOL §1: ordered KEX/cipher/MAC and host-key algorithm lists,
	// not x/crypto defaults (IAMT-173).
	sshx.ApplyClientConfig(clientCfg)

	// HandshakeTimeout goes on the socket: ClientConfig.Timeout is read only
	// by ssh.Dial, and NewClientConn on an open socket would wait for a
	// silent gateway's first byte for good - the reconnect loop stuck in
	// one attempt (IAMT-450). The deadline comes off once the handshake is
	// done: the tunnel lasts as long as it lasts.
	_ = raw.SetDeadline(time.Now().Add(cfg.HandshakeTimeout))
	conn, chans, reqs, err := ssh.NewClientConn(raw, cfg.GatewayAddr, clientCfg)
	if err != nil {
		_ = raw.Close()
		if mismatch != nil {
			return nil, mismatch
		}
		return nil, fmt.Errorf("server: ssh handshake with gateway: %w", err)
	}
	_ = raw.SetDeadline(time.Time{})

	dc, err := newDoorController(&cfg)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &Machine{cfg: cfg, conn: conn, chans: chans, reqs: reqs, door: dc}, nil
}

// SweepStale removes every door line unconditionally. The caller (Run, or
// a test driving Dial/Serve directly) must call this once before Dial on
// every connection attempt, including the first (SPEC §3.2: "Start:
// SweepStale... then connect to the gateway").
func (m *Machine) SweepStale() (int, error) { return m.door.sweepStale() }

// DoorOpen reports whether this Machine's door line is installed right
// now (IAMT-182). It is the one fact about a live session this process
// can state on its own authority: who is on the other end and until when
// they may stay are counted only on the gateway (docs/PROTOCOL.md
// §5.2/§5.4 — "sessions and reservations counters live on the
// gateway"), never here.
func (m *Machine) DoorOpen() bool { return m.door.isInstalled() }

// Serve runs the tunnel until the transport dies or ctx is cancelled, then
// returns. It always leaves the door clean on the way out: whatever line
// this Machine's doorController currently owns is removed before Serve
// returns, under the same lock every door.* handler uses (PROTOCOL §5.2
// layer 2).
func (m *Machine) Serve(ctx context.Context) error {
	waitErrCh := make(chan error, 1)
	go func() { waitErrCh <- m.conn.Wait() }()

	stopProbe := m.cfg.Keepalive.Probe(m.conn, func() { _ = m.conn.Close() })
	defer stopProbe()
	go m.cfg.Keepalive.Respond(m.reqs)

	chans := m.chans
	ctxDone := ctx.Done()
	for {
		select {
		case newCh, ok := <-chans:
			if !ok {
				chans = nil
				continue
			}
			m.handleNewChannel(newCh)
		case werr := <-waitErrCh:
			m.door.teardown("transport-closed")
			return werr
		case <-ctxDone:
			_ = m.conn.Close()
			ctxDone = nil
		}
	}
}

// handleNewChannel accepts exactly the two channel types PROTOCOL §5
// allows the gateway to open toward the machine and rejects everything
// else. Only one iamtunnel-control may be live per connection (PROTOCOL
// §5.1: "a second control channel for this tunnel is forbidden"); the
// first one is left running, matching the gateway's own posture
// toward a duplicate.
func (m *Machine) handleNewChannel(newCh ssh.NewChannel) {
	// ExtraData is the raw SSH channel-open initial payload, not an SSH
	// string to decode. Only zero bytes are empty: four zero bytes and an
	// encoded zero-length SSH string are still attacker-controlled payload.
	//
	// The refusal message is the protocol's own name for exactly this case
	// (PROTOCOL §6.1: "E_TARGET_CHANNEL_INVALID means a wrong name,
	// initial payload, or direction for a machine channel-open"); it
	// travels to the gateway inside SSH_MSG_CHANNEL_OPEN_FAILURE, so it
	// must match the §6.1 dictionary verbatim.
	if len(newCh.ExtraData()) != 0 {
		_ = newCh.Reject(ssh.Prohibited, "E_TARGET_CHANNEL_INVALID")
		return
	}
	switch newCh.ChannelType() {
	case "iamtunnel-control":
		if !m.controlTaken.CompareAndSwap(false, true) {
			_ = newCh.Reject(ssh.ResourceShortage, "E_CONTROL_CHANNEL_DUPLICATE")
			return
		}
		ch, reqs, err := newCh.Accept()
		if err != nil {
			return
		}
		// ctrlDone is created here, before serveControl starts, so that
		// its defer can close it unconditionally. The compare-and-swap
		// above guarantees this runs at most once per Machine, which is
		// what makes a bare close safe.
		done := make(chan struct{})
		m.ctrlMu.Lock()
		m.ctrlCh = ch
		m.ctrlDone = done
		m.ctrlMu.Unlock()
		go discardRequests(reqs)
		go m.serveControl(ch)
	case "iamtunnel-target":
		ch, reqs, err := newCh.Accept()
		if err != nil {
			return
		}
		go discardRequests(reqs)
		go m.spliceTarget(ch)
	default:
		// "unexpected channel type" was a phrase, not a code. An unknown
		// channel name is the same §6.1 case — "a wrong name ... machine
		// channel-open" — so it gets the same dictionary code.
		_ = newCh.Reject(ssh.UnknownChannelType, "E_TARGET_CHANNEL_INVALID")
	}
}

func discardRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
}

// serveControl is the one control-channel read loop. Every message is
// bounded in length and depth and strictly shaped (wire.go) before any
// door logic ever sees it; any framing failure — too long, truncated,
// unbalanced, wrong type, unknown field, duplicate key — ends the loop
// without a reply and tears the door down, the same posture
// internal/gateway/machine_conn.go's own readLoop takes on its side of
// this channel. A well-formed request that fails semantic validation
// (bad key shape, bad deadlines, over its own ceiling, unknown op, ...)
// gets a normal error response and the loop continues — see wire.go and
// door.go for exactly where that line falls.
func (m *Machine) serveControl(ch ssh.Channel) {
	defer func() {
		// Release every relay waiting on this channel before anything
		// else: once the read loop is gone no answer can arrive, and a
		// waiter left parked would sit out its whole timeout to learn a
		// fact that is already known. The two writes below happen under
		// the same lock as ctrlCh's clearing so that "the channel is
		// published" and "the channel is over" can never be observed
		// half-and-half — Tail's first act is to read ctrlCh, and a
		// channel it can still see is one it could still be told to use.
		m.ctrlMu.Lock()
		done := m.ctrlDone
		m.ctrlCh = nil
		m.ctrlMu.Unlock()
		if done != nil {
			close(done)
		}
		m.door.teardown("control-closed")
		_ = m.conn.Close()
	}()
	defer ch.Close()

	r := bufio.NewReaderSize(ch, m.cfg.ControlLineMax+1)
	for {
		line, err := readControlLine(r, m.cfg.ControlLineMax)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				m.cfg.logf("control: framing error, closing tunnel: %v", err)
			}
			return
		}
		// The channel carries both directions since IAMT-340: the
		// gateway's door.* requests and this machine's own tail
		// questions, with the gateway's answers to the latter coming
		// back on the same stream. claimTailReply separates them by the
		// §5.1 envelope's own shape (a request has an op, an answer does
		// not) and consumes the answers; everything else is a request
		// and goes through the same decode-and-dispatch as before.
		if m.claimTailReply(line) {
			continue
		}
		req, err := decodeControlRequest(line, m.cfg.ControlJSONDepth)
		if err != nil {
			var envelopeErr *invalidControlEnvelopeError
			if errors.As(err, &envelopeErr) {
				m.cfg.logf("control: invalid envelope rejected before dispatch, closing tunnel: %v", err)
			} else {
				m.cfg.logf("control: malformed message, closing tunnel: %v", err)
			}
			return
		}
		resp := m.dispatch(req)
		raw, err := encodeControlResponse(resp)
		if err != nil {
			return
		}
		if err := m.writeControl(raw); err != nil {
			return
		}
	}
}

func (m *Machine) dispatch(req controlRequest) controlResponse {
	switch req.Op {
	case "door.open":
		return m.door.open(req)
	case "door.close":
		return m.door.close(req)
	case "door.status":
		return m.door.status(req)
	case "door.sanitize":
		return m.door.sanitize(req)
	default:
		return errorResponse(req.ID, "E_CONTROL_PROTOCOL", "unknown op "+req.Op)
	}
}

// spliceTarget is the whole of this machine's handling of
// iamtunnel-target: dial the local sshd and pump raw bytes both ways with
// proper half-close, and nothing else — nothing besides this may pass
// through such a channel. No SSH parsing happens here —
// the gateway runs the nested SSH client handshake itself, straight
// through to the real sshd; this machine never sees anything but an
// opaque byte stream.
func (m *Machine) spliceTarget(ch ssh.Channel) {
	defer ch.Close()
	d, err := net.DialTimeout("tcp", m.cfg.TargetAddr, m.cfg.DialTimeout)
	if err != nil {
		m.cfg.logf("target: dial %s failed: %v", m.cfg.TargetAddr, err)
		return
	}
	defer d.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, rerr := ch.Read(buf)
			if n > 0 {
				m.door.touch()
				if _, werr := d.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		if tc, ok := d.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, rerr := d.Read(buf)
			if n > 0 {
				m.door.touch()
				if _, werr := ch.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		_ = ch.CloseWrite()
	}()
	wg.Wait()
}
