package admin

// client.go is the wire client: it dials the gateway as a command-login
// person (SPEC §5.1, PROTOCOL §1.2) and runs one exec command per call.
// It holds no policy - every decision belongs to the gateway - and it
// never trusts what comes back: a garbage, truncated or wrongly-typed
// response is always turned into a clean error, never a panic.

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
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

// maxResponseBytes bounds one exec response. It is generous enough for a
// single recordings.fetch chunk (<= 1 MiB raw, base64 plus envelope
// overhead) while still being finite: an unbounded read is exactly the
// kind of "long" garbage gate 8 asks to be defended against.
const maxResponseBytes = 8 << 20

// Peer identifies the gateway to dial: host:port and the pinned SHA-256
// fingerprint of its host key (SPEC §3.1). There is no TOFU path here -
// the fingerprint always comes from a connection string, enrol code or
// claim reference the caller already parsed (SPEC principle 7); Dial
// refuses to proceed without one.
type Peer struct {
	Addr        string // "host:port"
	Fingerprint string // canonical "SHA256:<43 base64 chars>"
}

// Conn is one authenticated command-login connection.
type Conn struct {
	client *ssh.Client
	// closeReqs releases the parked default global-request handler when
	// the connection closes (see Dial); sync.Once keeps a second Close
	// from panicking on an already-closed channel.
	closeReqs sync.Once
	noopReqs  chan *ssh.Request
	// broken is set once the connection can carry no more commands: it
	// closed, or a command failed below the gateway's own answer. A
	// caller that keeps one Conn for many commands (the window, IAMT-452)
	// asks Broken before the next one and dials again.
	broken atomic.Bool
	// openTimeout is how long a command waits for the gateway to answer
	// its channel open: Dial's own timeout (R1-CX F-08).
	openTimeout time.Duration
	// preflight is the whoami version preflight the first application
	// command waits for (R2-CX F-06, preflight.go); Dial arms it for every
	// login but the one-command ones.
	preflight preflight
}

// defaultOpenTimeout bounds a channel open on a Conn that did not come
// from Dial.
const defaultOpenTimeout = 10 * time.Second

// responseSilenceMultiplier is how long a command tolerates a gateway
// that accepted its exec request and then sends not one byte, expressed
// against the same wait that bounds the channel open. Six times it: the
// multiple PROTOCOL §4.2 itself uses between "alive" and "dead" (three
// keepalive misses × a 20 s interval = 60 s on production defaults), and
// deliberately far beyond the open — an answer worth having can take
// long to start arriving (risk key probes an external service;
// recordings.fetch relays chunk by chunk from the machine). The limit
// is on SILENCE, not on the command's lifetime: every byte that arrives
// re-arms it, so a fetch that trickles for an hour is never cut, and a
// gateway that went mute is hung up on in bounded time (IAMT-481a).
const responseSilenceMultiplier = 6

// errResponseSilence is what a command's read fails with when the
// gateway's answer went quiet past the silence limit.
var errResponseSilence = errors.New("no byte arrived from the gateway")

// Broken reports whether this connection is known to carry no more
// commands (see Conn.broken).
func (c *Conn) Broken() bool { return c.broken.Load() }

// Dial opens the connection: public-key auth as person with signer, and a
// host key callback that accepts only the pinned fingerprint. Nothing
// about "on mismatch, ask the user" happens here - SPEC §3.1 requires a
// hard refusal and a new connection string from the admin, so a mismatch
// is simply a returned error.
//
// The dial is built on NewClientConn + NewClient rather than ssh.Dial for
// one reason (IAMT-218): the gateway probes every person connection —
// command-login included — with keepalive@openssh.com (PROTOCOL §4.2), and
// the client MUST answer request success. ssh.Dial installs x/crypto's
// default handler that answers false to every global request, and a false
// reply counts as a miss: three in a row and the gateway declares the
// connection dead. With the connection numbers of §4.2 (20 s × 3) that
// would kill an idle-but-healthy admin session after a minute; the same
// Respond wiring also makes this client usable unchanged against test
// gateways that tighten HumanKeepalive. On the wire the swap changes
// exactly one name: keepalive@openssh.com now gets request success
// (PROTOCOL §4.1 table row); every other name keeps getting the failure
// reply ApplyDisposition sends for Drop/Reject.
func Dial(peer Peer, person string, signer ssh.Signer, timeout time.Duration) (*Conn, error) {
	if peer.Fingerprint == "" {
		return nil, fmt.Errorf("admin: no gateway fingerprint pinned; refusing to dial without one (SPEC §3.1, no TOFU)")
	}
	cfg := &ssh.ClientConfig{
		User:            person,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: pinnedHostKey(peer.Fingerprint),
	}
	// PROTOCOL §1: ordered KEX/cipher/MAC and host-key algorithm lists,
	// not x/crypto defaults (IAMT-173).
	sshx.ApplyClientConfig(cfg)
	// timeout bounds the TCP connect and the handshake together. The
	// handshake's part goes on the socket: ClientConfig.Timeout is read
	// only by ssh.Dial, and NewClientConn on an open socket would wait
	// for a silent gateway's first byte for good (IAMT-450). The deadline
	// comes off once the handshake is done.
	deadline := time.Now().Add(timeout)
	raw, err := net.DialTimeout("tcp", peer.Addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("admin: dial %s: %w", peer.Addr, err)
	}
	_ = raw.SetDeadline(deadline)
	conn, chans, reqs, err := ssh.NewClientConn(raw, peer.Addr, cfg)
	if err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("admin: dial %s: %w", peer.Addr, err)
	}
	_ = raw.SetDeadline(time.Time{})
	// NewClient starts x/crypto's default false-replier on whatever
	// request channel it is given, so give it a never-closed one and
	// serve the real requests with the protocol's own responder — the
	// same wiring the machine agent already uses. Close releases the
	// parked handler via closeReqs.
	noopReqs := make(chan *ssh.Request)
	c := &Conn{client: ssh.NewClient(conn, chans, noopReqs), noopReqs: noopReqs, openTimeout: timeout,
		preflight: preflight{needed: !oneCommandLogins[person]}}
	go sshx.Keepalive{}.Respond(reqs)
	go func() {
		_ = c.client.Wait()
		c.broken.Store(true)
	}()
	return c, nil
}

// pinnedHostKey accepts only a host key whose SHA-256 fingerprint equals
// want, computed the same way auth.Fingerprint does on the gateway side
// (this package does not import internal/gateway/auth to avoid a needless
// coupling for one formula).
func pinnedHostKey(want string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		got := fingerprintOf(key)
		if got != want {
			return fmt.Errorf("admin: gateway host key fingerprint changed (want %s, got %s) — get a new connection string from the admin", want, got)
		}
		return nil
	}
}

func fingerprintOf(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// Close closes the underlying connection.
func (c *Conn) Close() error {
	c.closeReqs.Do(func() { close(c.noopReqs) })
	return c.client.Close()
}

// CommandError is a failure the gateway itself named (PROTOCOL §1.2's
// error envelope), as opposed to a transport or parsing failure.
type CommandError struct {
	Code    string
	Message string
	// Category is the machine-readable failure class of this one refusal,
	// when the gateway names one (the risk.key reply's
	// "rejected"|"unavailable", IAMT-404). Empty when the gateway says
	// only prose — an older gateway, or an error that has no class.
	Category string
}

func (e *CommandError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

type envelope struct {
	Proto    int             `json:"proto"`
	Caps     []string        `json:"caps"`
	OK       bool            `json:"ok"`
	Result   json.RawMessage `json:"result"`
	Error    *envelopeError  `json:"error"`
	MinProto int             `json:"minProto"`
}

type envelopeError struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	Category string `json:"category,omitempty"`
}

// Exec sends one exec-channel command (PROTOCOL §1.2: the command name
// travels as the SSH "exec" request string, the JSON request body as
// channel stdin) and returns the decoded "result" object, still raw -
// callers unmarshal it into the shape they expect. req is marshaled as
// the request body; it must already carry "proto".
func (c *Conn) Exec(command string, req any) (json.RawMessage, error) {
	if err := c.ensurePreflight(command); err != nil {
		return nil, err
	}
	// The open waits for the gateway's answer no longer than Dial's own
	// timeout (R1-CX F-08). ssh.Conn.OpenChannel has no limit of its own,
	// and a gateway that kept the connection and answered keepalives, but
	// never the open, held every admin command - the window's among them -
	// for good. Such a gateway is hung up on; the next command dials anew.
	//
	// IAMT-481a: F-08 stopped at the open, and the ANSWER itself had no
	// limit - a gateway that answered the open, accepted the exec, and
	// then never sent a byte held every command for good anyway, because
	// decodeResponse reads to EOF and silence never sends one. The read
	// below is bounded on silence, not on the command's lifetime: slow
	// but alive (recordings.fetch, risk key) runs as long as it keeps
	// producing bytes; mute is hung up on in bounded time.
	wait := c.openTimeout
	if wait <= 0 {
		wait = defaultOpenTimeout
	}
	silence := responseSilenceMultiplier * wait
	ch, reqs, err := sshx.OpenChannelWithDeadline(c.client, "session", time.Now().Add(wait), nil)
	if err != nil {
		c.broken.Store(true)
		if errors.Is(err, sshx.ErrOpenChannelTimeout) {
			_ = c.Close()
			return nil, fmt.Errorf("admin: the gateway did not answer the channel open for %q within %s", command, wait)
		}
		return nil, fmt.Errorf("admin: open channel: %w", err)
	}
	defer ch.Close()
	go ssh.DiscardRequests(reqs)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("admin: encode request: %w", err)
	}

	ok, err := ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command}))
	if err != nil {
		c.broken.Store(true)
		return nil, fmt.Errorf("admin: exec request for %q: %w", command, err)
	}
	if !ok {
		return nil, fmt.Errorf("admin: gateway refused to run %q", command)
	}
	if _, err := ch.Write(body); err != nil {
		c.broken.Store(true)
		return nil, fmt.Errorf("admin: write request body: %w", err)
	}
	_ = ch.CloseWrite()

	result, err := decodeResponse(&silentGatewayReader{r: ch, limit: silence})
	var ce *CommandError
	if err != nil && !errors.As(err, &ce) {
		// Not the gateway's answer but the absence of one: whatever cut
		// it off may have cut the connection too.
		c.broken.Store(true)
		if errors.Is(err, errResponseSilence) {
			// The deferred ch.Close() below unblocks the read this failure
			// abandons, and the connection itself goes the way of the
			// command: a gateway mute for a minute is not owed another one.
			_ = c.Close()
			return nil, fmt.Errorf("admin: the gateway accepted %q and then sent no byte for %s — hanging up; the next command dials anew", command, silence)
		}
	}
	return result, err
}

// silentGatewayReader bounds one Read: if the underlying reader produces
// no byte within limit, the read fails with errResponseSilence. Every
// read that does return re-arms the bound — the limit is on silence, not
// on the command's total lifetime (IAMT-481a: recordings.fetch and
// risk key are allowed to be slow; they are not allowed to be mute).
//
// ssh.Channel has no read deadline of its own, so each read runs one
// goroutine out and races it against a timer. After a timeout the
// goroutine is still parked in Read; Exec's deferred ch.Close() — the
// silence ends the connection either way — unblocks it, and its late
// result lands in a buffered channel nobody reads again.
type silentGatewayReader struct {
	r     io.Reader
	limit time.Duration
}

func (sr *silentGatewayReader) Read(p []byte) (int, error) {
	type readResult struct {
		n   int
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		n, err := sr.r.Read(p)
		done <- readResult{n, err}
	}()
	timer := time.NewTimer(sr.limit)
	defer timer.Stop()
	select {
	case res := <-done:
		return res.n, res.err
	case <-timer.C:
		return 0, fmt.Errorf("%w for %s (IAMT-481a)", errResponseSilence, sr.limit)
	}
}

// decodeResponse defensively parses the single JSON line PROTOCOL §1.2
// promises. Every failure mode - long, truncated, unknown fields, wrong
// types, more than one value, no bytes at all - is turned into a plain
// error here; the recover is the last-resort backstop in case a future
// change to this function misses one.
func decodeResponse(r io.Reader) (result json.RawMessage, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			result, err = nil, fmt.Errorf("admin: gateway response could not be parsed (recovered: %v)", rec)
		}
	}()

	raw, rerr := io.ReadAll(io.LimitReader(r, maxResponseBytes+1))
	if rerr != nil {
		return nil, fmt.Errorf("admin: reading gateway response: %w", rerr)
	}
	if int64(len(raw)) > maxResponseBytes {
		return nil, fmt.Errorf("admin: gateway response exceeds %d bytes", maxResponseBytes)
	}
	trimmed := bytes.TrimRight(raw, "\n")
	if len(bytes.TrimSpace(trimmed)) == 0 {
		return nil, fmt.Errorf("admin: gateway sent an empty response")
	}

	var env envelope
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&env); derr != nil {
		return nil, fmt.Errorf("admin: gateway response is not valid JSON: %w", derr)
	}
	if dec.More() {
		return nil, fmt.Errorf("admin: gateway sent more than one JSON value in its response")
	}
	if env.Proto != 1 {
		return nil, fmt.Errorf("admin: gateway speaks protocol %d, this client only speaks 1", env.Proto)
	}
	if !env.OK {
		if env.Error == nil || env.Error.Code == "" {
			return nil, fmt.Errorf("admin: gateway reported failure without an error code")
		}
		return nil, &CommandError{Code: env.Error.Code, Message: env.Error.Message, Category: env.Error.Category}
	}
	return env.Result, nil
}
