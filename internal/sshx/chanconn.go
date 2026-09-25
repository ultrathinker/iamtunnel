package sshx

import (
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// chanconn.go: a net.Conn wrapper over ssh.Channel.
//
// In x/crypto/ssh a channel has neither SetDeadline nor
// LocalAddr/RemoteAddr. This file provides a net.Conn-compatible
// wrapper and holds the net.Conn contract wherever it can actually be
// held over an ssh.Channel:
//
//   - Read and write deadlines are independent. An expired read
//     deadline does not block Write, and vice versa — that is a direct
//     requirement of net.Conn.
//   - A "soft" timeout does not tear down the connection. If nobody is
//     blocked in Read (or Write) at the moment the deadline expires,
//     the wrapper only cuts off new calls in that direction;
//     SetReadDeadline(time.Time{}) lifts the cutoff, and the
//     connection keeps working. This is the ordinary heartbeat-loop
//     idiom.
//   - There is no way to interrupt an already-blocked Read on
//     ssh.Channel other than closing the channel. So, and only so — if
//     the deadline expires while someone is blocked in Read/Write, the
//     channel closes, and the connection is then dead for good. Such a
//     Read returns ErrDeadlineExceeded, not an anonymous close error.
//   - LocalAddr/RemoteAddr return dummy addresses; ssh.Channel does
//     not provide real peer addresses.
//
// ErrDeadlineExceeded implements net.Error with Timeout() == true:
// io.Copy over network wrappers, http.Transport, bufio, and any
// retry-on-timeout loop recognize it as a timeout, not a fatal error.

const (
	channelLocal  = "ssh-channel-local"
	channelRemote = "ssh-channel-remote"
)

// timeoutErr — the timeout sentinel type. A string type is needed so
// the sentinel can be declared as a constant: an exported variable can
// be reassigned by an importer, a constant cannot.
type timeoutErr string

func (e timeoutErr) Error() string   { return string(e) }
func (e timeoutErr) Timeout() bool   { return true }
func (e timeoutErr) Temporary() bool { return false }

// ErrDeadlineExceeded is returned by Read/Write when the deadline has
// expired. Implements net.Error (Timeout() == true) and is compared via errors.Is.
const ErrDeadlineExceeded = timeoutErr("sshx: deadline exceeded")

// Compile-time contract checks.
var (
	_ net.Conn  = (*ChannelConn)(nil)
	_ net.Error = ErrDeadlineExceeded
)

// ChannelConn — a net.Conn wrapper over ssh.Channel.
//
// The channel is deliberately placed in an unexported field rather
// than embedded: embedding would make ssh.Channel an exported field,
// and any importer could replace it or bypass the deadline bookkeeping
// by calling the channel's methods directly. Only net.Conn's methods
// are exposed.
type ChannelConn struct {
	ch ssh.Channel

	mu sync.Mutex
	// closed — the channel is closed (via an ordinary Close or by the timer).
	closed bool
	// rdExpired/wdExpired — a "soft" per-direction cutoff on deadline;
	// lifted by setting a new or zero deadline.
	rdExpired bool
	wdExpired bool
	// readers/writers — how many goroutines are blocked in
	// Channel.Read/Write right now. Only with a nonzero counter must
	// the timer close the channel to wake them; otherwise the
	// connection stays usable.
	readers int
	writers int
	rtimer  *time.Timer
	wtimer  *time.Timer
}

// NewChannelConn wraps ssh.Channel as a *ChannelConn.
func NewChannelConn(ch ssh.Channel) *ChannelConn {
	return &ChannelConn{ch: ch}
}

// Read reads from the channel. If the read deadline has already
// expired, it returns ErrDeadlineExceeded immediately without touching
// the channel. If the deadline expires during a blocking read, the
// channel closes (there is no other way to interrupt
// ssh.Channel.Read) and Read returns ErrDeadlineExceeded.
func (c *ChannelConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.rdExpired {
		c.mu.Unlock()
		return 0, ErrDeadlineExceeded
	}
	c.readers++
	c.mu.Unlock()

	n, err := c.ch.Read(p)

	c.mu.Lock()
	c.readers--
	expired := c.rdExpired
	c.mu.Unlock()

	if err != nil && expired {
		return n, ErrDeadlineExceeded
	}
	return n, err
}

// Write writes to the channel. The write deadline behaves symmetrically to Read
// and does not affect reading.
func (c *ChannelConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.wdExpired {
		c.mu.Unlock()
		return 0, ErrDeadlineExceeded
	}
	c.writers++
	c.mu.Unlock()

	n, err := c.ch.Write(p)

	c.mu.Lock()
	c.writers--
	expired := c.wdExpired
	c.mu.Unlock()

	if err != nil && expired {
		return n, ErrDeadlineExceeded
	}
	return n, err
}

// Close closes the channel. Idempotent.
func (c *ChannelConn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.stopTimersLocked()
	c.mu.Unlock()
	return c.ch.Close()
}

// CloseWrite signals the end of the outgoing stream without closing
// the channel: reads after it keep delivering data. Delegates to ssh.Channel.
func (c *ChannelConn) CloseWrite() error {
	return c.ch.CloseWrite()
}

// LocalAddr returns a dummy local address; ssh.Channel does not
// provide a real peer address.
func (c *ChannelConn) LocalAddr() net.Addr {
	return channelAddr(channelLocal)
}

// RemoteAddr returns a dummy remote address.
func (c *ChannelConn) RemoteAddr() net.Addr {
	return channelAddr(channelRemote)
}

// SetDeadline sets the deadline for both reading and writing at once.
func (c *ChannelConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armReadLocked(t)
	c.armWriteLocked(t)
	return nil
}

// SetReadDeadline sets the read deadline. A zero t clears the deadline
// and lifts the cutoff, if there was one: after a soft timeout the
// connection is usable again.
func (c *ChannelConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armReadLocked(t)
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *ChannelConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armWriteLocked(t)
	return nil
}

func (c *ChannelConn) armReadLocked(t time.Time) {
	if c.rtimer != nil {
		c.rtimer.Stop()
		c.rtimer = nil
	}
	c.rdExpired = false
	// The timer must not be armed after Close: there would be no way
	// left to cancel it — a repeated Close exits via an early return,
	// and the AfterFunc would hold a reference to the channel for the
	// whole deadline period.
	if c.closed || t.IsZero() {
		return
	}
	if d := time.Until(t); d > 0 {
		c.rtimer = time.AfterFunc(d, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.expireReadLocked()
		})
		return
	}
	c.expireReadLocked()
}

func (c *ChannelConn) armWriteLocked(t time.Time) {
	if c.wtimer != nil {
		c.wtimer.Stop()
		c.wtimer = nil
	}
	c.wdExpired = false
	if c.closed || t.IsZero() {
		return
	}
	if d := time.Until(t); d > 0 {
		c.wtimer = time.AfterFunc(d, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			c.expireWriteLocked()
		})
		return
	}
	c.expireWriteLocked()
}

func (c *ChannelConn) expireReadLocked() {
	c.rdExpired = true
	if c.readers > 0 {
		c.breakLocked()
	}
}

func (c *ChannelConn) expireWriteLocked() {
	c.wdExpired = true
	if c.writers > 0 {
		c.breakLocked()
	}
}

// breakLocked closes the channel to wake up blocked Read/Write calls.
// This is the only way to interrupt ssh.Channel; the connection is dead after it.
func (c *ChannelConn) breakLocked() {
	if c.closed {
		return
	}
	c.closed = true
	c.stopTimersLocked()
	_ = c.ch.Close()
}

func (c *ChannelConn) stopTimersLocked() {
	if c.rtimer != nil {
		c.rtimer.Stop()
		c.rtimer = nil
	}
	if c.wtimer != nil {
		c.wtimer.Stop()
		c.wtimer = nil
	}
}

// channelAddr — a dummy net.Addr for ssh.Channel.
type channelAddr string

func (a channelAddr) Network() string { return "ssh" }
func (a channelAddr) String() string  { return string(a) }
