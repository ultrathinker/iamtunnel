package sshx

import (
	"time"

	"golang.org/x/crypto/ssh"
)

// openchannel.go: channel-open with a deadline (IAMT-450).
//
// ssh.Conn.OpenChannel waits for the peer's answer — confirmation or
// refusal — with no limit at all: a peer that holds the transport and
// answers keepalive, but stays silent on channel-open, holds the
// caller forever. The protocol gives no way to cancel an open already
// sent, so the wait moves into a goroutine, and the caller waits on it
// until the deadline. An answer that arrives after the deadline is of
// no use to anyone: the channel is closed as soon as it arrives, so
// the other side is not left with an open channel with no owner. What
// to do about a peer that did not answer in time (usually: close the
// transport) is up to the caller.

// openErr — the type of the "waiting stopped via stop" sentinel.
// A string type, like timeoutErr and payloadErr: the sentinel is
// declared as a constant, which an importer cannot reassign.
type openErr string

func (e openErr) Error() string { return string(e) }

// ErrOpenChannelTimeout — the peer did not answer the channel-open by
// the deadline. Implements net.Error (Timeout() == true), compared via errors.Is.
const ErrOpenChannelTimeout = timeoutErr("sshx: the peer did not answer the channel open in time")

// ErrOpenChannelStopped — stop closed before an answer arrived.
const ErrOpenChannelStopped = openErr("sshx: the connection ended before the channel open was answered")

// OpenChannelWithDeadline opens a channel of type name with no initial
// data and waits for an answer no longer than deadline or until stop
// closes (nil — wait on nothing but the deadline). A peer's refusal
// error is returned as is; an expired deadline is ErrOpenChannelTimeout,
// a closed stop is ErrOpenChannelStopped.
func OpenChannelWithDeadline(conn ssh.Conn, name string, deadline time.Time, stop <-chan struct{}) (ssh.Channel, <-chan *ssh.Request, error) {
	type opened struct {
		ch   ssh.Channel
		reqs <-chan *ssh.Request
		err  error
	}
	// Unbuffered: the send succeeds only while the caller is still
	// waiting. Once it has left, the goroutine sees abandoned and
	// closes the late channel itself — buffered, it would sit there
	// and stay open forever.
	answer := make(chan opened)
	abandoned := make(chan struct{})
	go func() {
		ch, reqs, err := conn.OpenChannel(name, nil)
		select {
		case answer <- opened{ch: ch, reqs: reqs, err: err}:
		case <-abandoned:
			if err == nil {
				go ssh.DiscardRequests(reqs)
				_ = ch.Close()
			}
		}
	}()

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case o := <-answer:
		return o.ch, o.reqs, o.err
	case <-timer.C:
		close(abandoned)
		return nil, nil, ErrOpenChannelTimeout
	case <-stop:
		close(abandoned)
		return nil, nil, ErrOpenChannelStopped
	}
}
