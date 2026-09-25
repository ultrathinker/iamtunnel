package gateway

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// IAMT-466: stopping the gateway - an update, a restart of the service -
// cut every live session at once and without a word, the way a network
// fault does; SPEC §3.5 promised a drain and the service comments described
// one that did not exist. Drain is the gentle half of stopping, run before
// Close: nothing new is taken, every live session is told the gateway is
// restarting, and the gateway waits for them to leave, up to a timeout.
// What is still there after it, Close cuts as before.

// drainState is what Drain needs of the gateway.
type drainState struct {
	// draining is set once, by the first Drain, and read by gateway.status
	// and by every session that starts.
	draining atomic.Bool

	noticeMu sync.Mutex
	// notices is every live human session's channel, by session id: where
	// the "restarting" line goes. drainTimeout is what that line promises.
	notices      map[string]ssh.Channel
	drainTimeout time.Duration

	// F-24: the blind spot between a session's draining check and its
	// registration in the engine's session list - a whole setup (door
	// reservation, iamtunnel-target open, nested handshake) wide. A session
	// takes setupMu, re-reads draining, and counts itself in setupWG before
	// it may go on; Drain, after setting the flag, waits on setupWG under
	// the same mutex. So a stop cannot finish inside that spot: either the
	// setup saw the flag and was refused, or the drain waits for it to
	// become a counted session. The count is dropped the moment the session
	// is registered or its setup failed - waiting for sessions to LEAVE is
	// the poll's job, not this one's.
	setupMu sync.Mutex
	setupWG sync.WaitGroup
}

// drainNotice is the line a live session reads when the gateway begins to
// stop. It goes to the session's stderr, so it cannot land inside what the
// machine is writing to the terminal.
func drainNotice(timeout time.Duration) string {
	return fmt.Sprintf("\r\n[iamtunnel] The gateway is restarting: this session will be closed within %s. Finish what you are doing.\r\n", timeout.Round(time.Second))
}

// sendDrainNotice writes the restart line; it may block until the peer
// reads or Close cuts the connection, so callers run it on its own.
func sendDrainNotice(ch ssh.Channel, timeout time.Duration) {
	_, _ = ch.Stderr().Write([]byte(drainNotice(timeout)))
}

// drainRefusal is what a session that starts during the drain is told.
const drainRefusal = "Access to this machine is currently unavailable: the gateway is restarting.\r\n"

// watchDrain registers a live session's channel for the drain notice and
// returns its unregistration. A session that began a moment before a drain
// and registers a moment after it is told at once.
func (g *Gateway) watchDrain(sessionID string, human ssh.Channel) func() {
	g.noticeMu.Lock()
	if g.notices == nil {
		g.notices = make(map[string]ssh.Channel)
	}
	g.notices[sessionID] = human
	late, timeout := g.draining.Load(), g.drainTimeout
	g.noticeMu.Unlock()
	if late {
		go sendDrainNotice(human, timeout)
	}
	return func() {
		g.noticeMu.Lock()
		delete(g.notices, sessionID)
		g.noticeMu.Unlock()
	}
}

// Drain begins the stop (IAMT-466): the listener is closed, so no new
// connection is taken at all; a session that asks to start on a connection
// already in is refused (serveHumanSession); every live session is told the
// gateway is restarting; and Drain returns when the last of them has left or
// timeout has passed, whichever is first. Connections already in keep
// working meanwhile - an admin can still ask gateway.status, which says
// draining. Close follows and cuts whatever is left. A second Drain returns
// at once.
func (g *Gateway) Drain(timeout time.Duration) {
	g.noticeMu.Lock()
	if g.draining.Load() {
		g.noticeMu.Unlock()
		return
	}
	g.drainTimeout = timeout
	g.draining.Store(true)
	live := make([]ssh.Channel, 0, len(g.notices))
	for _, ch := range g.notices {
		live = append(live, ch)
	}
	g.noticeMu.Unlock()

	g.mu.Lock()
	ln := g.ln
	g.mu.Unlock()
	if ln != nil {
		_ = ln.Close()
	}
	// Each notice in its own goroutine (R4 F-12): a write into a channel
	// whose peer stopped granting window (Ctrl-S while output flows)
	// blocks until the window opens, and one such person would hold the
	// whole stop and keep Close - which cuts that transport and so ends
	// the write - from ever running. The same guard the revoke path has
	// (IAMT-448), for the drain.
	for _, ch := range live {
		go sendDrainNotice(ch, timeout)
	}

	// F-24: hold the stop until every setup that read draining==false has
	// either registered its session - the poll below then sees it and tells
	// it - or died trying. Under setupMu, so no setup can count itself in
	// behind this wait. The setup budget bounds the wait: a setup parked on
	// a quiet machine resolves within it.
	g.setupMu.Lock()
	g.setupWG.Wait()
	g.setupMu.Unlock()

	deadline := time.Now().Add(timeout)
	for len(g.aclE.Sessions()) > 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
}
