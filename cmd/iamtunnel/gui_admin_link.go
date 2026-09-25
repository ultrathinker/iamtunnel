//go:build (windows || linux || darwin) && !nogui

package main

import (
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

// guiAdminLink is the window's one connection to the gateway as its admin
// (IAMT-452). Every action used to dial afresh, and the Admin tab polls:
// one SSH login every second or two, each an auth.success in the gateway's
// journal. The window now logs in once and sends every command over that
// login - PROTOCOL §1.2 gives each command its own channel, so one
// connection carries them all - and dials again only when the connection
// has gone, or when the saved connection string or key is no longer the
// one it was made with (another gateway picked, a new string pasted).
//
// Reading a recording back goes over it too, window after window (M-12
// had given the reader a connection of its own). And it does not outlive
// its use: adminLinkIdleAfter after the last action let it go, it is
// closed, and the next action dials again.
var guiAdminLink adminLink

// adminLinkIdleAfter is how long the window keeps its connection with
// nothing going over it. A window in use never gets there - the Session
// tab's live view asks every second - and somebody who sat reading a
// transcript for longer costs one login when they come back.
const adminLinkIdleAfter = 5 * time.Minute

type adminLink struct {
	mu   sync.Mutex
	key  string
	conn *admin.Conn
	// leases is how many actions hold conn right now. The idle clock
	// runs only while it is zero, so the connection is never closed
	// under a command in flight; gen tells a firing clock whether it is
	// still the one that counts.
	leases int
	idle   *time.Timer
	gen    uint64
	// dial is dialAdmin; a test counts the logins through it.
	dial func(config.ConnString, ssh.Signer) (*admin.Conn, error)
	// idleAfter is adminLinkIdleAfter; a test shortens it.
	idleAfter time.Duration
}

// guiAdminConn is a lease on the window's connection. Close hands it back
// rather than closing it: the call sites keep their defer conn.Close(),
// written when each of them owned a connection of its own.
type guiAdminConn struct {
	*admin.Conn
	release func()
}

func (c guiAdminConn) Close() error {
	if c.release != nil {
		c.release()
	}
	return nil
}

// get returns the window's connection for this identity, dialing it if
// there is none, if it broke, or if the identity changed. The lock is held
// across the dial on purpose: two actions arriving together get one login,
// not two.
func (l *adminLink) get(cs config.ConnString, signer ssh.Signer) (guiAdminConn, error) {
	key := cs.Host + "\x00" + strconv.Itoa(cs.Port) + "\x00" + cs.Fingerprint + "\x00" + cs.Person + "\x00" + string(signer.PublicKey().Marshal())
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopIdleLocked()
	if l.conn != nil && (l.key != key || l.conn.Broken()) {
		_ = l.conn.Close()
		l.conn = nil
	}
	if l.conn == nil {
		dial := l.dial
		if dial == nil {
			dial = dialAdmin
		}
		c, err := dial(cs, signer)
		if err != nil {
			return guiAdminConn{}, err
		}
		l.conn, l.key, l.leases = c, key, 0
	}
	l.leases++
	conn := l.conn
	var once sync.Once
	return guiAdminConn{Conn: conn, release: func() { once.Do(func() { l.put(conn) }) }}, nil
}

// put hands a lease back; the last one out starts the idle clock. A lease
// on a connection the link has since replaced counts for nothing.
func (l *adminLink) put(conn *admin.Conn) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if conn != l.conn {
		return
	}
	if l.leases--; l.leases > 0 {
		return
	}
	after := l.idleAfter
	if after <= 0 {
		after = adminLinkIdleAfter
	}
	l.stopIdleLocked()
	gen := l.gen
	l.idle = time.AfterFunc(after, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.gen != gen || l.leases > 0 || l.conn == nil {
			return
		}
		_ = l.conn.Close()
		l.conn, l.idle = nil, nil
	})
}

// stopIdleLocked stops the idle clock. One already firing finds the
// generation moved on and leaves the connection alone.
func (l *adminLink) stopIdleLocked() {
	l.gen++
	if l.idle != nil {
		l.idle.Stop()
		l.idle = nil
	}
}

// reset closes the window's connection, if any.
func (l *adminLink) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.stopIdleLocked()
	if l.conn != nil {
		_ = l.conn.Close()
		l.conn = nil
	}
	l.leases = 0
}
