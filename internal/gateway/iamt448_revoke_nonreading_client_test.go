package gateway

// IAMT-448: revoking a grant closes the person's live sessions at once
// (SPEC §6.4) - unless the person's client has stopped reading. The
// revoke wrote its one-line notice to the channel and closed it only
// after that write returned; with the client's receive window full the
// write waited for a window that never opened, the close behind it never
// ran, and the session - door open, machine still taking keystrokes -
// outlived its grant for as long as the client cared to sit there.

import (
	"bytes"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestIAMT448_RevokeEndsTheSessionOfAClientThatStoppedReading(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "the session did not become active", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	// The client never reads again. It types, the machine echoes, and the
	// echo fills the window the client never reopens - until everything
	// between them stands still and the next write blocks.
	var written atomic.Int64
	go func() {
		chunk := bytes.Repeat([]byte("x"), 32*1024)
		for i := 0; i < 256; i++ {
			if _, err := hs.ch.Write(chunk); err != nil {
				return
			}
			written.Add(int64(len(chunk)))
		}
	}()
	last, since := int64(-1), time.Now()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if n := written.Load(); n != last {
			last, since = n, time.Now()
			continue
		}
		if last > 2<<20 && time.Since(since) > 300*time.Millisecond {
			break
		}
	}
	if last <= 2<<20 {
		t.Fatalf("precondition: the pipe never filled (%d bytes written); the gateway's writes to the client are not blocked", last)
	}

	if _, err := root.GrantsRevoke(f.person, f.machineID); err != nil {
		t.Fatalf("grants.revoke: %v", err)
	}
	waitUntil(t, "the revoked session is still running: its door stays open and the machine still takes its input, because the client stopped reading", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})
}

// A client that has stopped reading its connection altogether - a frozen
// process, or one that means to hold on - takes neither the line nor the
// channel's close, and never answers that close. Until an answer comes the
// bridge keeps waiting on the person's side of the channel, and the
// session stays counted with the door open for it. The keepalive probe
// would cut such a client in the end (20 s x 3 by default); a revoke acts
// at once (SPEC §6.4), so the probe is set out of the way here.
func TestIAMT448_RevokeEndsTheSessionOfAClientThatStoppedReadingItsConnection(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.HumanKeepalive = sshx.Keepalive{Interval: time.Hour, MaxMisses: 3, Name: "keepalive@openssh.com"}
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)

	raw, err := net.DialTimeout("tcp", f.addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn := &iamt448FreezableConn{Conn: raw, freeze: make(chan struct{}), thaw: make(chan struct{})}
	cfg := &ssh.ClientConfig{
		User:            f.person + ":" + f.machineID,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(f.personKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, f.addr, cfg)
	if err != nil {
		_ = conn.Close()
		t.Fatalf("handshake: %v", err)
	}
	// The same wiring as dialHumanClient: the protocol's own responder on
	// the real request stream, x/crypto's default one on a stream of its
	// own that closes with the real one.
	noopReqs := make(chan *ssh.Request)
	client := ssh.NewClient(sc, chans, noopReqs)
	go func() {
		defer close(noopReqs)
		sshx.Keepalive{}.Respond(reqs)
	}()
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	waitUntil(t, "the session did not become active", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 1
	})

	// The read already under way when the client stops takes whatever
	// comes next, so something is made to come next: a keystroke the
	// machine echoes. After that the client reads nothing at all.
	conn.stopReading()
	if _, err := hs.ch.Write([]byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitUntil(t, "precondition: the client never stopped reading", conn.stopped.Load)

	if _, err := root.GrantsRevoke(f.person, f.machineID); err != nil {
		t.Fatalf("grants.revoke: %v", err)
	}
	waitUntil(t, "the revoked session is still running: its client stopped reading its connection and never answered the channel's close, and nothing ended the session without that answer", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})
}

// iamt448FreezableConn is a client's connection that can stop being read:
// after stopReading, the next Read - and every one after it - waits until
// the connection is closed, and stopped says one is waiting.
type iamt448FreezableConn struct {
	net.Conn
	freeze, thaw         chan struct{}
	freezeOnce, thawOnce sync.Once
	stopped              atomic.Bool
}

func (c *iamt448FreezableConn) stopReading() { c.freezeOnce.Do(func() { close(c.freeze) }) }

func (c *iamt448FreezableConn) Read(p []byte) (int, error) {
	select {
	case <-c.freeze:
		c.stopped.Store(true)
		<-c.thaw
		return 0, net.ErrClosed
	default:
		return c.Conn.Read(p)
	}
}

func (c *iamt448FreezableConn) Close() error {
	c.thawOnce.Do(func() { close(c.thaw) })
	return c.Conn.Close()
}
