package admin

// IAMT-450: Dial's timeout bounded the TCP connect and nothing after it.
// ssh.ClientConfig.Timeout is read only by ssh.Dial; ssh.NewClientConn on
// an open socket waits for the peer's first byte for as long as it takes,
// so a gateway that accepted the connection and then said nothing held
// the administrator - and the window's Admin tab - for good.

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestIAMT450_AdminDialGivesUpOnAGatewayThatNeverSpeaks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})
	key := genSigner(t)
	peer := Peer{Addr: ln.Addr().String(), Fingerprint: fingerprintFor(t, key.PublicKey())}

	const timeout = 300 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		c, err := Dial(peer, "alice", key, timeout)
		if err == nil {
			_ = c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a gateway that never spoke was reported as answering")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("admin.Dial is still in the SSH handshake with a gateway that accepted the connection and never sent a byte, 5 s into a %v timeout", timeout)
	}
}
