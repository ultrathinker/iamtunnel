package client_test

// IAMT-450: the dial's timeout bounded the TCP connect and nothing after
// it. ssh.ClientConfig.Timeout is read only by ssh.Dial, which this
// package does not use; ssh.NewClientConn on an open socket waits for the
// peer's first byte for as long as it takes. A gateway that accepted the
// connection and then said nothing - hung, or a proxy that swallows the
// stream - held the person at "connecting" for good.

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

// iamt450SilentGateway accepts TCP connections and never sends a byte.
func iamt450SilentGateway(t *testing.T) string {
	t.Helper()
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
	return ln.Addr().String()
}

func TestIAMT450_TheClientGivesUpOnAGatewayThatNeverSpeaks(t *testing.T) {
	host, port := splitAddr(iamt450SilentGateway(t))
	cs := config.ConnString{Host: host, Port: port, Person: "alice", Fingerprint: "SHA256:" + repeat43('A')}
	dir, signer := t.TempDir(), testSigner(t)

	const timeout = 300 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		_, err := client.Machines(context.Background(), dir, cs, signer, timeout)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a gateway that never spoke was reported as answering")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the client is still in the SSH handshake with a gateway that accepted the connection and never sent a byte, 5 s into a %v timeout", timeout)
	}
}
