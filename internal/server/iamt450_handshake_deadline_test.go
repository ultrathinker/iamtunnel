package server

// IAMT-450: HandshakeTimeout was handed to ssh.ClientConfig.Timeout, which
// only ssh.Dial reads - for the TCP connect. ssh.NewClientConn on the open
// socket waits for the gateway's first byte for as long as it takes, and
// the context bounds only the connect as well. A gateway that accepted the
// connection and then said nothing - hung, or a proxy in between that
// swallows the stream - held the machine's reconnect loop in that one
// attempt for good, deaf to its own cancellation.

import (
	"context"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/testsupport"
)

func TestIAMT450_TheMachineGivesUpOnAGatewayThatNeverSpeaks(t *testing.T) {
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

	tree := testsupport.NewSSHTree(t)
	const handshake = 300 * time.Millisecond
	cfg := Config{
		GatewayAddr:        ln.Addr().String(),
		GatewayFingerprint: "SHA256:" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		MachineID:          "vm1",
		MachineKey:         mustSigner(t),
		KeyFile:            tree.KeyPath("administrators_authorized_keys"),
		DoorLockPath:       filepath.Join(tree.Home, "door.lock"),
		OwnerUID:           testUIDForDoor(),
		OwnerGID:           testGIDForDoor(),
		TargetAddr:         "127.0.0.1:1",
		SpawnWatchdog:      noopSpawnWatchdog,
		DialTimeout:        5 * time.Second,
		HandshakeTimeout:   handshake,
	}
	done := make(chan error, 1)
	go func() {
		m, err := Dial(context.Background(), cfg)
		if err == nil {
			_ = m.conn.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a gateway that never spoke was reported as answering")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("the machine is still in the SSH handshake with a gateway that accepted the connection and never sent a byte, 5 s into a %v handshake timeout", handshake)
	}
}
