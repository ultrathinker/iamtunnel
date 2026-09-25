package testsupport

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// SilentChannelPeer is an SSH server that completes the handshake, takes
// any public key, answers every global request - keepalives among them -
// and never answers a channel open (R1-CX F-08): a peer alive by every
// measure except the one its caller is waiting on. ssh.Conn.OpenChannel
// waits for that answer with no limit of its own.
type SilentChannelPeer struct {
	Addr    string
	HostKey ssh.Signer
}

// NewSilentChannelPeer starts one on 127.0.0.1. Everything it accepted is
// closed when the test ends, which also frees a caller still waiting.
func NewSilentChannelPeer(t *testing.T) *SilentChannelPeer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, raw)
			mu.Unlock()
			go func() {
				cfg := &ssh.ServerConfig{PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
					return &ssh.Permissions{}, nil
				}}
				cfg.AddHostKey(signer)
				_, chans, reqs, err := ssh.NewServerConn(raw, cfg)
				if err != nil {
					return
				}
				_ = chans // never read: no channel open is ever answered
				for r := range reqs {
					if r.WantReply {
						_ = r.Reply(true, nil)
					}
				}
			}()
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
	return &SilentChannelPeer{Addr: ln.Addr().String(), HostKey: signer}
}
