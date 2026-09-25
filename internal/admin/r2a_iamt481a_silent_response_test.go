package admin

// r2a_iamt481a_silent_response_test.go — IAMT-481a (the F-08 remainder,
// found independently in round 2 review): a gateway that answers the
// channel open, accepts the exec request, and then never sends a byte
// held every admin command — the window's and the CLI's alike — for
// good. F-08 bounded the channel open; the response itself had no limit
// of its own, and decodeResponse reads to EOF, which a silent gateway
// never sends.

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// openAndQuietPeer is an SSH server that completes the handshake, takes
// any public key, answers every global request, accepts every channel
// open and replies success to every channel request — and then sends
// not one byte of its own. It is the gateway IAMT-481a describes: alive
// by every measure the transport can take, dead on the one the command
// is waiting on.
type openAndQuietPeer struct {
	Addr    string
	HostKey ssh.Signer
}

func newOpenAndQuietPeer(t *testing.T) *openAndQuietPeer {
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
				go func() {
					for r := range reqs {
						if r.WantReply {
							_ = r.Reply(true, nil)
						}
					}
				}()
				for newCh := range chans {
					ch, inch, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range inch {
							if r.WantReply {
								_ = r.Reply(true, nil)
							}
						}
					}()
					_ = ch // accepted, exec answered — and then: silence
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
	return &openAndQuietPeer{Addr: ln.Addr().String(), HostKey: signer}
}

// TestIAMT481A_AnAdminCommandGivesUpOnAGatewayThatAnswersTheChannelOpenAndThenGoesSilent
// is the canary.
//
// Canary: delete the silence limit in Exec's read of the response (or
// widen it past caring). This test goes red on the Fatalf below: whoami
// is still waiting minutes later, because the F-08 bound stopped at the
// channel open and nothing since then has watched the answer itself.
func TestIAMT481A_AnAdminCommandGivesUpOnAGatewayThatAnswersTheChannelOpenAndThenGoesSilent(t *testing.T) {
	peer := newOpenAndQuietPeer(t)
	// A second, not less: under -race and a loaded host the handshake
	// itself must fit — the same reasoning the F-08 test records. The
	// response silence limit rides on the same Dial timeout (six times
	// it, to be exact), so the bound under test here is 6s and the 15s
	// ceiling below still catches a wait with no limit at all.
	const timeout = time.Second
	conn, err := Dial(Peer{Addr: peer.Addr, Fingerprint: fingerprintFor(t, peer.HostKey.PublicKey())}, "alice", genSigner(t), timeout)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	done := make(chan error, 1)
	go func() {
		_, err := conn.Whoami()
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("whoami succeeded against a gateway that opened the channel and never sent a byte")
		}
		if !conn.Broken() {
			t.Error("the connection whose gateway went silent mid-command is not marked broken: the window would send its next command down it again")
		}
		if !strings.Contains(err.Error(), "sent no byte") {
			t.Errorf("the error does not say the gateway went silent: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("an admin command is still waiting on a gateway that opened the channel and went silent, 15s into a %v dial timeout — the response itself has no limit (IAMT-481a)", timeout)
	}
}
