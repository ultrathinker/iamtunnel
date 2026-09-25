package client_test

// fakegateway_test.go: a minimal SSH peer that speaks just enough of the
// PROTOCOL.md wire shape (command-login + the exec envelope of §1.2/§6)
// to exercise internal/client's dialing and parsing code, without
// depending on internal/gateway's own implementation. It is not a copy
// of internal/gateway's own behavior and makes no claim to be: it exists
// to prove internal/client's side of the wire contract, including the
// garbage-response robustness it requires, independently of the peer's
// own correctness.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeGateway accepts one SSH connection at a time on a loopback
// listener and hands each "exec" request's raw JSON request body to
// respond, which returns the raw bytes to write back before the channel
// closes — including deliberately malformed bytes, for the garbage tests.
type fakeGateway struct {
	addr    string
	signer  ssh.Signer
	respond func(command string, request []byte) []byte
	// wantUser, if set, is checked against the SSH username; a mismatch
	// fails the handshake the way a real gateway's identity check would.
	wantUser string
	// cfgMod, if set, is applied to this fake gateway's own ssh.ServerConfig
	// before it starts accepting - IAMT-173's policy tests use it to pin
	// the server side to a single algorithm (in or out of PROTOCOL §1) so
	// the real wire handshake, not just a struct field, proves the
	// client's policy.
	cfgMod func(*ssh.ServerConfig)
}

func newFakeGateway(t *testing.T, respond func(command string, request []byte) []byte) *fakeGateway {
	t.Helper()
	return newFakeGatewayWithServerConfig(t, respond, nil)
}

// newFakeGatewayWithServerConfig is newFakeGateway plus a hook to narrow
// this fake gateway's own ssh.ServerConfig (e.g. to a single KEX algorithm)
// before it starts serving.
func newFakeGatewayWithServerConfig(t *testing.T, respond func(command string, request []byte) []byte, cfgMod func(*ssh.ServerConfig)) *fakeGateway {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("host key signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	fg := &fakeGateway{addr: ln.Addr().String(), signer: signer, respond: respond, cfgMod: cfgMod}
	go fg.serve(t, ln)
	return fg
}

func (fg *fakeGateway) fingerprint() string { return ssh.FingerprintSHA256(fg.signer.PublicKey()) }

func (fg *fakeGateway) serve(t *testing.T, ln net.Listener) {
	for {
		raw, err := ln.Accept()
		if err != nil {
			return
		}
		go fg.handle(t, raw)
	}
}

func (fg *fakeGateway) handle(t *testing.T, raw net.Conn) {
	defer raw.Close()
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			if fg.wantUser != "" && meta.User() != fg.wantUser {
				return nil, errFakeAuthRejected
			}
			return &ssh.Permissions{}, nil
		},
	}
	if fg.cfgMod != nil {
		fg.cfgMod(cfg)
	}
	cfg.AddHostKey(fg.signer)
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, creqs, err := n.Accept()
		if err != nil {
			continue
		}
		go fg.serveSession(ch, creqs)
	}
}

func (fg *fakeGateway) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		if r.Type != "exec" {
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
			continue
		}
		if r.WantReply {
			_ = r.Reply(true, nil)
		}
		command := parseExecCommand(r.Payload)
		body := readAllChannel(ch)
		out := fg.respond(command, body)
		_, _ = ch.Write(out)
		return
	}
}

var errFakeAuthRejected = fakeErr("fake gateway: unexpected username")

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

// parseExecCommand pulls the command name out of an "exec" request
// payload (RFC 4254 §6.5: one uint32-length-prefixed string) without
// importing internal/sshx, so this double stays independent of the
// package under test.
func parseExecCommand(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := int(payload[0])<<24 | int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if n < 0 || 4+n > len(payload) {
		return ""
	}
	return string(payload[4 : 4+n])
}

func readAllChannel(ch ssh.Channel) []byte {
	var out []byte
	buf := make([]byte, 4096)
	for {
		n, err := ch.Read(buf)
		if n > 0 {
			out = append(out, buf[:n]...)
		}
		if err != nil {
			return out
		}
	}
}

// canonicalMachinesMineOK is a well-formed, minimal "machines.mine"
// success envelope (PROTOCOL §1.2/§6).
func canonicalMachinesMineOK() []byte {
	env := map[string]interface{}{
		"proto": 1,
		"caps":  []string{},
		"ok":    true,
		"result": map[string]interface{}{
			"machines": []map[string]interface{}{
				{"id": "win01", "name": "win01", "until": "2026-09-12T18:00:00Z", "online": true, "state": "verified", "sshdListening": true, "doorOpen": false},
			},
		},
	}
	b, _ := json.Marshal(env)
	return b
}
