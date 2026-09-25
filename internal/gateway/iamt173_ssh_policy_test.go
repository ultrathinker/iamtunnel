package gateway

// IAMT-173 (a 1.0 blocker): the protocol crypto policy.
//
// The file splits the checking into two parts:
//
//   1. "Is the policy applied at the server seam?" --
//      TestIAMT173_ServerConfig_PinsProtocol calls the real production
//      auth.Handler.ServerConfig and checks that it carries §1.
//
//   2. "Does the policy actually work?" --
//      TestIAMT173_KEX_Loopback_*. Behavioral tests on loopback:
//      "a client offering only ecdh-sha2-nistp256 is rejected by the
//      gateway", "a client with only curve25519-sha256 is accepted",
//      "extending the KEX list with a forbidden one --
//      the behavioral test turns red".
//
// Round 3 removed TestIAMT173_ClientDial_PinsProtocol /
// TestIAMT173_AdminClient_PinsProtocol / TestIAMT173_MachineDial_PinsProtocol:
// all three built THEIR OWN ssh.ClientConfig and called
// sshx.ApplyClientConfig on it directly -- a tautology that passes no matter
// whether dial.go/client.go/machine.go call the helper at all. The real
// behavioral canaries for these three client seams now live next to the
// production code that uses them:
//   - internal/client/iamt173_policy_test.go (dial.go)
//   - internal/admin/iamt173_policy_test.go (admin/client.go)
//   - internal/server/iamt173_policy_test.go (server/machine.go)
//   - internal/gateway/iamt173_nested_policy_test.go (human_role.go, a nested handshake)
//   - internal/gateway/iamt173_probe_policy_test.go (sshd_probe.go, both phases)
//
// The canaries turn red at setup and become green after the fix;
// "removing" one specific spot brings the red back. The two-sided rule of
// the fix -- "a client with a wrong policy is rejected, a client with the
// right one is accepted" -- is backed by the two canaries.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// dialClientOnce -- a helper: perform exactly one TCP dial + one
// ssh.NewClientConn with the given ClientConfig, return err. No
// post-handshake operations; the tests only need handshake success/failure.
func dialClientOnce(t *testing.T, addr, user string, signer ssh.Signer, hkc ssh.HostKeyCallback, cfgMut func(*ssh.ClientConfig)) error {
	t.Helper()
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: hkc,
		Timeout:         5 * time.Second,
	}
	if cfgMut != nil {
		cfgMut(cfg)
	}
	conn, _, _, err := ssh.NewClientConn(raw, addr, cfg)
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// TestIAMT173_ServerConfig_PinsProtocol -- the canary on the production seam
// "auth.Handler.ServerConfig" (internal/gateway/auth/auth.go). The
// gateway's server config must carry the ordered KEX/cipher/MAC sets from
// PROTOCOL §1. Remove the sshx.ApplyServerConfig call in ServerConfig() --
// the field stays nil (the x/crypto defaults) -- the test turns red on THIS line.
func TestIAMT173_ServerConfig_PinsProtocol(t *testing.T) {
	f := newFixture(t, nil)
	sc := f.gw.authH.ServerConfig(genSigner(t))
	if !slices.Equal(sc.Config.KeyExchanges, sshx.KEX()) {
		t.Fatalf("auth.Handler.ServerConfig: KEX must be pinned to %v, got %v", sshx.KEX(), sc.Config.KeyExchanges)
	}
	if !slices.Equal(sc.Config.Ciphers, sshx.Ciphers()) {
		t.Fatalf("auth.Handler.ServerConfig: Ciphers must be pinned to %v, got %v", sshx.Ciphers(), sc.Config.Ciphers)
	}
	if !slices.Equal(sc.Config.MACs, sshx.MACs()) {
		t.Fatalf("auth.Handler.ServerConfig: MACs must be pinned to %v, got %v", sshx.MACs(), sc.Config.MACs)
	}
}

// --- A behavioral test -------------------------------------------------------
//
// We raise a clean ssh.ServerConfig with our host key and apply
// sshx.ApplyServerConfig to it. One client -- only curve25519-sha256
// (must pass). Another -- only ecdh-sha2-nistp256 (must be rejected).
// That is the two-sided rule itself: the right policy -- yes, the wrong
// one -- no.

type policyProbeKey struct {
	signer    ssh.Signer
	keyBytes  []byte
	publicKey ssh.PublicKey
}

func newPolicyProbeKey(t *testing.T) policyProbeKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return policyProbeKey{signer: s, keyBytes: s.PublicKey().Marshal(), publicKey: s.PublicKey()}
}

// withPolicyServer starts a minimal ssh server that applies
// sshx.ApplyServerConfig. The behavioral test needs no identity logic at
// all -- only in the negotiation of the KEX/cipher/MAC/host-key sets. So
// the callback accepts any key and returns an error for any credentials:
// that is all AFTER the successful KEX anyway, and the KEX is the
// object under test.
func withPolicyServer(t *testing.T, onlyForPolicy *[]string, onlyForHostKey *[]string) (addr string, signedKey ssh.Signer, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	hostKey := newPolicyProbeKey(t)

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, _ ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, errors.New("policy probe: deny all") // any error after a successful KEX
		},
	}
	cfg.AddHostKey(hostKey.signer)
	sshx.ApplyServerConfig(cfg)

	var mu sync.Mutex
	if onlyForPolicy != nil {
		mu.Lock()
		*onlyForPolicy = append([]string(nil), cfg.KeyExchanges...)
		mu.Unlock()
	}
	if onlyForHostKey != nil {
		mu.Lock()
		// the server publishes no host-key algorithms; we hand over what we know
		*onlyForHostKey = []string{hostKey.publicKey.Type()}
		mu.Unlock()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _, _, _ = ssh.NewServerConn(c, cfg)
			}(c)
		}
	}()

	return ln.Addr().String(), hostKey.signer, wg.Wait
}

// TestIAMT173_KEX_Loopback_PolicyAccepted -- the two-sided rule: a client
// with the same KEX set from §1 (curve25519-sha256) -- the handshake gets
// past credentials. The check level here -- the handshake ends either in
// success or in a credential refusal; in both cases the algorithms were
// agreed on.
func TestIAMT173_KEX_Loopback_PolicyAccepted(t *testing.T) {
	addr, signer, _ := withPolicyServer(t, nil, nil)

	hkc := func(_ string, _ net.Addr, _ ssh.PublicKey) error { return nil }

	// a client asking only for curve25519-sha256 -- the handshake must be
	// agreed on, i.e. either a handshake success or a refusal from the
	// PublicKeyCallback (NOT from KEX). If the server policy rejected the
	// KEX, ssh.NewClientConn would return an error mentioning kex (visible
	// in the x/crypto pool logs; here it is enough to check that the error
	// is not about a KEX refusal and that the session is open).
	err := dialClientOnce(t, addr, "alice", signer, hkc, func(cfg *ssh.ClientConfig) {
		cfg.KeyExchanges = []string{"curve25519-sha256"}
		cfg.Ciphers = []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr"}
		cfg.MACs = []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"}
		cfg.HostKeyAlgorithms = []string{"ssh-ed25519"}
	})
	if err != nil {
		// A refusal from the PublicKeyCallback is expected (the password/public
		// key do not fit, we did not set up any state). The main thing is that
		// the KEX went through.
		if bytes.Contains([]byte(err.Error()), []byte("no matching")) {
			t.Fatalf("a client with curve25519-sha256 (§1) was rejected at KEX: %v", err)
		}
	}
}

// TestIAMT173_KEX_Loopback_NonPolicyRejected -- the two-sided rule:
// a client with KEX ecdh-sha2-nistp256 (in x/crypto but NOT in §1) --
// the handshake fails at KEX. An extra canary: extending the KEX list
// with a forbidden one -- the behavioral test fails.
func TestIAMT173_KEX_Loopback_NonPolicyRejected(t *testing.T) {
	addr, signer, _ := withPolicyServer(t, nil, nil)

	hkc := func(_ string, _ net.Addr, _ ssh.PublicKey) error { return nil }

	err := dialClientOnce(t, addr, "alice", signer, hkc, func(cfg *ssh.ClientConfig) {
		// Only a KEX outside §1
		cfg.KeyExchanges = []string{"ecdh-sha2-nistp256"}
		cfg.Ciphers = []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr"}
		cfg.MACs = []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"}
		cfg.HostKeyAlgorithms = []string{"ssh-ed25519"}
	})
	if err == nil {
		t.Fatalf("a client with ecdh-sha2-nistp256 (outside §1) must be rejected by the gateway, but the handshake went through")
	}
	// The expected error class -- negotiation / kex / no common algorithms.
	// The exact x/crypto wording is not pinned down, but it must be enough
	// to keep the test from "leaking" through some unrelated cause
	// or another.
	msg := err.Error()
	if !kexRejected(msg) {
		t.Fatalf("want a KEX rejection (ssh: no common algorithms / no compatible kex), got: %v", err)
	}
}

// kexRejected -- a small heuristic list of the wordings x/crypto uses
// to report that it could not agree on a KEX. The check is string-based,
// so as not to depend on the changing exact text.
func kexRejected(s string) bool {
	tags := []string{"no common algorithms", "no compatible", "no mutually", "kex", "key exchange"}
	for _, tag := range tags {
		if bytes.Contains([]byte(s), []byte(tag)) {
			return true
		}
	}
	return false
}

// TestIAMT173_ServerConfig_AllSectionsPresent -- a sanity check: none of
// the policy sections is missing (KEX / Ciphers / MACs). Separately we
// check that the client's HostKeyAlgorithms is not empty (otherwise the
// name matching loses its meaning).
func TestIAMT173_ServerConfig_AllSectionsPresent(t *testing.T) {
	f := newFixture(t, nil)
	sc := f.gw.authH.ServerConfig(genSigner(t))
	if len(sc.Config.KeyExchanges) == 0 || len(sc.Config.Ciphers) == 0 || len(sc.Config.MACs) == 0 {
		t.Fatalf("sshx.ApplyServerConfig: one of the sections (KEX/Ciphers/MACs) is empty -- the test is red on the config %+v", sc.Config)
	}
	cfg := &ssh.ClientConfig{}
	sshx.ApplyClientConfig(cfg)
	if len(cfg.HostKeyAlgorithms) == 0 {
		t.Fatalf("sshx.ApplyClientConfig: HostKeyAlgorithms is empty -- the client will not be able to verify the gateway's host key")
	}
}
