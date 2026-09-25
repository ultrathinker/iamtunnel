package server

// IAMT-173 (1.0 blocker), round 3: a canary on internal/server/machine.go's
// sshx.ApplyClientConfig call must exercise the real product Dial path,
// not re-run the policy helper on a throwaway config (round 2's
// TestIAMT173_MachineDial_PinsProtocol built its own ssh.ClientConfig and
// asserted sshx.ApplyClientConfig filled it in - true whether or not
// machine.go ever calls it).
//
// Drives the real Dial() against a fakeGateway whose ssh.ServerConfig is
// pinned to a single KEX algorithm: one outside PROTOCOL §1
// (ecdh-sha2-nistp256 - still in x/crypto's own defaultKexAlgos, so
// removing machine.go's ApplyClientConfig call makes this handshake
// succeed instead of fail) and one inside it (curve25519-sha256, the
// control).

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestIAMT173_MachineDial_RejectsNonPolicyKEX(t *testing.T) {
	machineKey := mustSigner(t)
	gw := newFakeGateway(t, func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(machineKey.PublicKey().Marshal()) })
	gw.cfgMod = func(cfg *ssh.ServerConfig) {
		cfg.KeyExchanges = []string{"ecdh-sha2-nistp256"}
	}
	gw.startAccept()

	cfg := testConfig(t, gw, machineKey, "127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := Dial(ctx, cfg)
	if err == nil {
		_ = m.conn.Close()
		t.Fatal("machine dialed a gateway offering only a non-PROTOCOL-§1 KEX (ecdh-sha2-nistp256) and the handshake succeeded — machine.go is not applying sshx.ApplyClientConfig's KEX policy")
	}
	if !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("expected a KEX-negotiation failure, got a differently-shaped error: %v", err)
	}
}

// TestIAMT173_MachineDial_AcceptsPolicyKEX is the control: the same fake
// gateway, pinned to curve25519-sha256 (PROTOCOL §1's first KEX choice)
// instead, must let the machine client through.
func TestIAMT173_MachineDial_AcceptsPolicyKEX(t *testing.T) {
	machineKey := mustSigner(t)
	gw := newFakeGateway(t, func(k ssh.PublicKey) bool { return string(k.Marshal()) == string(machineKey.PublicKey().Marshal()) })
	gw.cfgMod = func(cfg *ssh.ServerConfig) {
		cfg.KeyExchanges = []string{"curve25519-sha256"}
	}
	gw.startAccept()

	cfg := testConfig(t, gw, machineKey, "127.0.0.1:1")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("machine client should accept a gateway offering curve25519-sha256 (PROTOCOL §1): %v", err)
	}
	defer m.conn.Close()
}
