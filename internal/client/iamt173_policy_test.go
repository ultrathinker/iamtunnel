package client_test

// IAMT-173 (1.0 blocker), round 3: a canary on internal/client/dial.go's
// sshx.ApplyClientConfig call must exercise the real product dial path,
// not re-run the policy helper on a throwaway config (that was round 2's
// tautology — TestIAMT173_ClientDial_PinsProtocol built its own
// ssh.ClientConfig and asserted sshx.ApplyClientConfig filled it in,
// which is true regardless of whether dial.go ever calls it).
//
// This test drives client.Machines - the actual product entrypoint that
// calls internal/client/dial.go's dial() - against a fake gateway whose
// own ssh.ServerConfig is pinned to a single KEX algorithm. Two fakes:
// one outside PROTOCOL §1 (ecdh-sha2-nistp256, which x/crypto's own
// defaultKexAlgos still offers, so removing dial.go's ApplyClientConfig
// call makes the handshake succeed instead of fail) and one inside it
// (curve25519-sha256, the control - proves a failure above is really
// about the KEX list, not some unrelated breakage).

import (
	"context"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/client"
)

// TestIAMT173_ClientDial_RejectsNonPolicyKEX: remove
// sshx.ApplyClientConfig(cfg) from internal/client/dial.go's dial() and
// this goes red - the client falls back to x/crypto's library defaults,
// which include ecdh-sha2-nistp256, and the handshake below - which this
// test expects to FAIL - succeeds instead.
func TestIAMT173_ClientDial_RejectsNonPolicyKEX(t *testing.T) {
	invoked := false
	fg := newFakeGatewayWithServerConfig(t,
		func(command string, request []byte) []byte {
			invoked = true
			return canonicalMachinesMineOK()
		},
		func(cfg *ssh.ServerConfig) {
			// Outside PROTOCOL §1's KEX list, but still one x/crypto
			// itself will propose by default (defaultKexAlgos includes
			// ecdh-sha2-nistp256) - a client that fell back to defaults
			// would still negotiate this successfully.
			cfg.KeyExchanges = []string{"ecdh-sha2-nistp256"}
		},
	)
	cs := connToFake(fg, "alice")
	dir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Machines(ctx, dir, cs, testSigner(t), time.Second)
	if err == nil {
		t.Fatal("client dialed a gateway offering only a non-PROTOCOL-§1 KEX (ecdh-sha2-nistp256) and the handshake succeeded — dial.go is not applying sshx.ApplyClientConfig's KEX policy")
	}
	if !strings.Contains(err.Error(), "handshake") && !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("expected a KEX-negotiation failure, got a differently-shaped error: %v", err)
	}
	if invoked {
		t.Fatal("the fake gateway's exec handler ran despite the KEX mismatch — a handshake happened that should have been rejected before any channel opened")
	}
}

// TestIAMT173_ClientDial_AcceptsPolicyKEX is the control for the test
// above: the same fake gateway, pinned to curve25519-sha256 (PROTOCOL
// §1's first KEX choice) instead, must let the client through. Without
// this, a bug that made EVERY handshake fail (not just non-policy ones)
// would still turn the rejection test green for the wrong reason.
func TestIAMT173_ClientDial_AcceptsPolicyKEX(t *testing.T) {
	fg := newFakeGatewayWithServerConfig(t,
		func(command string, request []byte) []byte {
			return canonicalMachinesMineOK()
		},
		func(cfg *ssh.ServerConfig) {
			cfg.KeyExchanges = []string{"curve25519-sha256"}
		},
	)
	cs := connToFake(fg, "alice")
	dir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	machines, err := client.Machines(ctx, dir, cs, testSigner(t), time.Second)
	if err != nil {
		t.Fatalf("client should accept a gateway offering curve25519-sha256 (PROTOCOL §1): %v", err)
	}
	if len(machines) != 1 || machines[0].ID != "win01" {
		t.Fatalf("machines = %+v, want one entry \"win01\"", machines)
	}
}
