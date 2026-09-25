package admin

// IAMT-173 (1.0 blocker), round 3: a canary on internal/admin/client.go's
// sshx.ApplyClientConfig call must exercise the real product Dial path,
// not re-run the policy helper on a throwaway config (round 2's
// TestIAMT173_AdminClient_PinsProtocol built its own ssh.ClientConfig and
// asserted sshx.ApplyClientConfig filled it in - true whether or not
// client.go ever calls it).
//
// Drives the real Dial() against a fake gateway whose ssh.ServerConfig is
// pinned to a single KEX algorithm: one outside PROTOCOL §1
// (ecdh-sha2-nistp256 - still in x/crypto's own defaultKexAlgos, so
// removing client.go's ApplyClientConfig call makes this handshake
// succeed instead of fail) and one inside it (curve25519-sha256, the
// control).

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestIAMT173_AdminDial_RejectsNonPolicyKEX(t *testing.T) {
	personKey := genSigner(t)
	invoked := false
	fg := newFakeGatewayWithServerConfig(t, personKey,
		func(string, []byte) []byte {
			invoked = true
			return []byte(`{"proto":1,"caps":[],"ok":true,"result":{}}` + "\n")
		},
		func(cfg *ssh.ServerConfig) {
			cfg.KeyExchanges = []string{"ecdh-sha2-nistp256"}
		},
	)
	_, err := Dial(Peer{Addr: fg.ln.Addr().String(), Fingerprint: fingerprintFor(t, fg.hostSigner.PublicKey())}, "alice", personKey, 5*time.Second)
	if err == nil {
		t.Fatal("admin client dialed a gateway offering only a non-PROTOCOL-§1 KEX (ecdh-sha2-nistp256) and the handshake succeeded — client.go is not applying sshx.ApplyClientConfig's KEX policy")
	}
	if !strings.Contains(err.Error(), "algorithm") {
		t.Fatalf("expected a KEX-negotiation failure, got a differently-shaped error: %v", err)
	}
	if invoked {
		t.Fatal("the fake gateway's exec handler ran despite the KEX mismatch — a session was opened that should never have completed a handshake")
	}
}

// TestIAMT173_AdminDial_AcceptsPolicyKEX is the control: the same fake
// gateway, pinned to curve25519-sha256 (PROTOCOL §1's first KEX choice)
// instead, must let the client through.
func TestIAMT173_AdminDial_AcceptsPolicyKEX(t *testing.T) {
	personKey := genSigner(t)
	fg := newFakeGatewayWithServerConfig(t, personKey,
		func(string, []byte) []byte {
			return []byte(`{"proto":1,"caps":[],"ok":true,"result":{"subject":"alice","role":"admin","serverTime":"2026-09-12T10:00:00Z","person":"alice"}}` + "\n")
		},
		func(cfg *ssh.ServerConfig) {
			cfg.KeyExchanges = []string{"curve25519-sha256"}
		},
	)
	c, err := Dial(Peer{Addr: fg.ln.Addr().String(), Fingerprint: fingerprintFor(t, fg.hostSigner.PublicKey())}, "alice", personKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin client should accept a gateway offering curve25519-sha256 (PROTOCOL §1): %v", err)
	}
	defer c.Close()
	if _, err := c.Whoami(); err != nil {
		t.Fatalf("whoami over the accepted connection: %v", err)
	}
}
