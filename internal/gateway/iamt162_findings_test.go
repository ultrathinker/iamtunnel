package gateway

// Canaries for the findings of the IAMT-162 review (phase 5, the
// round-4 review report). The bodies are written against the expected
// AFTER-the-fix behavior; finding G3 is closed by task IAMT-174 (the
// Skip lifted), finding G4 is held by a t.Skip while the hole is alive.
// Gate 10 (scripts/check_skips.go) will see the remaining skip.

import (
	"slices"
	"testing"
)

// TestIAMT162_G4_SSHPolicyPinnedToProtocol — finding G4: PROTOCOL §1
// defines the ordered sets of KEX/ciphers/MAC/host-key algorithms and
// outright forbids the x/crypto library defaults ("the client
// configuration ... MUST apply the same ordered set ... and not the
// library's defaults", PROTOCOL §5.2). In the product the policy is
// applied by internal/sshx.ApplyServerConfig / ApplyClientConfig, and
// the single source of truth is internal/sshx/policy.go. This test is
// a canary on the production seam: the expectation is written against
// the post-fix behavior; lifting the Skip took task IAMT-173.
func TestIAMT162_G4_SSHPolicyPinnedToProtocol(t *testing.T) {
	f := newFixture(t, nil)
	sc := f.gw.authH.ServerConfig(genSigner(t))

	wantKEX := []string{"mlkem768x25519-sha256", "curve25519-sha256", "diffie-hellman-group14-sha256"}
	if !slices.Equal(sc.Config.KeyExchanges, wantKEX) {
		t.Fatalf("PROTOCOL §1: the gateway's server config must pin KEX %v, got %v (empty = the x/crypto library defaults, forbidden by the protocol)", wantKEX, sc.Config.KeyExchanges)
	}
	wantCiphers := []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr"}
	if !slices.Equal(sc.Config.Ciphers, wantCiphers) {
		t.Fatalf("PROTOCOL §1: the gateway's server config must pin ciphers %v, got %v", wantCiphers, sc.Config.Ciphers)
	}
	wantMACs := []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"}
	if !slices.Equal(sc.Config.MACs, wantMACs) {
		t.Fatalf("PROTOCOL §1: the gateway's server config must pin MACs %v, got %v", wantMACs, sc.Config.MACs)
	}
}

// TestIAMT162_G3_RemoteGatewayLifecycleCommandsExist — finding G3:
// PROTOCOL §6 requires the admin exec commands gateway.rotate-hostkey
// and gateway.backup (remote, over the admin's SSH channel). The
// client sends them (internal/admin/commands.go:459+). Implemented by
// task IAMT-174: the handlers in admin_lifecycle.go, the entries in
// commandTable below; this test is the canary against the regression
// of "the command was removed from the table".
func TestIAMT162_G3_RemoteGatewayLifecycleCommandsExist(t *testing.T) {
	names := CommandNames()
	for _, want := range []string{"gateway.backup", "gateway.rotate-hostkey"} {
		if !slices.Contains(names, want) {
			t.Fatalf("PROTOCOL §6: the exec command %q is missing from the gateway's table; present: %v", want, names)
		}
	}
}
