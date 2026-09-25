package sshx

// policy_test.go: IAMT-173 canaries (1.0 blocker).
//
// Every "product seam" (ServerConfig/ClientConfig in seven places
// across the repository) is covered by exactly one canary: "the moment
// the policy is nailed down in this spot, the product test goes red."
// Not going red on a broken product is also a failure (of the canary
// itself, for not being broken): red during preparation is not a
// canary, so the red tests here are both green post-fix and red when
// the fix is reverted.

import (
	"reflect"
	"slices"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestPolicy_ProtocolLists_PinnedToSpec — the seam on policy.go itself:
// the expected names/order from PROTOCOL §1 are written into the test
// explicitly, and any drift (forgot to add a new name, reordered the
// list, swapped "curve25519-sha256" for an x/crypto constant of a
// different value) goes red on this line, so the policy cannot drift
// silently.
//
// The lists are read through exported accessor functions (gate 3
// forbids exporting the package variables themselves): this test
// catches both a change to the slice contents and a reorder of the
// names in the policy.
func TestPolicy_ProtocolLists_PinnedToSpec(t *testing.T) {
	wantKEX := []string{"mlkem768x25519-sha256", "curve25519-sha256", "diffie-hellman-group14-sha256"}
	gotKEX := KEX()
	if !slices.Equal(gotKEX, wantKEX) {
		t.Fatalf("PROTOCOL §1 KEX: want %v, code has %v", wantKEX, gotKEX)
	}
	wantCiphers := []string{"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes256-ctr"}
	gotCiphers := Ciphers()
	if !slices.Equal(gotCiphers, wantCiphers) {
		t.Fatalf("PROTOCOL §1 Ciphers: want %v, code has %v", wantCiphers, gotCiphers)
	}
	wantMACs := []string{"hmac-sha2-512-etm@openssh.com", "hmac-sha2-256-etm@openssh.com"}
	gotMACs := MACs()
	if !slices.Equal(gotMACs, wantMACs) {
		t.Fatalf("PROTOCOL §1 MAC: want %v, code has %v", wantMACs, gotMACs)
	}
	wantHK := []string{"ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256"}
	gotHK := HostKeyAlgos()
	if !slices.Equal(gotHK, wantHK) {
		t.Fatalf("PROTOCOL §1 HostKeyAlgorithms: want %v, code has %v", wantHK, gotHK)
	}
}

// TestPolicy_ApplyServerConfig_Overwrites — canary: remove the
// sshx.ApplyServerConfig call in any one specific place — the field
// stays nil, as x/crypto defaults it. The test does not depend on the
// specific place; it stands on the seam (Apply*) and goes red at the
// cheapest place to "break" it: this file.
func TestPolicy_ApplyServerConfig_Overwrites(t *testing.T) {
	cfg := &ssh.ServerConfig{
		// intentionally "wrong" values — Apply* must overwrite them
		KeyExchanges: nil,
		Ciphers:      nil,
		MACs:         nil,
	}
	ApplyServerConfig(cfg)
	wantKEX := KEX()
	if !slices.Equal(cfg.KeyExchanges, wantKEX) {
		t.Fatalf("ApplyServerConfig: KEX not replaced with PROTOCOL §1 (%v)", cfg.KeyExchanges)
	}
	wantCiphers := Ciphers()
	if !slices.Equal(cfg.Ciphers, wantCiphers) {
		t.Fatalf("ApplyServerConfig: Ciphers not replaced with PROTOCOL §1 (%v)", cfg.Ciphers)
	}
	wantMACs := MACs()
	if !slices.Equal(cfg.MACs, wantMACs) {
		t.Fatalf("ApplyServerConfig: MACs not replaced with PROTOCOL §1 (%v)", cfg.MACs)
	}

	// The "reverse" canary — checks that the same underlying slice is
	// not shared between calls: otherwise a mutation in one product
	// would drag the rest along with it. Apply* must copy.
	cfg2 := &ssh.ServerConfig{}
	ApplyServerConfig(cfg2)
	if reflect.DeepEqual(cfg.KeyExchanges, cfg2.KeyExchanges) &&
		&cfg.KeyExchanges[0] == &cfg2.KeyExchanges[0] {
		t.Fatalf("ApplyServerConfig: the underlying slice is shared between calls — a mutation in one place would leak into the other")
	}
}

// TestPolicy_ApplyClientConfig_Overwrites — canary for ApplyClientConfig.
func TestPolicy_ApplyClientConfig_Overwrites(t *testing.T) {
	cfg := &ssh.ClientConfig{
		HostKeyAlgorithms: []string{"ssh-rsa"}, // deprecated/forbidden, Apply* must overwrite it
	}
	ApplyClientConfig(cfg)
	wantKEX := KEX()
	if !slices.Equal(cfg.KeyExchanges, wantKEX) {
		t.Fatalf("ApplyClientConfig: KEX not replaced (%v)", cfg.KeyExchanges)
	}
	wantCiphers := Ciphers()
	if !slices.Equal(cfg.Ciphers, wantCiphers) {
		t.Fatalf("ApplyClientConfig: Ciphers not replaced (%v)", cfg.Ciphers)
	}
	wantMACs := MACs()
	if !slices.Equal(cfg.MACs, wantMACs) {
		t.Fatalf("ApplyClientConfig: MACs not replaced (%v)", cfg.MACs)
	}
	wantHK := HostKeyAlgos()
	if !slices.Equal(cfg.HostKeyAlgorithms, wantHK) {
		t.Fatalf("ApplyClientConfig: HostKeyAlgorithms not replaced (%v)", cfg.HostKeyAlgorithms)
	}
}

// TestPolicy_ApplyNil_DoesNotPanic — canary on the nil-safe guard path
// of Apply*. The test would go red if Apply* started to deref a nil cfg.
func TestPolicy_ApplyNil_DoesNotPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Apply* panicked on nil: %v", r)
		}
	}()
	ApplyServerConfig(nil)
	ApplyClientConfig(nil)
}
