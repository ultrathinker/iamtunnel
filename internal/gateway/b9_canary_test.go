package gateway

import (
	"encoding/json"
	"testing"
	"time"
)

// TestCanary_B9_PairingUsesClientNameAndReadableFallbacks is a security
// canary for the identity boundary: a pairing name is client input, while
// the key fingerprint remains the key identity and only a collision triggers
// the admin/admin2/admin3 fallback.
func TestCanary_B9_PairingUsesClientNameAndReadableFallbacks(t *testing.T) {
	f := newFixture(t, nil)
	seedPairingWindow(t, f, "424242", time.Hour)
	clientKey := genSigner(t)
	env, status := iamt143Exec(t, f.addr, "pairing", clientKey, "admin.pair", pairingRequest{
		Proto: 1, Pin: "424242", Pubkey: authorizedLine(clientKey.PublicKey()), Name: "second-admin",
	})
	if !env.OK || status != 0 {
		t.Fatalf("client name was not accepted: env=%+v status=%d", env, status)
	}
	var result pairingResult
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatalf("pairing result: %v", err)
	}
	if result.Person != "second-admin" {
		t.Fatalf("client name became %q, want second-admin", result.Person)
	}
	fp := fingerprintOf(t, clientKey.PublicKey())
	if result.Person == personNameFromFingerprint(fp) {
		t.Fatalf("pairing name still comes from fingerprint %q", fp)
	}

	seedPairingWindow(t, f, "424243", time.Hour)
	emptyKey := genSigner(t)
	env, status = iamt143Exec(t, f.addr, "pairing", emptyKey, "admin.pair", pairingRequest{
		Proto: 1, Pin: "424243", Pubkey: authorizedLine(emptyKey.PublicKey()),
	})
	if !env.OK || status != 0 {
		t.Fatalf("empty name pairing was not accepted: env=%+v status=%d", env, status)
	}
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatalf("empty-name pairing result: %v", err)
	}
	if result.Person != "admin" {
		t.Fatalf("empty name became %q, want admin (SPEC §3.3: admin first while it is free)", result.Person)
	}

	seedPairingWindow(t, f, "424244", time.Hour)
	thirdKey := genSigner(t)
	env, status = iamt143Exec(t, f.addr, "pairing", thirdKey, "admin.pair", pairingRequest{
		Proto: 1, Pin: "424244", Pubkey: authorizedLine(thirdKey.PublicKey()), Name: "admin",
	})
	if !env.OK || status != 0 {
		t.Fatalf("occupied name pairing was not accepted: env=%+v status=%d", env, status)
	}
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatalf("occupied-name pairing result: %v", err)
	}
	if result.Person != "admin2" {
		t.Fatalf("occupied name became %q, want admin2", result.Person)
	}
}
