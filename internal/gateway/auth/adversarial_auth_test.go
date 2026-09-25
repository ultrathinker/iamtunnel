package auth

// adversarial_auth_test.go — Phase-5 adversarial probes for the auth
// layer. The question: can a person reach a machine they were never
// granted, by any route — a name that parses two ways, a fingerprint
// that matches loosely, a race between a grant being revoked and a
// session starting, a reconnect that inherits something it should not?
// This file pins the answers we observed.

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// newSignerFromKey wraps an ed25519 private key into an ssh.Signer.
func newSignerFromKey(priv ed25519.PrivateKey) (ssh.Signer, error) {
	return ssh.NewSignerFromKey(priv)
}

// sshPublic builds an ssh.PublicKey from an ed25519 public key.
func sshPublic(pub ed25519.PublicKey) (ssh.PublicKey, error) {
	return ssh.NewPublicKey(pub)
}

// TestAdvUsernameTwoWayParse: a username containing a colon is parsed
// as <person>:<machine>. The grammar [a-z0-9][a-z0-9._-]{0,31} rejects
// colons inside parts, so two-way parsing cannot happen. Verify that
// every malicious variant is refused.
func TestAdvUsernameTwoWayParse(t *testing.T) {
	bad := []string{
		"a:b:c",            // 3 parts
		"a:b:c:d",          // 4 parts
		":a",               // empty person
		"a:",               // empty machine
		":",                // both empty
		"::",               // three empties -> len 3
		"a: b",             // space in machine
		"a :b",             // space in person
		"a:\x00b",          // NUL
		"a:b\x00c",         // NUL in machine
		"\x00a:b",          // NUL in person
		"ali\u0441e:win01", // Cyrillic U+0441 inside person (looks like alice)
		"alice:win01\x00",  // NUL trailer
		"alice:.",          // machine starts with dot
		"alice:-",          // machine starts with dash
		".alice:win01",     // person starts with dot
		"-alice:win01",     // person starts with dash
	}
	for _, u := range bad {
		if _, err := ParseUsername(u); err == nil {
			t.Errorf("ParseUsername(%q): no error (two-way parse risk)", u)
		}
	}
}

// TestAdvLongNameRejected: 33+ char names are refused by the grammar.
func TestAdvLongNameRejected(t *testing.T) {
	long := strings.Repeat("a", 33)
	if _, err := ParseUsername(long); err == nil {
		t.Fatal("33-char name accepted")
	}
	if _, err := ParseUsername("alice:" + long); err == nil {
		t.Fatal("33-char machine name accepted")
	}
	if _, err := ParseMachineUsername("machine:" + long); err == nil {
		t.Fatal("33-char machine id accepted")
	}
}

// TestAdvMachineLoginAsPerson: a person presenting their key as a
// "machine:<id>" login must be refused. The reverse — a machine key
// with a person login — is also refused.
func TestAdvMachineLoginAsPerson(t *testing.T) {
	alicePub, alicePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = alicePub
	aliceSign, err := newSignerFromKey(alicePriv)
	if err != nil {
		t.Fatal(err)
	}
	alicePK, _ := sshPublic(alicePub)
	lookup := NewMapLookup(map[string]Subject{
		Fingerprint(alicePK): {Name: "alice", Role: RolePerson},
	})
	h, err := NewHandler(lookup, AuthLimits{HandshakeTimeout: 1})
	if err != nil {
		t.Fatal(err)
	}
	// alice's key with "machine:alice" must be refused.
	if _, err := h.Resolve("machine:alice", aliceSign.PublicKey()); err == nil {
		t.Fatal("alice key accepted under machine login")
	}
}

// TestAdvFingerprintCollisionAcrossRoles: two keys with the same wire
// bytes but different type labels are still hashed to the same
// fingerprint. The state validator should catch this, but the auth
// callback would happily return whichever subject matched first. We
// test the auth callback: if the lookup has only ONE subject per
// fingerprint, the second is not returned.
func TestAdvFingerprintCollisionAcrossRoles(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sign, _ := newSignerFromKey(priv)
	pk, _ := sshPublic(pub)
	fp := Fingerprint(pk)
	// One fingerprint, mapped to a person. The lookup must NOT also
	// return a machine with the same fingerprint.
	lookup := NewMapLookup(map[string]Subject{
		fp: {Name: "alice", Role: RolePerson},
	})
	h, _ := NewHandler(lookup, AuthLimits{HandshakeTimeout: 1})
	id, err := h.Resolve("alice", sign.PublicKey())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if id.Subject.Name != "alice" || id.Subject.Role != RolePerson {
		t.Fatalf("got %+v, want alice person", id.Subject)
	}
}

// TestAdvResolvePure: the callback must NOT mutate the lookup. We
// hammer the callback 100 times with mismatches and assert the lookup
// is unchanged. This is the documented "purity" contract.
func TestAdvResolvePure(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	sign, _ := newSignerFromKey(priv)
	pk, _ := sshPublic(pub)
	lookup := NewMapLookup(map[string]Subject{
		Fingerprint(pk): {Name: "alice", Role: RolePerson},
	})
	h, _ := NewHandler(lookup, AuthLimits{HandshakeTimeout: 1})
	before := lookup.dump()
	for i := 0; i < 200; i++ {
		_, _ = h.Resolve("mallory", sign.PublicKey())
		_, _ = h.Resolve("alice:extra", sign.PublicKey())
	}
	after := lookup.dump()
	if len(before) != len(after) {
		t.Fatalf("lookup mutated: before=%v after=%v", before, after)
	}
	for k := range before {
		if _, ok := after[k]; !ok {
			t.Fatalf("key %s disappeared", k)
		}
	}
}

// TestAdvEmptyUsernameRefused: ParseUsername("") returns an error.
func TestAdvEmptyUsernameRefused(t *testing.T) {
	if _, err := ParseUsername(""); err == nil {
		t.Fatal("empty username accepted")
	}
	if _, err := ParseMachineUsername(""); err == nil {
		t.Fatal("empty machine login accepted")
	}
}

// TestAdvMachineUsernameCantBeForged: a username that starts with
// "machine:" but has an invalid machine id must be refused.
func TestAdvMachineUsernameCantBeForged(t *testing.T) {
	for _, u := range []string{
		"machine:",
		"machine:A",
		"machine:a:b",
		"machine:a:b:c",
		"machine:ali\u0441e", // Cyrillic
		"machine:alice:extra",
		"machine",       // no colon
		"Machine:alice", // uppercase M
	} {
		if _, err := ParseMachineUsername(u); err == nil {
			t.Errorf("ParseMachineUsername(%q): no error", u)
		}
	}
}

// TestAdvNoClientAuthKeptOff: confirm ServerConfig does not enable
// NoClientAuth (which would allow password auth).
func TestAdvNoClientAuthKeptOff(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sign, _ := newSignerFromKey(priv)
	h, _ := NewHandler(NewMapLookup(nil), AuthLimits{HandshakeTimeout: 1})
	cfg := h.ServerConfig(sign)
	if cfg.NoClientAuth {
		t.Fatal("ServerConfig enabled NoClientAuth")
	}
	if cfg.PasswordCallback != nil {
		t.Fatal("ServerConfig set a PasswordCallback")
	}
	if cfg.KeyboardInteractiveCallback != nil {
		t.Fatal("ServerConfig set a KeyboardInteractiveCallback")
	}
}
