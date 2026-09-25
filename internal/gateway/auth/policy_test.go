package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeKey lets the policy be probed with a crypto payload under an
// arbitrary wire type name - proving the decision comes from the key
// itself and not from Type() (SPEC 6.1).
type fakeKey struct {
	t   string
	crp crypto.PublicKey
}

func (f fakeKey) Type() string                                 { return f.t }
func (f fakeKey) CryptoPublicKey() crypto.PublicKey            { return f.crp }
func (f fakeKey) Marshal() []byte                              { return nil }
func (f fakeKey) Verify(data []byte, sig *ssh.Signature) error { return nil }

func TestAcceptKeyEd25519Accepted(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	if err := AcceptKey(k); err != nil {
		t.Fatalf("ed25519 rejected: %v", err)
	}
}

func TestAcceptKeyRSA2048Rejected(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pk, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	if err := AcceptKey(pk); err == nil {
		t.Fatal("rsa 2048 accepted, want rejection")
	}
}

func TestAcceptKeyRSA3072Boundary(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pk, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	if err := AcceptKey(pk); err != nil {
		t.Fatalf("rsa 3072 rejected: %v", err)
	}
}

func TestAcceptKeyECDSARejected(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pk, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	if err := AcceptKey(pk); err == nil {
		t.Fatal("ecdsa (nistp256) accepted, want rejection")
	}
}

// The policy must not be fooled by wire type names: a dsa-typed key and
// an "ecdsa-sha1"-typed key are rejected by their crypto payload, and an
// unknown payload under an ed25519 name is rejected too.
func TestAcceptKeyJudgesByPayloadNotName(t *testing.T) {
	cases := []struct {
		name string
		key  fakeKey
	}{
		{"ssh-dss payload", fakeKey{t: "ssh-dss", crp: struct{}{}}},
		{"ecdsa-sha1 name", fakeKey{t: "ecdsa-sha1", crp: ecdsa.PublicKey{}}},
		{"ed25519 name, opaque payload", fakeKey{t: "ssh-ed25519", crp: struct{}{}}},
	}
	for _, tc := range cases {
		if err := AcceptKey(tc.key); err == nil {
			t.Errorf("%s: accepted, want rejection", tc.name)
		}
	}
}
