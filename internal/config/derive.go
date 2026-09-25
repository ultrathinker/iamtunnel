package config

import (
	"crypto/ed25519"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

// Salts for the two ephemeral-key derivations PROTOCOL §3.2/§3.3 define.
// Both flows share the exact same formula and differ only in this
// string, so the derivation itself lives once, here, next to the code
// and token parsers that produce the secret it consumes.
const (
	EnrolKeySalt     = "iamtunnel-enrol-key-v1"
	BootstrapKeySalt = "iamtunnel-bootstrap-key-v1"
)

// DeriveEphemeralSigner implements PROTOCOL §3.2 ("the machine's
// ephemeral private key is deterministically derived as
// ed25519.NewKeyFromSeed(HKDF-SHA-256(raw-secret, salt=..., info="",
// L=32))") and §3.3's identical formula for the bootstrap token. It is
// deterministic: the same secret and salt always yield the same key,
// which is exactly what lets the gateway recognise the key from the
// secret's hash without ever storing the private half.
func DeriveEphemeralSigner(secret, salt string) (ssh.Signer, error) {
	r := hkdf.New(sha256.New, []byte(secret), []byte(salt), nil)
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed))
}
