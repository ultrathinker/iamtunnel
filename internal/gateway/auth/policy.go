package auth

import (
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// minRSABits is the SPEC 6.1 floor: rsa is accepted only from 3072 bits.
const minRSABits = 3072

// AcceptKey decides by the key itself, not by the wire type string: the
// crypto.PublicKey behind the SSH blob is inspected via the
// ssh.CryptoPublicKey view. ed25519 is the default; rsa must be at
// least 3072 bits; everything else - ecdsa (any curve, which subsumes
// the SPEC's "ecdsa-sha1" refusal), dsa and anything that does not even
// expose its crypto payload - is refused (SPEC 6.1).
//
// The wire type name is deliberately not consulted: a key claiming
// "ssh-ed25519" but carrying a foreign payload is caught by the switch
// below, and an unviewable payload is refused without looking at its
// name at all.
func AcceptKey(key ssh.PublicKey) error {
	view, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return fmt.Errorf("auth: key offers no crypto payload to inspect")
	}
	switch k := view.CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return fmt.Errorf("auth: malformed ed25519 public key")
		}
		return nil
	case *rsa.PublicKey:
		if bits := k.N.BitLen(); bits < minRSABits {
			return fmt.Errorf("auth: rsa key of %d bits is below the %d-bit floor", bits, minRSABits)
		}
		return nil
	default:
		return fmt.Errorf("auth: key algorithm %T is not accepted (ed25519 or rsa >= %d only)", k, minRSABits)
	}
}
