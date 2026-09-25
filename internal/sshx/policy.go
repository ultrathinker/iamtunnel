// Package sshx — crypto-policy seam for PROTOCOL §1 (IAMT-173).
//
// PROTOCOL §1 mandates an ordered, narrow set of KEX/cipher/MAC/host-key
// algorithm names; the same §5.2 line makes the nested client handshake
// apply the same ordered set, not x/crypto defaults. This file is the
// single source of truth for those lists and the helpers that apply them
// to *ssh.ServerConfig / *ssh.ClientConfig. Every place in this repo that
// builds an x/crypto Config must reach for Apply/ApplyClient here, never
// set the fields directly.
//
// What is *not* here: tests for any specific callsite (those belong
// alongside the callsite, so the test sees the actual product wiring),
// or anything role-specific (policy is protocol-wide).
//
// Names convention: the policy LISTS are non-exported package-level vars
// (gate 3 forbids exported package-level variables, with reason — any
// importer could overwrite the slice in place and silently weaken the
// protocol). The accessor functions (KEX, Ciphers, MACs,
// HostKeyAlgos) are exported and return a defensive copy of each list,
// so a caller cannot mutate the package-level state by mistake.
// ApplyServerConfig / ApplyClientConfig also do that copy themselves.
package sshx

import "golang.org/x/crypto/ssh"

// protocolKEX — PROTOCOL §1 KEX list, ordered. Names match the constants
// in x/crypto/ssh; the ordering is the protocol's preference ordering
// and must not be rearranged.
var protocolKEX = []string{
	// IAMT-226: the post-quantum hybrid first. OpenSSH 10 warns on every
	// connection that does not use one; peers without it (older OpenSSH,
	// older iamtunnel builds) fall back to curve25519-sha256.
	ssh.KeyExchangeMLKEM768X25519,
	ssh.KeyExchangeCurve25519,
	ssh.KeyExchangeDH14SHA256,
}

// protocolCiphers — PROTOCOL §1 cipher list, ordered.
var protocolCiphers = []string{
	ssh.CipherChaCha20Poly1305,
	ssh.CipherAES256GCM,
	ssh.CipherAES256CTR,
}

// protocolMACs — PROTOCOL §1 MAC list for non-AEAD (the ETM pair). Order
// matches §1.
var protocolMACs = []string{
	ssh.HMACSHA512ETM,
	ssh.HMACSHA256ETM,
}

// protocolHostKeyAlgos — PROTOCOL §1 host-key algorithm list for the
// *client* side: clients advertise these as the set of host keys they
// will accept from a server; the server presents whatever it is
// configured with.
var protocolHostKeyAlgos = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoRSASHA512,
	ssh.KeyAlgoRSASHA256,
}

// KEX returns the PROTOCOL §1 KEX list. The returned slice is a defensive
// copy: callers may mutate it freely without touching the package-level
// policy. Mostly used by tests that want to assert the policy shape;
// product code should always reach for ApplyServerConfig /
// ApplyClientConfig instead.
func KEX() []string { return append([]string(nil), protocolKEX...) }

// Ciphers returns the PROTOCOL §1 cipher list (defensive copy).
func Ciphers() []string { return append([]string(nil), protocolCiphers...) }

// MACs returns the PROTOCOL §1 MAC list (defensive copy).
func MACs() []string { return append([]string(nil), protocolMACs...) }

// HostKeyAlgos returns the PROTOCOL §1 host-key algorithm list for the
// client side (defensive copy).
func HostKeyAlgos() []string { return append([]string(nil), protocolHostKeyAlgos...) }

// ApplyServerConfig mutates cfg in place so that the ordered PROTOCOL §1
// KEX, cipher and MAC lists are the only ones offered to clients. The
// server does not declare its own host key algorithms — clients restrict
// theirs via ApplyClientConfig, and the server presents whatever it is
// configured with (PROTOCOL §1: only ssh-ed25519/rsa-sha2-{512,256} are
// accepted by clients; x/crypto enforces that pairing).
func ApplyServerConfig(cfg *ssh.ServerConfig) {
	if cfg == nil {
		return
	}
	cfg.KeyExchanges = append([]string(nil), protocolKEX...)
	cfg.Ciphers = append([]string(nil), protocolCiphers...)
	cfg.MACs = append([]string(nil), protocolMACs...)
}

// ApplyClientConfig mutates cfg so its KeyExchanges/Ciphers/MACs and
// HostKeyAlgorithms are the PROTOCOL §1 ordered lists. Clients must use
// the same lists; PROTOCOL §5.2 forbids "library defaults" for the
// nested handshake.
func ApplyClientConfig(cfg *ssh.ClientConfig) {
	if cfg == nil {
		return
	}
	cfg.KeyExchanges = append([]string(nil), protocolKEX...)
	cfg.Ciphers = append([]string(nil), protocolCiphers...)
	cfg.MACs = append([]string(nil), protocolMACs...)
	cfg.HostKeyAlgorithms = append([]string(nil), protocolHostKeyAlgos...)
}
