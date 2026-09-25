package client

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/datafile"
)

// knownHostsFile is the client's own, isolated host-key record (SPEC §3.1,
// PROTOCOL §3.1). It exists purely as a local audit trail of what was
// verified and when; it is never consulted to decide trust. Trust comes
// from exactly one place: the fingerprint pinned in the saved connection
// string (SPEC §2, "nowhere is there TOFU").
// This is deliberately stronger than SPEC's own wording, which still
// describes a known_hosts file ssh.exe would read for trust — this build
// embeds the SSH client instead of shelling out, so there is no second,
// file-based trust decision to keep in sync with the pin at all.
const knownHostsFile = "known_hosts"

// KnownHostsPath returns the path this package's HostKeyCallback records
// verified keys to inside dir. It is always dir-derived: this function
// never reads an environment variable or a user profile path, so it can
// never resolve to the real ~/.ssh/known_hosts by construction, not just
// by convention.
func KnownHostsPath(dir string) string { return filepath.Join(dir, knownHostsFile) }

// ErrFingerprintMismatch classifies the one refusal PROTOCOL §3.1 names by
// text: "The gateway's key fingerprint has changed." Callers use
// errors.As to detect it without string-matching the message.
type ErrFingerprintMismatch struct {
	Want, Got string
}

func (e *ErrFingerprintMismatch) Error() string {
	return fmt.Sprintf("the gateway host-key fingerprint changed: expected %s, got %s — obtain a new connection string from the administrator", e.Want, e.Got)
}

// pinnedHostKeyCallback returns a ssh.HostKeyCallback that accepts exactly
// one key: the one whose SHA-256 fingerprint equals pinned. Every other
// key — including one that used to match, in a rotated-gateway scenario —
// is refused before the handshake completes, so no channel is ever opened
// and no byte of the session is ever attempted — zero attempts to
// continue. On success it best-effort records the key into
// knownHostsPath; a failure to write that record does not fail the
// connection, since the security decision above already happened without
// consulting the file.
func pinnedHostKeyCallback(pinned, knownHostsPath string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		got := ssh.FingerprintSHA256(key)
		if got != pinned {
			return &ErrFingerprintMismatch{Want: pinned, Got: got}
		}
		_ = recordKnownHost(knownHostsPath, hostname, key)
		return nil
	}
}

// recordKnownHost appends (or refreshes) one line for hostname in the
// isolated known_hosts file: the line before it, if for the same host, is
// dropped rather than duplicated, mirroring OpenSSH's own known_hosts
// convention closely enough for the file to be human-readable — but never
// parsed back for a trust decision by this package.
//
// Both halves go through the datafile contract (IAMT-332 round 9): the
// read is datafile.ReadFile, so a symlink or FIFO planted at the name is
// refused instead of being read through or wedged on (this writer runs on
// EVERY successful connection, including from a privileged run aimed at
// the directory — SPEC §3.1); the write is WriteFileAtomic, never the
// flat path+".tmp" this function used before round 9, which a planted
// link could aim the rewrite at. A missing name stays os.ErrNotExist, so
// the first connection's create branch is unchanged, and the caller
// treats every error as best-effort, as before.
func recordKnownHost(path, hostname string, key ssh.PublicKey) error {
	line := hostname + " " + string(ssh.MarshalAuthorizedKey(key))
	// MarshalAuthorizedKey ends with "\n" already.
	existing, err := datafile.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	var kept []byte
	for _, l := range splitKeepNL(existing) {
		if hasHostPrefix(l, hostname) {
			continue
		}
		kept = append(kept, l...)
	}
	kept = append(kept, []byte(line)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return datafile.WriteFileAtomic(path, kept, datafile.WithMode(0o600))
}

func splitKeepNL(b []byte) [][]byte {
	var out [][]byte
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, b[start:i+1])
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, b[start:])
	}
	return out
}

func hasHostPrefix(line []byte, hostname string) bool {
	prefix := hostname + " "
	return len(line) >= len(prefix) && string(line[:len(prefix)]) == prefix
}
