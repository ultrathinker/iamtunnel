package state_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// TestFinding02_HostKeyVerdictAndObservationAreConsistent describes the
// invariant required for persisted IAMT-91 memory, not merely the enum
// membership already checked by Validate.
func TestFinding02_HostKeyVerdictAndObservationAreConsistent(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*state.Machine)
	}{
		{
			name: "mismatch_without_observed_key",
			mutate: func(m *state.Machine) {
				m.HostKeyStatus = state.HostKeyStatusMismatch
				m.ObservedSSHDHostKey = nil
			},
		},
		{
			name: "mismatch_without_pinned_key",
			mutate: func(m *state.Machine) {
				observed := edPub(43)
				m.SSHDHostKey = nil
				m.ObservedSSHDHostKey = &observed
				m.HostKeyStatus = state.HostKeyStatusMismatch
			},
		},
		{
			name: "match_without_observed_key",
			mutate: func(m *state.Machine) {
				m.HostKeyStatus = state.HostKeyStatusMatch
				m.ObservedSSHDHostKey = nil
			},
		},
		{
			name: "match_with_key_different_from_pin",
			mutate: func(m *state.Machine) {
				pinned, observed := edPub(40), edPub(41)
				m.SSHDHostKey = &pinned
				m.ObservedSSHDHostKey = &observed
				m.HostKeyStatus = state.HostKeyStatusMatch
			},
		},
		{
			name: "unverified_with_observed_key",
			mutate: func(m *state.Machine) {
				observed := edPub(42)
				m.ObservedSSHDHostKey = &observed
				m.HostKeyStatus = state.HostKeyStatusUnverified
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := baseState(t)
			tc.mutate(&st.Machines[0])
			if err := st.Validate(); err == nil {
				t.Fatalf("F-02: Validate accepted %s; a persisted host-key verdict must agree with the observed key and (for match) the pinned key", tc.name)
			}
		})
	}
}

// rsaHostKeyLinesWithDifferentBase64Padding returns the same SSH wire blob in
// two base64 spellings. StdEncoding accepts the non-zero trailing pad bits in
// the second spelling and decodes both strings to the same bytes.
func rsaHostKeyLinesWithDifferentBase64Padding() (string, string) {
	const algorithm = "ssh-rsa"
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	var blob bytes.Buffer
	_ = binary.Write(&blob, binary.BigEndian, uint32(len(algorithm)))
	blob.WriteString(algorithm)
	exponent := []byte{1, 0, 1}
	_ = binary.Write(&blob, binary.BigEndian, uint32(len(exponent)))
	blob.Write(exponent)
	modulus := make([]byte, 256)
	for i := range modulus {
		modulus[i] = byte(i + 1)
	}
	_ = binary.Write(&blob, binary.BigEndian, uint32(len(modulus)))
	blob.Write(modulus)

	canonical := base64.StdEncoding.EncodeToString(blob.Bytes())
	padBitIndex := strings.IndexByte(alphabet, canonical[len(canonical)-2])
	variant := canonical[:len(canonical)-2] + string(alphabet[padBitIndex+1]) + canonical[len(canonical)-1:]
	return algorithm + " " + canonical, algorithm + " " + variant
}

func TestFinding02_MatchAcceptsEquivalentKeyFormatting(t *testing.T) {
	st := baseState(t)
	pinned, observed := rsaHostKeyLinesWithDifferentBase64Padding()
	observed = "\tssh-rsa\t" + strings.TrimPrefix(observed, "ssh-rsa ") + "\tkey-comment  "
	st.Machines[0].SSHDHostKey = &pinned
	st.Machines[0].ObservedSSHDHostKey = &observed
	st.Machines[0].HostKeyStatus = state.HostKeyStatusMatch

	if err := st.Validate(); err != nil {
		t.Fatalf("F-02: Validate rejected equivalent formatting of the same host key: %v", err)
	}
}

// TestFinding03_EmptyHostKeyStatusToleratesObservedKey preserves the legacy
// in-memory compatibility promised by Validate: an empty status is not yet a
// verdict, so a valid observed key must not make the record invalid merely
// because the status field has not been filled by a disk boundary.
func TestFinding03_EmptyHostKeyStatusToleratesObservedKey(t *testing.T) {
	st := baseState(t)
	observed := edPub(42)
	st.Machines[0].HostKeyStatus = ""
	st.Machines[0].ObservedSSHDHostKey = &observed

	if err := st.Validate(); err != nil {
		t.Fatalf("empty hostKeyStatus must tolerate a valid observed SSHD host key: %v", err)
	}
}
