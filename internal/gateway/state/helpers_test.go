package state_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

// The tests use real SSH wire-format public keys, not "ssh-ed25519 AAAA...": since the
// fingerprint is computed from the decoded blob, a key that does not decode is no
// longer a key at all, and a test built on a fake one would be testing nothing.

// edBlob builds the base64 body of an ed25519 public key that is unique for the tag.
func edBlob(tag byte) string {
	const name = "ssh-ed25519"
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(name)))
	buf.WriteString(name)
	key := make([]byte, 32)
	for i := range key {
		key[i] = tag*7 + byte(i)
	}
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(key)))
	buf.Write(key)
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

// edPub returns a full authorized_keys line for the key identified by tag.
func edPub(tag byte) string {
	return "ssh-ed25519 " + edBlob(tag)
}

// fpOf returns the fingerprint of a public key line, failing the test if it is not one.
func fpOf(t *testing.T, pub string) string {
	t.Helper()
	fp, err := state.ComputeFingerprint(pub)
	if err != nil {
		t.Fatalf("ComputeFingerprint(%q): %v", pub, err)
	}
	return fp
}

// zt parses an ISO-8601 timestamp or fails the test.
func zt(t *testing.T, s string) state.ZonedTime {
	t.Helper()
	parsed, err := state.ParseZonedTime(s)
	if err != nil {
		t.Fatalf("ParseZonedTime(%q): %v", s, err)
	}
	return parsed
}

// zRel returns a timestamp at the given offset from the current time, for fixtures
// whose validity depends on the clock rather than on a fixed date: a deadline one
// hour ahead must stay ahead for as long as the suite exists, which a hardcoded
// "2026-09-12T..." cannot promise.
func zRel(t *testing.T, d time.Duration) state.ZonedTime {
	t.Helper()
	return state.NewZonedTime(time.Now().UTC().Add(d).Truncate(time.Second))
}

// personWith builds a person owning a single key, with the fingerprint derived from
// that key - the only combination the model accepts.
func personWith(t *testing.T, name, role string, tag byte) state.Person {
	t.Helper()
	pub := edPub(tag)
	return state.Person{
		Name: name,
		Role: role,
		Keys: []state.Key{{Fingerprint: fpOf(t, pub), Pub: pub, Added: zt(t, "2026-09-12T10:00:00Z")}},
	}
}

// machineWith builds a verified machine holding the key identified by tag.
func machineWith(id, name string, tag byte) state.Machine {
	return state.Machine{
		ID:         id,
		Name:       name,
		State:      "verified",
		MachineKey: edPub(tag),
		OSUser:     `CORP\svc`,
	}
}

// grantOn builds a grant pinned to the current key of the machine with that id.
func grantOn(t *testing.T, st *state.State, person, machineID string) state.Grant {
	t.Helper()
	m, ok := st.MachineByID(machineID)
	if !ok {
		t.Fatalf("grantOn: no machine %q in state", machineID)
	}
	return state.Grant{
		Person:                person,
		Machine:               machineID,
		MachineKeyFingerprint: fpOf(t, m.MachineKey),
		Caps:                  []string{"shell"},
	}
}

// baseState is the state every referential-integrity test starts from:
// alice (admin) holds a grant on machine vm1.
func baseState(t *testing.T) state.State {
	t.Helper()
	st := state.NewState()
	st.People = []state.Person{personWith(t, "alice", "admin", 1)}
	st.Machines = []state.Machine{machineWith("vm1", "vm1", 2)}
	st.Grants = []state.Grant{grantOn(t, st, "alice", "vm1")}
	if err := st.Validate(); err != nil {
		t.Fatalf("baseState is not valid: %v", err)
	}
	return *st
}
