package events

// F-03 (round-1 review, 24.09.2026): auth.failure's validator demands
// both an address and a fingerprint (§3.5), so a refusal that happened
// before any key was offered could not be written at all - AuthDenied
// dropped it instead. The fingerprint-less auth.handshake_failure type
// closes that gap: the validator must accept it with an address and no
// fingerprint (the absence is the very fact the type records), and must
// still refuse it without an address - an attempt you cannot correlate to
// a host is noise, not evidence.

import (
	"errors"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
)

func TestR1CX_F03_HandshakeFailureValidatesWithAnAddressAndNoFingerprint(t *testing.T) {
	base, _ := state.ParseZonedTime("2026-09-24T12:00:00Z")
	e := Event{
		Time:    base,
		Type:    EventType("auth.handshake_failure"),
		Actor:   "127.0.0.1:52344",
		Object:  "127.0.0.1:52344",
		Result:  "handshake or key authentication failed",
		Address: "127.0.0.1:52344",
	}
	if err := e.Validate(); err != nil {
		t.Fatalf("a fingerprint-less handshake failure with an address did not validate: %v - the type exists to record exactly this shape (F-03)", err)
	}
}

func TestR1CX_F03_HandshakeFailureWithoutAnAddressIsRejected(t *testing.T) {
	base, _ := state.ParseZonedTime("2026-09-24T12:00:00Z")
	e := Event{
		Time:   base,
		Type:   EventType("auth.handshake_failure"),
		Result: "handshake or key authentication failed",
	}
	err := e.Validate()
	if err == nil {
		t.Fatal("a handshake failure without an address validated - an attempt no host can be correlated to is noise, not evidence (F-03)")
	}
	if !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("refusing an addressless handshake failure answered %v, want an ErrInvalidEvent (F-03)", err)
	}
}
