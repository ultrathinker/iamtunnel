package server

import "testing"

// Probe for the IAMT-87 acceptance.
//
// doorIDPattern was narrowed from [0-9a-fA-F] to [0-9a-f], and the
// narrowing was essentially right: PROTOCOL §1.1 defines the `uuid`
// type as "an RFC 4122 UUID in lowercase", so the previous expression
// accepted what the protocol does not allow. But during acceptance the
// expression was reverted to [0-9a-fA-F] and the whole package run —
// not a single test went red. In other words, the narrowing was correct
// and yet held by nothing: any future edit would have widened it
// silently.
//
// There are two assertions here, and they hold exactly both places where
// this expression now applies: the door identifier in door.open and the
// envelope's own `id`.
func TestOrchProbe_UpperCaseUUIDIsNotAUUID(t *testing.T) {
	// The same UUID in two cases. Lowercase must pass, uppercase must
	// not; otherwise the assertion is checking something other than
	// case.
	const lower = "0b9e3f2a-6c1d-4e7a-9b3d-1a2b3c4d5e6f"
	const upper = "0B9E3F2A-6C1D-4E7A-9B3D-1A2B3C4D5E6F"

	if !validControlRequestID(lower) {
		t.Fatalf("PROTOCOL §1.1: lowercase uuid %q must be accepted", lower)
	}
	if validControlRequestID(upper) {
		t.Fatalf("PROTOCOL §1.1: the uuid type is defined in lowercase, but %q was accepted", upper)
	}

	// Mixed case, and uppercase in each of the five groups individually:
	// this shows the check covers the whole string, not just its start.
	for _, id := range []string{
		"0B9e3f2a-6c1d-4e7a-9b3d-1a2b3c4d5e6f",
		"0b9e3f2a-6C1d-4e7a-9b3d-1a2b3c4d5e6f",
		"0b9e3f2a-6c1d-4E7a-9b3d-1a2b3c4d5e6f",
		"0b9e3f2a-6c1d-4e7a-9B3d-1a2b3c4d5e6f",
		"0b9e3f2a-6c1d-4e7a-9b3d-1a2b3c4d5e6F",
	} {
		if validControlRequestID(id) {
			t.Fatalf("PROTOCOL §1.1: %q contains uppercase hex and is not a uuid, but was accepted", id)
		}
	}
}

// The same case check, but through a real parse of a control-channel
// string rather than a single function: this way the assertion stays
// valid even if the envelope check is someday moved elsewhere.
func TestOrchProbe_UpperCaseEnvelopeIDRefusedByDecoder(t *testing.T) {
	const lower = `{"proto":1,"caps":[],"id":"0b9e3f2a-6c1d-4e7a-9b3d-1a2b3c4d5e6f","op":"door.status"}`
	const upper = `{"proto":1,"caps":[],"id":"0B9E3F2A-6C1D-4E7A-9B3D-1A2B3C4D5E6F","op":"door.status"}`

	if _, err := decodeControlRequest([]byte(lower), DefaultControlJSONDepth); err != nil {
		t.Fatalf("an object with a lowercase uuid must parse, got: %v", err)
	}
	if req, err := decodeControlRequest([]byte(upper), DefaultControlJSONDepth); err == nil {
		t.Fatalf("PROTOCOL §5.1: an envelope with an uppercase id must be refused, was accepted as %+v", req)
	}
}
