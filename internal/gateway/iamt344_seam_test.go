package gateway

// iamt344_seam_test.go — the test that was missing, and whose absence is
// the whole reason IAMT-344 existed.
//
// Both halves of the live view were green on their own. The machine's
// own round-trip test was a REAL SSH connection carrying REAL JSON — and
// it still could not see the defect, because the fake gateway inside it
// decoded the request with the same struct the machine encodes it with.
// A fixture written from one side's model of the wire agrees with that
// model, including where the model is wrong.
//
// So this file crosses the seam the other way: it takes the bytes the
// MACHINE really writes and feeds them to the decoder the GATEWAY really
// uses, with nothing in between that either author invented. Since
// IAMT-344 both ends share one declaration (internal/proto), so the
// shapes can no longer drift apart silently; this pins the behaviour
// that declaration is there to protect.

import (
	"encoding/json"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/proto"
)

// machineTailLine is the exact line internal/server/tail.go puts on the
// control channel: the §5.1 envelope with the tail body nested inside
// it. It is built from the shared declaration, which is what the machine
// marshals, rather than hand-written here — a hand-written copy would be
// a third opinion about the wire, and three opinions are worse than two.
func machineTailLine(t *testing.T, sessionID string, offset uint64, limit uint32) []byte {
	t.Helper()
	raw, err := json.Marshal(proto.TailEnvelope{
		Proto: 1,
		Caps:  []string{},
		ID:    "00000000-0000-4000-8000-000000000344",
		Op:    proto.OpSessionsTail,
		Tail:  &proto.TailReq{Proto: 1, ID: sessionID, Offset: offset, Limit: limit},
	})
	if err != nil {
		t.Fatalf("marshalling the machine's own request: %v", err)
	}
	return raw
}

// TestIAMT344_TheGatewayReadsTheSessionIdTheMachineActuallySends.
//
// Canary: give controlInbound back its flat `SessionID string
// json:"sessionId"` and read that instead of in.Tail.ID. The line still
// decodes — Go ignores unknown fields, which is exactly why this went
// unnoticed — the id comes out empty, and the refusal below names it.
func TestIAMT344_TheGatewayReadsTheSessionIdTheMachineActuallySends(t *testing.T) {
	const sessionID = "1758191525000000000-alice-pc1"

	var in controlInbound
	if err := json.Unmarshal(machineTailLine(t, sessionID, 4096, 11520), &in); err != nil {
		t.Fatalf("the gateway cannot even decode the line the machine writes: %v", err)
	}

	if in.Op != proto.OpSessionsTail {
		t.Fatalf("op = %q, want %q — the gateway would not even recognise this as a request", in.Op, proto.OpSessionsTail)
	}
	if in.Tail == nil {
		t.Fatal("the tail body did not survive decoding: the gateway is reading a shape the machine does not write, and because unknown JSON fields are ignored it fails silently instead of loudly")
	}
	if in.Tail.ID != sessionID {
		t.Fatalf("session id = %q, want %q — every request a person makes to watch his own machine is refused as E_JSON_INVALID for a session id that was on the wire all along", in.Tail.ID, sessionID)
	}
	if in.Tail.Offset != 4096 {
		t.Errorf("offset = %d, want 4096", in.Tail.Offset)
	}
	if in.Tail.Limit != 11520 {
		t.Errorf("limit = %d, want 11520", in.Tail.Limit)
	}

	// The envelope id and the session id are different fields and must
	// not be confused for one another: the answer is routed by the
	// former and the recording is chosen by the latter.
	if in.ID == in.Tail.ID {
		t.Error("the envelope uuid and the session id decoded to the same value — they are two different fields (PROTOCOL §5.1)")
	}
}

// TestIAMT344_AWellFormedTailIsNotRefusedForItsShape checks the half
// that a decoding test alone would miss: the validation in
// tailForMachine must accept what the machine really sends. A machine
// that is not registered owns no session, so the answer here is the
// deliberate "not live" one — but it must be that answer, and never a
// complaint about the request's form.
func TestIAMT344_AWellFormedTailIsNotRefusedForItsShape(t *testing.T) {
	var in controlInbound
	if err := json.Unmarshal(machineTailLine(t, "1758191525000000000-alice-pc1", 0, 11520), &in); err != nil {
		t.Fatalf("decode: %v", err)
	}

	f := newFixture(t, nil)
	mc := &machineConn{id: "pc1", g: f.gw}
	resp := mc.tailForMachine(in)

	if resp.Error != nil {
		t.Fatalf("a request in the protocol's own shape was refused: %s — %s", resp.Error.Code, resp.Error.Message)
	}
	if !resp.OK {
		t.Fatal("the answer is neither ok nor an error")
	}
}
