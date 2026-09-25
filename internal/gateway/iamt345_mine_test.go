package gateway

// iamt345_mine_test.go — the machine asks what its own sessions are
// called (IAMT-345).
//
// This is the question that has to be answerable before a tail can be
// asked at all. The id of a session is minted here, on the gateway; the
// machine never sees it, because the tunnel between them carries a
// nested SSH session whose bytes the machine forwards without being able
// to read them. Until this operation existed the window filled the hole
// by inventing an id out of the person's name, the gateway answered —
// correctly — that no such session was live, and the owner watched an
// empty terminal while somebody really was working on his computer.

import (
	"encoding/json"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/proto"
)

func mineLine(t *testing.T) controlInbound {
	t.Helper()
	raw, err := json.Marshal(proto.TailEnvelope{
		Proto: 1,
		Caps:  []string{},
		ID:    "00000000-0000-4000-8000-000000000345",
		Op:    proto.OpSessionsMine,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var in controlInbound
	if err := json.Unmarshal(raw, &in); err != nil {
		t.Fatalf("the gateway cannot decode the line the machine writes: %v", err)
	}
	return in
}

func mineSessions(t *testing.T, resp controlResponse) []proto.MineSession {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("sessions.mine was refused: %s — %s", resp.Error.Code, resp.Error.Message)
	}
	var out proto.MineResult
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		t.Fatalf("the answer body does not decode: %v", err)
	}
	return out.Sessions
}

// TestIAMT345_AMachineLearnsTheIdsOfItsOwnSessions is the whole point:
// the id that comes back must be the one the gateway really minted, so
// that feeding it straight into sessions.tail finds the recording.
//
// Canary: in mineForMachine, build MineSession with anything other than
// s.ID.String() (for instance s.Person, which is what the window used to
// invent). This goes red naming the id it got.
func TestIAMT345_AMachineLearnsTheIdsOfItsOwnSessions(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	sess, err := f.gw.aclE.OpenSession(f.person, f.machineID, f.clock.Now(), func(acl.DenyReason) {})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	mc := &machineConn{id: f.machineID, g: f.gw}
	got := mineSessions(t, mc.mineForMachine(mineLine(t)))

	if len(got) != 1 {
		t.Fatalf("the machine was told about %d of its sessions, want 1 — with no list it has no id to ask a tail about, and the live view shows an empty terminal over a running session", len(got))
	}
	if got[0].ID != sess.ID.String() {
		t.Errorf("session id = %q, want the id the gateway minted, %q — an id that is not the gateway's own finds no recording, which is exactly the empty terminal this operation exists to end", got[0].ID, sess.ID.String())
	}
	if got[0].Person != f.person {
		t.Errorf("person = %q, want %q", got[0].Person, f.person)
	}
	if got[0].Started == "" {
		t.Error("started is empty: a person choosing between two sessions has nothing to choose by")
	}
}

// TestIAMT345_AMachineIsToldNothingAboutAnotherMachinesSessions pins the
// access rule. It is the tail's rule, unchanged: the list is built from
// the identity the SSH layer established, never from anything the
// request says about itself. A machine with no sessions and a machine
// asking about somebody else's must get the same empty answer, so that
// the shape of the reply never reveals that a session exists elsewhere.
//
// Canary: drop the `if s.Machine != mc.id { continue }` guard in
// mineForMachine — this goes red with the neighbour's session in hand.
func TestIAMT345_AMachineIsToldNothingAboutAnotherMachinesSessions(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	if _, err := f.gw.aclE.OpenSession(f.person, f.machineID, f.clock.Now(), func(acl.DenyReason) {}); err != nil {
		t.Fatalf("OpenSession: %v", err)
	}

	// A DIFFERENT machine asks.
	mc := &machineConn{id: "laptop", g: f.gw}
	got := mineSessions(t, mc.mineForMachine(mineLine(t)))

	if len(got) != 0 {
		t.Fatalf("a machine was told about %d session(s) belonging to another machine: %+v — the whole access rule of this direction is that a machine learns about its own guests and nobody else's", len(got), got)
	}
}
