package gateway

// iamt348_live_seam_test.go — the whole reverse direction, over a real
// SSH connection, with nothing faked on either side.
//
// This wave produced two blocking defects of the same kind, one after
// the other: the gateway read a flat `sessionId` the machine never sent
// (IAMT-344), and there was no way at all for a machine to learn the id
// it had to send (IAMT-345). Both halves were green throughout. The
// reason is worth stating plainly, because it is a property of the tests
// and not of the code: the machine's own "real round trip" test spoke to
// a fake gateway that decoded the request WITH THE SAME STRUCT the
// machine encodes it with, and the gateway's own tests called its
// command function directly, bypassing the decoder entirely. Each side
// was measured against its own model of the other. A fake built from one
// side's model cannot disprove that model.
//
// So this file has no fake in it. A real *server.Machine dials a real
// *Gateway over real SSH, opens a real control channel, and asks the two
// questions a person's window asks. If either end ever drifts from the
// protocol again, this is what goes red — at the seam, where the drift
// actually lives.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/server"
)

// dialRealMachine brings up a real machine role against the fixture's
// gateway: real Dial, real SSH auth, real control channel. Only the
// target sshd is a loopback stand-in, and this test never opens a door,
// so nothing about the machinery under test is simulated.
func dialRealMachine(t *testing.T, f *fixture) *server.Machine {
	t.Helper()
	cfg := iamt198ServerConfig(t, f.addr, fingerprintOf(t, f.gw.cfg.HostKey.PublicKey()), f.machineKey)
	cfg.MachineID = f.machineID

	ctx, cancel := context.WithCancel(context.Background())
	m, err := server.Dial(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatalf("the real machine could not dial the real gateway: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = m.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	})

	// Serve publishes the control channel a few instructions after the
	// connection is up; asking before that would fail for a reason that
	// has nothing to do with what these tests are about.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ctxProbe, cancelProbe := context.WithTimeout(context.Background(), time.Second)
		_, err := m.MineSessions(ctxProbe)
		cancelProbe()
		if err == nil {
			return m
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the machine's control channel never became usable")
	return nil
}

// TestIAMT348_AMachineAsksForItsSessionsAndThenWatchesOne is the path a
// person's window walks, end to end: learn what is happening on this
// machine, then follow it. Every byte below crosses a real wire.
//
// Canary: change either end's idea of the wire — for instance give
// controlInbound back a flat `sessionId` field and read that, which is
// exactly the IAMT-344 defect — and this goes red where the id is
// checked, because the request really is encoded by the machine and
// really is decoded by the gateway.
func TestIAMT348_AMachineAsksForItsSessionsAndThenWatchesOne(t *testing.T) {
	f := newFixture(t, nil)
	m := dialRealMachine(t, f)

	// A session, and a recording being written for it — the state a live
	// view exists to look at.
	sess, err := f.gw.aclE.OpenSession(f.person, f.machineID, f.clock.Now(), func(acl.DenyReason) {})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	castPath := filepath.Join(t.TempDir(), "live.cast")
	const castBody = "{\"version\":2,\"width\":80,\"height\":24}\n[0.5,\"o\",\"hello from the session\\r\\n\"]\n"
	if err := os.WriteFile(castPath, []byte(castBody), 0o600); err != nil {
		t.Fatalf("writing the fixture recording: %v", err)
	}
	f.gw.live.add(sess.ID.String(), castPath, f.machineID)
	t.Cleanup(func() { f.gw.live.remove(sess.ID.String()) })

	// 1. What is happening on me?
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	list, err := m.MineSessions(ctx)
	if err != nil {
		t.Fatalf("the machine could not ask what its own sessions are: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("the machine was told about %d sessions, want 1 — with no id it has nothing to watch, which is the state every window was in before IAMT-345", len(list))
	}
	if list[0].ID != sess.ID.String() {
		t.Fatalf("session id over the wire = %q, want the gateway's own %q", list[0].ID, sess.ID.String())
	}

	// 2. Show me it. The id used here is the one that came back above —
	// nothing in this test invents one, exactly as nothing in the
	// product may.
	answer, err := m.Tail(ctx, server.TailRequest{SessionID: list[0].ID, Offset: 0, Limit: 4096})
	if err != nil {
		t.Fatalf("the machine could not fetch the tail: %v", err)
	}
	if answer.Refusal != nil {
		t.Fatalf("the gateway refused a tail for a session on the asking machine: %s — %s (this is the IAMT-344 symptom: the id the gateway read was not the id the machine sent)", answer.Refusal.Code, answer.Refusal.Message)
	}

	var body struct {
		ID    string `json:"id"`
		Total uint64 `json:"total"`
		Live  bool   `json:"live"`
		Data  string `json:"data"`
	}
	if err := json.Unmarshal(answer.Result, &body); err != nil {
		t.Fatalf("the answer body does not decode: %v", err)
	}
	if !body.Live {
		t.Error("the answer says the session is not live, but it is registered as a live recording")
	}
	raw, err := base64.StdEncoding.DecodeString(body.Data)
	if err != nil {
		t.Fatalf("data is not valid base64: %v", err)
	}
	if string(raw) != castBody {
		t.Fatalf("the bytes that came back are not the bytes on disk:\n got %q\nwant %q", raw, castBody)
	}
}

// TestIAMT348_AMachineCannotWatchAnotherMachinesSession is the access
// rule over the same real wire. It is the one property of this direction
// that must hold even if everything else drifts: the identity is the
// SSH layer's, and nothing the request says about itself is trusted.
func TestIAMT348_AMachineCannotWatchAnotherMachinesSession(t *testing.T) {
	f := newFixture(t, nil)
	m := dialRealMachine(t, f)

	// A session on a DIFFERENT machine, with a recording that exists.
	// The asking machine must learn nothing about it — not its bytes,
	// and not even that it is there.
	const other = "someone-elses-session"
	castPath := filepath.Join(t.TempDir(), "other.cast")
	if err := os.WriteFile(castPath, []byte("{\"version\":2}\n[0.1,\"o\",\"secret\\r\\n\"]\n"), 0o600); err != nil {
		t.Fatalf("writing the fixture recording: %v", err)
	}
	f.gw.live.add(other, castPath, "somebody-else")
	t.Cleanup(func() { f.gw.live.remove(other) })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	answer, err := m.Tail(ctx, server.TailRequest{SessionID: other, Offset: 0, Limit: 4096})
	if err != nil {
		t.Fatalf("Tail: %v", err)
	}
	if answer.Refusal != nil {
		t.Fatalf("a foreign session was refused with %s instead of being answered as absent — the shape of the reply now tells the asker that the session exists", answer.Refusal.Code)
	}
	var body struct {
		Live bool   `json:"live"`
		Data string `json:"data"`
	}
	if err := json.Unmarshal(answer.Result, &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Live || body.Data != "" {
		t.Fatalf("a machine was shown a session belonging to somebody else: live=%v, %d bytes", body.Live, len(body.Data))
	}
}
