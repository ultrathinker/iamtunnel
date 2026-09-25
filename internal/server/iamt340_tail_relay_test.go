package server

// iamt340_tail_relay_test.go — IAMT-340, the machine's half of the live
// view: a "tail" leaves this machine over the control channel and the
// gateway's answer comes back, and neither of them is touched on the way
// through.
//
// Every test here is a REAL round trip: a real SSH connection to the
// fakeGateway fixture (testhelpers_test.go), a real iamtunnel-control
// channel, real JSON on the wire. The gateway's side is played by the
// fixture rather than by the production gateway package, which is the
// point — this file pins what the MACHINE writes and what it does with
// what comes back, and it does so without the gateway's own
// sessions.tail existing, exactly as the contract's §3 asks (that half
// is IAMT-338's).
//
// The reply lines below are hand-written byte strings, not marshalled
// from this package's own structs. A test that builds its expectation
// with the same struct the code under test decodes with would agree with
// any mistake that struct makes; raw strings pin the wire itself.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// tailFixture is one machine talking to a fake gateway's control channel.
type tailFixture struct {
	t    *testing.T
	m    *Machine
	gw   *fakeGateway
	ctrl ssh.Channel

	// lines carries whatever the machine writes on the control channel,
	// one entry per LF-terminated line. ssh.Channel has no read
	// deadline, so the read lives in its own goroutine and the tests
	// put a bounded select in front of the channel instead: a test that
	// hangs must report itself, not stall the suite. The goroutine ends
	// when the fixture closes the connection (fakeGateway.close).
	lines chan []byte
}

// newTailFixture dials a machine and opens the one control channel, with
// Serve running in the background.
//
// The keepalive is stretched to minutes for this file only. It has to
// be: fakeGateway answers global requests with `ssh.DiscardRequests`,
// which replies FAILURE, and PROTOCOL §5 counts a failure reply as a
// missed probe — so with this package's usual 200ms/3 test interval the
// tunnel is declared dead about 600ms in, which is shorter than the
// relay timeout one of these tests deliberately waits out. Nothing in
// the product reads this value; it is the fake's own pacing.
func newTailFixture(t *testing.T) *tailFixture {
	t.Helper()
	return newTailFixtureWith(t, nil)
}

// newTailFixtureWith is newTailFixture with a hand on the config before
// the machine is dialled. A test that wants an unusual setting must set
// it HERE and not on the running machine: Config is read by the serve
// goroutine from the moment Dial returns, so writing to it afterwards is
// a data race - one the race detector found in the first version of the
// tiny-line test, which reached into m.cfg of a live machine.
func newTailFixtureWith(t *testing.T, mod func(*Config)) *tailFixture {
	t.Helper()
	machineKey := mustSigner(t)
	gw := newFakeGateway(t, func(k ssh.PublicKey) bool { return true })
	gw.startAccept()

	cfg := testConfig(t, gw, machineKey, "127.0.0.1:1")
	cfg.Keepalive = sshx.Keepalive{Interval: 2 * time.Minute, MaxMisses: 3}
	if mod != nil {
		mod(&cfg)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	m, err := Dial(ctx, cfg)
	if err != nil {
		cancel()
		t.Fatalf("Dial: %v", err)
	}
	serveInBackground(t, ctx, cancel, m)

	ctrl := gw.openControl(t)
	f := &tailFixture{t: t, m: m, gw: gw, ctrl: ctrl, lines: make(chan []byte, 8)}
	go func() {
		r := bufio.NewReaderSize(ctrl, DefaultControlLineMax+1)
		for {
			line, err := r.ReadBytes('\n')
			if len(line) > 0 {
				f.lines <- line
			}
			if err != nil {
				close(f.lines)
				return
			}
		}
	}()

	// One door.status round trip before any test body runs. OpenChannel
	// returns when the MACHINE confirms the open, which its accept
	// handler does a few instructions before it publishes the channel to
	// Tail — so "the fake gateway has a control channel" is not yet "the
	// machine can send on it", and a tail fired into that window would
	// come back ErrNoControlChannel for a reason that has nothing to do
	// with what the test is about. A door.status answered on this channel
	// proves the read loop is running AND the writer is published, which
	// is exactly the state every test below wants to start from. The
	// request is a well-formed §5.1 door.status with a fixed id; whether
	// the door itself is installed is irrelevant here.
	const syncID = "00000000-0000-4000-8000-000000000340"
	if _, err := ctrl.Write([]byte(`{"proto":1,"caps":[],"id":"` + syncID + `","op":"door.status"}` + "\n")); err != nil {
		t.Fatalf("writing the fixture's door.status: %v", err)
	}
	line := f.readLine("door.status answer (fixture sync)")
	var resp controlResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("the fixture's door.status answer does not decode: %v (%q)", err, line)
	}
	if resp.ID != syncID {
		t.Fatalf("the fixture's door.status was answered with id %q, want %q", resp.ID, syncID)
	}
	return f
}

// readLine reads one LF-terminated line from the fake gateway's side of
// the control channel, failing the test rather than blocking forever.
// The bound is generous on purpose — everything in this file is local,
// so five seconds is enormous, and a hung test must report itself.
func (f *tailFixture) readLine(what string) []byte {
	f.t.Helper()
	select {
	case line, ok := <-f.lines:
		if !ok {
			f.t.Fatalf("the machine's control channel closed while waiting for %s", what)
		}
		return line
	case <-time.After(5 * time.Second):
		f.t.Fatalf("%s: nothing arrived on the machine's control channel within 5s", what)
		return nil
	}
}

// readTailRequest decodes the machine's outgoing line as the gateway
// would: the §5.1 envelope with a nested §1-shaped tail object.
func (f *tailFixture) readTailRequest() (controlTailRequest, string) {
	f.t.Helper()
	line := f.readLine("the tail request")
	var env controlTailRequest
	if err := json.Unmarshal(line, &env); err != nil {
		f.t.Fatalf("the machine's tail request does not decode as a control envelope: %v (line %q)", err, line)
	}
	if env.Tail == nil {
		f.t.Fatalf("the machine's tail request carries no tail object: %q", line)
	}
	return env, strings.TrimRight(string(line), "\n")
}

func (f *tailFixture) reply(line string) {
	f.t.Helper()
	// ssh.Channel carries no write deadline; a write here cannot block
	// for long in any case, because the machine's read loop is always
	// draining this direction (serveControl).
	if _, err := f.ctrl.Write([]byte(line)); err != nil {
		f.t.Fatalf("writing the gateway's reply: %v", err)
	}
}

// tailAnswer runs one Tail in its own goroutine and returns a channel
// with its outcome, so a test can drive the gateway's side of the
// exchange between the call and its answer.
type tailOutcome struct {
	answer TailAnswer
	err    error
}

func (f *tailFixture) tailAsync(req TailRequest) <-chan tailOutcome {
	f.t.Helper()
	out := make(chan tailOutcome, 1)
	go func() {
		a, err := f.m.Tail(context.Background(), req)
		out <- tailOutcome{answer: a, err: err}
	}()
	return out
}

func (f *tailFixture) await(out <-chan tailOutcome, what string) tailOutcome {
	f.t.Helper()
	select {
	case got := <-out:
		return got
	case <-time.After(10 * time.Second):
		f.t.Fatalf("%s did not return within 10s", what)
		return tailOutcome{}
	}
}

// ---- the number itself ---------------------------------------------------

// TestIAMT340_ChunkCeilingIsTheProtocolLineSolvedForLimit pins the
// arithmetic in the comment above TailChunkMax, so that "16 KiB minus the
// reserve, times three quarters" cannot quietly become something else.
//
// Canary: in TailChunkMax, swap the division by 4 and multiplication
// by 3 for a multiplication by 4 and division by 3 (i.e. take 4/3
// instead of 3/4) — turns "TailChunkMax = %d, want 11520 (16 KiB minus
// the reserve, ×3/4)" red.
func TestIAMT340_ChunkCeilingIsTheProtocolLineSolvedForLimit(t *testing.T) {
	if TailChunkMax != 11520 {
		t.Fatalf("TailChunkMax = %d, want 11520 (16 KiB minus the reserve, ×3/4)", TailChunkMax)
	}
	if got := tailChunkMaxFor(DefaultControlLineMax); got != TailChunkMax {
		t.Fatalf("tailChunkMaxFor(DefaultControlLineMax) = %d, want TailChunkMax = %d — the constant and the configured-limit path must be the same formula", got, TailChunkMax)
	}
}

// ---- 1. the request reaches the gateway unchanged ------------------------

// TestIAMT340_TailRequestReachesTheGatewayUnchanged is the first of the
// five claims required: what the caller asked for is what the
// gateway is asked, field for field, in §1's own shape.
//
// Canary: in Tail, replace `ID: req.SessionID` with `ID: ""` (or
// `Offset: req.Limit, Limit: uint32(req.Offset)`) — turns
// "tail request carried id %q offset %d limit %d, want %q/%d/%d" red.
func TestIAMT340_TailRequestReachesTheGatewayUnchanged(t *testing.T) {
	f := newTailFixture(t)
	const sid = "1758130000000000000-alice-vm1"
	out := f.tailAsync(TailRequest{SessionID: sid, Offset: 4096, Limit: 8192})

	env, _ := f.readTailRequest()
	if env.Op != tailOp {
		t.Fatalf("tail request op = %q, want %q (the name §1 gives the command)", env.Op, tailOp)
	}
	if env.Proto != 1 {
		t.Fatalf("tail request proto = %d, want 1", env.Proto)
	}
	if env.Caps == nil || len(env.Caps) != 0 {
		t.Fatalf("tail request caps = %v, want an empty array (PROTOCOL §5.1: v1 has no capabilities)", env.Caps)
	}
	// The envelope's own id is the correlation id, and PROTOCOL §5.1
	// requires it to be a uuid — validateControlRequestID is the same
	// check the gateway will apply to it.
	if !validControlRequestID(env.ID) {
		t.Fatalf("tail request envelope id = %q, want a lower-case RFC 4122 uuid", env.ID)
	}
	// And the question itself rides nested, in §1's shape, unmoved.
	if env.Tail.Proto != 1 || env.Tail.ID != sid || env.Tail.Offset != 4096 || env.Tail.Limit != 8192 {
		t.Fatalf("tail request carried id %q offset %d limit %d, want %q/%d/%d — the machine is a courier and must not rewrite the question",
			env.Tail.ID, env.Tail.Offset, env.Tail.Limit, sid, 4096, 8192)
	}
	// The session id must not have leaked into the envelope's id: they
	// are two different things, and a gateway correlating answers by a
	// session id would be reading a field §5.1 never defined that way.
	if env.ID == sid {
		t.Fatalf("the envelope id equals the session id (%q) — the correlation uuid and the session id are different fields", sid)
	}

	f.reply(`{"proto":1,"caps":[],"id":"` + env.ID + `","ok":true,"result":{"id":"` + sid + `","offset":4096,"total":4096,"live":true,"data":""}}` + "\n")
	got := f.await(out, "Tail")
	if got.err != nil {
		t.Fatalf("Tail: %v (the machine must not fail a request the gateway answered)", got.err)
	}
}

// ---- 2. the answer comes back unchanged ----------------------------------

// TestIAMT340_TailAnswerComesBackUnchanged hands the machine a §1 answer
// and demands the very same bytes back. Not "the same values": the same
// bytes. Anything this side did to the body — re-marshalling it,
// dropping an unknown field, trimming `data` — shows up here.
//
// Canary: in decodeTailAnswer, replace `Result: resp.Result` with
// `Result: mustJSON(map[string]any{"id": …})` (i.e. parse and
// reassemble the body) — turns "the answer came back as %q, want the
// gateway's own bytes %q" red.
func TestIAMT340_TailAnswerComesBackUnchanged(t *testing.T) {
	f := newTailFixture(t)
	const sid = "1758130000000000000-alice-vm1"
	out := f.tailAsync(TailRequest{SessionID: sid, Offset: 0, Limit: 1024})

	env, _ := f.readTailRequest()
	// The body is deliberately awkward: a field this side has no field
	// for ("machine"), a base64 payload with padding, and a total that
	// does not match offset+len(data). A courier that reconstructs the
	// body would drop, reorder or recompute one of them.
	const body = `{"id":"1758130000000000000-alice-vm1","offset":0,"total":81234,"live":true,"data":"AAECA/8=","machine":"vm1"}`
	f.reply(`{"proto":1,"caps":[],"id":"` + env.ID + `","ok":true,"result":` + body + `}` + "\n")

	got := f.await(out, "Tail")
	if got.err != nil {
		t.Fatalf("Tail: %v", got.err)
	}
	if got.answer.Refusal != nil {
		t.Fatalf("a successful answer came back as a refusal: %+v", got.answer.Refusal)
	}
	if string(got.answer.Result) != body {
		t.Fatalf("the answer came back as %q, want the gateway's own bytes %q — the machine is a courier and must not rewrite the answer", string(got.answer.Result), body)
	}
}

// ---- 3. the gateway's refusal is not replaced ----------------------------

// TestIAMT340_GatewayRefusalIsNotReplacedByTheMachine is the third claim:
// a refusal is the gateway's to state, and it arrives as the gateway
// stated it. The refusal is also not an ERROR here — server.Tail's error
// return is reserved for "this machine could not ask", so a caller can
// never mistake the gateway's no for the machine's own failure.
//
// Canary: in decodeTailAnswer, turn a refusal into an error (return
// `TailAnswer{}, fmt.Errorf("refused: %s", resp.Error.Code)`) — turns
// "Tail returned err … for a refusal — a refusal is the gateway's answer,
// not this machine's failure" red (and the next assertion about the
// code never runs).
func TestIAMT340_GatewayRefusalIsNotReplacedByTheMachine(t *testing.T) {
	f := newTailFixture(t)
	out := f.tailAsync(TailRequest{SessionID: "1758130000000000000-alice-vm1", Offset: 0, Limit: 1024})

	env, _ := f.readTailRequest()
	const code = "E_SESSION_DENIED"
	const message = "Access to this machine is currently unavailable."
	f.reply(`{"proto":1,"caps":[],"id":"` + env.ID + `","ok":false,"error":{"code":"` + code + `","message":"` + message + `"}}` + "\n")

	got := f.await(out, "Tail")
	if got.err != nil {
		t.Fatalf("Tail returned err %v for a refusal — a refusal is the gateway's answer, not this machine's failure", got.err)
	}
	if got.answer.Refusal == nil {
		t.Fatalf("Tail returned %q with no refusal — the gateway said no and this machine dropped it", string(got.answer.Result))
	}
	if got.answer.Refusal.Code != code || got.answer.Refusal.Message != message {
		t.Fatalf("refusal = %+v, want the gateway's own %s/%q — the machine must not restate the refusal in its own words",
			*got.answer.Refusal, code, message)
	}
	if len(got.answer.Result) != 0 {
		t.Fatalf("a refusal came back with a body too: %q", string(got.answer.Result))
	}
}

// ---- 5. someone else's session is refused BY THE GATEWAY -----------------

// TestIAMT340_AnotherMachinesSessionIsRefusedByTheGateway pins the shape
// of the access rule, not the rule itself: the machine does not screen
// session ids, does not know whose sessions are whose, and does not
// answer this one out of its own mouth. It asks the gateway (the fake
// sees the request arrive, id and all) and it hands back whatever the
// gateway says about it.
//
// The rule itself — "a machine reads only its own registration's
// sessions" — is checked by the gateway from the identity of the control
// channel, which is established by the SSH layer and is not a field in
// any body (contract §1). A machine that pre-empted it would be
// duplicating an authority it does not have; a machine that helpfully
// phrased the refusal would be inventing a verdict.
//
// Canary: add any local session check to Tail (for example
// `if !strings.HasPrefix(req.SessionID, m.cfg.MachineID) { return
// TailAnswer{Refusal: &TailRefusal{Code:"E_SESSION_DENIED"}}, nil }`) —
// turns "the tail request: nothing arrived on the machine's control
// channel within 5s" red: the request never reached the fake gateway,
// and the test's very first assertion — "the machine asked" — fails.
func TestIAMT340_AnotherMachinesSessionIsRefusedByTheGateway(t *testing.T) {
	f := newTailFixture(t)
	const foreign = "1758130000000000000-bob-other-machine"
	out := f.tailAsync(TailRequest{SessionID: foreign, Offset: 0, Limit: 1024})

	// The machine MUST have asked. Reading the request is the assertion;
	// if it never came, readTailRequest fails with the read timeout.
	env, rawLine := f.readTailRequest()
	if env.Tail.ID != foreign {
		t.Fatalf("the gateway was asked about %q, want the session the caller named (%q)", env.Tail.ID, foreign)
	}
	const code = "E_NOT_FOUND"
	f.reply(`{"proto":1,"caps":[],"id":"` + env.ID + `","ok":false,"error":{"code":"` + code + `","message":"no such session"}}` + "\n")

	got := f.await(out, "Tail")
	if got.err != nil {
		t.Fatalf("Tail returned err %v — the gateway answered, and its no is not this machine's failure", got.err)
	}
	if got.answer.Refusal == nil || got.answer.Refusal.Code != code {
		t.Fatalf("answer = %+v, want the gateway's own refusal %s passed through", got.answer, code)
	}
	// And nothing about this machine's identity was offered along with
	// it: contract §3 forbids "I am such-and-such a machine" in the body,
	// because the identity already came from the SSH layer. The line the
	// machine wrote is the whole of what it said.
	if strings.Contains(rawLine, f.m.cfg.MachineID) {
		t.Fatalf("the machine's own id (%q) appears in the request line — the gateway learns whose channel this is from the SSH layer, never from the body", f.m.cfg.MachineID)
	}
}

// ---- 4. an oversized limit is clamped, not fatal -------------------------

// TestIAMT340_LimitAboveTheCeilingIsClampedNotRefused asks for more than
// the wire can carry — both the §1 maximum and just over this side's
// ceiling — and requires a smaller question, not a refusal and not a torn
// control channel. Then it answers with a chunk that fills the ceiling
// exactly, which is the arithmetic proving itself: if TailChunkMax were a
// byte too generous, the answer would not fit one control line and this
// machine's own reader would refuse it (errLineTooLong) and tear the
// tunnel down.
//
// Canary: remove the `if limit > uint32(ceiling) { limit =
// uint32(ceiling) }` branch in Tail — turns "the machine asked the
// gateway for limit %d, want it clamped to %d" red; and if TailChunkMax
// is instead enlarged (for example, taking
// `DefaultControlLineMax/4*3` without subtracting the reserve) —
// turns "the full-size answer did not come back: …" red (the line
// did not fit in control, and the channel closed).
func TestIAMT340_LimitAboveTheCeilingIsClampedNotRefused(t *testing.T) {
	f := newTailFixture(t)

	for _, asked := range []uint32{1048576, TailChunkMax + 1, 4 * TailChunkMax} {
		out := f.tailAsync(TailRequest{SessionID: "1758130000000000000-alice-vm1", Offset: 0, Limit: asked})
		env, _ := f.readTailRequest()
		if env.Tail.Limit != TailChunkMax {
			t.Fatalf("the machine asked the gateway for limit %d, want it clamped to %d — an unclamped limit makes an answer this side's own reader would reject, taking the tunnel with it",
				env.Tail.Limit, TailChunkMax)
		}
		f.reply(`{"proto":1,"caps":[],"id":"` + env.ID + `","ok":true,"result":{"id":"1758130000000000000-alice-vm1","offset":0,"total":0,"live":true,"data":""}}` + "\n")
		if got := f.await(out, "Tail"); got.err != nil {
			t.Fatalf("limit %d: Tail returned %v, want an answer (the clamp is not a refusal)", asked, got.err)
		}
	}

	// A limit at or under the ceiling is passed through untouched: the
	// clamp is a ceiling, not a rewrite.
	out := f.tailAsync(TailRequest{SessionID: "1758130000000000000-alice-vm1", Offset: 0, Limit: TailChunkMax - 7})
	env, _ := f.readTailRequest()
	if env.Tail.Limit != TailChunkMax-7 {
		t.Fatalf("the machine asked for limit %d, want the caller's own %d (the ceiling must not move a request that already fits)", env.Tail.Limit, TailChunkMax-7)
	}
	f.reply(`{"proto":1,"caps":[],"id":"` + env.ID + `","ok":true,"result":{"id":"1758130000000000000-alice-vm1","offset":0,"total":0,"live":true,"data":""}}` + "\n")
	if got := f.await(out, "Tail"); got.err != nil {
		t.Fatalf("Tail: %v", got.err)
	}

	// The full ceiling, actually carried.
	raw := make([]byte, TailChunkMax)
	for i := range raw {
		raw[i] = byte(i)
	}
	body := fmt.Sprintf(`{"id":"1758130000000000000-alice-vm1","offset":0,"total":%d,"live":true,"data":%q}`,
		TailChunkMax, base64.StdEncoding.EncodeToString(raw))
	out = f.tailAsync(TailRequest{SessionID: "1758130000000000000-alice-vm1", Offset: 0, Limit: TailChunkMax})
	env, _ = f.readTailRequest()
	line := `{"proto":1,"caps":[],"id":"` + env.ID + `","ok":true,"result":` + body + `}` + "\n"
	if len(line) > DefaultControlLineMax {
		t.Fatalf("the fixture's own full-size answer is %d bytes, over the %d-byte control line — the test itself is wrong, not the code", len(line), DefaultControlLineMax)
	}
	f.reply(line)

	got := f.await(out, "Tail")
	if got.err != nil {
		t.Fatalf("the full-size answer did not come back: %v — a chunk at the ceiling must fit one control line", got.err)
	}
	if string(got.answer.Result) != body {
		t.Fatalf("the full-size answer came back as %d bytes, want the gateway's own %d", len(got.answer.Result), len(body))
	}
}

// ---- a late answer is not a protocol violation ---------------------------

// TestIAMT340_LateAnswerDoesNotTearDownTheTunnel is the failure mode the
// silence around TailTimeout creates. A gateway that answers just after
// this side gave up is not a broken gateway, and its answer must not be
// read as a malformed REQUEST — which is what would happen if
// claimTailReply let an answer fall through to decodeControlRequest:
// `ok` is not a field of a §5.1 request, so the line would be rejected as
// malformed and serveControl would tear the whole tunnel down, door and
// all, because a read got slow.
//
// Canary: in claimTailReply, replace `if !ok { return true }` with
// `if !ok { return false }` — turns "the machine's control channel
// closed while waiting for the door.status answer" red (the late
// answer falls through to decodeControlRequest, `ok` is an unknown
// field of a §5.1 request, the channel tears down, and door.status
// never gets answered).
func TestIAMT340_LateAnswerDoesNotTearDownTheTunnel(t *testing.T) {
	f := newTailFixture(t)
	out := f.tailAsync(TailRequest{SessionID: "1758130000000000000-alice-vm1", Offset: 0, Limit: 1024})
	env, _ := f.readTailRequest()

	got := f.await(out, "Tail")
	if got.err != ErrTailTimeout {
		t.Fatalf("Tail returned %v, want ErrTailTimeout — the gateway answered nothing at all", got.err)
	}
	if got.answer.Refusal != nil {
		t.Fatalf("a timeout produced a refusal (%+v) — silence is this machine's own fact, not the gateway's verdict", got.answer.Refusal)
	}

	// Now the answer finally arrives. Nobody is waiting for it.
	f.reply(`{"proto":1,"caps":[],"id":"` + env.ID + `","ok":true,"result":{"id":"1758130000000000000-alice-vm1","offset":0,"total":1,"live":true,"data":"AA=="}}` + "\n")

	// The channel must still be alive: a plain door.status goes out and
	// comes back. (It is answered from the key file in the fixture's
	// temp tree; its content is irrelevant here — that it is answered at
	// all is the assertion.)
	status := `{"proto":1,"caps":[],"id":"11111111-2222-4333-8444-555555555555","op":"door.status"}` + "\n"
	if _, err := f.ctrl.Write([]byte(status)); err != nil {
		t.Fatalf("writing door.status after the late answer: %v", err)
	}
	line := f.readLine("the door.status answer")
	var resp controlResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		t.Fatalf("door.status answer does not decode: %v (%q)", err, line)
	}
	if resp.ID != "11111111-2222-4333-8444-555555555555" || !resp.OK {
		t.Fatalf("the tunnel did not survive a late answer: the follow-up door.status was answered with %q", line)
	}
}

// ---- no channel, no invented verdict -------------------------------------

// TestIAMT340_TailWithoutAControlChannelIsHonest covers the machine-side
// failure case: when the question cannot be asked, the answer must be
// this machine's own, and it must not be dressed as the gateway's
// refusal.
//
// Canary: in Tail, replace `return TailAnswer{}, ErrNoControlChannel`
// with `return TailAnswer{Refusal: &TailRefusal{Code:"E_GATEWAY_UNREACHABLE"}}, nil`
// — turns "Tail returned %+v with no error — with no control channel
// the gateway has said nothing at all" red.
func TestIAMT340_TailWithoutAControlChannelIsHonest(t *testing.T) {
	machineKey := mustSigner(t)
	gw := newFakeGateway(t, func(k ssh.PublicKey) bool { return true })
	gw.startAccept()

	cfg := testConfig(t, gw, machineKey, "127.0.0.1:1")
	cfg.Keepalive = sshx.Keepalive{Interval: 2 * time.Minute, MaxMisses: 3}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m, err := Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// Nothing joins Serve here (it is never started), so this test closes
	// the transport itself: Dial's SSH transport has a mux goroutine that
	// outlives the call, and this package's goleak check is entitled to
	// see it end.
	t.Cleanup(func() { _ = m.conn.Close() })
	// Serve is deliberately NOT started and no control channel is opened:
	// the machine is connected but has nothing to ask over, which is the
	// state between Dial and the gateway's channel-open.
	got, err := m.Tail(ctx, TailRequest{SessionID: "1758130000000000000-alice-vm1", Limit: 1024})
	if err != ErrNoControlChannel {
		t.Fatalf("Tail returned %+v with no error — with no control channel the gateway has said nothing at all, so a refusal here would be invented", got)
	}
	if got.Refusal != nil || len(got.Result) != 0 {
		t.Fatalf("Tail returned %+v alongside its error — a failure must not carry an answer", got)
	}
}

// TestIAMT340_AnAbandonedQuestionIsNotPutOnTheWire keeps the courier from
// working for nobody. A caller that has already given up must not make
// the gateway read a file and answer into the void — that answer would
// only come back as one more late one to drop. The proof is not "the
// gateway saw nothing" (which is a five-second wait and proves little),
// but "the gateway's NEXT sight of this machine is the request somebody
// is waiting for".
//
// Canary: remove the `if err := ctx.Err(); err != nil {
// return TailAnswer{}, err }` check in Tail — turns "the gateway's first
// sight of this machine was %q, want the request somebody was waiting
// for (%q)" red: a question nobody is waiting for goes out on the wire.
func TestIAMT340_AnAbandonedQuestionIsNotPutOnTheWire(t *testing.T) {
	f := newTailFixture(t)

	abandoned, abandon := context.WithCancel(context.Background())
	abandon()
	got, err := f.m.Tail(abandoned, TailRequest{SessionID: "1758130000000000000-alice-vm1-abandoned", Limit: 1024})
	if err != context.Canceled {
		t.Fatalf("Tail with a cancelled context returned %+v and err %v, want context.Canceled", got, err)
	}

	const wanted = "1758130000000000000-alice-vm1-wanted"
	out := f.tailAsync(TailRequest{SessionID: wanted, Offset: 0, Limit: 1024})
	env, _ := f.readTailRequest()
	if env.Tail.ID != wanted {
		t.Fatalf("the gateway's first sight of this machine was %q, want the request somebody was waiting for (%q)", env.Tail.ID, wanted)
	}
	f.reply(`{"proto":1,"caps":[],"id":"` + env.ID + `","ok":true,"result":{"id":"` + wanted + `","offset":0,"total":0,"live":true,"data":""}}` + "\n")
	if got := f.await(out, "Tail"); got.err != nil {
		t.Fatalf("Tail: %v", got.err)
	}
}

// TestIAMT340_LimitBelowTheContractIsRaisedToTheSmallestLegalOne covers
// the other end of the same clamp. §1 defines limit as 1..1048576; zero
// is not a smaller request, it is an undefined one, and passing it on
// would hand the gateway a bound this side cannot honour (a peer that
// read 0 as "everything" would answer with a line that does not fit).
//
// Canary: remove the `if limit < 1 { limit = 1 }` branch in Tail —
// turns "the machine asked the gateway for limit 0, want 1" red.
func TestIAMT340_LimitBelowTheContractIsRaisedToTheSmallestLegalOne(t *testing.T) {
	f := newTailFixture(t)
	out := f.tailAsync(TailRequest{SessionID: "1758130000000000000-alice-vm1", Offset: 0, Limit: 0})
	env, _ := f.readTailRequest()
	if env.Tail.Limit != 1 {
		t.Fatalf("the machine asked the gateway for limit %d, want 1 — §1 defines limit as 1..1048576", env.Tail.Limit)
	}
	f.reply(`{"proto":1,"caps":[],"id":"` + env.ID + `","ok":true,"result":{"id":"1758130000000000000-alice-vm1","offset":0,"total":0,"live":true,"data":""}}` + "\n")
	if got := f.await(out, "Tail"); got.err != nil {
		t.Fatalf("Tail: %v", got.err)
	}
}
