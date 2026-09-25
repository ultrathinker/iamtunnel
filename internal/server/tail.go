package server

// tail.go — IAMT-340: the machine's half of "watch a live session".
//
// Why this file exists at all. The machine never sees its own session.
// The tunnel to the gateway carries a NESTED SSH: the gateway runs an
// SSH client against 127.0.0.1:22 *through* the tunnel, and this server
// splices opaque encrypted bytes (machine.go, spliceTarget). Nobody here
// can read the transcript, because there is no transcript here — the
// only party that sees text is the gateway, which is where the recorder
// lives. So "look at my own machine" is, unavoidably, a question ASKED
// OF THE GATEWAY: the owner's window asks this server, and this server
// has to carry the question across the control channel and carry the
// answer back.
//
// The machine is a courier on that path and nothing else (contract §3).
// It does not decide who may watch what — the gateway does, from the
// identity of the control channel the question arrived on, which is
// established by the SSH layer and is not a field in any body. It does
// not cache: a cached answer is a lie about a session that is still
// running. It does not replace the gateway's refusal with one of its
// own: a refusal is a fact about access, and this side has no standing
// to state it. The only thing this file decides is the SIZE of the
// question, and it decides that because the limit it must respect is
// its own wire's, not the gateway's (see TailChunkMax below).
//
// The wire. PROTOCOL §5.1 defines one message shape for the control
// channel: {proto,caps,id,op} plus whatever that op carries. The request
// and the answer of the tail itself are §1's shapes of the contract
// ({id,offset,limit} → {id,offset,total,live,data}), and they travel
// inside that envelope unchanged — nested whole under "tail" — so there
// is exactly one definition of what a tail request is, shared by the
// gateway's own exec command and by this relay, and no second copy of
// the field names to drift from it. This file names the op
// "sessions.tail", the same name §1 gives the command.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/proto"
)

// Sizing the question (contract §3, third bullet).
//
// One control-channel line is capped at 16 KiB (PROTOCOL §5.1;
// Config.ControlLineMax, whose default IS that number). The cap that
// bites here is on the ANSWER: the request is a few dozen bytes, while
// the answer carries a base64 chunk of the .cast, and base64 turns n raw
// bytes into 4*ceil(n/3). So an unclamped `limit` does not merely produce
// a big answer — it produces a line the machine's own reader refuses as
// errLineTooLong, which tears the whole tunnel down (serveControl's
// framing posture), taking a live session's door with it. That is the
// failure this limit exists to make impossible.
//
// The arithmetic, top to bottom:
//
//	16384   one control line (PROTOCOL §5.1)
//	-1024   reserved for everything that is not the base64 body: the
//	        §5.1 envelope, the JSON skeleton of §1's answer, and the
//	        session id. The skeleton is ~180 bytes and a session id of
//	        the §1 shape (<UnixNano>-<person>-<machine>) is under 90,
//	        so this leaves several hundred bytes of slack rather than
//	        counting on today's exact names and counters.
//	------
//	15360   left for the base64 body
//	×3/4    base64 costs 4/3 of the raw bytes
//	------
//	11520   = TailChunkMax
//
// 11520 is also a multiple of 3, so a full chunk encodes to exactly
// 15360 base64 characters with no padding tail — the reserve above is
// the entire margin, not a remainder nobody accounted for.
const (
	// TailLineReserve is what TailChunkMax leaves unused in one control
	// line for the envelope, the answer skeleton and the session id.
	TailLineReserve = 1024

	// TailChunkMax is the largest raw .cast chunk a "tail" may ask for
	// on this path. The gateway's own §1 wire allows limit up to
	// 1048576 for an admin exec; over the machine's control channel the
	// 16 KiB line is the binding constraint, and this is that
	// constraint solved for `limit`.
	TailChunkMax = (DefaultControlLineMax - TailLineReserve) / 4 * 3
)

// TailTimeout bounds one relay round trip. It is deliberately shorter
// than the local control socket's own 5-second wire deadline
// (cmd/iamtunnel/server.go, handleControlConn): the window must be told
// "no answer" by this side while it is still listening, not have the
// socket die under it with the question in flight. A gateway slower than
// this is not lost — the window polls again on its next tick, which is
// the whole reason the contract chose polling over a stream (§1).
const TailTimeout = 4 * time.Second

// tailChunkMaxFor solves the same inequality for a configured line
// limit. Production always runs with the protocol's 16 KiB
// (DefaultControlLineMax), so this equals TailChunkMax there; it exists
// so that a deployment that lowered ControlLineMax cannot be handed a
// chunk that no longer fits the wire it actually has. A line limit with
// no room left after the reserve admits no chunk at all, and zero is the
// honest answer to that.
func tailChunkMaxFor(lineMax int) int {
	if lineMax <= TailLineReserve {
		return 0
	}
	return (lineMax - TailLineReserve) / 4 * 3
}

// TailRequest is one question about a live session, in §1's request
// shape. SessionID is the id sessions.active hands out
// (<UnixNano>-<person>-<machine>); Limit is the raw byte count wanted
// and is clamped by Tail before it goes out.
type TailRequest struct {
	SessionID string
	Offset    uint64
	Limit     uint32
}

// TailRefusal is the gateway's own refusal, carried through untouched:
// the §5.1 error body with the code and message the gateway chose.
type TailRefusal struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// TailAnswer is the gateway's answer, exactly as it came back. Exactly
// one of Result and Refusal is set.
//
// Result is §1's answer body ({id,offset,total,live,data}) held as raw
// JSON: this side never parses `data`, never counts `total`, never reads
// `live`, and never repairs a body it did not like — it hands the window
// the bytes the gateway produced, which is what "return the response
// as is" means. Refusal is the same promise for a refusal: the gateway's
// code and message reach the window as the gateway's, so "this session
// belongs to another machine" is never rewritten into something this
// side made up.
type TailAnswer struct {
	Result  json.RawMessage
	Refusal *TailRefusal
}

// The wire types of this direction are NOT declared here. They live in
// internal/proto, where the gateway reads them from the same
// declaration, because when each end had its own the two came apart and
// nobody noticed (IAMT-344 — see the file comment there). These aliases
// keep this file's own prose readable without giving either side a
// private copy of the shape.
type (
	controlTail        = proto.TailReq
	controlTailRequest = proto.TailEnvelope
)

// tailOp is the control-channel op this file adds, named the way §1
// names the command.
const tailOp = proto.OpSessionsTail

// newControlRequestID mints a lower-case RFC 4122 uuid v4, the shape
// PROTOCOL §5.1 requires of every control message id and the shape
// validateControlRequestID already checks on the way in.
func newControlRequestID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand.Read's contract is that it never returns an error
		// on any platform this program builds for; if that ever stops
		// being true there is no correct id to mint, and inventing a
		// guessable one would be worse than refusing the relay.
		return ""
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	s := hex.EncodeToString(raw)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
}

// ErrNoControlChannel is returned by Tail when this Machine has no live
// control channel: either the tunnel is not up yet, or it has just gone
// away. It is the machine's own honest failure — the question never
// reached the gateway — and must never be reported as the gateway's
// refusal.
var ErrNoControlChannel = errors.New("server: no live control channel to the gateway")

// ErrTailTimeout is returned by Tail when the gateway did not answer
// within TailTimeout. Also a machine-side fact: the request went out and
// nothing came back, which is not the same statement as a refusal.
var ErrTailTimeout = errors.New("server: the gateway did not answer the tail request in time")

// ErrTailLineTooSmall is returned by Tail when this machine's configured
// control-line limit leaves no room for a tail answer at all: the
// reserve for the envelope, the answer skeleton and the session id
// already eats the whole line, so not even a one-byte chunk could come
// back inside it.
//
// the review of IAMT-340 found the first version of this path
// asking for one byte anyway, on the reasoning that 1 is the smallest
// LEGAL limit under the tail contract. It is - and that is the wrong
// question. The bound this side cannot honour is not the limit in the
// request but the SIZE OF THE ANSWER: the gateway would dutifully
// produce a well-formed response, this machine's own reader would find
// it over the configured line limit, and a control line that cannot be
// read tears down the channel, and the door and the tunnel with it
// (PROTOCOL 5.1). A person looking at a live session would have knocked
// his own machine off the gateway. Refusing here costs him a feature he
// cannot have on that configuration; asking anyway costs him the
// session.
var ErrTailLineTooSmall = errors.New("server: the configured control-line limit leaves no room for a tail answer")

// Tail carries one tail request to the gateway and returns the gateway's
// own answer. Everything it can fail with is a machine-side failure
// (no channel, write error, no answer in time, an answer that is not a
// §5.1 response at all); a REFUSAL is not a failure here — it comes back
// as TailAnswer.Refusal so the caller can hand it on unaltered.
func (m *Machine) Tail(ctx context.Context, req TailRequest) (TailAnswer, error) {
	m.ctrlMu.Lock()
	ch := m.ctrlCh
	done := m.ctrlDone
	m.ctrlMu.Unlock()
	if ch == nil {
		return TailAnswer{}, ErrNoControlChannel
	}
	// A caller who has already given up does not get a question put on
	// the wire. The same rule the gateway's own driveOneUntil applies to
	// door.open for the same reason: sending it would make the other end
	// read a file and answer nobody, and the answer would then have to be
	// dropped as one more late one.
	if err := ctx.Err(); err != nil {
		return TailAnswer{}, err
	}

	// ControlLineMax is filled in by setDefaults on every path into this
	// package (Dial is the only constructor of a Machine); the fallback
	// is the protocol's own number, so a zero here can never be read as
	// "no limit at all".
	lineMax := m.cfg.ControlLineMax
	if lineMax <= 0 {
		lineMax = DefaultControlLineMax
	}
	// The clamp is here, at the one place a tail request can be
	// encoded, so that no caller can put a limit on the wire that the
	// answer to it could not fit (see TailChunkMax). Above the ceiling
	// it truncates rather than refuses: the contract asks for a smaller
	// question, not for the window to be told no. Below the floor it
	// raises to 1, because a limit under 1 is not a smaller request but
	// an undefined one (§1: limit is 1..1048576), and passing it on
	// would be handing the gateway a bound this side cannot honour. And
	// when the ceiling itself has fallen below 1 there is no legal
	// question left to ask at all, which is a refusal, not a clamp.
	ceiling := tailChunkMaxFor(lineMax)
	if ceiling < 1 {
		// Nothing fits. Nothing is asked for: see ErrTailLineTooSmall
		// for why a one-byte question is worse than no question here.
		return TailAnswer{}, ErrTailLineTooSmall
	}
	limit := req.Limit
	if limit < 1 {
		limit = 1
	}
	if limit > uint32(ceiling) {
		limit = uint32(ceiling)
	}

	id := newControlRequestID()
	if id == "" {
		return TailAnswer{}, errors.New("server: could not mint a control request id")
	}
	raw, err := json.Marshal(controlTailRequest{
		Proto: 1,
		Caps:  []string{},
		ID:    id,
		Op:    tailOp,
		Tail: &controlTail{
			Proto:  1,
			ID:     req.SessionID,
			Offset: req.Offset,
			Limit:  limit,
		},
	})
	if err != nil {
		return TailAnswer{}, fmt.Errorf("server: encoding the tail request: %w", err)
	}
	raw = append(raw, '\n')

	replyCh := make(chan []byte, 1)
	m.tailMu.Lock()
	if m.tailWait == nil {
		m.tailWait = make(map[string]chan []byte)
	}
	m.tailWait[id] = replyCh
	m.tailMu.Unlock()
	// Every exit below must leave no waiter behind: the map is the
	// reader loop's only handle on this request, and a stale entry would
	// swallow the answer to some later, unrelated request that happened
	// to reuse the id (it cannot, ids are uuids — but "cannot" is not a
	// reason to leak).
	defer func() {
		m.tailMu.Lock()
		delete(m.tailWait, id)
		m.tailMu.Unlock()
	}()

	if err := m.writeControl(raw); err != nil {
		return TailAnswer{}, err
	}

	timer := time.NewTimer(TailTimeout)
	defer timer.Stop()
	select {
	case line := <-replyCh:
		return decodeTailAnswer(line)
	case <-timer.C:
		return TailAnswer{}, ErrTailTimeout
	case <-done:
		return TailAnswer{}, ErrNoControlChannel
	case <-ctx.Done():
		return TailAnswer{}, ctx.Err()
	}
}

// MineSessions asks the gateway which sessions are happening on THIS
// machine right now (IAMT-345). It is the question that has to be
// answered before Tail can be asked at all: a tail names a session id,
// and the id is the gateway's to mint - the tunnel carries a nested SSH
// session, so this machine forwards bytes it cannot read and never sees
// the id go by.
//
// Like Tail, this is pure carriage. The machine does not decide what it
// is allowed to know: the gateway builds the list from the identity of
// the control channel the question arrived on. An empty list is a
// perfectly good answer and means nobody is working here.
func (m *Machine) MineSessions(ctx context.Context) ([]proto.MineSession, error) {
	m.ctrlMu.Lock()
	ch := m.ctrlCh
	done := m.ctrlDone
	m.ctrlMu.Unlock()
	if ch == nil {
		return nil, ErrNoControlChannel
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	id := newControlRequestID()
	if id == "" {
		return nil, errors.New("server: could not mint a control request id")
	}
	raw, err := json.Marshal(proto.TailEnvelope{
		Proto: 1,
		Caps:  []string{},
		ID:    id,
		Op:    proto.OpSessionsMine,
	})
	if err != nil {
		return nil, fmt.Errorf("server: encoding the sessions.mine request: %w", err)
	}
	raw = append(raw, '\n')

	replyCh := make(chan []byte, 1)
	m.tailMu.Lock()
	if m.tailWait == nil {
		m.tailWait = make(map[string]chan []byte)
	}
	m.tailWait[id] = replyCh
	m.tailMu.Unlock()
	defer func() {
		m.tailMu.Lock()
		delete(m.tailWait, id)
		m.tailMu.Unlock()
	}()

	if err := m.writeControl(raw); err != nil {
		return nil, err
	}

	timer := time.NewTimer(TailTimeout)
	defer timer.Stop()
	select {
	case line := <-replyCh:
		answer, err := decodeTailAnswer(line)
		if err != nil {
			return nil, err
		}
		if answer.Refusal != nil {
			// The gateway's refusal, in the gateway's own words: this
			// side never rewrites it and never passes its own trouble
			// off as the gateway's.
			return nil, fmt.Errorf("server: the gateway refused sessions.mine: %s: %s", answer.Refusal.Code, answer.Refusal.Message)
		}
		var out proto.MineResult
		if err := json.Unmarshal(answer.Result, &out); err != nil {
			return nil, fmt.Errorf("server: the gateway's session list is unreadable: %w", err)
		}
		return out.Sessions, nil
	case <-timer.C:
		return nil, ErrTailTimeout
	case <-done:
		return nil, ErrNoControlChannel
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// decodeTailAnswer turns one §5.1 response into a TailAnswer. The only
// thing it interprets is the envelope, which PROTOCOL §5.1 defines; the
// body inside is passed through as the bytes it arrived as.
func decodeTailAnswer(line []byte) (TailAnswer, error) {
	var resp controlResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return TailAnswer{}, fmt.Errorf("server: the gateway's tail answer is not a control response: %w", err)
	}
	switch {
	case resp.OK:
		if len(resp.Result) == 0 {
			return TailAnswer{}, errors.New("server: the gateway's tail answer is ok:true with no result")
		}
		return TailAnswer{Result: resp.Result}, nil
	case resp.Error != nil:
		return TailAnswer{Refusal: &TailRefusal{Code: resp.Error.Code, Message: resp.Error.Message}}, nil
	default:
		// ok:false without an error body is a shape §5.1 does not
		// define. Reporting it as this side's error is not the same as
		// inventing a refusal for the gateway: nothing here claims the
		// gateway said no — it says the gateway's answer could not be
		// read, which is exactly what happened.
		return TailAnswer{}, errors.New("server: the gateway's tail answer is ok:false without an error body")
	}
}

// claimTailReply reports whether line is the answer to a relay this
// Machine is waiting for, and hands it to the waiter if so. It exists so
// serveControl can tell the two directions of this channel apart.
//
// The discriminator is PROTOCOL §5.1's own envelope: every message the
// GATEWAY sends on this channel is a request and therefore carries `op`
// (door.open, door.close, door.status, door.sanitize), while an answer
// to a machine-initiated request never does. A line with an op is left
// for the ordinary request path. A line without one and without an id is
// left there too, where decodeControlRequest will reject it and end the
// channel exactly as it does today for any other malformed message.
//
// An answer nobody is waiting for is dropped silently, which is
// deliberate and matches the gateway's own readLoop on its side of this
// same channel: it looks the id up in its pending set and ignores what
// it does not find. The case is reachable — TailTimeout can expire
// microseconds before the answer lands — and it is harmless: a late
// answer carries read data and nothing else, so unlike a late door.open
// there is nothing to reconcile and nobody to tell.
func (m *Machine) claimTailReply(line []byte) bool {
	var envelope struct {
		ID string `json:"id"`
		Op string `json:"op"`
	}
	if err := json.Unmarshal(line, &envelope); err != nil {
		return false
	}
	if envelope.Op != "" || envelope.ID == "" {
		return false
	}
	m.tailMu.Lock()
	waiter, ok := m.tailWait[envelope.ID]
	m.tailMu.Unlock()
	if !ok {
		return true
	}
	select {
	case waiter <- line:
	default:
		// The waiter takes exactly one line and leaves; a second answer
		// to the same id is a peer error this side cannot act on.
	}
	return true
}

// writeControl serializes one line onto the control channel. Both the
// request handlers in serveControl and Tail write here: the channel is a
// single byte stream, and an interleaved pair of writes would be one
// corrupt line, which the peer would rightly tear down.
func (m *Machine) writeControl(raw []byte) error {
	m.ctrlMu.Lock()
	ch := m.ctrlCh
	m.ctrlMu.Unlock()
	if ch == nil {
		return ErrNoControlChannel
	}
	m.ctrlWriteMu.Lock()
	defer m.ctrlWriteMu.Unlock()
	if _, err := ch.Write(raw); err != nil {
		return fmt.Errorf("server: writing to the control channel: %w", err)
	}
	return nil
}
