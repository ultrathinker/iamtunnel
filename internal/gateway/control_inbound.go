package gateway

// control_inbound.go — requests the MACHINE sends to the gateway over
// its own control channel (IAMT-338/340).
//
// Until this file the control channel was one-directional in its
// semantics: the gateway asked (door.open, door.close, door.status), the
// machine answered, and readLoop decoded every inbound line as a
// controlResponse belonging to a request the gateway had made. A line
// that was not such a response found no pending entry and was dropped in
// silence.
//
// That is exactly what happened to the first version of the live-session
// relay, and the review of IAMT-340 caught it: the machine wrote a
// perfectly well-formed `sessions.tail` request, the gateway decoded it
// as a nonsense response, discarded it, and the machine timed out four
// seconds later. Worse than the delay, a REFUSAL from the gateway could
// never reach the machine either — every refusal became a timeout.
//
// The fault was in the contract, not in the relay: it said "the server
// forwards it to the gateway over its control channel" and assumed the
// channel was symmetric. It was not. This file makes it so.
//
// WHY THE MACHINE MAY ASK AT ALL, and why this is not a new trust
// boundary. The machine's own server cannot read the session happening
// on it: the tunnel carries a nested SSH session, so the server forwards
// opaque encrypted bytes and only the gateway sees the text. The owner
// of the machine has every right to see what a stranger is doing on his
// computer, and the only party that can show him is the gateway. So the
// request has to travel this way; the question is only what it is
// allowed to ask for.
//
// THE ACCESS RULE, and the reason it is strong without a single check of
// anything the machine SAYS: this request arrived on the control channel
// of one authenticated machine, so the asker's identity is already
// established by the SSH layer. mc.id is that identity. A machine may
// follow a session only if the session's target is itself. Nothing in
// the body is trusted for authorization — the body cannot claim to be a
// different machine, because it is never asked who it is.
//
// On a Windows box shared by two people this falls out for free: since
// 1.4 each person's registration is its own machine identity with its
// own key and its own control channel, so one colleague's window cannot
// follow the other's session.

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/proto"
)

// controlInbound is one line read from the machine, before it is known
// whether it is a response to something the gateway asked or a request
// the machine is making of its own accord.
//
// The two are told apart by `op`: a response never carries one, and a
// request always must. That is a property of the wire as it already
// existed (controlRequest has Op, controlResponse does not), not a new
// convention invented here — which is what makes the change backward
// compatible with every machine built before it.
type controlInbound struct {
	Proto int `json:"proto"`
	// Caps is §5.1's capability list, always [] in version 1. It is here
	// because the machine sends it on every line and the reader refuses
	// fields the envelope does not declare (IAMT-443, control_read.go).
	Caps   []string          `json:"caps"`
	ID     string            `json:"id"`
	Op     string            `json:"op,omitempty"`
	OK     bool              `json:"ok"`
	Result json.RawMessage   `json:"result,omitempty"`
	Error  *controlErrorBody `json:"error,omitempty"`

	// Tail is the body of a machine-initiated sessions.tail, in the shape
	// PROTOCOL §5.1 writes out for the reverse direction:
	//
	//	{proto,caps,id,op:"sessions.tail",tail:{proto,id,offset,limit}}
	//
	// The `id` INSIDE tail is the session id; the `id` of the envelope is
	// the uuid of the request. They are two different fields, and the
	// first version of this file had neither: it read a flat `sessionId`
	// that exists nowhere in the protocol. Go's decoder ignores unknown
	// fields, so the nested body was dropped in silence, the session id
	// came out empty, and EVERY tail a machine sent came back
	// E_JSON_INVALID. The machine side (internal/server/tail.go)
	// implemented §5.1 to the letter; this side did not, and no test
	// touched the seam: the machine's own fixture decoded the request with
	// the same struct the machine encodes it with, so it agreed with the
	// machine about a shape the gateway never accepted.
	Tail *inboundTail `json:"tail,omitempty"`
}

// inboundTail is §6's request body as it travels inside the §5.1
// envelope — the SAME declaration the machine encodes with, taken from
// internal/proto rather than written out a second time here. A second
// copy is precisely what produced this defect.
type inboundTail = proto.TailReq

// asResponse rebuilds the controlResponse view for the gateway's own
// pending-request bookkeeping, which is unchanged.
func (in controlInbound) asResponse() controlResponse {
	return controlResponse{Proto: in.Proto, ID: in.ID, OK: in.OK, Result: in.Result, Error: in.Error}
}

// maxInboundSessionID bounds the session id a machine may name. The id
// the gateway itself mints is "<UnixNano>-<person>-<machine>", so a few
// dozen bytes; 256 leaves room for long names without letting the field
// become a way to push a control line past its limit. the review
// of IAMT-340 found the unbounded version: an id of seventeen thousand
// characters made the machine emit a line over 16 KiB, which a
// conforming reader must refuse — and refusing a control line tears down
// the channel, the door and the tunnel with it. A bound here is cheaper
// than a torn tunnel there.
const maxInboundSessionID = 256

// machineTailChunkMax is the most of a recording one sessions.tail answer
// on the control channel may carry (R2-CX F-01): the machine's own
// TailChunkMax (internal/server/tail.go), solved from the same 16-KiB
// line and the same 1-KiB reserve for the envelope, the answer's skeleton
// and the session id - three quarters of 15 KiB, 11520 bytes, which base64
// turns into 15360 characters. The honest machine never asks for more; a
// request that does gets this much, not an answer longer than the line.
const machineTailChunkMax = (controlLineMax - 1024) / 4 * 3

// handleMachineRequest answers a request the machine made of its own
// accord. The reply goes back on the same channel with the same id, in
// the same shape the machine uses for its own replies, so the relay on
// the other side needs no second parser.
func (mc *machineConn) handleMachineRequest(in controlInbound) {
	switch in.Op {
	case proto.OpSessionsTail:
		mc.replyControl(in.ID, mc.tailForMachine(in))
	case proto.OpSessionsMine:
		mc.replyControl(in.ID, mc.mineForMachine(in))
	default:
		// An unknown op is answered, not dropped. A machine built
		// against a later protocol must learn that this gateway does not
		// know the verb, rather than wait out a timeout and report it as
		// a network fault.
		//
		// It is also written down (F-04, round-1 review 24.09.2026): the
		// answer alone leaves the operator nothing, and "a registered
		// machine asked for a verb this gateway does not have" is a
		// version skew or a bug worth seeing. The human side records
		// every forbidden SSH request the same way
		// (human_role.go, recordSSHRequestReject).
		mc.recordUnknownOp(in.Op)
		mc.replyControl(in.ID, controlResponse{
			ID: in.ID, OK: false,
			// The code PROTOCOL 5.1 already assigns to an unknown op on
			// this channel - the same one the MACHINE returns when the
			// gateway names an op it does not know. Both ends refusing an
			// unknown verb the same way is worth more than a new code that
			// says the same thing, and the dictionary stays closed.
			//
			// The op is named clipped (R2-CX F-01): it came off a line that
			// may be all op, and named whole - quoted, then JSON-escaped -
			// it made the refusal longer than the line the machine reads it
			// from, which the machine answers by closing its tunnel.
			Error: &controlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: fmt.Sprintf("this gateway does not know the control op %q", clipForJournal(in.Op))},
		})
	}
}

// maxUnknownOpsPerConn bounds what one machine's unknown verbs may add to
// the journal. Past this many distinct unknown ops on one connection the
// gateway answers them and writes nothing more down: the fact is the
// skew, not the loop, and a connection is what an authenticated machine
// gets one of at a time (a second is refused as a duplicate,
// machine.rejected), so this is a bound on the journal, not on a sender's
// patience.
const maxUnknownOpsPerConn = 8

// recordUnknownOp journals, once per distinct op per connection, that the
// machine asked for a control op this gateway does not know. The op comes
// from the machine's own line, so it is clipped like every other
// sender-sized string on its way into the journal (IAMT-447) - the verb
// vocabulary is short, and a name too long for it is the machine's to
// explain, not the journal's to carry.
func (mc *machineConn) recordUnknownOp(op string) {
	mc.mu.Lock()
	if mc.unknownOps == nil {
		mc.unknownOps = make(map[string]bool)
	}
	first := !mc.unknownOps[op] && len(mc.unknownOps) < maxUnknownOpsPerConn
	if first {
		mc.unknownOps[op] = true
	}
	mc.mu.Unlock()
	if !first {
		return
	}
	clipped := clipForJournal(op)
	mc.g.appendEvent(events.Event{
		Type:   events.EventAdminOp,
		Actor:  mc.id,
		Object: clipped,
		Result: "unknown-control-op",
		Details: map[string]interface{}{
			"epoch": mc.epoch,
			"op":    clipped,
		},
	})
}

// tailForMachine is sessions.tail with the machine's own access rule
// applied. See the file comment: the rule is enforced against mc.id, the
// identity the SSH layer established, and never against anything the
// request claims about itself.
func (mc *machineConn) tailForMachine(in controlInbound) controlResponse {
	fail := func(code, msg string) controlResponse {
		return controlResponse{ID: in.ID, OK: false, Error: &controlErrorBody{Code: code, Message: msg}}
	}
	if in.Tail == nil {
		return fail("E_JSON_INVALID", "sessions.tail needs its tail body (PROTOCOL §5.1)")
	}
	body := in.Tail
	if len(body.ID) == 0 || len(body.ID) > maxInboundSessionID {
		return fail("E_JSON_INVALID", fmt.Sprintf("tail.id must be 1..%d bytes", maxInboundSessionID))
	}
	if body.Limit < 1 || body.Limit > 1<<20 {
		return fail("E_JSON_INVALID", "tail.limit must be between 1 and 1048576")
	}
	// R2-CX F-01: the answer goes back on this channel, one line of at
	// most 16 KiB, so the limit is clamped as the honest machine clamps
	// its own (PROTOCOL §5.1) - a smaller answer from the same offset, which
	// the viewer asks on from, rather than one the machine's reader would
	// refuse and tear the tunnel down over. §6's 1 MiB is the admin exec's
	// bound, where the answer is not held to a control line.
	limit := body.Limit
	if limit > machineTailChunkMax {
		limit = machineTailChunkMax
	}

	// The rule. A machine follows only sessions whose target is itself.
	// Asking about somebody else's session is answered exactly like
	// asking about a session that does not exist: a machine must not be
	// able to discover, by the shape of the refusal, that a session
	// exists somewhere else on this gateway.
	if !mc.ownsSession(body.ID) {
		return controlResponse{ID: in.ID, OK: true, Result: mustJSON(map[string]any{
			"id": body.ID, "offset": body.Offset, "total": body.Offset, "live": false, "data": "",
		})}
	}

	// While the journal is not written (IAMT-451) nothing that must leave a
	// trace is done, and watching must (R4 F-01): the admin's sessions.tail
	// is refused on that ground, and the machine's own path is too - it
	// used to go on handing out live bytes with its session.watch lost.
	if cerr := mc.g.auditRefusal(); cerr != nil {
		return fail(cerr.code, cerr.message)
	}

	// Watching is said out loud, once (IAMT-343). The event goes in
	// AFTER the access rule has passed, so a machine cannot make the
	// journal record an interest in a session it was never allowed to
	// see; and it goes in BEFORE the answer is built, so the record
	// exists even if reading the recording then fails. Watching that
	// began is the fact worth keeping either way.
	if err := mc.noteWatching(body.ID); err != nil {
		return fail("E_AUDIT_UNAVAILABLE", fmt.Sprintf("watching session %q has to be recorded in the audit journal, and the journal could not be written: %v", body.ID, err))
	}

	raw := mustJSON(map[string]any{"proto": 1, "id": body.ID, "offset": body.Offset, "limit": limit})
	out, cerr := cmdSessionsTail(mc.g, "", zeroTime, raw)
	if cerr != nil {
		return fail(cerr.code, cerr.message)
	}
	return controlResponse{ID: in.ID, OK: true, Result: mustJSON(out)}
}

// mineForMachine answers "which sessions are happening on me right now".
//
// It exists because a tail is asked for by session id and the machine
// cannot learn that id any other way: the gateway mints it, and the
// tunnel between them carries a nested SSH session whose bytes the
// machine forwards without being able to read them. Before this the
// window filled the gap by inventing an id from the person's name, the
// gateway answered - correctly - that no such session was live, and the
// owner watched an empty terminal while somebody really was working on
// his computer.
//
// The access rule is the tail's rule, unchanged and for the same reason:
// the list is built from mc.id, the identity the SSH layer established,
// so a machine learns about its own guests and about nobody else's. A
// machine with no sessions and a machine that asked about someone else's
// get the same answer - an empty list - because those two facts must not
// be distinguishable from outside.
func (mc *machineConn) mineForMachine(in controlInbound) controlResponse {
	out := make([]proto.MineSession, 0, 4)
	for _, s := range mc.g.aclE.Sessions() {
		if s.Machine != mc.id {
			continue
		}
		out = append(out, proto.MineSession{
			ID:      s.ID.String(),
			Person:  s.Person,
			Started: rfc3339(s.OpenedAt),
		})
	}
	// A stable order, so a list that has not changed does not reshuffle
	// itself under the reader's cursor between two polls.
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return controlResponse{ID: in.ID, OK: true, Result: mustJSON(proto.MineResult{Sessions: out})}
}

// noteWatching writes session.watch the first time this machine asks
// about this session, and never again for it.
//
// The live view is a poll loop - one request a second for as long as
// somebody is looking - so an event per request would turn the journal
// into a log of window refreshes and bury the events an operator
// actually reads. The question a person asks afterwards is "did anyone
// watch this session", and that is answered by the first request alone.
func (mc *machineConn) noteWatching(sessionID string) error {
	mc.mu.Lock()
	recorded := mc.watched[sessionID]
	mc.mu.Unlock()
	if recorded {
		return nil
	}
	// First requests that arrive together (each control request runs in
	// its own goroutine) record one session.watch between them (R4 review
	// N-09): the check is repeated under watchMu, held across the write.
	mc.watchMu.Lock()
	defer mc.watchMu.Unlock()
	mc.mu.Lock()
	recorded = mc.watched[sessionID]
	mc.mu.Unlock()
	if recorded {
		return nil
	}

	// The person whose session it is, from the gateway's own registry -
	// not from anything the machine said about it.
	person := ""
	for _, s := range mc.g.aclE.Sessions() {
		if s.ID.String() == sessionID {
			person = s.Person
			break
		}
	}
	// Marked only once the event is on disk (R4 review N-07): marked first,
	// a failed write went on serving live bytes and every later poll
	// skipped the event that was lost.
	if err := mc.g.appendEventChecked(events.Event{
		Type:    events.EventSessionWatch,
		Actor:   mc.id,
		Object:  sessionID,
		Result:  "ok",
		Details: map[string]any{"person": person},
	}); err != nil {
		return err
	}
	mc.mu.Lock()
	if mc.watched == nil {
		mc.watched = make(map[string]bool)
	}
	mc.watched[sessionID] = true
	mc.mu.Unlock()
	return nil
}

// ownsSession reports whether the named live session targets THIS
// machine. It asks the session registry, which is the gateway's own
// record of who is where — not the recording, not the request.
func (mc *machineConn) ownsSession(sessionID string) bool {
	// The walk deliberately does NOT stop at the match.
	//
	// The refusal bodies for a foreign session and for a session that
	// never existed are identical on purpose - that is the whole point of
	// the rule. But an early return made the two take measurably
	// different amounts of work: a foreign id was found partway through
	// and answered at once, while an unknown id walked the whole list. A
	// machine that repeated the question could tell, from timing alone,
	// that a session it is not allowed to see exists somewhere on this
	// gateway. The bodies matched and the secret leaked anyway.
	//
	// A full walk costs one pass over the live sessions of the whole
	// gateway - a handful of entries - and it costs it identically
	// whatever the answer turns out to be.
	owned := false
	for _, s := range mc.g.aclE.Sessions() {
		if s.ID.String() == sessionID && s.Machine == mc.id {
			owned = true
		}
	}
	if owned {
		return true
	}
	// A session that has just ended is no longer in the ACL, but its
	// recording is still readable for a short while so that whoever was
	// watching can drain the last of it (drainGrace). The right to read
	// it must outlive the session by exactly as long, and not one
	// caller longer - otherwise the final seconds of a session, which
	// are the ones a person leans in for, are the ones nobody may see.
	// The registry's own record of the machine decides, never the id.
	if machine, known := mc.g.live.machineOf(sessionID); known {
		return machine == mc.id
	}
	return false
}

// replyControl writes one response back to the machine under the write
// mutex the channel already uses for gateway-initiated requests, so a
// reply can never interleave with a request being written.
//
// R2-CX F-01: the reply is held to the frame the machine reads it in -
// 16 KiB a line, the bound this side holds the machine to - because the
// machine tears the tunnel down on a longer line, its door and every live
// session with it. The answers are sized to fit (an unknown op named
// clipped, a tail clamped to machineTailChunkMax); one that would not fit
// all the same is replaced by a short refusal of the request, and the
// channel stays. And every reply carries caps:[] (PROTOCOL §1.1, §5.1),
// not the caps:null a nil list encodes to.
func (mc *machineConn) replyControl(id string, resp controlResponse) {
	resp.Proto = 1
	resp.Caps = []string{}
	resp.ID = id
	raw, err := json.Marshal(resp)
	if err != nil {
		return
	}
	if len(raw) > controlLineMax {
		raw, err = json.Marshal(controlResponse{
			Proto: 1, Caps: []string{}, ID: id, OK: false,
			Error: &controlErrorBody{Code: "E_CONTROL_PROTOCOL", Message: fmt.Sprintf("the answer to this request would not fit one control line (%d bytes)", controlLineMax)},
		})
		if err != nil {
			return
		}
	}
	raw = append(raw, '\n')
	mc.writeMu.Lock()
	defer mc.writeMu.Unlock()
	if mc.ctrlCh != nil {
		_, _ = mc.ctrlCh.Write(raw)
	}
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return raw
}

// zeroTime is the clock value sessions.tail does not use. The command
// takes a time for the shape every command in the table shares; it reads
// the file and nothing else, so there is no moment for it to be wrong
// about.
var zeroTime = time.Time{}
