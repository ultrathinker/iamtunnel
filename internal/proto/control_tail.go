package proto

// control_tail.go — the one description of the reverse direction of the
// control channel, shared by both ends (IAMT-344).
//
// PROTOCOL §5.1 writes the shape out in full:
//
//	{proto,caps,id,op:"sessions.tail",tail:{proto,id,offset,limit}}
//
// The `id` of the envelope is the uuid of the request; the `id` inside
// `tail` is the id of the SESSION. They are two different fields, and
// that is exactly where the two halves of IAMT-338/340 came apart: the
// machine encoded the protocol to the letter while the gateway decoded a
// flat `sessionId` that exists nowhere in it. Go's decoder ignores
// unknown fields, so nothing failed loudly — the session id simply
// arrived empty and every request a person made to watch his own machine
// came back E_JSON_INVALID, forever.
//
// Neither side was reviewed against the other: the machine's own test
// fixture decoded the request with the same struct the machine encodes
// it with, so it agreed with the machine about a shape the gateway never
// accepted. A fake built from one side's mental model cannot disprove
// that model.
//
// Hence this file. The types live here, in the package whose doc comment
// already says it holds marshaling and nothing else, and both ends
// import them. Two halves can no longer disagree about the shape,
// because there is only one shape and disagreeing with it does not
// compile.
//
// The struct tags are the protocol's own names. Nothing here is renamed
// for either side's convenience: being the same bytes the other side
// wrote is the entire purpose.

// OpSessionsTail is the only control operation the machine may start in
// v1 (PROTOCOL §5.1, "reverse direction").
const OpSessionsTail = "sessions.tail"

// TailEnvelope is the §5.1 envelope carrying a machine-initiated
// sessions.tail. The two directions are told apart by Op: a request has
// one, a response does not.
type TailEnvelope struct {
	Proto int      `json:"proto"`
	Caps  []string `json:"caps"`
	ID    string   `json:"id"`
	Op    string   `json:"op"`
	Tail  *TailReq `json:"tail,omitempty"`
}

// TailReq is §6's request body as it travels inside that envelope.
// ID here is the session id, never the envelope's uuid.
type TailReq struct {
	Proto  int    `json:"proto"`
	ID     string `json:"id"`
	Offset uint64 `json:"offset"`
	Limit  uint32 `json:"limit"`
}

// OpSessionsMine is the second operation of the reverse direction
// (IAMT-345). It answers the question the machine cannot answer for
// itself: WHICH sessions are happening on me right now, and what are
// they called.
//
// Without it the reverse direction is headless. A tail is asked for by
// session id; the id is minted on the gateway
// ("<UnixNano>-<person>-<machine>") and the machine never sees it,
// because the tunnel carries a nested SSH session and the machine
// forwards opaque bytes. So a machine could ask "give me the tail of
// session X" while having no way on earth to learn X. The window filled
// the hole by inventing an id out of the person's name; the gateway
// then correctly reported that no such session was live, and the owner
// watched an empty terminal for a session that was in fact running.
//
// The same access rule applies as for a tail, for the same reason and by
// the same means: the answer lists only sessions whose target is the
// machine that asked, and the asker's identity comes from the SSH layer,
// never from the request.
const OpSessionsMine = "sessions.mine"

// MineSession is one live session on the asking machine: who is in,
// since when, and the id needed to follow them. It deliberately carries
// nothing else — this is the owner's own machine asking about its
// guests, not an admin console — and in particular it carries no
// deadline, because the session registry does not hold one. The grant
// does, and inventing a value here out of the grant would be this side
// claiming something the source of truth never said.
type MineSession struct {
	ID      string `json:"id"`
	Person  string `json:"person"`
	Started string `json:"started"`
}

// MineResult is the body of a successful sessions.mine answer. An empty
// list is a normal answer and means exactly what it says: nobody is
// working on this machine at this moment.
type MineResult struct {
	Sessions []MineSession `json:"sessions"`
}
