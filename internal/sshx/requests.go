package sshx

// requests.go: the table of fate for human and machine requests.
//
// The normative source is PROTOCOL.md §4.1 (channel and global
// requests, exact payloads and the answer rule) and §5
// (keepalive@iamtunnel), checked against SPEC §5.1/§5.2. Every
// table row is a separate line of the spec.
//
// PROTOCOL §4.1's answer rule applies to all four dispositions: "If
// want-reply=true, the gateway MUST send exactly one
// SSH_MSG_CHANNEL_SUCCESS/FAILURE or SSH_MSG_REQUEST_SUCCESS/FAILURE;
// if false, sending an answer is forbidden." That is why Drop answers
// with a failure when want-reply=true — silence would leave the
// client hanging until its own timeout.
//
// The tables and the list of allowed env names are unexported. Only
// functions are exposed: an importer can neither rewrite a row nor
// add a name nor weaken default-deny. This is required by
// HINT-CANARY item 4 and round 3's rule.

import (
	"strings"
	"sync"
)

// Disposition describes what to do with a channel or global request.
//
// The zero value is Reject: an unset variable means "reject", not
// "let through". Default-deny must also be the type's default value.
type Disposition int

const (
	// Reject — the request is explicitly rejected; on want-reply, we
	// answer with a failure. Accompanied by an event at the caller
	// (PROTOCOL §4.1: "reject, event").
	Reject Disposition = iota
	// Drop — the request is allowed, but is not forwarded and creates
	// no event. On want-reply=true we still answer with a failure —
	// PROTOCOL §4.1's spec leaves no room for "stay silent".
	Drop
	// Answer — answer with a local success, without forwarding
	// anywhere. This is PROTOCOL §5's form for keepalive: "the
	// receiver answers with a request success and an empty payload" —
	// and §4.1's for keepalive@openssh.com: "request success, do not forward".
	Answer
	// Forward — the request is forwarded to the other side; the other
	// side's answer is returned to the initiator.
	Forward
)

// String returns the disposition's name, for logs and tests.
func (d Disposition) String() string {
	switch d {
	case Forward:
		return "forward"
	case Drop:
		return "drop"
	case Answer:
		return "answer"
	case Reject:
		return "reject"
	default:
		return "unknown"
	}
}

// requestRow — one row of the normative table.
type requestRow struct {
	name string
	disp Disposition
}

// channelRequestTable — channel requests, PROTOCOL §4.1 row by row.
//
// There are no "eof", "eof@" or "close" rows here: PROTOCOL §4.1 says
// so directly — "`eof` and `close` are carved out into their true
// packet types", which are SSH_MSG_CHANNEL_EOF/SSH_MSG_CHANNEL_CLOSE,
// which have neither a name nor a want-reply. They are forwarded via
// Channel.CloseWrite()/Channel.Close() (RFC 4254 §5.3), not through the
// request table. A channel request named "eof@" never existed at all.
var channelRequestTable = []requestRow{
	{"pty-req", Forward},       // §4.1: true; forward, return the machine's result
	{"shell", Forward},         // §4.1: true; forward
	{"exec", Forward},          // §4.1: true; forward, the command goes into the event
	{"window-change", Forward}, // §4.1: false; forward
	{"signal", Forward},        // §4.1: false; forward
	{"exit-status", Forward},   // §4.1: false; machine → human
	{"exit-signal", Forward},   // §4.1: false; machine → human

	// env — the decision depends on the payload, see LookupChannelRequest/EnvDisposition.
	// The row is needed so IsKnownChannelRequest can tell "an explicit
	// rule" from "an unknown name"; the disposition here is just a safe minimum.
	{"env", Drop},

	// §4.1: allow as a compatible OpenSSH notification, do not
	// forward, and create no event.
	{"eow@openssh.com", Drop},

	// §4.1: forbidden ones. Reject, event, on want-reply — failure.
	{"subsystem", Reject},                  // E_SSH_SUBSYSTEM_FORBIDDEN
	{"x11-req", Reject},                    // E_SSH_X11_FORBIDDEN
	{"auth-agent-req@openssh.com", Reject}, // E_SSH_AGENT_FORBIDDEN
}

// globalRequestTable — global requests, PROTOCOL §4.1 and §5 row by row.
var globalRequestTable = []requestRow{
	// §5: "Keepalive in BOTH directions is called keepalive@iamtunnel:
	// a global request with an empty payload and want-reply=true; the
	// receiver answers with a request success and an empty payload."
	// It cannot be forwarded — that would make the answer depend on a
	// third party, and SPEC §5.1 requires "an answer, no hanging".
	{"keepalive@iamtunnel", Answer},
	// §4.1: "true; request success with an empty payload, do not forward".
	{"keepalive@openssh.com", Answer},
	// §4.1: "false; allow as an OpenSSH notification, do not forward,
	// and create no event".
	{"no-more-sessions@openssh.com", Drop},
	// §4.1: "reject, event; on true a request failure, E_SSH_FORWARD_FORBIDDEN".
	{"tcpip-forward", Reject},
	{"cancel-tcpip-forward", Reject},
	// §4.1: an incoming hostkeys-00@openssh.com from a client violates
	// the direction — "on want-reply=true it gets a request failure and an event".
	{"hostkeys-00@openssh.com", Reject},
}

// allowedEnvNames — the only names SPEC §5.1 allows through to
// the target machine. The comparison is exact, with no case or
// whitespace normalization.
var allowedEnvNames = map[string]struct{}{
	"TERM": {},
	"LANG": {},
}

// env-request limits. SPEC §5.1 restricts the names; the content
// and count are not described by the spec, and that was a hole: the
// TERM value could carry any octets (NUL, CR/LF, terminal escape
// sequences), and the number of requests was unbounded.
const (
	// MaxEnvNameLen — the length limit for an env variable's name, in bytes.
	MaxEnvNameLen = 64
	// MaxEnvValueLen — the length limit for an env variable's value, in bytes.
	MaxEnvValueLen = 256
	// MaxEnvRequests — how many env requests are allowed in one session.
	MaxEnvRequests = 16
)

// EnvDisposition returns Forward for an allowed name, Drop for
// everything else. Name case is preserved as is — SSH env variables
// are conventionally sent in uppercase; sshx does not normalize case,
// so as not to mask potential differences between clients.
func EnvDisposition(name string) Disposition {
	if len(name) > MaxEnvNameLen {
		return Drop
	}
	if _, ok := allowedEnvNames[name]; ok {
		return Forward
	}
	return Drop
}

// envValueAllowed allows only printable ASCII with no control bytes.
// TERM and LANG are naturally like that ("xterm-256color",
// "en_US.UTF-8"), whereas NUL, CR/LF and ESC inside the value would
// smuggle a control sequence into the target machine's process environment.
func envValueAllowed(value string) bool {
	if len(value) > MaxEnvValueLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// EnvBudget caps the number of env requests within one session. A nil
// pointer is allowed and means "no need to count" (for example, in
// unit tests of a single decision). Fields are unexported: the budget
// cannot be raised from outside.
type EnvBudget struct {
	mu   sync.Mutex
	used int
}

// NewEnvBudget creates a budget of MaxEnvRequests requests.
func NewEnvBudget() *EnvBudget { return &EnvBudget{} }

// take spends one unit of the budget and reports whether it was available.
func (b *EnvBudget) take() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used >= MaxEnvRequests {
		return false
	}
	b.used++
	return true
}

// Decide — the decision for one env request, accounting for the
// session budget. payload is the type-specific payload of the "env"
// request (RFC 4254 §6.4). Parsing, name filter, value filter, and the
// counter all live in one place.
func (b *EnvBudget) Decide(payload []byte) Disposition {
	d := envDisposition(payload)
	if d != Forward {
		return d
	}
	if !b.take() {
		return Drop
	}
	return Forward
}

// envDisposition — the decision for an env request without accounting
// for the budget.
func envDisposition(payload []byte) Disposition {
	e, err := ParseEnv(payload)
	if err != nil {
		// A malformed payload is not "an unknown variable", but a
		// violation of the RFC 4254 §6.4 layout. We reject it
		// explicitly, with an event.
		return Reject
	}
	if EnvDisposition(e.Name) != Forward {
		return Drop
	}
	if !envValueAllowed(e.Value) {
		return Drop
	}
	return Forward
}

// LookupChannelRequest — the single entry point for a human's channel request.
//
// payload is needed for "env": per SPEC §5.1 the decision depends
// on the variable's name inside the payload, not on the request's
// name. For every other name, payload is unused and may be nil. An
// unknown name is Reject (PROTOCOL §4.1: "An unknown channel/global
// request is rejected with E_SSH_REQUEST_FORBIDDEN").
//
// Capping the number of env requests per session is EnvBudget.Decide's
// job; this function is stateless and does not check the count limit.
func LookupChannelRequest(name string, payload []byte) Disposition {
	if name == "env" {
		return envDisposition(payload)
	}
	for _, row := range channelRequestTable {
		if row.name == name {
			return row.disp
		}
	}
	return Reject
}

// LookupGlobalRequest returns the Disposition for a global request by name.
// Unknown names get Reject.
func LookupGlobalRequest(name string) Disposition {
	for _, row := range globalRequestTable {
		if row.name == name {
			return row.disp
		}
	}
	return Reject
}

// IsKnownChannelRequest reports whether the name has an explicit table
// entry. Lets the caller distinguish "an explicit prohibition"
// (E_SSH_SUBSYSTEM_FORBIDDEN and the like) from "an unknown request"
// (E_SSH_REQUEST_FORBIDDEN) in events.
func IsKnownChannelRequest(name string) bool {
	for _, row := range channelRequestTable {
		if row.name == name {
			return true
		}
	}
	return false
}

// IsKnownGlobalRequest — the same for global requests. Needed to
// distinguish E_SSH_FORWARD_FORBIDDEN (tcpip-forward has an explicit
// table entry) from the generic E_SSH_REQUEST_FORBIDDEN.
func IsKnownGlobalRequest(name string) bool {
	for _, row := range globalRequestTable {
		if row.name == name {
			return true
		}
	}
	return false
}

// IsChannelControlPacket reports that the name belongs to the
// SSH_MSG_CHANNEL_EOF/SSH_MSG_CHANNEL_CLOSE packet types, not to a
// channel request. PROTOCOL §4.1: "`eof` and `close` are carved out
// into their true packet types". Such names never arrive as a
// request; if they do, it is a forgery of a protocol-level packet, and
// the table rejects it under the general default-deny rule. This
// function exists so the caller can distinguish that forgery in events.
func IsChannelControlPacket(name string) bool {
	switch name {
	case "eof", "close":
		return true
	}
	return false
}

// IsCompatibilityNotification reports that the name is a compatible
// OpenSSH notification. PROTOCOL §4.1 requires for these "allow, do
// not forward, and do NOT create an event": eow@openssh.com and
// no-more-sessions@openssh.com arrive constantly from ordinary
// clients, and an event for each would clutter the security journal.
// Every other Drop does create an event.
func IsCompatibilityNotification(name string) bool {
	switch name {
	case "eow@openssh.com", "no-more-sessions@openssh.com":
		return true
	}
	return false
}

// ApplyDisposition applies a Disposition to a request. It is a
// wrapper so the gateway does not repeat the switch-case. Arguments:
//
//   - reqType, wantReply, replyFunc: the request's characteristics and
//     how to send an answer to the client. A typical call from the
//     gateway is ApplyDisposition(r.Type, r.WantReply, r.Reply, disp,
//     forward). replyFunc may be nil (in tests without a full SSH
//     simulation) — then no answer is sent.
//   - d: the Disposition from the table.
//   - forward: called only when d == Forward. An error (transport
//     unavailable) always yields a final Reject. The bool ("ok")
//     forward() returns is x/crypto/ssh Channel.SendRequest's ok,
//     which for want-reply=false is ALWAYS false: SendRequest in that
//     case does not wait for or read an answer (see
//     golang.org/x/crypto/ssh/channel.go, SendRequest), so it
//     physically has no source for true. window-change, signal,
//     exit-status, exit-signal all travel with want-reply=false
//     (PROTOCOL §4.1, RFC 4254 §6.7/§6.9/§6.10) — a real x/crypto/ssh
//     client calls Session.WindowChange exactly that way. So ok is
//     only consulted when wantReply=true, where it genuinely comes
//     off the wire; when wantReply=false, the only sign of failure is
//     a send error.
//
// Returns the Disposition actually applied.
func ApplyDisposition(reqType string, wantReply bool, replyFunc func(ok bool, payload []byte) error, d Disposition, forward func() (bool, error)) Disposition {
	reply := func(ok bool) {
		if wantReply && replyFunc != nil {
			_ = replyFunc(ok, nil)
		}
	}
	switch d {
	case Drop:
		// PROTOCOL §4.1: on want-reply=true an answer is mandatory, on
		// false it is forbidden. Drop differs from Reject not on the
		// wire, but in the absence of an event at the caller.
		reply(false)
		return Drop
	case Answer:
		reply(true)
		return Answer
	case Reject:
		reply(false)
		return Reject
	case Forward:
		if forward == nil {
			reply(false)
			return Reject
		}
		ok, err := forward()
		if err != nil || (wantReply && !ok) {
			reply(false)
			return Reject
		}
		reply(true)
		return Forward
	default:
		reply(false)
		return Reject
	}
}

// requestNames — the table rows' names, for diagnostics within the package.
func requestNames(rows []requestRow) string {
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		names = append(names, r.name)
	}
	return strings.Join(names, ", ")
}
