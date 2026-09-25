package gateway

// enrol_role.go handles the username "enrol" SSH connection of
// PROTOCOL §3.2/§6: the machine dials as username "enrol" with the
// HKDF-derived ephemeral key, runs exactly one "enrol" exec with the
// raw secret, and the runtime consumes the EnrolPending entry in the
// same atomic write that creates the machine.
//
// Scope:
//   - Anything other than the single "enrol" exec command is rejected
//     with E_EXEC_UNKNOWN. The "enrol" login exists for the lifetime
//     of one machine's enrol code and nothing else: it cannot open
//     sessions, list people/machines/grants, or play any other role
//     here. The test matrix enforces that by enumeration.
//   - A second connection as "enrol" against the same machine finds no
//     EnrolPending (because the first one consumed it) and is refused
//     at the SSH PublicKeyCallback with "unknown key" — exactly the
//     "replay must look like an unknown key" rule of PROTOCOL §3.2.
//   - The expiry is enforced HERE, not at handshake time, so a key
//     whose secret expired after the SSH login still authenticates and
//     then is rejected with E_ENROL_SECRET_EXPIRED at exec time. This
//     keeps the rate limiter from seeing an auth failure on a key the
//     gateway did issue.

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// enrolRequest is the JSON body of the "enrol" exec. Wire shape is
// kept stable from before IAMT-336 / 1.3 (PROTOCOL §6):
// {proto, secret, machine, osUser, machineKey}.
//
// Since 1.4 the two fields are answered by different parties, which is
// the whole design: the NAME comes from the invitation, because the
// administrator chose it and only he could; the OS ACCOUNT comes from
// the body, because the machine is the only one who knows it.
//
// `machine` is therefore OPTIONAL and, when sent, is only checked for
// agreement with the invitation — a client that still names itself is
// told no rather than silently renamed. `osUser` is REQUIRED and must
// validate against the §4.3 grammar.
//
// `requestedOsUser` is never used for login or for admitting a
// person — only `verifiedOsUser` is, and only after the gateway's
// own SSH public-key user-auth probe on the target sshd (SPEC §3.4
// step 3). A claimed osUser cannot therefore grant anything.
type enrolRequest struct {
	Proto      int    `json:"proto"`
	Secret     string `json:"secret"`
	Machine    string `json:"machine"`
	OSUser     string `json:"osUser"`
	MachineKey string `json:"machineKey"`
}

// enrolResult is the success response shape PROTOCOL §6 prescribes for
// "enrol": the machine id assigned by the gateway, its state, the
// requestedOsUser/osUserStatus pair that opens the §7 state machine
// for sshd verification, the hostKeyStatus (always "unverified" at
// this point — verification happens later over the established
// tunnel), and the server's notion of time.
type enrolResult struct {
	Machine         string `json:"machine"`
	State           string `json:"state"`
	RequestedOSUser string `json:"requestedOsUser"`
	OSUserStatus    string `json:"osUserStatus"`
	HostKeyStatus   string `json:"hostKeyStatus"`
	ServerTime      string `json:"serverTime"`
}

// enrolOutcome carries a runEnrol Update closure's verdict out of the
// store transaction: the success response, or the named failure, plus
// the machine id for the journal event appended once the transaction
// has committed.
type enrolOutcome struct {
	res     *enrolResult
	err     *cmdError
	machine string
}

// runEnrolFromPending is runEnrol's branch for a code that has no
// matching Machine record yet (the IAMT-336 path: every minted
// code is unbound and lives in state.PendingEnrolments). It looks
// the entry up by its secret hash, validates the secret hash and
// expiry, validates the machine-reported name and OS user against
// the §4.3 grammars, refuses a name collision with an existing
// machine, and finally creates the Machine record and removes the
// pending entry in the same Store.Update — the machine is created as
// enrolled in one atomic write (PROTOCOL §3.2).
//
// `actor` is the SHA256 fingerprint of the ephemeral key the caller
// authenticated with. Lookup is by `presented` (the secret hash), not
// by the fingerprint; the fingerprint's job is to classify the failure
// when no entry matches the hash, which is the only way to keep
// "somebody mistyped their secret" apart from "somebody replayed an
// invitation that has already been redeemed" (see below).
func (g *Gateway) runEnrolFromPending(st *state.State, actor string, req enrolRequest, presented [32]byte, now time.Time, out *enrolOutcome) error {
	pe, ok := st.FindPendingEnrolmentBySecretHash(presented)
	if !ok {
		// No entry carries this secret. Two quite different things
		// produce that, and telling them apart matters: "the replay
		// kind is the leak indicator the machine's owner must
		// be able to spot".
		//
		// If the invitation this connection authenticated with is
		// STILL here, then it was never redeemed — the caller simply
		// presented a secret that is not the one their key was derived
		// from. A typo, a truncated paste, a line wrapped by a chat
		// client. That is "invalid", and journalling it as a replay
		// would fire the leak alarm on every fat-fingered paste until
		// nobody reads the alarm any more.
		//
		// If it is GONE, it was there moments ago — the handshake
		// resolved this very key against it — and is not now. It was
		// redeemed or revoked in between. That is the replay, and the
		// one worth an operator's attention: two parties held the same
		// invitation.
		if _, live := st.FindPendingEnrolmentByFingerprint(actor); live {
			out.err = errEnrolSecretInvalid("the secret presented is not the one this invitation carries")
			return nil
		}
		out.err = errEnrolSecretUsed("pending entry not found")
		return nil
	}
	if !pe.Expires.After(now) {
		out.err = errEnrolSecretExpired("enrol code expired at " + pe.Expires.String())
		return nil
	}
	// The NAME comes from the invitation, not from the body (IAMT-337 /
	// 1.4): the administrator chose it when he minted the code, and it
	// is the only thing in this exchange he was in a position to choose.
	// It was validated at mint time and is validated again here, because
	// state.json is a file and a file can be edited.
	name := pe.Name
	// Recorded on the outcome straight away, before anything can refuse:
	// every enrol.failed from here on is ABOUT this registration, and an
	// administrator reading the journal to find out why a machine will
	// not come up needs to see which one it was. Only the success path
	// used to set this, so a refusal named nothing at all.
	out.machine = name
	if !validEnrolMachineName(name) {
		// Not the caller's doing — the entry itself is malformed — so
		// the refusal says nothing about what they sent.
		out.err = errEnrolSecretInvalid("this invitation carries no usable name; ask the administrator for a new one")
		return nil
	}
	// A body that names a machine must agree with the invitation. An
	// old client that still sends its hostname would otherwise be
	// silently overridden, and silently getting a different name than
	// you asked for is worse than being told no.
	if req.Machine != "" && req.Machine != name {
		out.err = errEnrolSecretInvalid("this invitation registers %q; the machine asked to be called %q instead", name, clipForJournal(req.Machine))
		return nil
	}
	// The OS ACCOUNT still comes from the machine, because it is the
	// one fact only the machine knows, and the gateway does not take
	// its word for it: requestedOsUser grants nothing until the
	// gateway's own SSH login as that account succeeds (SPEC §3.4
	// step 3). The refusal quotes what was refused — a person staring
	// at a machine that will not register needs to see what it sent —
	// but quotes it CLIPPED, because the sender is whoever holds an
	// invitation and this text is copied into the journal verbatim.
	if !validEnrolOSUser(req.OSUser) {
		out.err = errEnrolSecretInvalid("osUser %q is not a valid Windows principal or POSIX local name (SPEC §4.3)", clipForJournal(req.OSUser))
		return nil
	}
	// The name was free when the invitation was minted (cmdMachines-
	// EnrolCode checks it there, in front of the person who chose it),
	// but minting and redeeming are minutes apart and a machine can be
	// registered in between. So the check runs again here, inside the
	// transaction that would create the record. It looks at BOTH the
	// machine id and the machine name, since the spec reserves the
	// right to either ("§2.1 reserved-literal set" — a name in id space
	// blocks the same name in label space and vice versa).
	for i := range st.Machines {
		m := &st.Machines[i]
		if m.ID == name || m.Name == name {
			// The remedy belongs in the refusal. A machine being
			// REINSTALLED is handed an invitation for the name it
			// already has, and meets this every time — the ordinary
			// path, not a corner case — and "already in use" alone
			// would leave its owner with nothing to try. Naming the
			// remedy leaks nothing: the name came from the invitation
			// this caller is holding.
			out.err = errEnrolSecretInvalid(
				"the name %q is already registered (a second machine cannot take over an existing identity). "+
					"If this machine is being reinstalled, an administrator must remove the old record first: iamtunnel admin machines remove %s",
				name, name)
			return nil
		}
	}
	// The success path: create the Machine record, drop the pending
	// entry. Both happen in the same atomic write. MachineKey is the
	// long-term ed25519 key the enrolling machine just presented
	// (PROTOCOL §3.2: it memorizes the public key). The name is the
	// administrator's, from the invitation; requestedOsUser is the
	// machine's own report and grants nothing until the gateway's
	// login as that account succeeds.
	osUser := req.OSUser
	st.Machines = append(st.Machines, state.Machine{
		ID:              name,
		Name:            name,
		State:           "enrolled",
		MachineKey:      req.MachineKey,
		OSUser:          osUser,
		RequestedOSUser: osUser,
		OSUserStatus:    state.OSUserStatusPending,
	})
	// The clear is unconditional, same discipline as the existing-machine
	// branch: the pending entry is what makes the secret redeemable, and
	// leaving it behind would turn the one-shot code into a reusable one.
	st.PendingEnrolments = removePendingByHash(st.PendingEnrolments, presented)

	out.res = &enrolResult{
		Machine:         name,
		State:           "enrolled",
		RequestedOSUser: osUser,
		OSUserStatus:    "pending",
		HostKeyStatus:   "unverified",
		ServerTime:      rfc3339(now),
	}
	out.machine = name
	return nil
}

// removePendingByHash drops the pending enrolment whose SecretHash
// matches the given hash and returns the resulting slice. Helper for
// runEnrolFromPending — the obvious "find-and-remove" loop, isolated
// so the test that asserts "the consumed entry is gone" can target
// this function directly.
func removePendingByHash(list []state.PendingEnrolment, hash [32]byte) []state.PendingEnrolment {
	for i := range list {
		if hmac.Equal(list[i].SecretHash[:], hash[:]) {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// validEnrolMachineName applies the §2.1 name grammar to the
// machine's claimed hostname and refuses reserved literals (PROTOCOL
// §2.1 — "machine", "enrol", "bootstrap", "pairing"). The reserved
// set is the same one `machines.enrol-code` itself once consulted
// before IAMT-336 made it argument-less, kept here so an enrol body
// claiming one of those literals still gets a clean refusal.
func validEnrolMachineName(s string) bool {
	if s == "" {
		return false
	}
	if reservedPersonNames[s] {
		return false
	}
	return state.ValidateName(s) == nil
}

// validEnrolOSUser applies the §4.3 osUser grammar to the machine's
// claimed OS account. The gateway accepts either of the two forms
// (Windows principal or POSIX local name) and the per-OS gate at
// `server start` time is what rejects a Windows form on a Linux
// machine (see run_darwin.go and run_linux.go's pre-flight).
func validEnrolOSUser(s string) bool {
	if s == "" {
		return false
	}
	return state.ValidateOSUser(s) == nil
}

// clipForJournalCap is the longest a caller-supplied string may be once
// it reaches events.jsonl. It sits above every value the enrol grammars
// accept — a machine name is at most 32 characters (SPEC §4.3), an
// osUser at most 64 per half — so a LEGITIMATE value is never clipped
// and only a refused one ever is.
const clipForJournalCap = 64

// clipForJournal bounds one caller-supplied string on its way into the
// journal or into a refusal the journal will carry.
//
// The enrol body is the only place in this product where somebody who
// has authenticated with nothing but a one-shot invitation hands the
// gateway free-form strings, and since 1.3 that is by design: the
// machine reports its own hostname and OS account. A refused attempt
// still gets journalled — that is the point of enrol.failed — and
// without a bound the size of that record is chosen by the sender.
// events.jsonl is append-only and lives on the gateway's data disk, so
// one attempt per megabyte is both a disk-space attack and a way to
// bury every other entry in the log an administrator reads to find out
// what happened.
//
// The byte count is kept in the clipped form: an administrator looking
// at the entry should be able to tell "somebody sent 200 kB" from
// "somebody typed a name with a capital letter in it", and the two look
// identical once the tail is gone.
func clipForJournal(s string) string {
	return clipForJournalTo(s, clipForJournalCap)
}

// clipForJournalTo is clipForJournal with the bound named by the caller,
// for a field whose longest legitimate value is not clipForJournalCap -
// an SSH username in auth.* (IAMT-447), say, which may legitimately be 65
// bytes.
func clipForJournalTo(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	return s[:limit] + fmt.Sprintf("… (%d bytes)", len(s))
}

// handleEnrol serves one "enrol"-login connection. Only "enrol" exec
// is permitted; anything else returns E_EXEC_UNKNOWN at the wire and
// closes the channel.
//
// `actor` is the SHA256 fingerprint of the invitation's ephemeral key,
// and it is the ONLY identity that exists at this point: since 1.3 an
// invitation names no machine (SPEC 3.4), so there is no machine id to
// attribute anything to until the exec body arrives and claims one.
// Every event this role writes is attributed to that fingerprint,
// because the alternative — the empty string the old machine-bound
// parameter now always holds — would give an auditor a journal of
// blanks for the whole enrol flow, with no way to tell one session
// from another or to tie a session back to the `machines.enrol-code`
// that minted its invitation.
func (g *Gateway) handleEnrol(sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, actor string) {
	defer sconn.Close()
	g.appendEvent(events.Event{
		Type:   events.EventEnrolStart,
		Actor:  actor,
		Object: "",
		Result: "started",
	})
	go func() {
		for r := range reqs {
			d := sshx.LookupGlobalRequest(r.Type)
			_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, nil)
		}
	}()
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session channels are allowed")
			continue
		}
		ch, chReqs, err := n.Accept()
		if err != nil {
			return
		}
		g.serveEnrolSession(actor, ch, chReqs)
		return
	}
}

// serveEnrolSession is the enrol-login counterpart of
// serveCommandSession: it accepts exactly one "exec" request, parses
// the enrol body, runs it against the pending entry, and writes the
// success or named failure. Anything other than the first request
// being "exec" is refused without consuming the pending entry.
func (g *Gateway) serveEnrolSession(actor string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	finished := false
	finish := func(result any, cerr *cmdError) {
		// Mark the one response as attempted before entering the wire writer: if
		// a broken channel implementation panics there, the recovery below must
		// not recursively try to write another response.
		finished = true
		g.finishEnrol(ch, result, cerr)
	}
	// This is the request boundary: one accepted session channel carries one
	// exec request and one body. Recover here, rather than in handleConn, so an
	// enrol panic becomes an E_INTERNAL response for this channel only; panics
	// elsewhere in the runtime remain visible to their owning tests and handlers.
	defer func() {
		if recovered := recover(); recovered != nil {
			g.appendEvent(events.Event{
				Type:   events.EventEnrolFailed,
				Actor:  actor,
				Object: "",
				Result: "panic",
				Details: map[string]interface{}{
					"reason":  "panic",
					"panic":   fmt.Sprint(recovered),
					"errCode": "E_INTERNAL",
				},
			})
			if !finished {
				finish(nil, errEnrolInternal("internal error handling enrol request"))
			}
		}
		_ = ch.Close()
	}()
	req, ok := <-reqs
	if !ok {
		return
	}
	go func() {
		for extra := range reqs {
			if extra.WantReply {
				_ = extra.Reply(false, nil)
			}
		}
	}()
	if req.Type != "exec" {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		finish(nil, errEnrolExecUnknown(req.Type))
		return
	}
	execMsg, perr := sshx.ParseExec(req.Payload)
	if perr != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		finish(nil, errEnrolProtocol("malformed exec payload"))
		return
	}
	if execMsg.Command != "enrol" {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		finish(nil, errEnrolExecUnknown(execMsg.Command))
		return
	}
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
	body, rerr := readBounded(ch, maxExecRequestBytes)
	if rerr != nil {
		finish(nil, errEnrolProtocol(rerr.Error()))
		return
	}
	// IAMT-451: not while the audit journal cannot record it; and a
	// record this enrolment lost while it ran is answered as lost, not
	// "ok" (F-15, 24.09.2026) -- runAuditedRole.
	now := g.cfg.Now()
	res, cerr := g.runAuditedRole(actor, "the enrolment", func() (any, *cmdError) {
		return g.runEnrol(actor, body, now)
	})
	finish(res, cerr)
}

func (g *Gateway) runEnrol(actor string, body []byte, now time.Time) (any, *cmdError) {
	var req enrolRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, classifyEnrolDecodeErr(err)
	}
	if dec.More() {
		return nil, errEnrolProtocol("request must be exactly one JSON object")
	}
	if req.Proto < 1 {
		return nil, errEnrolProto("missing or non-positive proto")
	}
	if req.Proto > 1 {
		return nil, errEnrolProtoClientNewer(req.Proto)
	}
	if req.Secret == "" {
		return nil, errEnrolSecretInvalid("missing secret")
	}
	if req.MachineKey == "" {
		return nil, errEnrolSecretInvalid("missing machineKey")
	}
	if err := state.ValidateKeyMaterial(req.MachineKey); err != nil {
		return nil, errEnrolProtocol("machineKey: " + err.Error())
	}
	// Hash the presented secret with the gateway's HMAC key and look
	// for the matching pending entry. Lookup is by hashed value, NOT
	// by plaintext - the secret itself is never in state.json. The
	// hash always goes through state.HashEnrolSecret: there is no
	// wrapper and no way to substitute it - no product switch may be
	// able to disable that invariant.
	presented := state.HashEnrolSecret(g.enrolHMAC, []byte(req.Secret))

	// The whole decision is under the store's mutex: read pending,
	// compare hash, expire check, then commit machine + clear pending
	// in one Update. Two concurrent attempts against the same pending
	// entry cannot both win: the first Update sees the pending entry,
	// the second Update sees nil and reports E_ENROL_SECRET_USED.
	//
	// IAMT-336: codes minted by `machines.enrol-code` no longer bind
	// to a machine name, so EVERY code is a brand-new enrolment.
	// re-enrolment of an existing machine is now done by an admin
	// `machines.set-user` flow followed by a fresh enrol from the
	// machine; there is no re-key-only branch here. The
	// Machine.EnrolPending field is removed alongside this commit and
	// runEnrol therefore always takes the PendingEnrolments path.
	var out enrolOutcome
	// The state write and the line that records it are ONE publication
	// (R2-CX F-10, round-2 review 24.09.2026): "gateway backup"
	// reads the pair and accepts it only if nothing moved under it, and
	// this role publishes who may enter the gateway. Holding
	// accessPublishMu from the state write to its journal line keeps a
	// backup from archiving a state that the role's own record does not
	// describe.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	err := g.cfg.Store.Update(func(st *state.State) error {
		// IAMT-336: there is no existing-machine path through runEnrol
		// anymore. `machines.enrol-code` is argument-less and the
		// resulting code lives in state.PendingEnrolments; the machine
		// that consumes it sends its hostname in the enrol body and
		// the new Machine record is built from that. runEnrolFromPending
		// does the whole job and runs the collision check on its own.
		return g.runEnrolFromPending(st, actor, req, presented, now, &out)
	})
	if err != nil {
		return nil, errEnrolInternal("could not commit enrol state: " + err.Error())
	}

	// A successful enrol that re-keys a previously registered machine is
	// the third place reconcileGrants withdraws a grant (state/model.go's
	// RevokedMachineRekeyed). drainRevocations is the only seam that
	// reaches both halves of the consequence: it makes aclE forget the
	// grant (and kill any live session on it), and writes the journal entry
	// that an administrator reads to know WHY the access disappeared. The
	// other two re-key entry points (people.remove, machines.remove) drain
	// their own Store.Update results at admin_role.go:484 and :712; the
	// enrol path was missing this call and so the store's revocation
	// queue silently leaked into the next admin command's journal, with
	// its timestamp and context.
	//
	// Done BEFORE the EventEnrolVerified journal write below: the order
	// matters because applyRevocations writes its own events with the
	// same `now`, and a reader scanning the log in arrival order needs
	// to see "grant revoked" before "machine re-enrolled with a new key".
	g.applyRevocations(now)

	if out.err != nil {
		// Distinguish failure modes in the journal — the operator must
		// be able to tell "wrong code" from "code replayed" from
		// "code expired" without reading the response body.
		var kind string
		switch out.err.code {
		case "E_ENROL_SECRET_USED":
			kind = "replay"
		case "E_ENROL_SECRET_EXPIRED":
			kind = "expired"
		case "E_ENROL_SECRET_INVALID":
			kind = "invalid"
		default:
			kind = "other"
		}
		g.appendEvent(events.Event{
			Type:  events.EventEnrolFailed,
			Actor: actor,
			// The registration this attempt was about — the name from
			// the INVITATION since 1.4, not from the body. A machine
			// being reinstalled meets the collision refusal on every
			// attempt, and an administrator reading the journal to find
			// out why needs to see which name it was. Clipped all the
			// same: a malformed entry could carry anything.
			Object: clipForJournal(out.machine),
			Result: kind,
			Details: map[string]interface{}{
				"reason":  kind,
				"errCode": out.err.code,
				"errMsg":  out.err.message,
			},
		})
		return nil, out.err
	}

	g.appendEvent(events.Event{
		Type:   events.EventEnrolVerified,
		Actor:  actor,
		Object: out.machine,
		Result: "enrolled",
		Details: map[string]interface{}{
			"machine": out.machine,
		},
	})
	return out.res, nil
}

// finishEnrol is the wire-side counterpart of finishCommand: one JSON
// envelope, the channel closed, an exit-status sent. The structure is
// identical, but the helper is local to this file because the enrol
// path does not share admin's commandTable or its E_EXEC_UNKNOWN
// semantics (every non-"enrol" command here is, structurally, the same
// refusal — they just differ in the reason text).
func (g *Gateway) finishEnrol(ch ssh.Channel, result any, cerr *cmdError) {
	var raw []byte
	var procCode uint32
	switch {
	case cerr != nil:
		raw, _ = json.Marshal(execEnvelopeErr{Proto: 1, Caps: []string{}, OK: false,
			Error: &execErrorBody{Code: cerr.code, Message: cerr.message}})
		procCode = uint32(cerr.exit)
	default:
		res, merr := json.Marshal(result)
		if merr != nil {
			raw, _ = json.Marshal(execEnvelopeErr{Proto: 1, Caps: []string{}, OK: false,
				Error: &execErrorBody{Code: "E_INTERNAL", Message: "failed to encode response"}})
			procCode = 70
		} else {
			raw, _ = json.Marshal(execEnvelopeOK{Proto: 1, Caps: []string{}, OK: true, Result: res})
		}
	}
	raw = append(raw, '\n')
	_, _ = ch.Write(raw)
	_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: procCode}))
}

// err helpers — one per PROTOCOL §6.1 code the enrol path can return.

func errEnrolExecUnknown(name string) *cmdError {
	return errf("E_EXEC_UNKNOWN", 2, "unknown command %q on enrol-login (only \"enrol\" is accepted)", name)
}

func errEnrolProtocol(msg string) *cmdError {
	return errf("E_CONTROL_PROTOCOL", 5, "enrol request malformed: %s", msg)
}

func errEnrolProto(msg string) *cmdError {
	return errf("E_PROTO_GATEWAY_NEWER", 4, "%s", msg)
}

func errEnrolProtoClientNewer(p int) *cmdError {
	return errf("E_PROTO_CLIENT_NEWER", 4, "client protocol version %d is newer than this gateway (supports 1)", p)
}

func errEnrolSecretInvalid(format string, a ...any) *cmdError {
	return errf("E_ENROL_SECRET_INVALID", 2, format, a...)
}

func errEnrolSecretExpired(msg string) *cmdError {
	return errf("E_ENROL_SECRET_EXPIRED", 2, "%s", msg)
}

func errEnrolSecretUsed(format string, a ...any) *cmdError {
	return errf("E_ENROL_SECRET_USED", 2, format, a...)
}

func errEnrolInternal(msg string) *cmdError {
	return errf("E_INTERNAL", 70, "%s", msg)
}

// classifyEnrolDecodeErr mirrors admin_role.classifyDecodeErr but for
// the enrol-only JSON decoder. Kept separate because enrol's allowed
// command set is smaller, and a strict parser cannot share state with
// admin's.
func classifyEnrolDecodeErr(err error) *cmdError {
	msg := err.Error()
	if i := strings.Index(msg, "unknown field "); i >= 0 {
		return errEnrolProtocol("unexpected field in request: " + strings.TrimPrefix(msg[i:], "unknown field "))
	}
	return errEnrolProtocol("malformed request JSON: " + err.Error())
}
