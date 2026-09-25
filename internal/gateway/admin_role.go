package gateway

// admin_role.go serves the command-login exec surface (PROTOCOL §1.2,
// §5.1 "command-login", §6): "whoami" for any role, and the SPEC §3.3
// admin command groups for a person whose state.Person.Role is "admin".
//
// This is the "outer part" of the command-login surface: human_role.go
// hands a connection with no machine component over to it. It lives here
// rather than in internal/proto or cmd/iamtunnel. It holds no policy of
// its own: every decision that
// matters (who may access what, whether a session survives) is answered
// by acl.Engine, state.Store and events.Log exactly as construction in
// gateway.go already wires them - this file only parses a command,
// calls the right accepted function, and renders the result.
//
// Scope decisions:
//   - machines.verify explicitly retries the live sshd probe; machines.rekey
//     explicitly replaces a recorded mismatching host key after its observed
//     fingerprint has been confirmed by an administrator.
//   - gateway.backup / gateway.rotate-hostkey (IAMT-174) delegate to
//     internal/gateway/lifecycle.go, the same implementation the local
//     "iamtunnel gateway backup|rotate-hostkey" CLI verbs run
//     (admin_lifecycle.go); admin.claim (bootstrap-login) is still not
//     part of this table: it belongs to the bootstrap role.
//   - machines.enrol-code issues a code but does not persist a
//     verifiable secret (state.Machine has no field for one yet), so
//     the one-time-use/expiry enforcement of PROTOCOL §3.2 is enforced
//     by the machine's own enrol handling, not by
//     this file - it is out of the admin role's testable surface.

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/config"
	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// maxExecRequestBytes bounds the single JSON object PROTOCOL §1.2 allows
// on stdin. The control channel caps its own JSON at 16 KiB (PROTOCOL
// §1.5); admin requests carry more data (e.g. public keys), so the limit
// here is generous but still finite - an unbounded read is a resource
// exhaustion path a garbage/hostile client must not be able to open.
const maxExecRequestBytes = 1 << 20 // 1 MiB

// ---- wire envelope (local to this package, same reasoning as
// control_wire.go: internal/proto is a doc.go stub with no marshaling
// code, so a package that needs marshaling does it itself) ----------

type execEnvelopeOK struct {
	Proto  int             `json:"proto"`
	Caps   []string        `json:"caps"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
}

type execErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// Category is the machine-readable failure class of ONE command's
	// refusal, the risk.key reply's "rejected"|"unavailable" (IAMT-404,
	// PROTOCOL §1.2). Empty on every error that names no class; a client
	// must treat empty as "the gateway says only prose".
	Category string `json:"category,omitempty"`
}

type execEnvelopeErr struct {
	Proto    int            `json:"proto"`
	Caps     []string       `json:"caps"`
	OK       bool           `json:"ok"`
	Error    *execErrorBody `json:"error"`
	MinProto int            `json:"minProto,omitempty"`
}

// cmdError is a dispatch failure carrying both the PROTOCOL §6.1 error
// code and the exit-process code of its third column.
type cmdError struct {
	code    string
	exit    int
	message string
	// category is the optional machine-readable failure class the reply's
	// error body carries beside the prose (IAMT-404). Empty almost always.
	category string
}

func (e *cmdError) Error() string { return e.message }

func errf(code string, exit int, format string, a ...any) *cmdError {
	return &cmdError{code: code, exit: exit, message: fmt.Sprintf(format, a...)}
}

// ---- entry point --------------------------------------------------------

// handleCommand serves one command-login connection (SPEC §5.1: bare
// "<person>", used for whoami and every admin exec). whoami and
// risk.approve are open to any role; every other command in commandTable
// requires the person's
// state.Person.Role to be "admin" - checked fresh on every request, never
// cached, because an admin can be demoted or removed mid-connection. The
// same goes for the key the connection authenticated with (IAMT-449): it
// must still be the person's when each command runs.
func (g *Gateway) handleCommand(sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, person string, key *keyConn) {
	defer sconn.Close()
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
			continue
		}
		// IAMT-172: serveCommandSession writes events.jsonl via the
		// command it runs (runCommand → logAdminOp → appendEvent). It
		// is fire-and-forget under the SSH "exec" model — Close would
		// not wait for it otherwise, and a last write could land in
		// events.jsonl after t.TempDir cleanup begins (the same
		// shape as the sshd probe in IAMT-161). Count it under g.wg
		// so Close blocks until serveCommandSession returns.
		g.wg.Add(1)
		g.serveCmdInFlight.Add(1)
		go func() {
			defer g.wg.Done()
			defer g.serveCmdInFlight.Add(-1)
			g.serveCommandSession(person, key, ch, chReqs)
		}()
	}
}

// serveCommandSession waits for exactly one "exec" request (PROTOCOL
// §1.2: one exec command), runs it, writes the single JSON response
// line plus exit-status, and closes the channel. Any other first request
// (shell, pty-req, ...) is refused: a command-login connection never
// gets an interactive shell.
func (g *Gateway) serveCommandSession(person string, key *keyConn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	req, ok := <-reqs
	if !ok {
		return
	}
	// Drain and refuse anything further on this channel: one exec, once.
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
		return
	}
	execMsg, perr := sshx.ParseExec(req.Payload)
	if perr != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
	body, rerr := readBounded(ch, maxExecRequestBytes)
	if rerr != nil {
		g.finishCommand(ch, nil, errf("E_JSON_INVALID", 3, "%v", rerr))
		return
	}
	// IAMT-449: the key that opened this connection must still be the
	// person's when the command runs, as the role must be (runCommand).
	// Taken away, it gets no answer and no connection - as if it came
	// back now, when the handshake would refuse it.
	//
	// F-07 (24.09.2026): the check and the command hold keyGate together,
	// so a revocation cannot land between them and leave a command that
	// runs after a completed revocation (key_conns.go).
	if commandsThatRevokeKeys[execMsg.Command] {
		keyGate.Lock()
		defer keyGate.Unlock()
	} else {
		keyGate.RLock()
		defer keyGate.RUnlock()
	}
	if !g.keyStillHeld(key) {
		g.AuthDenied(key.addr, person, key.fingerprint, "the key is no longer registered to this person")
		_ = key.close()
		return
	}
	if afterKeyCheckFn != nil {
		afterKeyCheckFn(person, execMsg.Command)
	}
	result, cerr := g.runCommand(person, execMsg.Command, body)
	g.finishCommand(ch, result, cerr)
	// people.keys.remove and people.remove take keys away; every
	// connection one of them opened ends now - this one too, after its
	// answer.
	g.cutRemovedKeys()
}

func readBounded(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, fmt.Errorf("reading request: %w", err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("request exceeds %d bytes", max)
	}
	return b, nil
}

func (g *Gateway) finishCommand(ch ssh.Channel, result any, cerr *cmdError) {
	var raw []byte
	var procCode uint32
	switch {
	case cerr != nil:
		raw, _ = json.Marshal(execEnvelopeErr{Proto: 1, Caps: []string{}, OK: false,
			Error: &execErrorBody{Code: cerr.code, Message: cerr.message, Category: cerr.category}})
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

// ---- dispatch ------------------------------------------------------------

type commandSpec struct {
	adminOnly bool
	// auditOps names the ops this command's own admin.op lines carry; the
	// wire name is used when this is empty. The verdict on a lost record
	// is matched against these, so a command whose line is called
	// something else has to say so (risk.key writes risk.key.replace) -
	// without it its lost line is nobody's and the command answers "ok"
	// for work it did not record (F-02, round-3 review 24.09.2026).
	// The exhaustive test in r3_f02_audit_attribution_test.go holds the
	// table and the code together.
	auditOps []string
	// readOnly marks a command that writes nothing to the audit journal.
	// Only these run while the journal cannot write (IAMT-451): they are
	// how an operator finds out what is wrong. Everything else is refused
	// then, so a command added later without the mark fails closed.
	readOnly bool
	run      func(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError)
}

// ownRecords is the ops this command writes about itself: what its
// verdict on a lost journal line is matched against.
func (s commandSpec) ownRecords(command string) []string {
	if len(s.auditOps) == 0 {
		return []string{command}
	}
	return s.auditOps
}

var commandTable = map[string]commandSpec{
	"whoami":                   {readOnly: true, run: cmdWhoami},
	"machines.mine":            {readOnly: true, run: cmdMachinesMine},
	"people.add":               {adminOnly: true, run: cmdPeopleAdd},
	"people.rename":            {adminOnly: true, run: cmdPeopleRename},
	"people.remove":            {adminOnly: true, run: cmdPeopleRemove},
	"people.list":              {adminOnly: true, readOnly: true, run: cmdPeopleList},
	"people.keys.add":          {adminOnly: true, run: cmdPeopleKeysAdd},
	"people.keys.remove":       {adminOnly: true, run: cmdPeopleKeysRemove},
	"people.connection-string": {adminOnly: true, readOnly: true, run: cmdPeopleConnString},
	"pairing.start":            {adminOnly: true, run: cmdAdminPairingStart},
	"pairing.stop":             {adminOnly: true, run: cmdAdminPairingStop},
	"machines.list":            {adminOnly: true, readOnly: true, run: cmdMachinesList},
	"machines.remove":          {adminOnly: true, run: cmdMachinesRemove},
	"machines.rename":          {adminOnly: true, run: cmdMachinesRename},
	"grants.set-caps":          {adminOnly: true, run: cmdGrantsSetCaps},
	"grants.extend":            {adminOnly: true, run: cmdGrantsExtend},
	"machines.enrol-code":      {adminOnly: true, run: cmdMachinesEnrolCode},
	"machines.set-user":        {adminOnly: true, run: cmdMachinesSetUser},
	"machines.verify":          {adminOnly: true, run: cmdMachinesVerify},
	"machines.rekey":           {adminOnly: true, run: cmdMachinesRekey},
	"grants.grant":             {adminOnly: true, run: cmdGrantsGrant},
	"grants.revoke":            {adminOnly: true, run: cmdGrantsRevoke},
	"grants.list":              {adminOnly: true, readOnly: true, run: cmdGrantsList},
	"sessions.active":          {adminOnly: true, readOnly: true, run: cmdSessionsActive},
	"sessions.history":         {adminOnly: true, readOnly: true, run: cmdSessionsHistory},
	"sessions.kill":            {adminOnly: true, run: cmdSessionsKill},
	"sessions.tail":            {adminOnly: true, run: cmdSessionsTail},
	"recordings.list":          {adminOnly: true, readOnly: true, run: cmdRecordingsList},
	"recordings.fetch":         {adminOnly: true, run: cmdRecordingsFetch},
	"gateway.status":           {adminOnly: true, readOnly: true, run: cmdGatewayStatus},
	"gateway.fingerprint":      {adminOnly: true, readOnly: true, run: cmdGatewayFingerprint},
	"gateway.backup":           {adminOnly: true, run: cmdGatewayBackup},
	"gateway.rotate-hostkey":   {adminOnly: true, run: cmdGatewayRotateHostkey},
	"goal.set":                 {adminOnly: true, run: cmdGoalSet},
	"goal.current":             {adminOnly: true, readOnly: true, run: cmdGoalCurrent},
	"goal.history":             {adminOnly: true, readOnly: true, run: cmdGoalHistory},
	"goal.list":                {adminOnly: true, readOnly: true, run: cmdGoalList},
	"risk.check":               {adminOnly: true, readOnly: true, run: cmdRiskCheck},
	"risk.mode":                {adminOnly: true, run: cmdRiskMode},
	"risk.source":              {adminOnly: true, run: cmdRiskSource},
	// risk.key's own line is called risk.key.replace (the op is older than
	// the wire name); declaring it is what makes the lost-record verdict
	// about THIS command's line (F-02, round 3).
	"risk.key": {adminOnly: true, auditOps: []string{"risk.key.replace"}, run: cmdRiskKeyReplace},
	// A person approves only their own pending red command. This is
	// intentionally not adminOnly: an administrator can configure the mode,
	// but the human who launched the command is the only approver.
	"risk.approve": {adminOnly: false, run: cmdRiskApprove},
	"risk.pending": {adminOnly: false, readOnly: true, run: cmdRiskPending},
	"risk.deny":    {adminOnly: false, run: cmdRiskDeny},
}

// CommandNames returns every exec command this gateway's command table
// knows, sorted. It is the enumeration source for the RBAC tests that
// prove the one-shot enrol/bootstrap logins cannot run anything but
// their single command: the list must come from the gateway itself, so
// a command added to commandTable later is automatically covered by
// the enumeration. The returned slice is a copy; callers cannot modify
// the table through it.
func CommandNames() []string {
	names := make([]string, 0, len(commandTable))
	for name := range commandTable {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// runCommand looks up and authorizes the command, then runs it. A panic
// inside any handler (e.g. a garbage-shaped-but-valid-JSON request that
// trips an unanticipated assumption) is turned into E_INTERNAL rather
// than taking the whole connection handler down.
func (g *Gateway) runCommand(person, command string, body []byte) (result any, cerr *cmdError) {
	defer func() {
		if r := recover(); r != nil {
			result, cerr = nil, errf("E_INTERNAL", 70, "internal error handling %q: %v", command, r)
		}
	}()
	spec, ok := commandTable[command]
	if !ok {
		return nil, errf("E_EXEC_UNKNOWN", 2, "unknown command %q", command)
	}
	now := g.cfg.Now()
	if spec.adminOnly {
		st := g.cfg.Store.Get()
		role, known := personRoleOf(st, person)
		if !known || role != "admin" {
			// PROTOCOL §6.1's closed error dictionary has no separate
			// "not an admin" code; a non-admin is refused exactly like an
			// unknown command so the response never confirms which admin
			// commands exist for a person who cannot run any of them.
			return nil, errf("E_EXEC_UNKNOWN", 2, "unknown command %q", command)
		}
	}
	if !spec.readOnly {
		// IAMT-451: nothing that has to be put on record is done while the
		// journal cannot write; and a command whose own record was lost
		// while it ran has done its work, which it says instead of "ok".
		if cerr := g.auditRefusal(); cerr != nil {
			return nil, cerr
		}
		// F-01 (round-1 review, 24.09.2026) and F-03 (round-2 review,
		// 24.09.2026): the answer is about the journal writes THIS
		// command lost. It used to be about every write the gateway lost,
		// so a parallel administrator's failed write turned a command
		// that had been recorded into "carried out, but nowhere on
		// record"; watching the person alone then left the same false
		// verdict between two commands of one administrator, whose own
		// record may be in the journal while the other's was refused. A
		// command's own records are the ones it writes about itself
		// (logAdminOp writes "<op>:<result>"), so the watch names the
		// person AND the command.
		watch := g.audit.watchCmd(person, spec.ownRecords(command))
		if afterAuditWatchFn != nil {
			afterAuditWatchFn(person, command)
		}
		defer func() {
			if cerr == nil && g.audit.lostSince(watch) {
				result, cerr = nil, g.auditLost(command)
			}
		}()
	}
	return spec.run(g, person, now, body)
}

// ---- shared helpers -------------------------------------------------------

func personRoleOf(st state.State, name string) (string, bool) {
	for _, p := range st.People {
		if p.Name == name {
			return p.Role, true
		}
	}
	return "", false
}

var reservedPersonNames = map[string]bool{"machine": true, "enrol": true, "bootstrap": true, "pairing": true}

func decodeStrict(body []byte, v any) *cmdError {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return classifyDecodeErr(err)
	}
	if dec.More() {
		return errf("E_JSON_INVALID", 3, "request must be exactly one JSON object")
	}
	return nil
}

// classifyDecodeErr tells an unknown-field rejection (PROTOCOL §1.3:
// any field absent from the message's own shape yields
// E_JSON_FIELD_UNKNOWN") from every other decode failure, the same way
// internal/config's ParseFile already does for the config file.
//
// The dependency on the wording is deliberate and is as narrow as the
// standard library allows (F-07, round-1 review 24.09.2026). Classic
// encoding/json builds this one error as text and nothing else:
// `saveError(fmt.Errorf("json: unknown field %q", key))` (Go 1.27,
// encoding/json/decode.go) - it is neither a *json.SyntaxError nor a
// *json.UnmarshalTypeError, so there is no typed handle to take instead.
// A typed one does exist in encoding/json/v2 (ErrUnknownName inside
// *jsonv2.SemanticError), and moving the strict decode there is the way
// to be rid of the string match - but that changes the decoder behind
// every command body and the message this product's tests and documents
// quote, so that swap is deliberately left out of scope for a low
// finding and stays as it is by design.
//
// What keeps the match honest meanwhile is that a Go release renaming the
// phrase cannot pass unnoticed: internal/config/settings_test.go pins the
// rendered config message, and TestIAMT336_NoOldFields_AtWire pins the
// code the wire answers for an unknown field. Either goes red on the day
// the wording changes, instead of the classification quietly degrading to
// E_JSON_INVALID.
func classifyDecodeErr(err error) *cmdError {
	msg := err.Error()
	if i := strings.Index(msg, "unknown field "); i >= 0 {
		return errf("E_JSON_FIELD_UNKNOWN", 3, "unexpected field in request: %s", strings.TrimPrefix(msg[i:], "unknown field "))
	}
	return errf("E_JSON_INVALID", 3, "malformed request JSON: %v", err)
}

func checkProto(p int) *cmdError {
	switch {
	case p < 1:
		return errf("E_PROTO_GATEWAY_NEWER", 4, "request is missing proto (or proto < 1); minimum supported is 1")
	case p > 1:
		return errf("E_PROTO_CLIENT_NEWER", 4, "client protocol version %d is newer than this gateway (supports 1)", p)
	}
	return nil
}

// applyRevocations drains every grant the store withdrew on its own
// during the last mutation (a removed/re-keyed machine, a removed
// person) and makes both live worlds agree with it: acl.Engine forgets
// the grant and kills any of its live sessions, and the journal records
// why (state.Revocation -> events.NewGrantRevokedEvent is exactly the
// seam events/event.go's doc comment describes).
//
// It returns how many live sessions went with the grants, for the caller
// whose own journal line has to carry the number (P-02, round-1 review
// 24.09.2026): machines.remove ends every session on the machine it removes
// and said nothing about it, while its siblings (grants.revoke,
// people.rename, grants.set-caps, grants.extend) all count them. The number
// is what acl.Engine itself returned, so the grant.revoke lines and the
// admin.op line agree.
func (g *Gateway) applyRevocations(now time.Time) int {
	killed := 0
	for _, rev := range g.cfg.Store.DrainRevocations() {
		n, _ := g.aclE.Revoke(rev.Person, rev.Machine, now)
		killed += n
		g.appendEvent(events.NewGrantRevokedEvent(rev, state.NewZonedTime(now)))
	}
	return killed
}

func (g *Gateway) logAdminOp(actor, op, object, result string, details map[string]interface{}) {
	g.appendEvent(events.Event{Type: events.EventAdminOp, Actor: actor, Object: object, Result: op + ":" + result, Details: details})
}

func viewKeys(keys []state.Key) []keyView {
	out := make([]keyView, 0, len(keys))
	for _, k := range keys {
		out = append(out, keyView{Fingerprint: k.Fingerprint, Pub: k.Pub, Added: k.Added.String()})
	}
	return out
}

type keyView struct {
	Fingerprint string `json:"fingerprint"`
	Pub         string `json:"pubkey"`
	Added       string `json:"added"`
}

type personView struct {
	Name string    `json:"name"`
	Role string    `json:"role"`
	Keys []keyView `json:"keys"`
}

// ---- whoami ---------------------------------------------------------------

type whoamiResult struct {
	Subject    string `json:"subject"`
	Role       string `json:"role"`
	ServerTime string `json:"serverTime"`
	Person     string `json:"person,omitempty"`
}

func cmdWhoami(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	st := g.cfg.Store.Get()
	role, known := personRoleOf(st, person)
	if !known {
		role = "user"
	}
	return whoamiResult{Subject: person, Role: role, ServerTime: rfc3339(now), Person: person}, nil
}

// ---- machines.mine ----------------------------------------------------------

type machineMineView struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Until         string `json:"until"`
	Online        bool   `json:"online"`
	State         string `json:"state"`
	SSHDListening bool   `json:"sshdListening"`
	DoorOpen      bool   `json:"doorOpen"`
	// Caps is this person's own grant capability on this machine
	// (["shell"] or ["exec"], acl.Grant's own field) — added 1.8 so a
	// client can tell an exec-only grant apart from a shell
	// grant before ever attempting "connect", instead of only finding
	// out from the SSH-level refusal. It is the same value grants.grant
	// already accepts and admin exec already returns; machines.mine
	// simply had never carried it for the person it belongs to.
	Caps []string `json:"caps"`
}

func cmdMachinesMine(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	grants := g.aclE.GrantsFor(person, now)
	st := g.cfg.Store.Get()
	out := make([]machineMineView, 0, len(grants))
	for _, gr := range grants {
		m, ok := st.MachineByID(gr.Machine)
		if !ok {
			continue
		}
		var until string
		if gr.Until != nil {
			until = rfc3339(*gr.Until)
		}
		mv := machineMineView{
			ID:    m.ID,
			Name:  m.Name,
			Until: until,
			State: m.State,
			Caps:  append([]string(nil), gr.Caps...),
		}
		if mc, ok := g.reg.get(m.ID); ok {
			snap := mc.doorMachine.Snapshot()
			mv.Online = snap.Online
			mv.DoorOpen = snap.State == "open"
		}
		// SSHDListening reflects whether the machine has passed verification
		// (State == "verified" or HostKeyStatus == match, without mismatch) while
		// having an active reverse tunnel (Online == true).
		//
		// CONTRACT / LIMITATION:
		// This is derived from historical verification and online tunnel status,
		// NOT a real-time live TCP probe to the target machine's local sshd port.
		// A live probe during listing would require either:
		//   (a) Opening the door (mc.reserve) and doing a nested handshake to 127.0.0.1:22
		//       for every listed machine, which consumes door tokens, drops ephemeral
		//       keys via watchdog, and introduces high network latency; or
		//   (b) An out-of-band daemon healthcheck protocol not present in the design.
		// Therefore, if sshd crashes while the machine server process keeps its
		// tunnel online, SSHDListening remains true until an actual human session
		// attempts connection and hits DenyMachineSSHDUnreachable.
		mv.SSHDListening = mv.Online && (m.State == "verified" || m.HostKeyStatus == state.HostKeyStatusMatch) && m.HostKeyStatus != state.HostKeyStatusMismatch
		out = append(out, mv)
	}
	return map[string]any{"machines": out}, nil
}

// ---- people.* ---------------------------------------------------------------

func cmdPeopleAdd(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int      `json:"proto"`
		Name  string   `json:"name"`
		Role  string   `json:"role"`
		Keys  []string `json:"keys"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if !config.ValidName(req.Name) {
		return nil, errf("E_JSON_INVALID", 3, "name %q is not valid — want [a-z0-9][a-z0-9._-]{0,31} (SPEC §4.3)", req.Name)
	}
	if reservedPersonNames[req.Name] {
		return nil, errf("E_PERSON_NAME_RESERVED", 2, "name %q is reserved by the protocol and cannot be a person (SPEC §2.1)", req.Name)
	}
	if req.Role != "user" && req.Role != "admin" {
		return nil, errf("E_JSON_INVALID", 3, "role %q must be \"user\" or \"admin\"", req.Role)
	}
	if len(req.Keys) == 0 {
		return nil, errf("E_JSON_INVALID", 3, "keys must be a non-empty array of OpenSSH public key lines")
	}
	keys := make([]state.Key, 0, len(req.Keys))
	seen := make(map[string]bool, len(req.Keys))
	for _, line := range req.Keys {
		if _, err := config.CheckPublicKey(line); err != nil {
			return nil, errf("E_JSON_INVALID", 3, "key %q is invalid: %v", line, err)
		}
		fp, err := state.ComputeFingerprint(line)
		if err != nil {
			return nil, errf("E_JSON_INVALID", 3, "key %q: %v", line, err)
		}
		if seen[fp] {
			return nil, errf("E_JSON_INVALID", 3, "key %q is repeated in the request", line)
		}
		seen[fp] = true
		keys = append(keys, state.Key{Fingerprint: fp, Pub: line, Added: state.NewZonedTime(now)})
	}
	var created state.Person
	// The state write and the line that records it are ONE publication
	// (R2-CX F-10, round-2 review 24.09.2026): whoever reads the
	// pair - "gateway backup" above all, which reads state.json and the
	// journal and accepts only a pair that did not move under it - has to
	// see both or neither. Taking accessPublishMu here, as the grants
	// commands do, is what makes the two writes atomic to that reader;
	// without it a backup taken between them archives a state its own
	// journal does not describe.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	err := g.cfg.Store.Update(func(st *state.State) error {
		if st.HasPerson(req.Name) {
			return fmt.Errorf("person %q already exists", req.Name)
		}
		created = state.Person{Name: req.Name, Role: req.Role, Keys: keys}
		st.People = append(st.People, created)
		return nil
	})
	if err != nil {
		return nil, errf("E_CONFLICT", 2, "%v", err)
	}
	// Who became what, with which keys (R4 F-10): "people.add backup ok"
	// alone never said backup was made an administrator.
	addedFPs := make([]string, 0, len(keys))
	for _, k := range keys {
		addedFPs = append(addedFPs, k.Fingerprint)
	}
	g.logAdminOp(person, "people.add", req.Name, "ok", map[string]interface{}{"role": req.Role, "fingerprints": addedFPs})
	return personView{Name: created.Name, Role: created.Role, Keys: viewKeys(created.Keys)}, nil
}

// errLastAdmin travels out of the store's transaction so the refusal can
// be graded as a conflict rather than an internal fault: the update
// closure may only return error, and E_INTERNAL 70 would tell the person
// the gateway broke when in fact it declined.
var errLastAdmin = errors.New("last administrator")

func cmdPeopleRemove(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int    `json:"proto"`
		Name  string `json:"name"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	found := false
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	// The gateway refuses to remove its last administrator, whoever asks
	// and however sure they are (21.09.2026).
	//
	// Until now nothing stopped it. Over SSH that took `--yes` and the
	// name typed out, which is deliberate enough that the hole never
	// opened; on 21.09 this verb also became a button in the window, one
	// press away from a gateway with nobody left who may administer it.
	// Recovery from that is `gateway install --rebootstrap` over SSH --
	// possible, but it means the owner finds out by being locked out.
	//
	// Removing yourself is allowed while another administrator remains:
	// handing over and stepping down is a real errand, and the survivor
	// can undo it. Removing the last one is not an errand, it is an
	// accident with a plausible-looking button.
	if err := g.cfg.Store.Update(func(st *state.State) error {
		victim := -1
		admins := 0
		for i, p := range st.People {
			if p.Role == "admin" {
				admins++
			}
			if p.Name == req.Name {
				victim = i
			}
		}
		if victim < 0 {
			return nil
		}
		if st.People[victim].Role == "admin" && admins <= 1 {
			return errLastAdmin
		}
		st.People = append(st.People[:victim], st.People[victim+1:]...)
		found = true
		return nil
	}); err != nil {
		if errors.Is(err, errLastAdmin) {
			return nil, errf("E_CONFLICT", 2,
				"%q is the only administrator this gateway has, and removing it would leave nobody who may administer it. "+
					"Make somebody else an administrator first -- open a pairing window and let them join -- and then remove this one.",
				req.Name)
		}
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	if !found {
		return nil, errf("E_NOT_FOUND", 2, "no such person %q", req.Name)
	}
	if accessPublishPause != nil {
		accessPublishPause()
	}
	g.applyRevocations(now)
	g.logAdminOp(person, "people.remove", req.Name, "ok", nil)
	return map[string]string{"removed": req.Name}, nil
}

// cmdPeopleRename changes a person's name (23.09.2026). Until now a typo
// in a name could only be fixed by removing the record and adding it
// again -- which takes the grants, the goals and the keys with it.
//
// The state write and the engine re-publication are one piece, exactly
// as for grants.grant/revoke (the accessPublishMu seam): the rename
// moves the grants in the state, and the engine must never be left
// holding the old name's live grants while a parallel administrator's
// command could revive or remove them mid-flight. Publication itself is
// revoke-then-readd under the new name, so a session already open under
// the old name dies by the revoke rules: the person's key now
// authenticates as the new name, and the old name must not keep any
// live access anywhere.
//
// What deliberately does NOT move: the journal. Lines already written
// name the person as they were at the time; a journal rewritten after
// the fact would be a journal nobody could audit.
func cmdPeopleRename(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int    `json:"proto"`
		From  string `json:"from"`
		To    string `json:"to"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if !config.ValidName(req.To) {
		return nil, errf("E_JSON_INVALID", 3, "name %q is not valid — want [a-z0-9][a-z0-9._-]{0,31} (SPEC §4.3)", req.To)
	}
	if reservedPersonNames[req.To] {
		return nil, errf("E_PERSON_NAME_RESERVED", 2, "name %q is reserved by the protocol and cannot be a person (SPEC §2.1)", req.To)
	}

	// moved is the person's still-live grants, captured inside the same
	// transaction that renames them: these are what the engine holds
	// under the old name, and what must reappear under the new one.
	type movedGrant struct {
		machine string
		until   *time.Time
		caps    []string
	}
	var moved []movedGrant
	renamed := false
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		for _, gr := range st.Grants {
			if gr.Person != req.From {
				continue
			}
			if gr.Until != nil && !gr.Until.After(now) {
				continue // already expired: the engine holds nothing for it
			}
			mg := movedGrant{machine: gr.Machine, caps: append([]string(nil), gr.Caps...)}
			if gr.Until != nil {
				u := gr.Until.Time
				mg.until = &u
			}
			moved = append(moved, mg)
		}
		ok, err := st.RenamePerson(req.From, req.To)
		if err != nil {
			return err
		}
		renamed = ok
		return nil
	}); err != nil {
		return nil, errf("E_CONFLICT", 2, "%v", err)
	}
	if !renamed {
		return nil, errf("E_NOT_FOUND", 2, "no such person %q", req.From)
	}
	if accessPublishPause != nil {
		accessPublishPause()
	}
	killed := 0
	for _, mg := range moved {
		n, err := g.aclE.RevokeBecause(req.From, mg.machine, now, acl.DenyPersonRenamed)
		if err != nil && err != acl.ErrNoGrant {
			return nil, errf("E_INTERNAL", 70, "%v", err)
		}
		killed += n
	}
	for _, mg := range moved {
		if err := g.aclE.AddGrant(acl.Grant{Person: req.To, Machine: mg.machine, Until: mg.until, Caps: mg.caps}, now); err != nil {
			return nil, errf("E_INTERNAL", 70, "rename was persisted but the new name could not be activated: %v", err)
		}
	}
	g.logAdminOp(person, "people.rename", req.From+" -> "+req.To, "ok",
		map[string]interface{}{"killedSessions": killed})
	return map[string]any{"from": req.From, "to": req.To, "terminatedSessions": killed}, nil
}

func cmdPeopleList(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	st := g.cfg.Store.Get()
	out := make([]personView, 0, len(st.People))
	for _, p := range st.People {
		out = append(out, personView{Name: p.Name, Role: p.Role, Keys: viewKeys(p.Keys)})
	}
	return map[string]any{"people": out}, nil
}

// keyTakenError travels out of the store's transaction the way
// errLastAdminKey does: the collision is a conflict with the state, not an
// internal fault, and carrying the owner out with it is what lets the
// command answer in its own words (R2-MX F-01, round-2 review 24.09.2026).
type keyTakenError struct{ owner string }

func (e *keyTakenError) Error() string { return "key is already registered for " + e.owner }

// keyOwnerOtherThan is the identity that already carries this fingerprint
// when it is somebody other than name - "person \"alice\"",
// "machine \"vm1\"" or "machine \"vm1\" door key" - and "" when the
// fingerprint is nobody else's. The person being edited is skipped because
// the caller answers for them separately ("key is already registered for
// %q"), and a key already on the same person is an ordinary duplicate
// rather than somebody else's key.
//
// The machine keys are asked about for the same reason the people's are:
// §6.1's one namespace of fingerprints covers people, machines and door
// keys alike, and state/validate.go counts them together
// (seenFingerprints) - so a command that only looked at st.People would be
// leaving a third of the question to the validator.
func keyOwnerOtherThan(st *state.State, fp, name string) string {
	for _, p := range st.People {
		if p.Name == name {
			continue
		}
		for _, k := range p.Keys {
			if k.Fingerprint == fp {
				return fmt.Sprintf("person %q", p.Name)
			}
		}
	}
	for _, m := range st.Machines {
		if m.MachineKey != "" {
			if mfp, err := state.ComputeFingerprint(m.MachineKey); err == nil && mfp == fp {
				return fmt.Sprintf("machine %q", m.ID)
			}
		}
		if m.Door != nil && m.Door.PubKey != "" {
			if dfp, err := state.ComputeFingerprint(m.Door.PubKey); err == nil && dfp == fp {
				return fmt.Sprintf("machine %q door key", m.ID)
			}
		}
	}
	return ""
}

func cmdPeopleKeysAdd(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto  int    `json:"proto"`
		Name   string `json:"name"`
		Pubkey string `json:"pubkey"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if _, err := config.CheckPublicKey(req.Pubkey); err != nil {
		return nil, errf("E_JSON_INVALID", 3, "%v", err)
	}
	fp, err := state.ComputeFingerprint(req.Pubkey)
	if err != nil {
		return nil, errf("E_JSON_INVALID", 3, "%v", err)
	}
	var added state.Key
	found := false
	// Why the transaction refused, for the journal line below: a refusal
	// that leaves no trace is the one errand an audit trail is read for
	// (R2-MX F-03, round-2 review 24.09.2026).
	var refused map[string]interface{}
	// The state write and the line that records it are ONE publication
	// (R2-CX F-10, round-2 review 24.09.2026): whoever reads the
	// pair - "gateway backup" above all, which reads state.json and the
	// journal and accepts only a pair that did not move under it - has to
	// see both or neither. Taking accessPublishMu here, as the grants
	// commands do, is what makes the two writes atomic to that reader;
	// without it a backup taken between them archives a state its own
	// journal does not describe.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		// R2-MX F-01 (round-2 review 24.09.2026): a key belongs to exactly
		// one identity, and this command asks that question itself. Until
		// now it looked only at the keys of the person being edited, and
		// the state validator refused the collision a moment later
		// (state/validate.go, "keys must be uniquely owned") - the right
		// barrier for the file, in the wrong voice for the administrator:
		// "updated state validation failed: duplicate key fingerprint ...
		// shared between ..." reads as a fault of the gateway's own state
		// rather than an answer about the key, and names the other owner
		// only by accident of its wording.
		if owner := keyOwnerOtherThan(st, fp, req.Name); owner != "" {
			refused = map[string]interface{}{"reason": "key already registered", "existingOwner": owner, "fingerprint": fp}
			return &keyTakenError{owner: owner}
		}
		for i := range st.People {
			if st.People[i].Name != req.Name {
				continue
			}
			for _, k := range st.People[i].Keys {
				if k.Fingerprint == fp {
					refused = map[string]interface{}{"reason": "key already registered for this person", "fingerprint": fp}
					return fmt.Errorf("key is already registered for %q", req.Name)
				}
			}
			added = state.Key{Fingerprint: fp, Pub: req.Pubkey, Added: state.NewZonedTime(now)}
			st.People[i].Keys = append(st.People[i].Keys, added)
			found = true
			return nil
		}
		return nil
	}); err != nil {
		if refused != nil {
			g.logAdminOp(person, "people.keys.add", req.Name, "failed", refused)
		}
		var taken *keyTakenError
		if errors.As(err, &taken) {
			return nil, errf("E_CONFLICT", 2,
				"this key is already registered for %s — a fingerprint belongs to one identity only (§6.1), so it cannot be added to %q as well; remove it there first if the key really moved",
				taken.owner, req.Name)
		}
		return nil, errf("E_CONFLICT", 2, "%v", err)
	}
	if !found {
		g.logAdminOp(person, "people.keys.add", req.Name, "failed", map[string]interface{}{"reason": "no such person", "fingerprint": fp})
		return nil, errf("E_NOT_FOUND", 2, "no such person %q", req.Name)
	}
	g.logAdminOp(person, "people.keys.add", req.Name, "ok", map[string]interface{}{"fingerprint": fp})
	return map[string]any{"person": req.Name, "key": keyView{Fingerprint: added.Fingerprint, Pub: added.Pub, Added: added.Added.String()}}, nil
}

// errLastAdminKey travels out of the store's transaction for the same
// reason errLastAdmin does: the refusal is a conflict with the state, not
// an internal fault.
var errLastAdminKey = errors.New("last administrator key")

// adminKeysInState counts the keys all administrators carry together.
func adminKeysInState(st *state.State) int {
	n := 0
	for _, p := range st.People {
		if p.Role == "admin" {
			n += len(p.Keys)
		}
	}
	return n
}

func cmdPeopleKeysRemove(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto       int    `json:"proto"`
		Name        string `json:"name"`
		Fingerprint string `json:"fingerprint"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	fp, err := config.NormalizeFingerprint(req.Fingerprint)
	if err != nil {
		return nil, errf("E_JSON_INVALID", 3, "%v", err)
	}
	found := false
	// Why the transaction refused, for the journal line below (R2-MX F-03,
	// round-2 review 24.09.2026): the refusals here are exactly the errands
	// an operator reads the history for - a key that is not there, a person
	// that is not there, and an attempt to take the last administrator key
	// the gateway has, which is an attempt to lock everybody out.
	var refused map[string]interface{}
	// The state write and the line that records it are ONE publication
	// (R2-CX F-10, round-2 review 24.09.2026): whoever reads the
	// pair - "gateway backup" above all, which reads state.json and the
	// journal and accepts only a pair that did not move under it - has to
	// see both or neither. Taking accessPublishMu here, as the grants
	// commands do, is what makes the two writes atomic to that reader;
	// without it a backup taken between them archives a state its own
	// journal does not describe.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		for i := range st.People {
			if st.People[i].Name != req.Name {
				continue
			}
			for j, k := range st.People[i].Keys {
				if k.Fingerprint != fp {
					continue
				}
				// The gateway refuses to take the last administrator key
				// the state has, whoever asks (24.09.2026). people.remove
				// guards the last administrator record, but until now the
				// key next to it was unprotected: the only administrator
				// could remove their own last key, be told ok, and lose
				// every connection that key had opened to cutRemovedKeys
				// -- leaving an administrator record nobody can
				// authenticate as, recoverable only by rebootstrap. The
				// count runs over all administrators, not this one: two
				// admins, one of them already keyless, is the same lockout
				// once the keyed one's last key goes. Taking one of
				// several keys, or the last key of an admin while another
				// admin keeps theirs, stays an ordinary errand.
				if st.People[i].Role == "admin" && adminKeysInState(st) <= 1 {
					refused = map[string]interface{}{"reason": "last administrator key", "fingerprint": fp}
					return errLastAdminKey
				}
				st.People[i].Keys = append(st.People[i].Keys[:j], st.People[i].Keys[j+1:]...)
				found = true
				return nil
			}
			refused = map[string]interface{}{"reason": "person has no such key", "fingerprint": fp}
			return fmt.Errorf("person %q has no key with fingerprint %s", req.Name, fp)
		}
		return nil
	}); err != nil {
		if refused != nil {
			g.logAdminOp(person, "people.keys.remove", req.Name, "failed", refused)
		}
		if errors.Is(err, errLastAdminKey) {
			return nil, errf("E_CONFLICT", 2,
				"this is the last administrator key the gateway has left, and removing it would leave nobody who may sign in to administer it. "+
					"Add a key for an administrator first (people.keys.add) or let a new administrator join through a pairing window, and then remove this one.")
		}
		return nil, errf("E_NOT_FOUND", 2, "%v", err)
	}
	if !found {
		g.logAdminOp(person, "people.keys.remove", req.Name, "failed", map[string]interface{}{"reason": "no such person", "fingerprint": fp})
		return nil, errf("E_NOT_FOUND", 2, "no such person %q", req.Name)
	}
	g.logAdminOp(person, "people.keys.remove", req.Name, "ok", map[string]interface{}{"fingerprint": fp})
	return map[string]string{"person": req.Name, "removedFingerprint": fp}, nil
}

func cmdPeopleConnString(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int    `json:"proto"`
		Name  string `json:"name"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	st := g.cfg.Store.Get()
	if !st.HasPerson(req.Name) {
		return nil, errf("E_NOT_FOUND", 2, "no such person %q", req.Name)
	}
	fp := strings.TrimPrefix(auth.Fingerprint(g.cfg.HostKey.PublicKey()), "SHA256:")
	cs := fmt.Sprintf("iamtunnel://%s:%d/%s#%s", g.cfg.PublicHost, g.cfg.PublicPort, req.Name, fp)
	return map[string]string{"connectionString": cs}, nil
}

// ---- machines.* -------------------------------------------------------------

// machineView is what `machines.list` renders and what internal/admin's
// MachineView decodes with DisallowUnknownFields, so the two stay in lockstep
// field for field.
//
// The five §4.3 fields are here because an administrator who cannot see
// hostKeyStatus cannot act on it: "mismatch" is a machine whose sshd presented
// a foreign key and which must not get a door until it is re-verified, while
// "unverified" means no comparison has ever happened. Collapsing those two
// into one silence is the defect IAMT-91 exists to remove. The two optional
// fields are omitempty for the reason they are pointers in the model: absent
// means "never seen", which is not the same as "seen as empty".
type machineView struct {
	ID                  string `json:"id"`
	Name                string `json:"name"`
	State               string `json:"state"`
	Online              bool   `json:"online"`
	OSUser              string `json:"osUser"`
	RequestedOSUser     string `json:"requestedOsUser"`
	VerifiedOSUser      string `json:"verifiedOsUser,omitempty"`
	OSUserStatus        string `json:"osUserStatus"`
	HostKeyStatus       string `json:"hostKeyStatus"`
	ObservedSSHDHostKey string `json:"observedSSHDHostKey,omitempty"`
	DoorState           string `json:"doorState"`
	DoorOpen            bool   `json:"doorOpen"`
	Reservations        uint32 `json:"reservations"`
}

// pendingEnrolmentView is what `machines.list` renders for an
// outstanding enrol code that has not yet been redeemed (IAMT-336 /
// 1.3: codes are unbound, so this is a flat list with no per-name
// grouping). It is a separate array, not a fake row in `machines`,
// because PROTOCOL §1.6 fixes `machine.state` to exactly
// `enrolled`/`verified`. The view only carries the expiry: a name
// and an OS user are not bound at mint time and are only known once
// the enrol body arrives.
type pendingEnrolmentView struct {
	Expires string `json:"expires"`
}

func cmdMachinesList(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	st := g.cfg.Store.Get()
	out := make([]machineView, 0, len(st.Machines))
	for _, m := range st.Machines {
		mv := machineView{
			ID: m.ID, Name: m.Name, State: m.State, OSUser: m.OSUser, DoorState: "closed",
			RequestedOSUser: m.RequestedOSUser,
			OSUserStatus:    m.OSUserStatus,
			HostKeyStatus:   m.HostKeyStatus,
		}
		if m.VerifiedOSUser != nil {
			mv.VerifiedOSUser = *m.VerifiedOSUser
		}
		if m.ObservedSSHDHostKey != nil {
			mv.ObservedSSHDHostKey = *m.ObservedSSHDHostKey
		}
		if mc, ok := g.reg.get(m.ID); ok {
			snap := mc.doorMachine.Snapshot()
			mv.Online = snap.Online
			mv.DoorState = string(snap.State)
			mv.DoorOpen = snap.State == "open"
			mv.Reservations = snap.Reservations
		}
		out = append(out, mv)
	}
	pending := make([]pendingEnrolmentView, 0, len(st.PendingEnrolments))
	for _, pe := range st.PendingEnrolments {
		pending = append(pending, pendingEnrolmentView{Expires: rfc3339(pe.Expires.Time)})
	}
	return map[string]any{"machines": out, "pendingEnrolments": pending}, nil
}

func cmdMachinesRemove(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int    `json:"proto"`
		ID    string `json:"id"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	found := false
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		for i, m := range st.Machines {
			if m.ID == req.ID {
				st.Machines = append(st.Machines[:i], st.Machines[i+1:]...)
				found = true
				return nil
			}
		}
		// IAMT-336: pending enrolments are no longer keyed by a
		// machine name (codes are unbound). `machines.remove <id>` no
		// longer matches a pending entry — there is nothing to revoke
		// by machine id when the code doesn't carry one. A live
		// pending entry self-evicts on its 15-minute expiry, the same
		// as before, and a redemption is irreversible from the
		// admin side by design (PROTOCOL §3.2: one-time use).
		return nil
	}); err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	if !found {
		return nil, errf("E_NOT_FOUND", 2, "no such machine %q", req.ID)
	}
	if mc, ok := g.reg.get(req.ID); ok {
		mc.teardown("removed-by-admin")
	}
	if accessPublishPause != nil {
		accessPublishPause()
	}
	// The sessions that went with the machine are counted, not just ended:
	// the journal is where the second administrator reads back what the
	// removal cost (P-02, round-1 review 24.09.2026). The wire answer stays
	// {removed:id}, which is what PROTOCOL §6 prescribes for this command.
	killed := g.applyRevocations(now)
	g.logAdminOp(person, "machines.remove", req.ID, "ok", map[string]interface{}{"killedSessions": killed})
	return map[string]string{"removed": req.ID}, nil
}

// cmdMachinesRename changes a machine's display label (23.09.2026).
//
// It is the quiet twin of people.rename, and the asymmetry is the
// protocol's own: every durable reference to a machine -- Grant.Machine,
// GoalRecord.Machine, the journal -- carries the machine's ID, which is
// assigned once at enrol and never moves. The name is what the admin
// reads and what the client resolves a connection by, so renaming it
// touches the label and nothing else: grants stay live, open sessions
// stay open, and the ACL engine is not consulted at all. The next
// machines.list (and the client's next machines.mine) shows the new
// name; a connection string already handed out keeps resolving, because
// it carries the id, not the label.
//
// The new name is checked against every OTHER machine's name AND id: the
// client resolves by name, and a name that collides with another
// machine's id would make that resolution ambiguous.
func cmdMachinesRename(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int    `json:"proto"`
		ID    string `json:"id"`
		Name  string `json:"name"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if err := state.ValidateName(req.Name); err != nil {
		return nil, errf("E_JSON_INVALID", 2, "name: %v", err)
	}
	if reservedPersonNames[req.Name] {
		return nil, errf("E_JSON_INVALID", 2, "name %q is reserved — it is an SSH login role of this gateway", req.Name)
	}
	renamed := false
	// The state write and the line that records it are ONE publication
	// (R2-CX F-10, round-2 review 24.09.2026): whoever reads the
	// pair - "gateway backup" above all, which reads state.json and the
	// journal and accepts only a pair that did not move under it - has to
	// see both or neither. Taking accessPublishMu here, as the grants
	// commands do, is what makes the two writes atomic to that reader;
	// without it a backup taken between them archives a state its own
	// journal does not describe.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		ok, err := st.RenameMachine(req.ID, req.Name)
		if err != nil {
			return err
		}
		renamed = ok
		return nil
	}); err != nil {
		return nil, errf("E_CONFLICT", 2, "%v", err)
	}
	if !renamed {
		return nil, errf("E_NOT_FOUND", 2, "no such machine %q", req.ID)
	}
	g.logAdminOp(person, "machines.rename", req.ID+" -> "+req.Name, "ok", nil)
	return map[string]string{"id": req.ID, "name": req.Name}, nil
}

func cmdMachinesSetUser(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto  int    `json:"proto"`
		ID     string `json:"id"`
		OSUser string `json:"osUser"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if !config.ValidOSUser(req.OSUser) {
		return nil, errf("E_JSON_INVALID", 3, "osUser %q must be a Windows principal (DOMAIN\\name or MACHINE\\name) or a POSIX local name (^[a-z_][a-z0-9_-]{0,31}$) (SPEC §4.3)", req.OSUser)
	}
	found := false
	// The state write and the line that records it are ONE publication
	// (R2-CX F-10, round-2 review 24.09.2026): whoever reads the
	// pair - "gateway backup" above all, which reads state.json and the
	// journal and accepts only a pair that did not move under it - has to
	// see both or neither. Taking accessPublishMu here, as the grants
	// commands do, is what makes the two writes atomic to that reader;
	// without it a backup taken between them archives a state its own
	// journal does not describe.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID == req.ID {
				st.Machines[i].OSUser = req.OSUser
				st.Machines[i].RequestedOSUser = req.OSUser
				st.Machines[i].VerifiedOSUser = nil
				st.Machines[i].OSUserStatus = state.OSUserStatusPending
				st.Machines[i].State = "enrolled"
				found = true
				return nil
			}
		}
		return nil
	}); err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	if !found {
		return nil, errf("E_NOT_FOUND", 2, "no such machine %q", req.ID)
	}
	for _, session := range g.aclE.Sessions() {
		if session.Machine == req.ID {
			g.aclE.Kill(session.ID, now, acl.DenyMachineUnverified)
		}
	}
	if mc, ok := g.reg.get(req.ID); ok {
		mc.closeForOSUserChange()
		if mc.IsOnline() {
			// IAMT-161: same WaitGroup bookkeeping as handleMachine —
			// this is a fire-and-forget probe; Close must wait for it.
			g.probesWG.Add(1)
			g.probesInFlight.Add(1)
			go func() {
				defer g.probesWG.Done()
				defer g.probesInFlight.Add(-1)
				g.runSSHDProbe(mc)
			}()
		}
	}
	g.logAdminOp(person, "machines.set-user", req.ID, "ok", map[string]interface{}{"osUser": req.OSUser})
	// The shape PROTOCOL §6 gives (IAMT-440): it answered {id,osUser},
	// which no document named.
	return map[string]string{
		"id":              req.ID,
		"requestedOsUser": req.OSUser,
		"osUserStatus":    state.OSUserStatusPending,
		"state":           "enrolled",
	}, nil
}

func cmdMachinesVerify(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int    `json:"proto"`
		ID    string `json:"id"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	mc, ok := g.reg.get(req.ID)
	if !ok || !mc.IsOnline() {
		return nil, errf("E_MACHINE_OFFLINE", 1, "machine %q is not online for sshd verification", req.ID)
	}
	if err := g.runSSHDProbeForAdmin(mc); err != nil {
		g.logAdminOp(person, "machines.verify", req.ID, "failed", map[string]interface{}{"err": err.Error()})
		return nil, errf("E_MACHINE_UNVERIFIED", 1, "sshd verification failed: %v", err)
	}
	g.logAdminOp(person, "machines.verify", req.ID, "ok", nil)
	return machineViewFor(g, req.ID), nil
}

func cmdMachinesRekey(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto              int    `json:"proto"`
		ID                 string `json:"id"`
		ConfirmFingerprint string `json:"confirmFingerprint"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	confirmed, err := config.NormalizeFingerprint(req.ConfirmFingerprint)
	if err != nil {
		return nil, errf("E_JSON_INVALID", 3, "confirmFingerprint: %v", err)
	}

	var oldHostKey, newHostKey string
	var found, unavailable, confirmationMismatch bool
	// The state write and the line that records it are ONE publication
	// (R2-CX F-10, round-2 review 24.09.2026): whoever reads the
	// pair - "gateway backup" above all, which reads state.json and the
	// journal and accepts only a pair that did not move under it - has to
	// see both or neither. Taking accessPublishMu here, as the grants
	// commands do, is what makes the two writes atomic to that reader;
	// without it a backup taken between them archives a state its own
	// journal does not describe.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	err = g.cfg.Store.Update(func(st *state.State) error {
		for i := range st.Machines {
			m := &st.Machines[i]
			if m.ID != req.ID {
				continue
			}
			found = true
			if m.HostKeyStatus != state.HostKeyStatusMismatch || m.SSHDHostKey == nil || m.ObservedSSHDHostKey == nil {
				unavailable = true
				return nil
			}
			observedFP, err := state.ComputeFingerprint(*m.ObservedSSHDHostKey)
			if err != nil {
				return fmt.Errorf("observed SSHD host key: %w", err)
			}
			if confirmed != observedFP {
				confirmationMismatch = true
				return nil
			}
			oldHostKey, err = state.ComputeFingerprint(*m.SSHDHostKey)
			if err != nil {
				return fmt.Errorf("pinned SSHD host key: %w", err)
			}
			newHostKey = observedFP
			newPinned := *m.ObservedSSHDHostKey
			m.SSHDHostKey = &newPinned
			m.HostKeyStatus = state.HostKeyStatusMatch
			return nil
		}
		return errors.New("machine disappeared during rekey")
	})
	if err != nil {
		g.logAdminOp(person, "machines.rekey", req.ID, "failed", map[string]interface{}{"err": err.Error()})
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	if !found {
		return nil, errf("E_NOT_FOUND", 2, "no such machine %q", req.ID)
	}
	if unavailable {
		g.logAdminOp(person, "machines.rekey", req.ID, "failed", map[string]interface{}{"reason": "no observed host-key mismatch"})
		return nil, errf("E_MACHINE_REKEY_UNAVAILABLE", 1, "machine %q has no observed SSHD host-key mismatch to confirm", req.ID)
	}
	if confirmationMismatch {
		g.logAdminOp(person, "machines.rekey", req.ID, "failed", map[string]interface{}{"reason": "confirmFingerprint does not match observed SSHD host key"})
		return nil, errf("E_MACHINE_REKEY_CONFIRMATION", 1, "confirmFingerprint does not match machine %q's observed SSHD host key", req.ID)
	}
	g.logAdminOp(person, "machines.rekey", req.ID, "ok", map[string]interface{}{"oldHostKey": oldHostKey, "newHostKey": newHostKey})
	return map[string]string{"id": req.ID, "oldHostKey": oldHostKey, "newHostKey": newHostKey, "state": "verified", "hostKeyStatus": state.HostKeyStatusMatch}, nil
}

func machineViewFor(g *Gateway, id string) machineView {
	st := g.cfg.Store.Get()
	m, _ := st.MachineByID(id)
	mv := machineView{ID: m.ID, Name: m.Name, State: m.State, OSUser: m.OSUser, DoorState: "closed", RequestedOSUser: m.RequestedOSUser, OSUserStatus: m.OSUserStatus, HostKeyStatus: m.HostKeyStatus}
	if m.VerifiedOSUser != nil {
		mv.VerifiedOSUser = *m.VerifiedOSUser
	}
	if m.ObservedSSHDHostKey != nil {
		mv.ObservedSSHDHostKey = *m.ObservedSSHDHostKey
	}
	if mc, ok := g.reg.get(id); ok {
		snap := mc.doorMachine.Snapshot()
		mv.Online, mv.DoorState, mv.DoorOpen, mv.Reservations = snap.Online, string(snap.State), snap.State == "open", snap.Reservations
	}
	return mv
}

func cmdMachinesEnrolCode(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int    `json:"proto"`
		Name  string `json:"name"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	// IAMT-337 / 1.4: the invitation carries ONE thing — the name this
	// registration will be known by — and the administrator chooses it.
	//
	// This is not a return to the pre-1.3 binding, and the difference is
	// the whole point. 1.3 removed from the invitation the two facts
	// only the MACHINE knows: its hostname, and the `DOMAIN\user` its
	// server runs as. An administrator had to go and ask somebody for
	// those before he could hand out an invitation at all, and that is
	// the defect 1.3 fixed. A name is not such a fact. It is the
	// administrator's own choice — the label he will see in the machine
	// list, grant access against and revoke by — and he is the only one
	// who can make it.
	//
	// The OS account still comes from the machine, in the enrol body,
	// and the gateway still proves it by logging in as it (SPEC §3.4
	// step 3). So: the human names, the machine reports, the gateway
	// verifies. Nothing anyone cannot know is asked of them.
	//
	// It is also what makes several registrations on ONE physical box
	// possible, which is the point of 1.4: `office-pc` and `lab-pc`
	// are two names an administrator invents, two registrations, two
	// OS accounts, two sets of grants and two audit trails.
	if err := state.ValidateName(req.Name); err != nil {
		return nil, errf("E_JSON_INVALID", 2, "name: %v", err)
	}
	if reservedPersonNames[req.Name] {
		return nil, errf("E_JSON_INVALID", 2, "name %q is reserved — it is an SSH login role of this gateway", req.Name)
	}
	//
	// 32 random bytes = 256 bits of entropy. We use the BASE64URL form
	// of those bytes (43 chars, no padding) as the canonical "secret"
	// everywhere downstream: it is what goes into the wire code, what
	// the CLI parses back out via config.ParseEnrolCode, what
	// DeriveEphemeralSigner hashes, and what HashEnrolSecret hashes.
	// Mixing raw bytes and base64url at different layers would make
	// the gateway and the CLI derive DIFFERENT keys from the SAME wire
	// code, which is the bug the original build was protecting
	// against — once a wire form is set, every layer MUST agree on the
	// interpretation of the field. Raw bytes have no place here.
	rawSecret := make([]byte, 32)
	if _, err := rand.Read(rawSecret); err != nil {
		return nil, errf("E_INTERNAL", 70, "could not generate a secret: %v", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(rawSecret)
	// Derive the same ephemeral ed25519 key the client derives
	// (PROTOCOL §3.2: ed25519.NewKeyFromSeed(HKDF-SHA-256(raw-secret,
	// salt="iamtunnel-enrol-key-v1", info="", L=32))). Only the PUBLIC
	// half is stored; the private half is never on the gateway.
	eph, err := config.DeriveEphemeralSigner(secret, config.EnrolKeySalt)
	if err != nil {
		return nil, errf("E_INTERNAL", 70, "could not derive enrol key: %v", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(eph.PublicKey())))

	// 1.3: TTL is 15 minutes (was 24 hours). A 24 h secret was the
	// single biggest weakness of the previous scheme — a one-shot
	// token left in a chat for a day is what an interceptor could
	// actually reach — and the new wire form (one line that carries
	// host, port, fingerprint AND the secret, §3.6) makes the
	// interception surface large enough that a quarter-hour is all
	// the cover this scheme should ever have.
	expires := now.Add(15 * time.Minute)
	// The hash goes straight through state.HashEnrolSecret: no
	// wrapper, no substitution point. The raw secret is used to build
	// the wire code below and is otherwise never persisted.
	hash := state.HashEnrolSecret(g.enrolHMAC, []byte(secret))

	// The name is checked for collisions INSIDE the transaction, against
	// both the machines that exist and the invitations already in
	// flight. Checking before the Update would be a race with a second
	// administrator minting the same name in the same second, and the
	// redeem-time check in runEnrolFromPending — which stays, because
	// a machine can be registered while an invitation is in the post —
	// would then refuse a code somebody had already been handed. It is
	// far kinder to refuse the mint, in front of the person who chose
	// the name, than the redemption, in front of somebody who cannot
	// change it.
	var clash string
	// The state write and the line that records it are ONE publication
	// (R2-CX F-10, round-2 review 24.09.2026): whoever reads the
	// pair - "gateway backup" above all, which reads state.json and the
	// journal and accepts only a pair that did not move under it - has to
	// see both or neither. Taking accessPublishMu here, as the grants
	// commands do, is what makes the two writes atomic to that reader;
	// without it a backup taken between them archives a state its own
	// journal does not describe.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		for i := range st.Machines {
			if st.Machines[i].ID == req.Name || st.Machines[i].Name == req.Name {
				clash = "a machine"
				return nil
			}
		}
		for i := range st.PendingEnrolments {
			if st.PendingEnrolments[i].Name == req.Name &&
				st.PendingEnrolments[i].Expires.After(now) {
				clash = "an invitation that has not been redeemed yet"
				return nil
			}
		}
		entry := state.PendingEnrolment{
			Name:       req.Name,
			SecretHash: hash,
			PublicKey:  pubLine,
			Expires:    state.NewZonedTime(expires.UTC()),
		}
		st.PendingEnrolments = append(st.PendingEnrolments, entry)
		return nil
	}); err != nil {
		return nil, errf("E_INTERNAL", 70, "could not persist enrol code: %v", err)
	}
	if clash != "" {
		return nil, errf("E_CONFLICT", 2, "the name %q is already taken by %s — pick another, or remove the old registration first with \"machines remove %s\"", req.Name, clash, req.Name)
	}

	// Zero the raw bytes as soon as we are done with them. The hash
	// and the wire code (which only the human at the terminal will
	// ever see) are the only things that need to outlive this function.
	for i := range rawSecret {
		rawSecret[i] = 0
	}

	fp := strings.TrimPrefix(auth.Fingerprint(g.cfg.HostKey.PublicKey()), "SHA256:")
	code := fmt.Sprintf("iamtunnel-enrol://%s:%d#%s:%s", g.cfg.PublicHost, g.cfg.PublicPort, fp, secret)
	g.logAdminOp(person, "machines.enrol-code", req.Name, "ok", map[string]interface{}{"expires": rfc3339(expires)})
	return map[string]string{"enrolCode": code, "expires": rfc3339(expires)}, nil
}

// ---- grants.* ---------------------------------------------------------------

// Every access-changing command below (grants.grant / grants.revoke /
// grants.set-caps, and people.remove / machines.remove whose engine
// publication is the revocation drain) writes state.json first and
// publishes to the ACL engine second. Two unsynchronized commands can
// interleave in that seam: a revoke that completes between the other
// command's state write and engine write finds no engine grant
// (ErrNoGrant is deliberately tolerated) and returns success -- and the
// late AddGrant then resurrects in the engine an access state.json no
// longer has, until the next restart (M-6). Holding one mutex across
// BOTH steps makes the seam unenterable: whoever publishes an access
// change does the whole write-and-publish as one unit.
//
// A package-level mutex, not a Gateway field: the struct lives in
// gateway.go, and the change is confined to admin_role.go. One gateway
// per process serves every admin exec there is, so a package mutex
// serializes exactly the commands that need serializing; tests run
// sequentially and pay only an uncontended lock.
var accessPublishMu sync.Mutex

// accessPublishPause, when non-nil, is called by every access-changing
// command at the seam between its state write and its engine publication.
// Production leaves it nil; the atomicity test parks a command there to
// hold the seam open while a second command runs through it (M-6: the
// resurrected-grant race). Tests must restore nil when done.
var accessPublishPause func()

type grantView struct {
	Person  string `json:"person"`
	Machine string `json:"machine"`
	// Until is a pointer so the JSON output omits the field entirely
	// for an indefinite grant (SPEC 4.3: "absence != zero time"). The
	// empty string stays a legal INPUT meaning "no deadline"; on output
	// we refuse to emit it, so a machine reader cannot mistake "" for
	// an RFC 3339 instant.
	Until *string  `json:"until,omitempty"`
	Caps  []string `json:"caps"`
}

func cmdGrantsGrant(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int      `json:"proto"`
		Person  string   `json:"person"`
		Machine string   `json:"machine"`
		Until   string   `json:"until"`
		Caps    []string `json:"caps"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if len(req.Caps) != 1 || (req.Caps[0] != "shell" && req.Caps[0] != "exec") {
		return nil, errf("E_CAP_UNSUPPORTED", 4, "caps must be exactly [\"shell\"] or [\"exec\"] in 1.0, got %v", req.Caps)
	}
	var untilPtr *time.Time
	var zonedPtr *state.ZonedTime
	// untilView is the wire form: nil for indefinite, &str for the
	// RFC 3339 deadline. We never set it to &"" - "" on the wire means
	// "indefinite", and a machine reader should see "no field" rather
	// than a possibly-ambiguous empty string (SPEC 4.3).
	var untilView *string
	if req.Until != "" {
		until, uerr := config.ParseUntil(req.Until)
		if uerr != nil {
			return nil, errf("E_JSON_INVALID", 3, "%v", uerr)
		}
		if !until.After(now) {
			return nil, errf("E_JSON_INVALID", 3, "until %q must be strictly after the gateway's current time (%s)", req.Until, rfc3339(now))
		}
		u := until.UTC()
		untilPtr = &u
		zoned := state.NewZonedTime(u)
		zonedPtr = &zoned
		s := rfc3339(until)
		untilView = &s
	}
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		if !st.HasPerson(req.Person) {
			return fmt.Errorf("no such person %q", req.Person)
		}
		if _, ok := st.MachineByID(req.Machine); !ok {
			return fmt.Errorf("no such machine %q", req.Machine)
		}
		return st.GrantAccess(req.Person, req.Machine, zonedPtr, req.Caps...)
	}); err != nil {
		return nil, errf("E_CONFLICT", 2, "%v", err)
	}
	if accessPublishPause != nil {
		accessPublishPause()
	}
	if err := g.aclE.AddGrant(acl.Grant{Person: req.Person, Machine: req.Machine, Until: untilPtr, Caps: req.Caps}, now); err != nil {
		return nil, errf("E_INTERNAL", 70, "grant was persisted but could not be activated: %v", err)
	}
	// The caps as they now stand, defaults applied (R4 F-10): shell or
	// exec is the difference between a session the classifier can judge
	// and one it cannot, and the journal did not say which was given.
	caps := req.Caps
	for _, gr := range g.cfg.Store.Get().Grants {
		if gr.Person == req.Person && gr.Machine == req.Machine {
			caps = gr.Caps
			break
		}
	}
	g.logAdminOp(person, "grants.grant", req.Person+" -> "+req.Machine, "ok", map[string]interface{}{"until": req.Until, "caps": caps})
	return map[string]any{"grant": grantView{Person: req.Person, Machine: req.Machine, Until: untilView, Caps: req.Caps}}, nil
}

func cmdGrantsRevoke(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int    `json:"proto"`
		Person  string `json:"person"`
		Machine string `json:"machine"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	removed := false
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		removed = st.RevokeAccess(req.Person, req.Machine)
		return nil
	}); err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	if !removed {
		return nil, errf("E_NOT_FOUND", 2, "no grant for %s -> %s", req.Person, req.Machine)
	}
	if accessPublishPause != nil {
		accessPublishPause()
	}
	killed, err := g.aclE.Revoke(req.Person, req.Machine, now)
	if err != nil && err != acl.ErrNoGrant {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	g.logAdminOp(person, "grants.revoke", req.Person+" -> "+req.Machine, "ok", map[string]interface{}{"killedSessions": killed})
	return map[string]any{"revoked": true, "terminatedSessions": killed}, nil
}

// cmdGrantsSetCaps changes what an existing grant permits, in place
// (21.09.2026). The owner wanted the mode -- one command, or a whole
// shell -- named in the client's own machine row and changeable from
// there.
//
// adminOnly, and that is the entire security content of this verb. The
// row it is reached from belongs to the person ENTERING, and the whole
// point of an exec-only grant is that the one entering cannot widen it:
// an AI agent that could press "give me a shell" would make the narrow
// mode decorative. So the window offers the change only to a machine that
// also carries an administrator's key, the request travels as an
// administrator's, and the gateway decides by the key rather than by
// which screen asked.
//
// Narrowing kills what is already open. A shell session running when the
// grant becomes exec-only would otherwise outlive the decision that
// closed it -- the administrator would watch the very terminal they just
// forbade. Widening kills nothing: nothing open under exec is illegal
// under shell.
func cmdGrantsSetCaps(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int      `json:"proto"`
		Person  string   `json:"person"`
		Machine string   `json:"machine"`
		Caps    []string `json:"caps"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if len(req.Caps) != 1 || (req.Caps[0] != "shell" && req.Caps[0] != "exec") {
		return nil, errf("E_CAP_UNSUPPORTED", 4, "caps must be exactly [\"shell\"] or [\"exec\"] in 1.0, got %v", req.Caps)
	}

	var was string
	var found bool
	var until *state.ZonedTime
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		was, found = st.SetGrantCaps(req.Person, req.Machine, req.Caps)
		if found {
			for _, gr := range st.Grants {
				if gr.Person == req.Person && gr.Machine == req.Machine {
					until = gr.Until
				}
			}
		}
		return nil
	}); err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	if !found {
		return nil, errf("E_NOT_FOUND", 2, "no grant for %s -> %s", req.Person, req.Machine)
	}
	if was == req.Caps[0] {
		return map[string]any{"caps": req.Caps, "was": was, "terminatedSessions": 0}, nil
	}

	if accessPublishPause != nil {
		accessPublishPause()
	}
	killed := 0
	if was == "shell" && req.Caps[0] == "exec" {
		n, err := g.aclE.RevokeBecause(req.Person, req.Machine, now, acl.DenyGrantChanged)
		if err != nil && err != acl.ErrNoGrant {
			return nil, errf("E_INTERNAL", 70, "%v", err)
		}
		killed = n
	}
	var untilPtr *time.Time
	if until != nil {
		t := until.Time
		untilPtr = &t
	}
	if err := g.aclE.AddGrant(acl.Grant{
		Person:  req.Person,
		Machine: req.Machine,
		Until:   untilPtr,
		Caps:    req.Caps,
	}, now); err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	g.logAdminOp(person, "grants.set-caps", req.Person+" -> "+req.Machine, "ok",
		map[string]interface{}{"was": was, "caps": req.Caps[0], "killedSessions": killed})
	return map[string]any{"caps": req.Caps, "was": was, "terminatedSessions": killed}, nil
}

// cmdGrantsExtend moves the deadline of an existing grant in place
// (23.09.2026). Until now the only way to change a deadline was revoke
// plus grant, and GrantAccess refuses a pair that already has a grant:
// an administrator had to tear down a live session to change one date.
// Extending a specialist's working day should not throw them off the
// machine they are working on.
//
// Only shortening tears anything down, and then by the revoke rules,
// exactly as set-caps narrows shell to exec: live sessions die now
// instead of quietly outliving the decision that cut them. Extension --
// a later deadline, or a finite one made indefinite -- touches no
// session: the engine consults the grant at every sweep, so what is
// already open simply lives until the new deadline.
//
// The wire shape follows grantView (SPEC 4.3): "until" is absent when
// the grant now has no deadline, "was" is absent when it had none
// before. An empty string is a legal INPUT meaning "no deadline" and is
// never emitted.
func cmdGrantsExtend(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int    `json:"proto"`
		Person  string `json:"person"`
		Machine string `json:"machine"`
		Until   string `json:"until"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	var newUntilPtr *time.Time
	var newZoned *state.ZonedTime
	var untilView *string
	if req.Until != "" {
		until, uerr := config.ParseUntil(req.Until)
		if uerr != nil {
			return nil, errf("E_JSON_INVALID", 3, "%v", uerr)
		}
		if !until.After(now) {
			return nil, errf("E_JSON_INVALID", 3, "until %q must be strictly after the gateway's current time (%s)", req.Until, rfc3339(now))
		}
		u := until.UTC()
		newUntilPtr = &u
		zoned := state.NewZonedTime(u)
		newZoned = &zoned
		s := rfc3339(until)
		untilView = &s
	}

	var was *state.ZonedTime
	var caps []string
	var found bool
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		was, found = st.SetGrantUntil(req.Person, req.Machine, newZoned)
		if found {
			for _, gr := range st.Grants {
				if gr.Person == req.Person && gr.Machine == req.Machine {
					caps = gr.Caps
				}
			}
		}
		return nil
	}); err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	if !found {
		return nil, errf("E_NOT_FOUND", 2, "no grant for %s -> %s", req.Person, req.Machine)
	}
	var wasView *string
	if was != nil {
		s := rfc3339(was.Time)
		wasView = &s
	}
	if was == nil && newUntilPtr == nil {
		// indefinite to indefinite: nothing moved, nothing to publish
		return struct {
			Until              *string `json:"until,omitempty"`
			Was                *string `json:"was,omitempty"`
			TerminatedSessions int     `json:"terminatedSessions"`
		}{nil, nil, 0}, nil
	}

	shortening := false
	switch {
	case was == nil:
		// a deadline where none existed always cuts the other end
		shortening = true
	case newUntilPtr == nil:
		shortening = false
	default:
		shortening = newUntilPtr.Before(was.Time)
	}
	killed := 0
	if shortening {
		if accessPublishPause != nil {
			accessPublishPause()
		}
		n, err := g.aclE.RevokeBecause(req.Person, req.Machine, now, acl.DenyGrantChanged)
		if err != nil && err != acl.ErrNoGrant {
			return nil, errf("E_INTERNAL", 70, "%v", err)
		}
		killed = n
	}
	if accessPublishPause != nil {
		accessPublishPause()
	}
	if err := g.aclE.AddGrant(acl.Grant{Person: req.Person, Machine: req.Machine, Until: newUntilPtr, Caps: caps}, now); err != nil {
		return nil, errf("E_INTERNAL", 70, "grant was persisted but could not be activated: %v", err)
	}
	g.logAdminOp(person, "grants.extend", req.Person+" -> "+req.Machine, "ok",
		map[string]interface{}{"until": req.Until, "shortened": shortening, "killedSessions": killed})
	return struct {
		Until              *string `json:"until,omitempty"`
		Was                *string `json:"was,omitempty"`
		TerminatedSessions int     `json:"terminatedSessions"`
	}{untilView, wasView, killed}, nil
}

func cmdGrantsList(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int    `json:"proto"`
		Person  string `json:"person,omitempty"`
		Machine string `json:"machine,omitempty"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	st := g.cfg.Store.Get()
	out := make([]grantView, 0, len(st.Grants))
	for _, gr := range st.Grants {
		if req.Person != "" && gr.Person != req.Person {
			continue
		}
		if req.Machine != "" && gr.Machine != req.Machine {
			continue
		}
		var until *string
		if gr.Until != nil {
			s := gr.Until.String()
			until = &s
		}
		out = append(out, grantView{Person: gr.Person, Machine: gr.Machine, Until: until, Caps: gr.Caps})
	}
	return map[string]any{"grants": out}, nil
}

// ---- sessions.* -------------------------------------------------------------

type sessionView struct {
	ID       string `json:"id"`
	Person   string `json:"person"`
	Machine  string `json:"machine"`
	Started  string `json:"started"`
	BytesIn  int64  `json:"bytesIn"`
	BytesOut int64  `json:"bytesOut"`
}

func cmdSessionsActive(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	live := g.aclE.Sessions()
	out := make([]sessionView, 0, len(live))
	for _, s := range live {
		out = append(out, sessionView{ID: s.ID.String(), Person: s.Person, Machine: s.Machine, Started: rfc3339(s.OpenedAt)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return map[string]any{"sessions": out}, nil
}

// cmdSessionsHistory answers "who connected, when, to what, and what
// happened" -- one row per SESSION, newest first, a page at a time.
//
// Requested 21.09.2026: a full history for an
// administrator, with filters and pages, so the whole list does not come
// out at once -- say, 20 or 50 rows at a time.
//
// It used to return one row per EVENT, unpaged. Both were wrong for the
// question. A session produces a start, possibly several risk decisions
// and a stop, and a person reading a history wants one line per visit,
// not four lines they have to reassemble in their head. And an unpaged
// answer over a month of use is a reply nobody can hold, let alone draw.
//
// Grouping is by the session id the events already carry in their
// details. Events without one -- the early refusals that happen before a
// session id exists -- are kept, each as its own row, because "somebody
// was turned away at the door" belongs in this history more than most
// things in it.
func cmdSessionsHistory(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int    `json:"proto"`
		From    string `json:"from,omitempty"`
		To      string `json:"to,omitempty"`
		Person  string `json:"person,omitempty"`
		Machine string `json:"machine,omitempty"`
		Limit   int    `json:"limit,omitempty"`
		Offset  int    `json:"offset,omitempty"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	filter := events.Filter{Types: []events.EventType{events.EventSessionStart, events.EventSessionStop, events.EventSessionDrop, events.EventSessionRisk}}
	if req.Person != "" {
		filter.Actor = req.Person
	}
	if req.Machine != "" {
		filter.Object = req.Machine
	}
	if req.From != "" {
		t, err := config.ParseUntil(req.From)
		if err != nil {
			return nil, errf("E_JSON_INVALID", 3, "from: %v", err)
		}
		filter.Since = &t
	}
	if req.To != "" {
		t, err := config.ParseUntil(req.To)
		if err != nil {
			return nil, errf("E_JSON_INVALID", 3, "to: %v", err)
		}
		filter.Until = &t
	}
	// ReadAll, not Read: a history that stopped at the current journal
	// file would lose everything before the last rotation, which is
	// precisely the "a month ago" this tab exists to answer.
	evs, _, err := g.cfg.Log.ReadAll(filter)
	if err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}

	// histWhen parses a journal stamp for ordering. An unparsable stamp
	// sorts oldest rather than crashing or floating to the top: a row we
	// cannot date is a row we cannot claim is recent.
	histWhen := func(ts string) time.Time {
		t, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return time.Time{}
		}
		return t
	}

	type histRow struct {
		SessionID string `json:"sessionId,omitempty"`
		Person    string `json:"person"`
		Machine   string `json:"machine"`
		Started   string `json:"started"`
		Ended     string `json:"ended,omitempty"`
		Kind      string `json:"kind"`              // "exec" | "shell"
		Command   string `json:"command,omitempty"` // exec only
		Goal      string `json:"goal,omitempty"`
		Outcome   string `json:"outcome"`
		Risks     int    `json:"risks"`
		RiskLevel string `json:"riskLevel,omitempty"`
		RiskRule  string `json:"riskRule,omitempty"`
		// RiskReason is the WORST decision's own words. A count tells a
		// reader that something was stopped; only the reason tells them
		// what, and that is the whole value of a history to somebody
		// asking what a person actually did.
		RiskReason string `json:"riskReason,omitempty"`

		// firstSeen is the earliest event of this row, used only when no
		// session.start was in the answer at all.
		firstSeen string
	}

	order := []string{}
	byID := map[string]*histRow{}
	worst := map[string]int{"green": 0, "yellow": 1, "red": 2}

	for _, e := range evs {
		id, _ := e.Details["sessionId"].(string)
		// The key carries the actor and the object as well as the id.
		// An id is supposed to be unique, and if it ever is not, two
		// people's sessions merging into one row would be a history that
		// lies about who did what -- the one thing a history may never
		// do. Keying on all three makes a collision show up as two rows
		// rather than as one wrong one.
		key := id + "|" + e.Actor + "|" + e.Object
		if id == "" {
			// No session id: a refusal before the session existed. Give
			// it a key of its own so it cannot merge with anything.
			key = "evt:" + e.Time.String() + ":" + string(e.Type)
		}
		row, seen := byID[key]
		if !seen {
			// Kind and Started stay unknown until a session.start is
			// seen. Assuming "shell" and taking the first event's time
			// was how a session whose start fell outside the window --
			// before a `from`, or before a rotation -- came out claiming
			// to have begun at the moment it ended.
			row = &histRow{SessionID: id, Person: e.Actor, Machine: e.Object, Kind: "unknown", Outcome: "unknown", firstSeen: e.Time.String()}
			byID[key] = row
			order = append(order, key)
		}
		switch e.Type {
		case events.EventSessionStart:
			row.Started = e.Time.String()
			row.Kind = "shell"
			row.Outcome = "ok"
			if cmd, ok := e.Details["command"].(string); ok && cmd != "" {
				row.Kind = "exec"
				row.Command = cmd
			}
			if goal, ok := e.Details["goal"].(string); ok {
				row.Goal = goal
			}
		case events.EventSessionStop:
			row.Ended = e.Time.String()
			if row.Outcome == "unknown" || row.Outcome == "ok" {
				row.Outcome = "ended"
			}
		case events.EventSessionDrop:
			row.Ended = e.Time.String()
			row.Outcome = e.Result
		case events.EventSessionRisk:
			row.Risks++
			if row.RiskLevel == "" || worst[e.Result] > worst[row.RiskLevel] {
				row.RiskLevel = e.Result
				if e.Details != nil {
					if reason, ok := e.Details["reason"].(string); ok {
						row.RiskReason = reason
					}
					if rule, ok := e.Details["rule"].(string); ok {
						row.RiskRule = rule
					}
				}
			}
		}
	}

	// A row whose start was never seen still has to say WHEN, or it is
	// unreadable. It says the only honest thing available: the first
	// moment of it this answer knows about.
	for _, r := range byID {
		if r.Started == "" {
			r.Started = r.firstSeen
		}
	}

	// Newest first: a history is read from the top, and the top is now.
	//
	// Sorted on the parsed instant, not on the string. RFC 3339 text
	// sorts by time only while every stamp shares one offset and one
	// fractional-second shape -- "12:00:00Z" and "12:00:00.1Z" already
	// break it, and a journal written by a gateway in another zone
	// breaks it completely.
	rows := make([]*histRow, 0, len(order))
	for _, k := range order {
		rows = append(rows, byID[k])
	}
	sort.SliceStable(rows, func(i, j int) bool {
		return histWhen(rows[i].Started).After(histWhen(rows[j].Started))
	})

	total := len(rows)
	offset := req.Offset
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	limit := req.Limit
	if limit <= 0 {
		// A caller that asks for no page gets a page anyway. The
		// unbounded answer is what made this verb unusable over a month
		// of history, and an unbounded default would leave the trap set
		// for the next caller.
		limit = 50
	}
	if limit > 500 {
		limit = 500
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := rows[offset:end]
	out := make([]histRow, 0, len(page))
	for _, r := range page {
		out = append(out, *r)
	}
	return map[string]any{"sessions": out, "total": total, "offset": offset, "limit": limit}, nil
}

func cmdSessionsKill(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto  int    `json:"proto"`
		ID     string `json:"id"`
		Reason string `json:"reason,omitempty"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	id, perr := acl.ParseSessionID(req.ID)
	if perr != nil {
		return nil, errf("E_JSON_INVALID", 3, "%v", perr)
	}
	if !g.aclE.Kill(id, now, acl.DenyAdminKilled) {
		return nil, errf("E_NOT_FOUND", 2, "no live session %q", req.ID)
	}
	g.logAdminOp(person, "sessions.kill", req.ID, "ok", nil)
	return map[string]any{"id": req.ID, "killed": true}, nil
}

// ---- recordings.* -----------------------------------------------------------

// recordingEntry is one recording found under RecordingBaseDir, identified
// by a hash of its path rather than the path itself: admin requests name
// recordings by this opaque id, never by a filesystem path, so a garbled
// or hostile id can never walk outside RecordingBaseDir (an outsider
// must never get them) - the id space itself carries no
// path to escape with).
type recordingEntry struct {
	id       string
	base     string // absolute path without extension
	metadata record.Metadata
}

// scanRecordings walks the recordings tree by NAME (filepath.WalkDir), and
// that is the one place IAMT-332's no-follow contract deliberately stops:
// the create-or-refuse open (state.OpenDataFile and siblings) protects a
// final pathname, while a walk enumerates entries — a name swapped for a
// symlink (or a directory swapped for another) in a race with the walk is
// not caught here. The accepted exposure is bounded: this function only
// LISTS what the walk found, and every subsequent open of a found entry
// goes through record.ReadMeta and the state contract, so the worst case
// is a listing that momentarily misses or double-counts a swapped name —
// never an open through the plant. Closing the listing gap itself needs a
// walk with the parent directory held open, openat style — the primitive
// Go's portable os package grew (os.Root) — and is consciously deferred
// HERE, like the symlinked-parent TOCTOU of the ownership step, because
// this listing is the input to ReadMeta opens that re-check each path
// through the state contract anyway. The sibling walks that had no such
// second check moved to os.Root in IAMT-333 (P1.5):
// internal/gateway/record/rotation.go (cleanEmptyDirs's listing and
// removal), internal/gateway/events/log.go (ReadHistory's archive
// listing), internal/gateway/state/store.go (cleanStaleTempFiles).
// The remaining name-based walks over data directories stand on the same
// bounded reasoning: rotation.go's scanSessions (the retention listing
// whose deletions act on walked names), cmd/iamtunnel/iohelpers.go
// (hardenServerDirChildren — its chmod re-checks nothing, but it is the
// POSIX lockdown itself, IAMT-213) and the install-time ACL hardening,
// which since R2-CX F-12 classifies and locks every entry through its
// own handle (winkeys.LockTree) and only LISTS names by directory order.
func scanRecordings(baseDir string) ([]recordingEntry, error) {
	var out []recordingEntry
	err := filepath.WalkDir(baseDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".meta") {
			return nil
		}
		meta, merr := record.ReadMeta(path)
		if merr != nil {
			return nil // a broken meta file is skipped, not fatal to the listing
		}
		base := strings.TrimSuffix(path, ".meta")
		id := recordingID(baseDir, base)
		out = append(out, recordingEntry{id: id, base: base, metadata: meta})
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].base < out[j].base })
	return out, nil
}

func recordingID(baseDir, base string) string {
	rel, err := filepath.Rel(baseDir, base)
	if err != nil {
		rel = base
	}
	sum := sha256.Sum256([]byte(filepath.ToSlash(rel)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ---- recordings index and hash memo (M-12, review F-09 / review F-17) ----------
//
// A chunked fetch used to redo the two once-per-recording jobs on every
// chunk: the full tree walk that resolves the opaque id, and the SHA-256
// of the WHOLE part file. A 500 MB recording in 256 KiB chunks cost
// ~2000 walks and ~2000 full-file hashes. The work now happens once:
// the id is resolved through a per-baseDir cache (a miss falls back to
// one fresh walk), and the hash is served from the .meta the recorder
// wrote at finalization — computed and memoized only for recordings
// whose .meta predates that rule.

// recordingMemoEntry is the remembered hash of one part of one
// recording, stamped with the .meta state it was computed against: a
// stamp that stopped matching means the path came back under a
// different recording (rotation removed the old one), and the memo
// dies.
type recordingMemoEntry struct {
	modTime time.Time
	size    int64
	sum     string
}

var (
	// recordingsIndexMu guards the per-baseDir table below. Like
	// accessPublishMu, it is package-level rather than a Gateway field:
	// the field lives in gateway.go, outside the recordings surface.
	recordingsIndexMu sync.Mutex
	recordingsIndex   = map[string]*recordingsIndexEntry{}
	// recordingsHashMu guards the legacy-hash memo. Keyed by
	// "<id>\x00<part>"; ids are unique per baseDir, and every baseDir a
	// process serves carries disjoint id spaces.
	recordingsHashMu   sync.Mutex
	recordingsHashMemo = map[string]recordingMemoEntry{}
)

type recordingsIndexEntry struct {
	mu   sync.Mutex
	byID map[string]string
}

func recordingsIndexFor(baseDir string) *recordingsIndexEntry {
	recordingsIndexMu.Lock()
	defer recordingsIndexMu.Unlock()
	e, ok := recordingsIndex[baseDir]
	if !ok {
		e = &recordingsIndexEntry{byID: map[string]string{}}
		recordingsIndex[baseDir] = e
	}
	return e
}

// invalidateRecordingsIndex drops the id→path caches and the hash
// memos wholesale. The recording-rotation loop calls it after a pass
// that deleted sessions: the entries name files that no longer exist.
// The cache stays correct even without the call — a lookup re-checks
// the .meta under the cached path, and a vanished one falls back to a
// fresh walk — so this is hygiene that keeps dead ids and stale memos
// from accumulating for the life of the process, not a correctness
// dependency.
func invalidateRecordingsIndex() {
	recordingsIndexMu.Lock()
	recordingsIndex = map[string]*recordingsIndexEntry{}
	recordingsIndexMu.Unlock()
	recordingsHashMu.Lock()
	recordingsHashMemo = map[string]recordingMemoEntry{}
	recordingsHashMu.Unlock()
}

// resolveRecordingBase maps the opaque recording id to the recording's
// base path (its path without the part extension). A cache miss falls
// back to one fresh scanRecordings walk — so a recording created after
// the cache was built is found and cached — and a cache hit is trusted
// only while the .meta under the cached path still exists: rotation (or
// an operator) may have removed the recording since, and the fresh walk
// then answers E_NOT_FOUND honestly instead of a stale hit resolving a
// dead path. A path reused by a NEW recording needs no invalidation:
// the id is the hash of the path, so the new recording owns the same id.
func resolveRecordingBase(baseDir, id string) (string, *cmdError) {
	e := recordingsIndexFor(baseDir)
	e.mu.Lock()
	base, ok := e.byID[id]
	e.mu.Unlock()
	if ok {
		if _, err := os.Stat(base + ".meta"); err == nil {
			return base, nil
		}
		e.mu.Lock()
		delete(e.byID, id)
		e.mu.Unlock()
	}
	entries, err := scanRecordingsFn(baseDir)
	if err != nil {
		return "", errf("E_INTERNAL", 70, "%v", err)
	}
	for i := range entries {
		if entries[i].id == id {
			e.mu.Lock()
			e.byID[id] = entries[i].base
			e.mu.Unlock()
			return entries[i].base, nil
		}
	}
	return "", errf("E_NOT_FOUND", 2, "no such recording %q", id)
}

// metaHashForPart reads the hash the recorder wrote into the .meta at
// finalization for the given part: CastFile/TxtFile for a terminal
// recording, ExecFile for an exec one. "" when this .meta predates the
// field — or when the part is the .meta itself, which cannot carry its
// own hash.
func metaHashForPart(meta record.Metadata, part string) string {
	switch part {
	case "cast":
		return meta.CastFile.SHA256
	case "txt":
		return meta.TxtFile.SHA256
	case "exec":
		if meta.ExecFile != nil {
			return meta.ExecFile.SHA256
		}
	}
	return ""
}

// recordingPartSHA256 answers recordings.fetch's "sha256" field
// (PROTOCOL §6): the hash of the WHOLE part file. The hash is a fact of
// the finished recording, so the recorder computes it exactly once — at
// finalization — and this function serves it from the .meta; the
// gateway hashes nothing. Two fallbacks remain, both legacy shapes:
// part "meta" (which cannot carry its own hash), and a .meta written
// before the hash-at-finalization rule. Both compute at the first
// request and memoize the result in gateway memory for the rest of the
// download, stamped with the .meta's modtime and size. A recording
// still marked "recording" is growing — its hash is computed per
// request and never memoized, because a memoized prefix hash would be
// a lie about the finished file.
func recordingPartSHA256(baseDir, id, base, part string) (string, *cmdError) {
	var stamp recordingMemoEntry
	memoAllowed := false
	if st, meta, ok := recordingMetaWithStamp(base + ".meta"); ok {
		stamp = st
		if h := metaHashForPart(meta, part); h != "" {
			return h, nil
		}
		memoAllowed = meta.Status != "recording"
	}
	key := id + "\x00" + part
	recordingsHashMu.Lock()
	memo, hasMemo := recordingsHashMemo[key]
	recordingsHashMu.Unlock()
	if hasMemo && memoAllowed && memo.modTime.Equal(stamp.modTime) && memo.size == stamp.size {
		return memo.sum, nil
	}
	sum, err := fileSHA256HexFn(base + recordingPartExt(part))
	if err != nil {
		return "", errf("E_INTERNAL", 70, "%v", err)
	}
	if memoAllowed {
		stamp.sum = sum
		recordingsHashMu.Lock()
		recordingsHashMemo[key] = stamp
		recordingsHashMu.Unlock()
	}
	return sum, nil
}

// recordingOpenMetaFn is a test-only seam, nil in production - the shape
// M-12's fileSHA256HexFn and the gateway's probeDeadlineFn share. It hands
// out the descriptor a recording's .meta is read through, so a test can
// show that the stamp and the content come from ONE open (R2-MX F-05,
// round-2 review 24.09.2026). Production opens it the way every other read
// of a data file does: no-follow, regular files only (IAMT-332).
var recordingOpenMetaFn func(path string) (*os.File, error)

func openRecordingMeta(path string) (*os.File, error) {
	if fn := recordingOpenMetaFn; fn != nil {
		return fn(path)
	}
	return state.OpenExistingDataFile(path, os.O_RDONLY)
}

// recordingMetaWithStamp reads a recording's .meta and the stamp the hash
// memo is keyed by - its size and mtime - from the SAME open file.
//
// The stamp used to be taken by name (os.Stat) and the content by name
// (record.ReadMeta): two opens of one path, so a .meta replaced between
// them gave the memo a stamp belonging to one file and a hash read from
// another, and the memo then answered for a .meta that was never read -
// the one invariant a cache keyed by a stamp has to hold (F-05). The
// recorder's own writes are not the worry here; the recordings directory
// is the gateway's own storage, and what the operator is shown has to be
// what was read.
func recordingMetaWithStamp(path string) (recordingMemoEntry, record.Metadata, bool) {
	var stamp recordingMemoEntry
	var meta record.Metadata
	f, err := openRecordingMeta(path)
	if err != nil {
		return stamp, meta, false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return stamp, meta, false
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return stamp, meta, false
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return stamp, meta, false
	}
	stamp.modTime, stamp.size = info.ModTime(), info.Size()
	return stamp, meta, true
}

// recordingStillBeingWritten reports whether the .meta beside base says
// status:"recording" - the one growing state of the four a recording's
// .meta can name ("completed", "aborted", "recording", "error"): the
// recorder writes the initial .meta the moment the session starts
// (recorder.go) and rewrites it at finalize. An unreadable .meta answers
// false: without a positive status there is nothing to refuse on, and a
// corrupt .meta must not make an otherwise servable recording vanish
// from fetch.
func recordingStillBeingWritten(base string) bool {
	meta, err := record.ReadMeta(base + ".meta")
	return err == nil && meta.Status == "recording"
}

// recordingPartExt maps a recordings.fetch part name to the extension
// its file carries under the recording's base path (PROTOCOL §8: the
// lossless exec stream is .exec.jsonl, not .exec).
func recordingPartExt(part string) string {
	switch part {
	case "cast":
		return ".cast"
	case "txt":
		return ".txt"
	case "exec":
		return ".exec.jsonl"
	default:
		return ".meta"
	}
}

// fileSHA256HexFn is the seam production's recordings.fetch calls its
// hasher through (M-12): the hash-once guarantee is proven by counting
// how many times the gateway really streams a part into SHA-256 during
// a chunked download. Production always sees the real hasher.
var fileSHA256HexFn = fileSHA256Hex

// scanRecordingsFn is the matching seam for scanRecordings (M-12): the
// index's "one walk per download, not per chunk" claim is proven the
// same way. Production always sees the real walker.
var scanRecordingsFn = scanRecordings

// fileSHA256Hex streams a recording file into its SHA-256. The open is
// the same no-follow regular-file-only open as every other data-file
// read (IAMT-332 round six); the hash stays a stream — recordings can
// be large.
func fileSHA256Hex(path string) (string, error) {
	f, err := state.OpenExistingDataFile(path, os.O_RDONLY)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type recordingView struct {
	ID      string `json:"id"`
	Machine string `json:"machine"`
	Person  string `json:"person"`

	// SessionID is the id the session was known by while it ran -- the
	// one History lists and the one a person sees on screen (22.09.2026).
	//
	// ID above is a hash of the recording's path on this gateway: stable,
	// opaque, and impossible to arrive at from anything a caller already
	// has. Without SessionID a window holding a history row could reach
	// its recording only by guessing on (person, machine, start instant),
	// which is a guess about whose terminal somebody is about to read.
	SessionID string `json:"sessionId"`

	// Mode says which shape the recording has: "exec" for a single
	// command recorded line by line, anything else (including empty, for
	// the .meta files written before the distinction existed) for a
	// terminal session recorded as asciicast.
	//
	// A reader MUST know this before it opens the bytes: the two are
	// different formats, and feeding a line-per-command journal to a
	// terminal emulator produces neither an error nor the text -- it
	// produces plausible-looking rubbish.
	Mode string `json:"mode,omitempty"`

	Started  string `json:"started"`
	Ended    string `json:"ended"`
	BytesIn  int64  `json:"bytesIn"`
	BytesOut int64  `json:"bytesOut"`
}

func cmdRecordingsList(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int    `json:"proto"`
		Machine string `json:"machine,omitempty"`
		From    string `json:"from,omitempty"`
		To      string `json:"to,omitempty"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}

	// PROTOCOL §6: from?/to?, bounds inclusive on StartedAt.
	// The same parsing as sessions.history — RFC3339 with a mandatory zone.
	var fromTime, toTime time.Time
	hasFrom, hasTo := false, false
	if req.From != "" {
		t, perr := config.ParseUntil(req.From)
		if perr != nil {
			return nil, errf("E_JSON_INVALID", 3, "from: %v", perr)
		}
		fromTime = t
		hasFrom = true
	}
	if req.To != "" {
		t, perr := config.ParseUntil(req.To)
		if perr != nil {
			return nil, errf("E_JSON_INVALID", 3, "to: %v", perr)
		}
		toTime = t
		hasTo = true
	}

	entries, err := scanRecordings(g.cfg.RecordingBaseDir)
	if err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	out := make([]recordingView, 0, len(entries))
	for _, e := range entries {
		if req.Machine != "" && e.metadata.Machine != req.Machine {
			continue
		}
		// The window bounds are inclusive: a session matches when
		// from <= StartedAt and StartedAt <= to (when both are set).
		if hasFrom && e.metadata.StartedAt.Before(fromTime) {
			continue
		}
		if hasTo && toTime.Before(e.metadata.StartedAt) {
			continue
		}
		// bytesOut lives in Metadata as BytesOut; bytesIn as BytesIn.
		// Old meta files may carry only TotalBytes; then BytesOut=0 —
		// the client treats TotalBytes as an alias for it (see the
		// record.Metadata comment) and substitutes it when BytesOut is zero.
		bytesOut := e.metadata.BytesOut
		if bytesOut == 0 {
			bytesOut = e.metadata.TotalBytes
		}
		out = append(out, recordingView{
			ID:        e.id,
			Machine:   e.metadata.Machine,
			Person:    e.metadata.Person,
			SessionID: e.metadata.SessionID,
			Mode:      e.metadata.RecordingMode,
			Started:   e.metadata.StartedAt.UTC().Format(time.RFC3339),
			Ended:     e.metadata.EndedAt.UTC().Format(time.RFC3339),
			BytesIn:   e.metadata.BytesIn,
			BytesOut:  bytesOut,
		})
	}
	return map[string]any{"recordings": out}, nil
}

func cmdRecordingsFetch(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto  int    `json:"proto"`
		ID     string `json:"id"`
		Part   string `json:"part"`
		Offset int64  `json:"offset"`
		Limit  int64  `json:"limit"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	switch req.Part {
	case "cast", "txt", "meta", "exec":
	default:
		return nil, errf("E_JSON_INVALID", 3, "part %q must be one of \"cast\", \"txt\", \"exec\" or \"meta\"", req.Part)
	}
	if req.Offset < 0 {
		return nil, errf("E_JSON_INVALID", 3, "offset must be >= 0, got %d", req.Offset)
	}
	if req.Limit < 1 || req.Limit > 1<<20 {
		return nil, errf("E_JSON_INVALID", 3, "limit must be between 1 and 1048576, got %d", req.Limit)
	}
	base, cerr := resolveRecordingBase(g.cfg.RecordingBaseDir, req.ID)
	if cerr != nil {
		return nil, cerr
	}
	// F-13 (round-1 review 24.09.2026): a recording that is still being
	// written is not fetched, in any part. Its "total" is one Stat and its
	// "sha256" a separate pass, so one answer's facts already belong to
	// different moments of a growing file - and the file keeps growing
	// between the chunks of one download, so the client walks offsets
	// against a moving end. PROTOCOL §6 leaves the live view to
	// sessions.tail; fetch serves finished recordings only. The refusal
	// reads the small .meta and nothing else. A .meta that cannot be read
	// changes nothing: this check refuses on a POSITIVE "recording" status
	// and never turns a corrupt .meta into an unfetchable recording.
	if recordingStillBeingWritten(base) {
		return nil, errf("E_CONFLICT", 2, "recording %q is still being written - fetch it after the session ends; a session in progress is watched live with sessions.tail", req.ID)
	}
	// Belt and suspenders: even though the id is an opaque hash, refuse to
	// serve any resolved path that somehow fell outside RecordingBaseDir.
	absBase, err := filepath.Abs(g.cfg.RecordingBaseDir)
	if err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	var path string
	switch req.Part {
	case "cast":
		path = base + ".cast"
	case "txt":
		path = base + ".txt"
	case "exec":
		path = base + ".exec.jsonl"
	case "meta":
		path = base + ".meta"
	}
	absPath, err := filepath.Abs(path)
	if err != nil || !strings.HasPrefix(absPath, absBase) {
		return nil, errf("E_NOT_FOUND", 2, "no such recording %q", req.ID)
	}
	// The serving open is a data-file read like any other: no-follow,
	// regular files only (IAMT-332 round six). A refusal lands in the
	// same E_NOT_FOUND mapping below, with the actionable wording in
	// place of a raw open error.
	f, err := state.OpenExistingDataFile(absPath, os.O_RDONLY)
	if err != nil {
		return nil, errf("E_NOT_FOUND", 2, "recording %q part %q is not available: %v", req.ID, req.Part, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, errf("E_INTERNAL", 70, "%v", err)
	}
	total := info.Size()
	sum, cerr := recordingPartSHA256(g.cfg.RecordingBaseDir, req.ID, base, req.Part)
	if cerr != nil {
		return nil, cerr
	}
	var data []byte
	if req.Offset < total {
		buf := make([]byte, req.Limit)
		n, rerr := f.ReadAt(buf, req.Offset)
		if rerr != nil && rerr != io.EOF {
			return nil, errf("E_INTERNAL", 70, "%v", rerr)
		}
		data = buf[:n]
	}
	g.logAdminOp(person, "recordings.fetch", req.ID, "ok", map[string]interface{}{"part": req.Part})
	return map[string]any{
		"id": req.ID, "part": req.Part, "offset": req.Offset, "total": total,
		"sha256": sum, "data": base64.StdEncoding.EncodeToString(data),
	}, nil
}

// ---- goal.* ---------------------------------------------------------------

type goalHistoryView struct {
	Goal  string `json:"goal"`
	SetAt string `json:"setAt"`
}

type goalView struct {
	Person  string            `json:"person"`
	Machine string            `json:"machine"`
	Goal    string            `json:"goal"`
	History []goalHistoryView `json:"history,omitempty"`
}

func goalViewFor(record state.GoalRecord, includeHistory bool) goalView {
	out := goalView{Person: record.Person, Machine: record.Machine, Goal: record.Current}
	if includeHistory {
		out.History = make([]goalHistoryView, 0, len(record.History))
		for _, entry := range record.History {
			out.History = append(out.History, goalHistoryView{Goal: entry.Goal, SetAt: entry.SetAt.String()})
		}
	}
	return out
}

func checkGoalMachine(g *Gateway, machine string) *cmdError {
	if err := state.ValidateName(machine); err != nil {
		return errf("E_JSON_INVALID", 3, "machine: %v", err)
	}
	st := g.cfg.Store.Get()
	if _, ok := st.MachineByID(machine); !ok {
		return errf("E_NOT_FOUND", 2, "no such machine %q", machine)
	}
	return nil
}

func checkGoalPerson(g *Gateway, person string) *cmdError {
	if err := state.ValidateName(person); err != nil {
		return errf("E_JSON_INVALID", 3, "person: %v", err)
	}
	st := g.cfg.Store.Get()
	if !st.HasPerson(person) {
		return errf("E_NOT_FOUND", 2, "no such person %q", person)
	}
	return nil
}

// cmdGoalSet, cmdGoalCurrent and cmdGoalHistory all key the goal by
// (req.Person, req.Machine) - the grant holder who will actually open the
// session, never the admin identity that authenticated the command. A
// goal belongs to the same pair a grant does (grants.grant takes the same
// two fields), because it is the pair that opens a session and the pair
// serveHumanSession looks the goal up under (review19 finding 3): if the
// admin's own identity leaked in here instead, the goal would only ever
// reach a session opened by the admin, and would silently never reach one
// opened by anybody else the admin granted access to.
func cmdGoalSet(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int    `json:"proto"`
		Person  string `json:"person"`
		Machine string `json:"machine"`
		Goal    string `json:"goal"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if cerr := checkGoalPerson(g, req.Person); cerr != nil {
		return nil, cerr
	}
	if cerr := checkGoalMachine(g, req.Machine); cerr != nil {
		return nil, cerr
	}
	if err := state.ValidateGoalText(req.Goal); err != nil {
		return nil, errf("E_JSON_INVALID", 3, "goal: %v", err)
	}
	var updated state.GoalRecord
	// The state write and the line that records it are ONE publication
	// (R2-CX F-10, round-2 review 24.09.2026): whoever reads the
	// pair - "gateway backup" above all, which reads state.json and the
	// journal and accepts only a pair that did not move under it - has to
	// see both or neither. Taking accessPublishMu here, as the grants
	// commands do, is what makes the two writes atomic to that reader;
	// without it a backup taken between them archives a state its own
	// journal does not describe.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	if err := g.cfg.Store.Update(func(st *state.State) error {
		var err error
		updated, err = st.SetGoal(req.Person, req.Machine, req.Goal, now)
		return err
	}); err != nil {
		return nil, errf("E_INTERNAL", 70, "could not persist goal: %v", err)
	}
	g.logAdminOp(person, "goal.set", req.Person+" -> "+req.Machine, "ok", map[string]interface{}{
		"goal":    risk.ScrubCommand(strings.TrimSpace(req.Goal)),
		"cleared": strings.TrimSpace(req.Goal) == "",
	})
	return goalViewFor(updated, true), nil
}

func cmdGoalCurrent(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int    `json:"proto"`
		Person  string `json:"person"`
		Machine string `json:"machine"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if cerr := checkGoalPerson(g, req.Person); cerr != nil {
		return nil, cerr
	}
	if cerr := checkGoalMachine(g, req.Machine); cerr != nil {
		return nil, cerr
	}
	st := g.cfg.Store.Get()
	record, found := st.GoalFor(req.Person, req.Machine)
	if !found {
		record = state.GoalRecord{Person: req.Person, Machine: req.Machine}
	}
	return goalViewFor(record, false), nil
}

func cmdGoalHistory(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int    `json:"proto"`
		Person  string `json:"person"`
		Machine string `json:"machine"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if cerr := checkGoalPerson(g, req.Person); cerr != nil {
		return nil, cerr
	}
	if cerr := checkGoalMachine(g, req.Machine); cerr != nil {
		return nil, cerr
	}
	st := g.cfg.Store.Get()
	record, found := st.GoalFor(req.Person, req.Machine)
	if !found {
		record = state.GoalRecord{Person: req.Person, Machine: req.Machine}
	}
	return goalViewFor(record, true), nil
}

// goalListResult is goal.list's reply: every (person, machine) pair
// carrying a goal record, each with its current goal and bounded
// history - the whole table in one round trip (IAMT-405).
type goalListResult struct {
	Goals []goalView `json:"goals"`
}

// cmdGoalList answers with every goal record the state carries. It
// checks nothing about persons or machines on purpose: a record exists
// only for a pair that was granted and declared a goal, and
// reconcileGoals has already dropped any record whose pair left the
// state - re-checking would only teach this read to fail on a snapshot
// that is consistent by construction.
func cmdGoalList(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	st := g.cfg.Store.Get()
	out := goalListResult{Goals: make([]goalView, 0, len(st.Goals))}
	for _, record := range st.Goals {
		out.Goals = append(out.Goals, goalViewFor(record, true))
	}
	return out, nil
}

// ---- risk.key ---------------------------------------------------------------

type riskKeyReplaceResult struct {
	Replaced    bool   `json:"replaced"`
	Present     bool   `json:"present"`
	Fingerprint string `json:"fingerprint"`
}

func cmdRiskKeyReplace(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int    `json:"proto"`
		Key   string `json:"key"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	key, formErr := normalizeExternalRiskKey(req.Key)
	if formErr != nil {
		return nil, errf("E_JSON_INVALID", 3, "%v", formErr)
	}
	// The state write and the line that records it are ONE publication,
	// the same lock every other command takes (R3 extra, round-3
	// review 24.09.2026). This command writes the new key metadata into
	// the state through replaceExternalRiskKey - one level down, which is
	// why the sweep of R2-CX F-10 walked past it - and its own admin.op
	// line after that; a backup taken in between used to archive a state
	// whose classifier key is already the new one, with a journal that
	// still names the old one (or nothing).
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	previous := g.externalRiskKeyStatus().Fingerprint
	status, err := g.replaceExternalRiskKey(key)
	if err != nil {
		reason := err.Error()
		code, exit, category := "E_INTERNAL", 70, ""
		var probeErr *externalRiskKeyProbeError
		if errors.As(err, &probeErr) {
			code, exit = "E_RISK_KEY_REJECTED", 1 // errdict:internal
			reason = externalRiskKeyReplacementReason(probeErr.cause)
			// IAMT-404: the class travels with the prose, so the window
			// never reads the sentence to tell "the key is bad" from "the
			// service was down".
			category = externalRiskKeyFailureCategory(probeErr.cause)
		}
		g.logAdminOp(person, "risk.key.replace", "external-risk-classifier", "failed", map[string]interface{}{
			"previousFingerprint": previous,
			"reason":              reason,
		})
		refusal := errf(code, exit, "%s", reason)
		refusal.category = category
		return nil, refusal
	}
	g.logAdminOp(person, "risk.key.replace", "external-risk-classifier", "ok", map[string]interface{}{
		"previousFingerprint": previous,
		"fingerprint":         status.Fingerprint,
	})
	return riskKeyReplaceResult{Replaced: true, Present: status.Present, Fingerprint: status.Fingerprint}, nil
}

// ---- gateway.* --------------------------------------------------------------

func cmdGatewayStatus(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	st := g.cfg.Store.Get()
	online, verified := 0, 0
	for _, m := range st.Machines {
		if m.State == "verified" {
			verified++
		}
		if mc, ok := g.reg.get(m.ID); ok && mc.doorMachine.Snapshot().Online {
			online++
		}
	}
	fp := auth.Fingerprint(g.cfg.HostKey.PublicKey())
	twentyFourHoursAgo := now.Add(-24 * time.Hour)
	// The audit journal's state leads the answer (IAMT-451), and a journal
	// that cannot even be read is no reason to withhold it: the risk counts
	// stay at zero and the read error goes with the audit state.
	audit := struct {
		AuditHealth
		ReadError string `json:"readError,omitempty"`
	}{AuditHealth: g.audit.snapshot()}
	// The whole history, not just the file being written (R2-CX F-02,
	// round-2 review 24.09.2026). ReadAll is what "the last 24
	// hours" means when the gateway rotates its own journal (IAMT-452):
	// the risk events it counts are exactly the ones a rotation moves
	// aside, so reading the current file alone reported a gateway that
	// had never refused anything - and the CLI prints that line as a
	// fact ("last 24h"). The same difference was caught in the History
	// tab on 21.09.2026 (see the comment on Log.Read); this is its
	// neighbour.
	riskEvents, _, err := g.cfg.Log.ReadAll(events.Filter{
		Since: &twentyFourHoursAgo,
		Types: []events.EventType{events.EventSessionRisk},
	})
	if err != nil {
		riskEvents, audit.ReadError = nil, err.Error()
	}
	type latestRedRisk struct {
		Time    string `json:"time"`
		Person  string `json:"person"`
		Machine string `json:"machine"`
		Rule    string `json:"rule"`
	}
	currentRisk := g.currentRiskMode()
	keyStatus := g.externalRiskKeyStatus()
	currentSource := g.currentRiskSource()
	riskSummary := struct {
		Mode             string         `json:"mode"`
		Source           string         `json:"source"`
		Classifier       string         `json:"classifier"`
		ClassifierSource string         `json:"classifierSource"`
		ClassifierKey    bool           `json:"classifierKey"`
		Yellow           int            `json:"yellow"`
		Red              int            `json:"red"`
		Blocked          int            `json:"blocked"`
		LatestRed        *latestRedRisk `json:"latestRed,omitempty"`
	}{
		Mode: string(currentRisk.mode), Source: currentRisk.source,
		// The LIVE classifier choice, not cfg's. Reporting the frozen
		// config value was harmless while the choice could only come from
		// the config; since 21.09.2026 it can be switched at runtime, and
		// a status that answered with the file would be answering about a
		// gateway that no longer exists.
		Classifier: string(currentSource.classifier), ClassifierSource: currentSource.source,
		// Whether a switch to ai or both is even possible from here.
		ClassifierKey: g.currentExternalRiskClassifier() != nil,
	}
	for _, event := range riskEvents {
		switch event.Result {
		case "yellow":
			riskSummary.Yellow++
		case "red":
			riskSummary.Red++
			latest := &latestRedRisk{Time: event.Time.Format("15:04"), Person: event.Actor, Machine: event.Object}
			if event.Details != nil {
				if r, ok := event.Details["rule"]; ok && r != nil {
					latest.Rule = fmt.Sprint(r)
				}
				if event.Details["action"] == string(RiskActionBlock) {
					riskSummary.Blocked++
				}
			}
			riskSummary.LatestRed = latest
		}
	}
	// The pairing window's state, not its PIN (IAMT-331): every other
	// administrator's card draws what pairing.start told IT, and a window
	// ended from the far side — a Stop by another client, another admin's
	// successful pair, a replacement — dies there without this one
	// hearing a word. The expiry rides along so a card can tell its own
	// window from a replacement. Always stated: "no window" is an answer,
	// not silence.
	pairing := struct {
		Active  bool   `json:"active"`
		Expires string `json:"expires,omitempty"`
	}{}
	if pp := st.PairingPending; pp != nil {
		pairing.Active = true
		pairing.Expires = rfc3339(pp.Expires.Time)
	}
	result := map[string]any{
		"online": true, "fingerprints": []string{fp},
		"machinesOnline": online, "machinesVerified": verified,
		"sessions": len(g.aclE.Sessions()), "serverTime": rfc3339(now), "risk": riskSummary,
		"externalRiskKey": keyStatus, "audit": audit, "pairing": pairing,
		// IAMT-466: which build answers, how full its recordings disk is,
		// and whether it is stopping (PROTOCOL §6).
		"version": g.cfg.Version, "draining": g.draining.Load(),
	}
	if used, err := record.DiskUsedPercent(g.cfg.RecordingBaseDir); err != nil {
		result["diskError"] = err.Error()
	} else {
		result["diskPercent"] = used
	}
	return result, nil
}

func cmdGatewayFingerprint(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	return map[string]any{"fingerprints": []string{auth.Fingerprint(g.cfg.HostKey.PublicKey())}}, nil
}

// cmdRiskCheck classifies against the gateway's selected decision source. The
// client calls this endpoint rather than a local copy so its answer describes
// the gateway that will execute the command.
func cmdRiskCheck(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto   int    `json:"proto"`
		Command string `json:"command"`
		Goal    string `json:"goal,omitempty"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if req.Command == "" {
		return nil, errf("E_JSON_INVALID", 3, "command must not be empty")
	}
	// History is nil on purpose: this is a dry-run probe of one command, not
	// an exec on a pair. It has no person-machine pair to read a buffer for
	// (req carries no machine), and answering "what would the classifier say"
	// must not quietly depend on which pair the asker had in mind.
	classification := g.classifyExec(req.Command, req.Goal, nil)
	result := map[string]any{
		"level": classification.Verdict.Level.String(), "rule": classification.Verdict.Rule, "reason": classification.Verdict.Reason,
		"classifier": string(classification.Classifier),
		"goal":       classification.Goal, "goalApplied": classification.GoalApplied,
	}
	if classification.ExternalError != nil {
		result["externalError"] = classification.ExternalError.Error()
	}
	return result, nil
}
