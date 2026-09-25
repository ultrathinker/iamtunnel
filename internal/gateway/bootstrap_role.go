package gateway

// bootstrap_role.go handles the username "bootstrap" SSH connection of
// PROTOCOL §3.3/§6: the operator dials as "bootstrap" with the
// HKDF-derived ephemeral key, runs exactly one "admin.claim" exec
// with the raw token and their long-term public key, and the runtime
// creates the first admin user atomically with the bootstrap token
// being burned.
//
// The invariant the test matrix on §4.4 enforces: this role can run
// "admin.claim" and nothing else. whoami is not here either — the
// admin must be created before any other command works for them, and
// "whoami" would answer "you are nothing" anyway.

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

// bootstrapRequest is the JSON body of the "admin.claim" exec, exactly
// PROTOCOL §6: {proto, bootstrap, pubkey}. The token is the raw secret
// the operator received at install time; pubkey is the long-term key
// they want to use as the first admin's first key.
type bootstrapRequest struct {
	Proto     int    `json:"proto"`
	Bootstrap string `json:"bootstrap"`
	Pubkey    string `json:"pubkey"`
}

// bootstrapResult is the success response shape PROTOCOL §6 prescribes
// for "admin.claim": {person, role:"admin"}.
type bootstrapResult struct {
	Person string `json:"person"`
	Role   string `json:"role"`
}

// handleBootstrap serves one "bootstrap"-login connection. Only
// "admin.claim" exec is permitted; anything else is E_EXEC_UNKNOWN.
func (g *Gateway) handleBootstrap(sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
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
			return
		}
		g.serveBootstrapSession(ch, chReqs)
		return
	}
}

// serveBootstrapSession is the bootstrap-login counterpart of
// serveEnrolSession: one "exec" request, one "admin.claim" command, one
// JSON body, one response.
func (g *Gateway) serveBootstrapSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	finished := false
	finish := func(result any, cerr *cmdError) {
		// Mark the one response as attempted before entering the wire writer: if
		// a broken channel implementation panics there, the recovery below must
		// not recursively try to write another response.
		finished = true
		g.finishEnrol(ch, result, cerr)
	}
	// This is the request boundary: one accepted session channel carries one
	// exec request and one body. Recover here, rather than in handleConn, so a
	// bootstrap panic becomes an E_INTERNAL response for this channel only;
	// panics elsewhere in the runtime remain visible to their owning tests and
	// handlers.
	defer func() {
		if recovered := recover(); recovered != nil {
			g.appendEvent(events.Event{
				Type:   events.EventAdminOp,
				Actor:  "bootstrap",
				Object: "admin.claim",
				Result: "bootstrap:panic",
				Details: map[string]interface{}{
					"reason":  "panic",
					"panic":   fmt.Sprint(recovered),
					"errCode": "E_INTERNAL",
				},
			})
			if !finished {
				finish(nil, errBootstrapInternal("internal error handling bootstrap request"))
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
		finish(nil, errBootstrapExecUnknown(req.Type))
		return
	}
	execMsg, perr := sshx.ParseExec(req.Payload)
	if perr != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		finish(nil, errBootstrapProtocol("malformed exec payload"))
		return
	}
	if execMsg.Command != "admin.claim" {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		finish(nil, errBootstrapExecUnknown(execMsg.Command))
		return
	}
	if req.WantReply {
		_ = req.Reply(true, nil)
	}
	body, rerr := readBounded(ch, maxExecRequestBytes)
	if rerr != nil {
		finish(nil, errBootstrapProtocol(rerr.Error()))
		return
	}
	// IAMT-451: not while the audit journal cannot record it; and a
	// record this claim lost while it ran is answered as lost, not
	// "ok" (F-15, 24.09.2026) -- runAuditedRole.
	now := g.cfg.Now()
	res, cerr := g.runAuditedRole("bootstrap", "the bootstrap claim", func() (any, *cmdError) {
		return g.runBootstrap(body, now)
	})
	finish(res, cerr)
}

func (g *Gateway) runBootstrap(body []byte, now time.Time) (any, *cmdError) {
	var req bootstrapRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return nil, classifyBootstrapDecodeErr(err)
	}
	if dec.More() {
		return nil, errBootstrapProtocol("request must be exactly one JSON object")
	}
	if req.Proto < 1 {
		return nil, errBootstrapProto("missing or non-positive proto")
	}
	if req.Proto > 1 {
		return nil, errBootstrapProtoClientNewer(req.Proto)
	}
	if req.Bootstrap == "" {
		return nil, errBootstrapUsed("missing bootstrap token")
	}
	if req.Pubkey == "" {
		return nil, errBootstrapUsed("missing pubkey")
	}
	if err := state.ValidateKeyMaterial(req.Pubkey); err != nil {
		return nil, errBootstrapProtocol("pubkey: " + err.Error())
	}

	presented := state.HashEnrolSecret(g.enrolHMAC, []byte(req.Bootstrap))

	type result struct {
		res *bootstrapResult
		err *cmdError
		// name is the person name we created, for the journal.
		name string
		fp   string
	}
	var out result
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
		// An admin claim on an already-set-up gateway (PROTOCOL §3.3:
		// the bootstrap token is one-shot).
		// Even if the bootstrap token still exists in state.json
		// (because nobody cleared the file), the first time any admin
		// is created the gateway refuses every subsequent admin.claim.
		// The check must happen BEFORE the secret-hash comparison so
		// that an attacker holding a copy of the bootstrap-token file
		// cannot even learn whether their token is the right one — the
		// response shape is the same regardless.
		if st.HasAnyAdmin() {
			out.err = errBootstrapUsed("an admin already exists; bootstrap is one-shot")
			return nil
		}
		if st.BootstrapPending == nil {
			out.err = errBootstrapUsed("no pending bootstrap token (already consumed or never issued)")
			return nil
		}
		if !st.BootstrapPending.Expires.After(now) {
			out.err = errBootstrapExpired("bootstrap token expired at " + st.BootstrapPending.Expires.String())
			return nil
		}
		if !hmac.Equal(st.BootstrapPending.SecretHash[:], presented[:]) {
			out.err = errBootstrapUsed("token does not match the pending bootstrap entry")
			return nil
		}
		// All three checks pass. Create the first admin in this same
		// transaction. The person name is derived from the public key's
		// fingerprint — there is no "user picks their username" path in
		// bootstrap, because there is no admin to ask.
		fp, ferr := state.ComputeFingerprint(req.Pubkey)
		if ferr != nil {
			out.err = errBootstrapProtocol("presented pubkey fingerprint: " + ferr.Error())
			return nil
		}
		// Name from fingerprint — personNameFromFingerprint below: the
		// bootstrap algorithm, shared with the pairing role (PROTOCOL
		// §3.4) so both one-shot paths mint names the same way.
		personName := firstAdminName(st, fp)
		st.People = append(st.People, state.Person{
			Name: personName,
			Role: "admin",
			Keys: []state.Key{{
				Fingerprint: fp,
				Pub:         req.Pubkey,
				Added:       state.NewZonedTime(now),
			}},
		})
		// Burn the token. A second claim, even with the right token,
		// now finds BootstrapPending == nil and gets E_BOOTSTRAP_USED.
		st.BootstrapPending = nil
		out.res = &bootstrapResult{Person: personName, Role: "admin"}
		out.name = personName
		out.fp = fp
		return nil
	})
	if err != nil {
		return nil, errBootstrapInternal("could not commit bootstrap state: " + err.Error())
	}

	if out.err != nil {
		var kind string
		switch out.err.code {
		case "E_BOOTSTRAP_USED":
			kind = "replay"
		case "E_BOOTSTRAP_EXPIRED":
			kind = "expired"
		default:
			kind = "other"
		}
		g.appendEvent(events.Event{
			Type:   events.EventAdminOp,
			Actor:  "bootstrap",
			Object: "admin.claim",
			Result: "bootstrap:" + kind,
			Details: map[string]interface{}{
				"reason":  kind,
				"errCode": out.err.code,
				"errMsg":  out.err.message,
			},
		})
		return nil, out.err
	}

	g.appendEvent(events.Event{
		Type:   events.EventAdminOp,
		Actor:  "bootstrap",
		Object: "admin.claim",
		Result: "bootstrap:ok",
		Details: map[string]interface{}{
			"person": out.name,
		},
	})
	return out.res, nil
}

// err helpers.

// firstAdminName names the very first administrator of a gateway.
//
// It is "admin". The fingerprint-derived form below is what PAIRING
// mints, and must stay so: people join by pairing again and again, and
// two of them must never collide. Bootstrap runs exactly ONCE per
// gateway, before anybody exists, so its name can be the obvious one.
//
// Until 19.09.2026 it was not, and the first administrator appeared as
// "a60lyahqwz0z9is6o" -- on every screen, and by hand in every grant
// typed. A name nobody can say out loud is a name nobody can use.
//
// The fingerprint form remains as the fallback for the one case that
// makes "admin" unsafe: a person of that name already existing. state
// is editable by hand and restorable from a backup, and a duplicate
// name is a far worse defect than an ugly one.
func firstAdminName(st *state.State, fp string) string {
	const want = "admin"
	for _, p := range st.People {
		if p.Name == want {
			return personNameFromFingerprint(fp)
		}
	}
	return want
}

// personNameFromFingerprint derives a deterministic §4.3 person name from
// a key fingerprint — the bootstrap rule, now shared with the pairing
// role (PROTOCOL §3.4): take the "SHA256:" form sans the prefix, cut to
// 24 characters, and drop every byte outside the name class
// [a-z0-9._-]. base64 fingerprint bytes can contain '+' or '/', which
// are NOT in the allowed name class, so the filter is what keeps the
// name legal. The deterministic shape means the admin stays referable by
// the same name across gateway restarts (the fingerprint itself does not
// change), and the "a" prefix keeps the name from starting with a
// character the grammar forbids.
func personNameFromFingerprint(fp string) string {
	rawName := strings.TrimPrefix(fp, "SHA256:")
	if len(rawName) > 24 {
		rawName = rawName[:24]
	}
	var filtered []byte
	for i := 0; i < len(rawName); i++ {
		c := rawName[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			filtered = append(filtered, c)
		}
	}
	return "a" + string(filtered)
}

func errBootstrapExecUnknown(name string) *cmdError {
	return errf("E_EXEC_UNKNOWN", 2, "unknown command %q on bootstrap-login (only \"admin.claim\" is accepted)", name)
}

func errBootstrapProtocol(msg string) *cmdError {
	return errf("E_CONTROL_PROTOCOL", 5, "bootstrap request malformed: %s", msg)
}

func errBootstrapProto(msg string) *cmdError {
	return errf("E_PROTO_GATEWAY_NEWER", 4, "%s", msg)
}

func errBootstrapProtoClientNewer(p int) *cmdError {
	return errf("E_PROTO_CLIENT_NEWER", 4, "client protocol version %d is newer than this gateway (supports 1)", p)
}

func errBootstrapUsed(format string, a ...any) *cmdError {
	return errf("E_BOOTSTRAP_USED", 2, format, a...)
}

func errBootstrapExpired(msg string) *cmdError {
	return errf("E_BOOTSTRAP_EXPIRED", 2, "%s", msg)
}

func errBootstrapInternal(msg string) *cmdError {
	return errf("E_INTERNAL", 70, "%s", msg)
}

func classifyBootstrapDecodeErr(err error) *cmdError {
	msg := err.Error()
	if i := strings.Index(msg, "unknown field "); i >= 0 {
		return errBootstrapProtocol("unexpected field in request: " + strings.TrimPrefix(msg[i:], "unknown field "))
	}
	return errBootstrapProtocol("malformed request JSON: " + err.Error())
}
