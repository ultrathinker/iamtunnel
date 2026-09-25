package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/auth"
	"github.com/ultrathinker/iamtunnel/internal/gateway/core"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/record"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// handleHuman routes one authenticated person connection. SPEC §5.1: exactly
// one session channel per connection; everything else is rejected.
//
// PROBE: PROTOCOL §4.2 keeps the gateway alive with respect to a silent
// human peer. After auth the transport's wall-clock deadline has already
// been cleared (gateway.go finishHandshake), so without an active probe
// a peer that holds its transport and stops sending — disconnected cable,
// closed laptop lid, a peer that never opens its keepalive responder —
// sits in ESTABLISHED forever, the io.Copy in core.Bridge stays blocked
// in a read, and sessions>0 keeps the door's idle-close path out. The
// probe below is the same sshx.Keepalive.Probe that already drives the
// machine side in machine_role.go (PROTOCOL §5, same numbers), only
// retargeted at the human end with Name="keepalive@openssh.com" so it
// matches §4.1's wire convention. The on-dead callback closes sconn:
// that cuts the underlying transport, Bridge's Read returns an error,
// stop() runs, recording aborts, and the same teardown path that any
// other transport loss takes cleans the session up. No new policy, no
// new event type — the existing TransportLost semantics carry it.
func (g *Gateway) handleHuman(sconn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request, username, fingerprint string) {
	defer sconn.Close()

	// PROBE START: parameterised by Config.HumanKeepalive (default 20 s /
	// 3 misses / openssh.com). Stop is deferred so the probe is cancelled
	// exactly once on every exit path: clean end (Bridge returns), denial
	// (early return on ACL/door/host-key mismatch), panic (the deferred
	// stop runs in that case too). The probe is also idempotent: Probe
	// returns a stop closure that is safe to call multiple times and
	// blocks until its goroutine actually exits, so the next closure call
	// from the deferred line does not race the gateway shutdown sweep.
	// probeKilled records whether onDead below is the reason this
	// connection went away. core.Bridge cannot tell these two apart on its
	// own: closing sconn surfaces to the human->target copy as a plain
	// read EOF, the same clean-end shape a human who closes their own
	// channel produces (PROTOCOL §4.2, IAMT-220 — the live session that
	// prompted this: a real OpenSSH peer went quiet, the probe killed it,
	// and events.jsonl recorded session.stop "ok", indistinguishable from
	// a normal exit). serveHumanSession reads this flag after Bridge
	// returns to tell the two apart and journal the probe kill as
	// session.drop instead.
	var probeKilled atomic.Bool
	stopHumanProbe := g.cfg.HumanKeepalive.Probe(sconn, func() {
		// Callback fires at most once per probe: sshx.Keepalive.Probe
		// declares the cycle done before invoking onDead, so a stop()
		// call inside this callback would deadlock. The probe's own
		// goroutine has finished by the time we get here. Closing
		// sconn is enough: the reqs handler below observes the
		// closed channel and exits; the chans range loop in this
		// function exits next iteration; Bridge's io.Copy fails on
		// the human side; the normal teardown path takes over.
		probeKilled.Store(true)
		_ = sconn.Close()
	})
	defer stopHumanProbe()

	parsed, err := auth.ParseUsername(username)
	if err != nil {
		for n := range chans {
			_ = n.Reject(ssh.Prohibited, "not implemented")
		}
		return
	}
	go func() {
		for r := range reqs {
			d := sshx.LookupGlobalRequest(r.Type)
			if d == sshx.Reject {
				_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, nil)
				g.recordSSHRequestReject(parsed.Person, parsed.Machine, r.Type, false)
				continue
			}
			_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, nil)
		}
	}()
	// The connection is good only while the key it authenticated with is
	// still the person's (IAMT-449, key_conns.go).
	key := &keyConn{person: parsed.Person, fingerprint: fingerprint, addr: sconn.RemoteAddr().String(), close: sconn.Close}
	defer g.trackKeyConn(key)()
	if parsed.Machine == "" {
		// command-login ("<person>" alone): whoami, machines.mine, and the admin
		// exec surface of admin_role.go (SPEC §3.3, §5.1, PROTOCOL §2.1, §6).
		g.handleCommand(sconn, chans, reqs, parsed.Person, key)
		return
	}

	sessionAccepted := false
	for n := range chans {
		if n.ChannelType() != "session" {
			_ = n.Reject(ssh.UnknownChannelType, "only session channels are allowed")
			g.recordSSHRequestReject(parsed.Person, parsed.Machine, n.ChannelType(), false)
			continue
		}
		if sessionAccepted {
			_ = n.Reject(ssh.Prohibited, "only one session channel is allowed")
			g.recordSSHRequestReject(parsed.Person, parsed.Machine, "session", false)
			continue
		}
		human, hreqs, err := n.Accept()
		if err != nil {
			return
		}
		sessionAccepted = true
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			g.serveHumanSession(parsed.Person, parsed.Machine, human, hreqs, &probeKilled, sconn, key)
			// Before IAMT-189 serveHumanSession ran synchronously and this
			// handler's deferred Close ended the transport when it returned.
			// Keep that lifecycle after accepting a concurrent second-channel
			// refusal: a finished first session must not leave a quiet SSH
			// connection alive indefinitely.
			_ = sconn.Close()
		}()
	}
}

// serveHumanSession is the human path: parse -> ask ACL -> ask
// the door automaton to reserve -> wait for it to actually open -> open the
// proof inside the machine -> bridge bytes through the recording. Every
// door decision is a core.Machine call (Check happens first and unconditionally
// gates reservation: a denial here never touches mc.reserve, so a denied
// human never causes so much as a door.status).
func (g *Gateway) serveHumanSession(person, machine string, human ssh.Channel, hreqs <-chan *ssh.Request, probeKilled *atomic.Bool, transport io.Closer, key *keyConn) {
	// IAMT-451: a session whose start and end cannot be put on record is
	// not started. The person gets what every refusal gives them
	// (E_SESSION_DENIED); why is in gateway.status.
	if g.auditRefusal() != nil {
		// F-03 (round-1 review, 24.09.2026): the session.drop that used to
		// be written here went into the journal that is refusing it, so it
		// could not be written - it only counted one more lost record that
		// never existed. The one log that still works says who was turned
		// away and from where, and gateway.status carries the state.
		if g.cfg.Diagnostics != nil {
			fmt.Fprintf(g.cfg.Diagnostics, "iamtunnel gateway: refused %s a session to %s: the audit journal is not being written (gateway status has the state).\n", person, machine)
		}
		g.writeAndClose(human, "Access to this machine is currently unavailable.\r\n")
		return
	}
	// IAMT-466: a gateway that is stopping takes nothing new, not even on
	// a connection that got in just before the stop.
	// F-24: this check and the session's registration below (OpenSession)
	// are one decision the stop must not straddle. The check runs under
	// setupMu together with counting this setup in setupWG, and Drain waits
	// on setupWG under the same mutex after setting the flag: either this
	// setup sees the flag and is refused, or the stop waits for it to show
	// up in the engine's session list. The count is dropped the moment the
	// session is registered or its setup failed - waiting for sessions to
	// end is the drain poll's job, not this one's.
	g.setupMu.Lock()
	if g.draining.Load() {
		g.setupMu.Unlock()
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: "gateway restarting"})
		g.writeAndClose(human, drainRefusal)
		return
	}
	g.setupWG.Add(1)
	g.setupMu.Unlock()
	setupCounted := true
	defer func() {
		if setupCounted {
			g.setupWG.Done()
		}
	}()
	now := g.cfg.Now()
	decision := g.aclE.Check(person, machine, now)
	if !decision.Allowed {
		g.denyHuman(human, person, machine, decision.Reason)
		return
	}

	mc, ok := g.reg.get(machine)
	if !ok {
		g.denyHuman(human, person, machine, acl.DenyMachineOffline)
		return
	}

	// SPEC §5.1 lists the door's preconditions: the permission, the machine
	// being verified and online with the current epoch - and NO host-key
	// mismatch. The record is read here, before mc.reserve, for the same reason
	// the ACL check runs first: a refusal must not cost the machine so much as
	// a door.status, and the door automaton is not asked to hold a rule it was
	// never given. This is the rule §4.3 states and the reason step 2 exists:
	// without it the verdict would be recorded and ignored.
	pre := g.cfg.Store.Get()
	if m, known := pre.MachineByID(machine); !known || m.State != "verified" || m.OSUserStatus != state.OSUserStatusVerified || m.VerifiedOSUser == nil {
		g.denyHuman(human, person, machine, acl.DenyMachineUnverified)
		return
	} else if m.HostKeyStatus == state.HostKeyStatusMismatch {
		g.denyHumanHostKeyMismatch(human, person, machine)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), g.cfg.SessionSetupTimeout)
	defer cancel()
	// One budget for the whole setup (PROTOCOL §1.4): the reservation, the
	// iamtunnel-target open, the nested handshake with the machine's sshd
	// and the session channel inside it. Every wait after the reservation
	// used to be unbounded, and a machine or sshd that went quiet there
	// held the reservation - the door could not close on idle - and the
	// person at "connecting" (IAMT-450).
	setupDeadline, _ := ctx.Deadline()
	opened, reason := mc.reserve(ctx)
	if !opened {
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: reason})
		g.writeAndClose(human, "Access to this machine is currently unavailable.\r\n")
		return
	}

	st := g.cfg.Store.Get()
	target, targetReqs, err := sshx.OpenChannelWithDeadline(mc.sconn, "iamtunnel-target", setupDeadline, mc.doneCh)
	if err != nil {
		mc.nestedHandshakeFailed()
		g.denyHuman(human, person, machine, acl.DenyMachineOffline)
		return
	}
	go discardRequests(targetReqs)

	stMachine, foundMachine := st.MachineByID(machine)
	if !foundMachine || stMachine.SSHDHostKey == nil || stMachine.OSUserStatus != state.OSUserStatusVerified || stMachine.VerifiedOSUser == nil {
		mc.nestedHandshakeFailed()
		_ = target.Close()
		g.denyHuman(human, person, machine, acl.DenyMachineUnverified)
		return
	}
	pinnedBlob, err := state.DecodeKeyBlob(*stMachine.SSHDHostKey)
	if err != nil {
		mc.nestedHandshakeFailed()
		_ = target.Close()
		g.denyHuman(human, person, machine, acl.DenyMachineUnverified)
		return
	}
	signer, doorID := mc.currentDoorSigner()
	if signer == nil {
		mc.nestedHandshakeFailed()
		_ = target.Close()
		g.denyHuman(human, person, machine, acl.DenyMachineOffline)
		return
	}

	// Set by the HostKeyCallback below when the target sshd presented a foreign
	// key. The nested handshake then fails for THAT reason, and the refusal has
	// to name it rather than report the machine as merely unverified. The
	// callback runs synchronously inside ssh.NewClientConn on this goroutine,
	// so a plain local is enough and no lock is involved.
	hostKeyMismatch := false

	// handshake runs the nested SSH handshake over one iamtunnel-target
	// channel with one door key. It is a function because it may run twice
	// (IAMT-461, below).
	handshake := func(target ssh.Channel, signer ssh.Signer) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
		nestedCfg := &ssh.ClientConfig{
			User: *stMachine.VerifiedOSUser,
			Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
				if !bytes.Equal(key.Marshal(), pinnedBlob) {
					pinnedFP, _ := state.ComputeFingerprint(*stMachine.SSHDHostKey)
					hostKeyMismatch = true
					g.recordHostKeyObservation(person, machine, key, pinnedFP, false)
					return fmt.Errorf("gateway: target sshd host key does not match the pinned key")
				}
				g.recordHostKeyObservation(person, machine, key, "", true)
				return nil
			},
		}
		// PROTOCOL §5.2: the nested handshake MUST apply the same ordered
		// KEX/cipher/MAC/host-key algorithm lists as the outer handshake, not
		// x/crypto defaults (IAMT-173).
		sshx.ApplyClientConfig(nestedCfg)
		// ClientConfig.Timeout would bound nothing here: only ssh.Dial reads
		// it. The deadline goes on the connection itself, as the sshd probe
		// does, and comes off once the handshake is done - the session that
		// follows lasts as long as it lasts.
		targetConn := sshx.NewChannelConn(target)
		_ = targetConn.SetDeadline(setupDeadline)
		nested, nchans, nreqs, err := ssh.NewClientConn(targetConn, "iamtunnel-target", nestedCfg)
		if err == nil {
			_ = targetConn.SetDeadline(time.Time{})
		}
		return nested, nchans, nreqs, err
	}
	nested, nchans, nreqs, err := handshake(target, signer)
	if err != nil && !hostKeyMismatch && isSSHAuthFailed(err) {
		// IAMT-461: sshd refusing the door key is, as often as not, a door
		// the machine has already closed on its own timer - it does not
		// tell the gateway, and a session still inside kept the gateway's
		// automaton at open. Ask before blaming sshd; if the door is gone,
		// come in once more through the new one.
		switch mc.recheckDoor(ctx, doorID) {
		case doorUnavailable:
			// The reservation is already released; the door did not come
			// back within this person's setup budget.
			g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: "door did not reopen"})
			g.writeAndClose(human, "Access to this machine is currently unavailable.\r\n")
			return
		case doorReopened:
			target, targetReqs, err = sshx.OpenChannelWithDeadline(mc.sconn, "iamtunnel-target", setupDeadline, mc.doneCh)
			if err != nil {
				mc.nestedHandshakeFailed()
				g.denyHuman(human, person, machine, acl.DenyMachineOffline)
				return
			}
			go discardRequests(targetReqs)
			if signer, _ = mc.currentDoorSigner(); signer == nil {
				mc.nestedHandshakeFailed()
				_ = target.Close()
				g.denyHuman(human, person, machine, acl.DenyMachineOffline)
				return
			}
			nested, nchans, nreqs, err = handshake(target, signer)
		}
	}
	if err != nil {
		mc.nestedHandshakeFailed()
		if hostKeyMismatch {
			g.denyHumanHostKeyMismatch(human, person, machine)
			return
		}
		if isSSHAuthFailed(err) {
			g.denyHumanSSHAuthFailed(human, person, machine)
			return
		}
		g.denyHumanSSHDUnreachable(human, person, machine)
		return
	}
	defer nested.Close()
	go func() {
		for n := range nchans {
			_ = n.Reject(ssh.UnknownChannelType, "no reverse channels")
		}
	}()
	go discardRequests(nreqs)

	nestedSession, mreqs, err := sshx.OpenChannelWithDeadline(nested, "session", setupDeadline, mc.doneCh)
	if err != nil {
		mc.nestedHandshakeFailed()
		g.denyHuman(human, person, machine, acl.DenyMachineUnverified)
		return
	}
	defer nestedSession.Close()

	// The reservation the door granted becomes a counted session only now
	// that the nested handshake to sshd actually succeeded (PROTOCOL §5.2).
	mc.nestedHandshakeSucceeded()

	sessionID := fmt.Sprintf("%d-%s-%s", g.cfg.Now().UnixNano(), person, machine)
	revoked := new(atomic.Bool)
	sess, err := g.aclE.OpenSession(person, machine, g.cfg.Now(), func(reason acl.DenyReason) {
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: reason.String(),
			Details: map[string]interface{}{"sessionId": sessionID}})
		revoked.Store(true)
		g.endRevokedSession(human, nested, transport, sessionClosedMessage(reason))
	})
	if err != nil {
		mc.finishSession()
		g.denyHuman(human, person, machine, acl.DenyGrantRevoked)
		return
	}
	// F-24: the session is counted in the engine's list from here on, so
	// the stop's wait may end and its poll will find this session (and
	// watchDrain below tells it). The count was for the blind spot; the
	// session's remaining life is the poll's to watch.
	setupCounted = false
	g.setupWG.Done()
	// From here a removed key ends the session through the engine
	// (IAMT-449). A removal that landed while the session was being set up
	// found no session to kill and only closed the connection; it is
	// caught here instead.
	key.carries(sess.ID)
	if !g.keyStillHeld(key) {
		g.cutKeyConn(key)
	}
	// Told if the gateway begins to stop while this session lives
	// (IAMT-466, drain.go).
	defer g.watchDrain(sessionID, human)()

	start, ok := awaitSessionStart(hreqs, nestedSession, human, g.cfg.SessionSetupTimeout, sess.ExecOnly, func(code, requestType string) {
		g.recordSSHRequestRejectCode(person, machine, code, requestType)
	})
	if !ok {
		g.aclE.Close(sess.ID, g.cfg.Now())
		mc.finishSession()
		if start.denyCode != "" {
			// awaitSessionStart already wrote the refusal to human's
			// stderr and closed human itself (A2) — this call must not
			// write or close again, only journal the same code in
			// place of the generic "timeout".
			g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: start.denyCode,
				Details: map[string]interface{}{"sessionId": sessionID}})
			return
		}
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: "timeout",
			Details: map[string]interface{}{"sessionId": sessionID}})
		g.writeAndClose(human, "Access to this machine is currently unavailable.\r\n")
		return
	}

	// Snapshot the pair's explicitly declared current goal for this session.
	// It is not derived from history, and every exec barrier in this session
	// uses the same snapshot even if an administrator declares a later goal.
	// The pair's recent-command buffer (IAMT-409) is snapshotted next to it:
	// every classifier request of this session rides the same history, and a
	// command this barrier forwards appends to the buffer only after the
	// session's own teardown, so the snapshot cannot see its own write.
	sessionGoal := ""
	st = g.cfg.Store.Get()
	if declared, found := st.GoalFor(person, machine); found {
		sessionGoal = declared.Current
	}
	sessionHistory := pairRecentCommandHistory(st, person, machine)

	// An exec request is the one session shape whose complete command is
	// known before a byte reaches the machine. Interactive shell input is a
	// stream with no trustworthy command boundary and is intentionally not
	// classified here.
	var verdict risk.Verdict
	var action RiskAction
	var policyAction RiskAction
	var approvalID string
	var classification riskClassification
	failureAction := RiskActionLog
	failureStops := false
	if start.exec {
		classification = g.classifyExec(start.command, sessionGoal, sessionHistory)
		failureAction, failureStops = g.riskClassifierFailurePolicy(classification)
		verdict = classification.Verdict
		verdict = failedClassifierVerdict(classification, failureAction, verdict)
		if classification.ExternalAsync {
			g.observeExternalRisk(sessionID, person, machine, start.command, sessionGoal, sessionHistory, classification.Local, classification.ExternalClient)
		}
		if verdict.Level != risk.Green || classification.ExternalError != nil {
			action = RiskActionLog
			if failureStops {
				action = RiskActionBlock
			} else if verdict.Level == risk.Green && classification.ExternalError != nil {
				action = failureAction
			} else if classification.failsClosed() && failureAction == RiskActionAsk {
				policyAction, action, approvalID = g.prepareRiskActionWithPolicy(RiskActionAsk,
					person, machine, sessionID, start.command, verdict)
			} else {
				policyAction, action, approvalID = g.prepareRiskAction(person, machine, sessionID, start.command, verdict)
			}
			eventAction := action
			if verdict.Level != risk.Green {
				eventAction = policyAction
			}
			details := riskEventDetails(sessionID, start.command, verdict, eventAction)
			details["classifier"] = string(classification.Classifier)
			details["goal"] = classification.Goal
			details["goalApplied"] = classification.GoalApplied
			if classification.Classifier != RiskClassifierRules {
				details["local"] = classification.Local.Level.String()
				details["externalCalled"] = classification.ExternalCalled || classification.ExternalAsync
				details["threshold"] = risk.ExternalRiskThreshold
				if classification.ExternalCalled {
					details["latency_ms"] = classification.ExternalWait.Milliseconds()
				}
				if classification.ExternalScores != nil {
					details["probabilities"] = classification.ExternalScores
					details["external"] = classification.External.Level.String()
				}
				if classification.ExternalError != nil {
					details["externalError"] = classification.ExternalError.Error()
					details["failureKind"] = string(risk.ExternalFailureKindOf(classification.ExternalError))
					if status := risk.ExternalFailureStatusCode(classification.ExternalError); status != 0 {
						details["status"] = status
					}
				}
			}
			if approvalID != "" {
				details["approvalId"] = approvalID
				if action == RiskActionLog {
					details["approval"] = "consumed"
				}
			}
			result := verdict.Level.String()
			if verdict.Level == risk.Green && classification.ExternalError != nil {
				result = "external-error"
			}
			g.appendEvent(events.Event{
				Type:    events.EventSessionRisk,
				Actor:   person,
				Object:  machine,
				Result:  result,
				Details: details,
			})
		}
	}

	rec, err := g.cfg.NewRecording(SessionInfo{Person: person, Machine: machine, OSUser: *stMachine.VerifiedOSUser,
		SessionID: sessionID, Cols: start.cols, Rows: start.rows, Exec: start.exec && !start.pty, Command: start.command})
	if err != nil {
		g.aclE.Close(sess.ID, g.cfg.Now())
		mc.finishSession()
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: "recording: " + err.Error()})
		g.writeAndClose(human, "Access to this machine is currently unavailable.\r\n")
		return
	}
	// A command let through by an approval says so. The condition below
	// deliberately hides a Log action, and "the policy is ask, the action
	// became log, and there is an approval id" is the one case where that
	// silence misleads: see riskApprovedNotice.
	approvalUsed := policyAction == RiskActionAsk && action == RiskActionLog && approvalID != ""
	if verdict.Level != risk.Green && action != RiskActionLog || classification.ExternalError != nil || approvalUsed {
		// This is emitted before forwardSessionStart, so the warning is always
		// visible before the target can produce command output. Writing through
		// execRecordingWriter makes it an ordinary stderr chunk in .exec.jsonl.
		//
		// A2: this write's error used to be dropped on the floor; the A2
		// remark was that errors from execRec.Finish() and the stderr
		// warning write must not be swallowed silently any more. SPEC's own
		// recording invariant (a failed recording write closes the session
		// before an unwritten byte is passed on) applies
		// here exactly as it does to every other recording write in this
		// file: a failure ends the session instead of silently letting an
		// unwarned or unlogged command proceed to the machine.
		var notice []byte
		if failureStops {
			notice = riskClassifierFailureStop(classification.Classifier, classification.ExternalError, false)
		} else if verdict.Level == risk.Green && classification.ExternalError != nil {
			if classification.failsClosed() {
				notice = riskClassifierFailureWarningWithAction(classification.Classifier, classification.ExternalError, failureAction, false)
			} else {
				notice = riskClassifierFailureWarning(classification.Classifier, classification.ExternalError, false)
			}
		} else if approvalUsed {
			notice = riskApprovedNotice(verdict, approvalID, false)
		} else {
			notice = riskWarningWithClassifier(verdict, policyAction, approvalID, classification.Classifier, classification.ExternalError, false)
		}
		var writeErr error
		if execRec, isExec := rec.(*record.ExecRecorder); isExec {
			_, writeErr = execRecordingWriter{rec: execRec, dst: human.Stderr()}.Write(notice)
		} else {
			_, writeErr = human.Stderr().Write(notice)
		}
		if writeErr != nil {
			_ = rec.Abort("stderr notice write failed: " + writeErr.Error())
			g.aclE.Close(sess.ID, g.cfg.Now())
			mc.finishSession()
			g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: "recording: " + writeErr.Error(),
				Details: map[string]interface{}{"sessionId": sessionID}})
			_ = human.Close()
			return
		}
	}
	if failureStops {
		if start.request != nil && start.request.WantReply {
			_ = start.request.Reply(true, nil)
		}
		var finishErr error
		if execRec, isExec := rec.(*record.ExecRecorder); isExec {
			_ = execRec.ExitStatus(126)
			finishErr = execRec.Finish()
		} else {
			finishErr = rec.Close()
		}
		_, _ = human.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 126}))
		g.aclE.Close(sess.ID, g.cfg.Now())
		mc.finishSession()
		details := classifierFailureEventDetails(sessionID, start.command, classification)
		if finishErr != nil {
			details["recordingError"] = finishErr.Error()
		}
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine,
			Result:  riskClassifierFailureCode, // errdict:internal
			Details: details,
		})
		_ = human.Close()
		return
	}
	if policyAction == RiskActionAsk && action == RiskActionAsk {
		if start.request != nil && start.request.WantReply {
			_ = start.request.Reply(true, nil)
		}
		var finishErr error
		if execRec, isExec := rec.(*record.ExecRecorder); isExec {
			_ = execRec.ExitStatus(126)
			finishErr = execRec.Finish()
		} else {
			finishErr = rec.Close()
		}
		_, _ = human.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 126}))
		g.aclE.Close(sess.ID, g.cfg.Now())
		mc.finishSession()
		details := map[string]interface{}{
			"sessionId":   sessionID,
			"approvalId":  approvalID,
			"goal":        classification.Goal,
			"goalApplied": classification.GoalApplied,
		}
		if finishErr != nil {
			details["recordingError"] = finishErr.Error()
		}
		// A command held because the classifier was silent keeps its own
		// code in the journal (21.09.2026). Both are "waiting for a
		// person", but an operator reading a month of drops needs to tell
		// "the AI judged this dangerous, and often" apart from "the AI was
		// down all Tuesday" -- those call for opposite actions.
		dropCode := "E_APPROVAL_REQUIRED" // errdict:internal
		if verdict.Rule == riskClassifierFailureRule {
			dropCode = riskClassifierFailureCode
			details["failureKind"] = string(risk.ExternalFailureKindOf(classification.ExternalError))
			details["failureReason"] = riskClassifierFailureReason(classification.ExternalError)
		}
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine,
			Result:  dropCode,
			Details: details,
		})
		_ = human.Close()
		return
	}
	if action == RiskActionBlock {
		// The exec request was syntactically accepted, but its program is not
		// allowed to start. Acknowledge the request and return the conventional
		// shell status for "found but not executable" without forwarding it.
		if start.request != nil && start.request.WantReply {
			_ = start.request.Reply(true, nil)
		}
		// A2: finishErr used to be dropped by "_ = execRec.Finish()". It now
		// rides in Details next to the E_COMMAND_BLOCKED the session
		// actually ended for, instead of vanishing: the block is still the
		// reason this session ended, a recording fault is secondary
		// operational information for whoever reads the journal.
		var finishErr error
		if execRec, isExec := rec.(*record.ExecRecorder); isExec {
			_ = execRec.ExitStatus(126)
			finishErr = execRec.Finish()
		} else {
			finishErr = rec.Close()
		}
		_, _ = human.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 126}))
		g.aclE.Close(sess.ID, g.cfg.Now())
		mc.finishSession()
		details := map[string]interface{}{
			"sessionId":   sessionID,
			"goal":        classification.Goal,
			"goalApplied": classification.GoalApplied,
		}
		if finishErr != nil {
			details["recordingError"] = finishErr.Error()
		}
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine,
			Result:  "E_COMMAND_BLOCKED", // errdict:internal
			Details: details,
		})
		_ = human.Close()
		return
	}
	// IAMT-338: say where this session is being recorded, so it can be
	// watched while it is still happening. The registration is deferred
	// out immediately, which is what makes it leak-proof: every exit
	// below — refusal, drop, revoke, panic, the normal end — passes
	// through it, and none of them has to remember to.
	//
	// The paths come through a type assertion rather than through
	// core.Recording, on purpose. core.Recording is the interface the
	// bridge needs, and widening it would force every test double in
	// this package to grow a method whose only reader is this feature.
	// A recorder that cannot name its own files registers nothing and
	// is simply not watchable, which is the right answer for a double.
	//
	// Registered under the ACL id -- the one "sessions active" PRINTS --
	// and not under the journal's sessionID (IAMT-361). They are
	// different strings: the journal's is "<nanos>-<person>-<machine>",
	// the ACL's is "session:<n>". Every reader of this registry already
	// assumed the ACL id: the machine-initiated tail compares it against
	// s.ID.String(), and the seam test registers it that way by hand.
	// Only the production registration used the other one, so
	// "sessions tail" with the id the product itself had just printed
	// found nothing -- and answered, well-formed and silent, "there is
	// nothing to follow", which reads as an empty session rather than as
	// a wrong id. Watching a live session had therefore never worked
	// from anywhere except a test that keyed it itself.
	//
	// IAMT-453: the file comes as a record.LiveFile, which both recorders
	// give. It used to come from Paths(), whose two shapes differ, and the
	// assertion here matched only the terminal one: an exec session was
	// never registered and could not be watched.
	if p, ok := rec.(interface{ LiveFile() record.LiveFile }); ok {
		g.live.addFile(sess.ID.String(), p.LiveFile(), machine)
		defer g.live.remove(sess.ID.String())
	}

	if !forwardSessionStart(start, nestedSession) {
		_ = rec.Abort("target rejected session start")
		g.aclE.Close(sess.ID, g.cfg.Now())
		mc.finishSession()
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: "target rejected session start",
			Details: map[string]interface{}{"sessionId": sessionID}})
		g.writeAndClose(human, "Access to this machine is currently unavailable.\r\n")
		return
	}

	// R4 F-03: an exec-only grant never carries stdin, so the machine must
	// not sit there reading commands past the classifier. Close the target
	// side's stdin the instant the command has been forwarded — iamtunnel's
	// own client has always done exactly this for its exec (internal/client/
	// execrun.go), so a real machine sees the same shape from both paths. A
	// bare `powershell` / `bash` launched by name gets EOF and exits instead
	// of turning into an interactive, unclassified shell. Bytes the person
	// writes anyway are refused by execStdinGuard below, not silently
	// dropped: the session ends with a named code rather than a mystery.
	// (The CloseWrite itself is best-effort; the guard is the enforcement.)
	if start.exec && sess.ExecOnly {
		_ = nestedSession.CloseWrite()
	}

	// IAMT-210: one session.start per session, period. The exec case
	// used to ALSO append a second session.start with
	// Actor:"exec", Object:<command>, which `sessions history`
	// rendered as a confusing "exec -> whoami; hostname; …" line
	// alongside the legitimate "liveuser -> desktop-i3fl2s5" one —
	// two starts per session, and the second one mis-typed the
	// actor as a noun that is not a person, machine, gateway or
	// admin (PROTOCOL §1.7's closed vocabulary for `actor`). The
	// fix consolidates the command into the existing session.start
	// event's Details, where it stays searchable in events.jsonl
	// without becoming a separate row in the history view. The
	// PROTOCOL §1.7 event dictionary is closed, so adding a new
	// event type is not an option (gate 12).
	details := map[string]interface{}{
		"sessionId":   sessionID,
		"goal":        risk.ScrubCommand(sessionGoal),
		"goalApplied": start.exec && classification.GoalApplied,
	}
	if start.exec {
		// Scrubbed like the goal above and like session.risk (R4 F-09,
		// THREATS: journal output). The full command stays in the
		// session record, which is 0600.
		details["command"] = risk.ScrubCommand(start.command)
	}
	g.appendEvent(events.Event{Type: events.EventSessionStart, Actor: person, Object: machine, Result: "ok",
		Details: details})

	// "until" is the deadline text shown in the recorded-session
	// banner (PROTOCOL §5: ASCII "This session is recorded. Machine X,
	// until T.\r\n", where T is the grant's RFC 3339 UTC deadline).
	// Three states:
	//
	//   - grant has a deadline (Until != nil): use that RFC 3339.
	//   - grant exists but is indefinite (Until == nil): "revoked"
	//     (IAMT-208 — matches the same word `grants list` and
	//     `grants grant` already use, so the line is unambiguous and
	//     a tired administrator cannot mistake it for a typo).
	//   - no grant for (person, machine): "unknown". ACL upstream
	//     forbids this case; leaving "unknown" makes a future ACL
	//     regression visible in the banner instead of silently
	//     printing a different machine's deadline. "revoked"
	//     here would actively mislead.
	until := "unknown"
	for _, gr := range st.Grants {
		if gr.Person != person || gr.Machine != machine {
			continue
		}
		if gr.Until != nil {
			until = gr.Until.String()
		} else {
			until = "revoked"
		}
		break
	}
	// exec: the banner goes to stderr, so a command's own stdout stays exactly
	// what the command printed (an agent piping it into a file or a hash got
	// the banner mixed in). A terminal shows stderr just the same.
	banner := []byte(fmt.Sprintf("This session is recorded. Machine %s, until %s.\r\n", machine, until))
	if start.exec {
		_, _ = human.Stderr().Write(banner)
	} else {
		_, _ = human.Write(banner)
	}

	// IAMT-172: proxyChannelRequests writes events.jsonl (the "exec"
	// branch in particular) and resizes the recording. Both writes can
	// run after Gateway.Close has finished if the goroutine is
	// fire-and-forget, so count this under g.wg and let Close wait for
	// it.
	g.wg.Add(1)
	g.proxyReqsInFlight.Add(1)
	go func() {
		defer g.wg.Done()
		defer g.proxyReqsInFlight.Add(-1)
		g.proxyChannelRequests(hreqs, nestedSession, human, rec, sess.ExecOnly, person, machine, sessionID, sessionGoal)
	}()
	// IAMT-409: an exec session captures the first lines of what the machine
	// answered, so the teardown below can append one complete entry to the
	// pair's recent-command buffer. Shell sessions have no command boundary
	// and never capture.
	var respCap *responseCapture
	if start.exec {
		respCap = newResponseCapture()
	}
	var stderrDrained <-chan struct{}
	if execRec, isExec := rec.(*record.ExecRecorder); isExec {
		done := make(chan struct{})
		stderrDrained = done
		// IAMT-172: this goroutine writes the exec recording for its
		// whole lifetime (WriteStderr -> the .exec.jsonl file), so a
		// fire-and-forget launch could keep writing after Gateway.Close
		// has returned and cleanup has begun. Count it under g.wg like
		// the two proxy writers: Close cuts the transports first, the
		// copy sees the dead stream and returns, Done runs.
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			defer close(done)
			stderrSrc := io.Reader(nestedSession.Stderr())
			if respCap != nil {
				stderrSrc = captureReader{r: stderrSrc, c: respCap}
			}
			_, err := io.Copy(execRecordingWriter{rec: execRec, dst: human.Stderr()}, stderrSrc)
			if err != nil {
				_ = human.Close()
				_ = nestedSession.Close()
			}
		}()
	}

	// targetDrained closes the instant core.Bridge's target -> human copy
	// below returns - see that parameter's doc comment on Bridge. outputDrained
	// additionally waits for the exec stderr copy above (when there is one),
	// so it closes only once every byte the machine sent - stdout and stderr -
	// has actually been committed. proxyMachineRequests waits on it before
	// recording exit-status/exit-signal (IAMT-306: fixes the .exec.jsonl
	// ordering), and the exec-only goroutine below waits on it for the same
	// reason before forcing the human channel closed.
	targetDrained := make(chan struct{})
	outputDrained := make(chan struct{})
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		defer close(outputDrained)
		<-targetDrained
		if stderrDrained != nil {
			<-stderrDrained
		}
	}()

	// mreqsDrained closes once proxyMachineRequests(mreqs, ...) returns -
	// i.e. once the nested session channel is fully closed (PROTOCOL par.4.1:
	// the request stream dies with the channel). exit-status travels only
	// on mreqs (machine -> human), so this is exactly the signal
	// closeAfterMachineDrain waits for below - see its comment for the
	// full reasoning and sshx.ExitStatusGrace comment for why the wait
	// is bounded.
	mreqsDrained := make(chan struct{})
	// IAMT-409: pairExit keeps the outcome the machine reported on mreqs —
	// a decimal exit status or "signal <NAME>" — or stays unset when none
	// arrived before the channel died. proxyMachineRequests writes it from
	// its own goroutine; the exec teardown below reads it only after
	// mreqsDrained has closed, and the close is the handoff that makes the
	// write visible.
	var pairExit atomic.Value
	goProxyExit := func(status string) { pairExit.Store(status) }
	g.wg.Add(1)
	g.proxyReqsInFlight.Add(1)
	go func() {
		defer g.wg.Done()
		defer g.proxyReqsInFlight.Add(-1)
		defer close(mreqsDrained)
		g.proxyMachineRequests(mreqs, human, rec, outputDrained, func() {
			_ = human.Close()
			_ = nestedSession.Close()
		}, goProxyExit)
	}()

	// IAMT-306: a plain exec channel has no reason for the human side to
	// ever close on its own. The command has already run to completion on
	// the machine; a client with a live, non-redirected stdin (an ordinary
	// interactive terminal running `ssh gw 'cmd'`, not iamtunnel's own
	// client) is not obliged to send its own channel EOF just because it
	// received the command's output and exit-status, and plenty of
	// well-behaved SSH clients wait for the SERVER to close first - live
	// repro: after a completed exec, ssh -vv showed a perfectly normal
	// exit-status/eof/channel-free exchange and then sat connected for
	// ten minutes, until the human's own connection idle-closed the door
	// that whole time was still open. core.Bridge's human -> target copy
	// blocks forever on exactly that Read in this situation, and nothing
	// else in this function ever unblocks it, because closing the human
	// channel today happens only after Bridge returns (closeAfterMachineDrain,
	// IAMT-108) - and Bridge does not return until human -> target also ends.
	//
	// Once outputDrained and mreqsDrained both close, the machine has
	// nothing further to say: every byte and the exit-status have already
	// been delivered. There is no more reason to wait for the human's own
	// initiative, so this goroutine sends the channel close itself.
	// human.Close() only puts SSH_MSG_CHANNEL_CLOSE on the wire; every
	// compliant SSH peer - including a bare `ssh` client with a live tty -
	// is required to reply with its own close on receipt (RFC 4254 §5.3,
	// and the same auto-ack golang.org/x/crypto/ssh itself performs on
	// this end), and that reply is what actually unblocks Bridge's
	// human -> target Read with a clean EOF instead of an error, so the
	// session still ends as session.stop, not session.drop.
	if start.exec {
		g.wg.Add(1)
		go func() {
			defer g.wg.Done()
			<-outputDrained
			<-mreqsDrained
			// IAMT-409: the command was forwarded to the machine, so it
			// belongs in the pair's buffer with whatever outcome and answer
			// arrived. Both drain signals have closed: exit-status travels
			// on mreqs, so it has been processed, and every output byte has
			// been committed — the entry is complete, nothing can still
			// append to the capture. A command the barrier stopped never
			// reaches this goroutine and never enters the buffer.
			exit, _ := pairExit.Load().(string)
			g.recordRecentCommand(person, machine, start.command, exit, respCap.Response())
			_ = human.Close()
		}()
	}

	// mc.ctx, not context.Background(): if the machine's transport dies
	// mid-session, only the target side of this bridge breaks on its own -
	// the human side stays blocked reading from a human who is still
	// connected and has sent nothing. mc.ctx is cancelled by teardown
	// specifically to unblock that Read (see machine_conn.go's comment
	// on the ctx field).
	// A2/A1 finding: when this session is exec-with-stderr, target is
	// wrapped so core.Bridge cannot signal EOF on the machine's regular
	// stream until the stderr-forwarder goroutine above has also finished
	// writing to human. See drainedAfter's own doc comment for the race
	// this closes — it was found by internal/client's own exec canary
	// (execrun_test.go), which failed intermittently with a truncated
	// session and a missing exit-status.
	bridgeTarget := core.Stream(nestedSession)
	if respCap != nil {
		// IAMT-409: machine stdout feeds the pair's response capture on its
		// way through Bridge's target -> human copy. Innermost on purpose:
		// the capture must see the bytes before drainedAfter gates them.
		bridgeTarget = captureStream{Stream: bridgeTarget, c: respCap}
	}
	if start.exec && sess.ExecOnly {
		// R4 F-03: the CloseWrite above tells the machine there is no more
		// stdin; this guard is what tells the PERSON. A plain swallow would
		// be wrong twice over — bytes dropped silently, and Bridge would read
		// a clean EOF-ish end as an ordinary end of input — so the first
		// stdin byte instead breaks the copy with errExecStdinForbidden, the
		// same way any other bridging fault breaks it, and the drop below
		// journals the named code.
		bridgeTarget = &execStdinGuard{Stream: bridgeTarget, stderr: human.Stderr()}
	}
	if stderrDrained != nil {
		bridgeTarget = drainedAfter{Stream: bridgeTarget, drained: stderrDrained}
	}
	bridgeErr := core.Bridge(mc.ctx, revocableHuman{Channel: human, revoked: revoked}, bridgeTarget, rec, targetDrained)
	closeAfterMachineDrain(bridgeErr, mreqsDrained, human, nestedSession)
	if stderrDrained != nil {
		<-stderrDrained
	}
	if execRec, isExec := rec.(*record.ExecRecorder); isExec && bridgeErr == nil {
		if err := execRec.Finish(); err != nil {
			bridgeErr = err
		}
	}

	g.aclE.Close(sess.ID, g.cfg.Now())
	mc.finishSession()
	switch {
	case bridgeErr != nil:
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: bridgeErr.Error(),
			Details: map[string]interface{}{"sessionId": sessionID}})
	case probeKilled != nil && probeKilled.Load():
		// PROTOCOL §4.2 (IAMT-220): the probe's onDead closed sconn, which
		// reached Bridge as a plain clean-end EOF on the human side —
		// bridgeErr == nil, same shape a human closing their own channel
		// produces. Without this check that would journal as session.stop
		// "ok", indistinguishable from a normal exit; the whole point of
		// this fix is that a keepalive kill must be nameable in the log.
		g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: "keepalive-timeout",
			Details: map[string]interface{}{"sessionId": sessionID}})
	default:
		g.appendEvent(events.Event{Type: events.EventSessionStop, Actor: person, Object: machine, Result: "ok",
			Details: map[string]interface{}{"sessionId": sessionID}})
	}
}

// closeAfterMachineDrain is the day-to-day answer to who closes the
// channels, and when, for IAMT-108 gateway fix. core.Bridge no longer
// closes human and target itself when it ends cleanly (see core/bridge.go
// doc comment on Bridge) - closing is left to this call specifically so it
// can wait for the machine -> human request stream to drain first.
//
// Why the wait is needed: exit-status (PROTOCOL par.4.1, only machine to
// human, forwarded) travels on mreqs, which the goroutine started next to
// core.Bridge above forwards to human on its own; drained closes only once
// that goroutine returns, which happens only once the nested session
// channel is fully closed - the request stream dies with the channel, the
// same fact sshx.ExitStatusGrace comment starts from. On a clean end the
// machine has normally already sent exit-status before the data EOF the
// bridge saw, on the same ordered transport, so by the time Bridge returns
// the request is usually already sitting in mreqs buffer and this wait
// covers only the forwarding goroutine getting scheduled.
//
// The wait is bounded by sshx.ExitStatusGrace for the reason given on that
// constant: a machine that half-closed its data side (so the bridge still
// ends cleanly) and then went silent - never sending exit-status, never
// closing the channel - must end the session without one rather than hang
// it forever. It is the same constant the client waits on
// (internal/client/connect.go): one number and one doctrine for both ends
// of this pipe, on purpose - two different bounds would drift apart at the
// very first edit to either one.
//
// On any non-clean end (bridgeErr != nil: a bridging error, or mc.ctx
// cancelled because the machine transport died - see machine_conn.go
// comment on the ctx field), core.Bridge has already closed both channels
// itself before returning, precisely to unblock a human read that would
// otherwise stay blocked forever on a human who is still connected and has
// sent nothing. Waiting here too would reopen exactly that hang, so this
// function does nothing on that path - it must not even close again,
// since Bridge already did.
func closeAfterMachineDrain(bridgeErr error, drained <-chan struct{}, human, target io.Closer) {
	if bridgeErr != nil {
		return
	}
	timer := time.NewTimer(sshx.ExitStatusGrace)
	select {
	case <-drained:
		timer.Stop()
	case <-timer.C:
	}
	_ = human.Close()
	_ = target.Close()
}

// recordHostKeyObservation writes the verdict of one nested-handshake host key
// comparison into the machine record (§4.3: hostKeyStatus plus the key actually
// seen) and, for a mismatch, into the journal.
//
// One place, one order. The state transaction goes first because the record is
// what the door rule reads (SPEC §5.1: a machine that has a host-key mismatch
// must not get a door), so a failure there must never leave the event as the
// only trace, and the journal append follows immediately inside this same
// function - no caller in between can write one and skip the other. The append
// itself stays best-effort, as every other appendEvent in this package is, and
// a lost event cannot hide the verdict: the verdict is in the record. The
// observation is idempotent and repeats on every attempt, so a state write that
// failed is retried by the next handshake instead of being forgotten.
//
// A mismatch recorded here is NOT cleared here. match and unverified describe
// the last comparison; mismatch is a suspicion of substitution, and §4.3/§6.2
// clear it only through an administrator's re-verification (machines.verify /
// machines.rekey) - never as a side effect of a later handshake that happens to
// agree. Today nothing can reach such a handshake anyway: a machine recorded as
// mismatch is refused before its door opens (see the guard in
// serveHumanSession), and this rule is what keeps that true if a future path
// ever connects to a machine without a door.
func (g *Gateway) recordHostKeyObservation(person, machineID string, presented ssh.PublicKey, pinnedFP string, matched bool) {
	status := state.HostKeyStatusMatch
	if !matched {
		status = state.HostKeyStatusMismatch
	}

	// The key seen is stored the way the pinned sshdHostKey is stored - an
	// authorized_keys line - so that state.DecodeKeyBlob and
	// state.ComputeFingerprint work on it exactly as they do on the pinned key
	// (a later `machines.rekey --confirm-fingerprint` has to compare against a
	// fingerprint of the observed key).
	seen := presented.Type() + " " + base64.StdEncoding.EncodeToString(presented.Marshal())

	// The state write and the line that records it are ONE publication
	// (R3 F-03, round-3 review 24.09.2026), the same lock the admin
	// commands, enrol, bootstrap and pairing take: a backup taken in the
	// pause between the two used to read a state that calls the machine's
	// key wrong, twice, with a journal that never says so - and the sticky
	// mismatch rule is read from the state while the audit of it is read
	// from the journal.
	//
	// Nothing here is called from under a command: this runs while a human
	// session is being set up, before any command of it.
	accessPublishMu.Lock()
	defer accessPublishMu.Unlock()
	st := g.cfg.Store.Get()
	if current, found := st.MachineByID(machineID); found {
		alreadyRecorded := current.HostKeyStatus == status &&
			current.ObservedSSHDHostKey != nil && *current.ObservedSSHDHostKey == seen
		if matched && current.HostKeyStatus == state.HostKeyStatusMismatch {
			alreadyRecorded = true // sticky: see the comment above
		}
		if !alreadyRecorded {
			// The transaction is scoped to these two fields: a comparison is
			// the only writer of them, and it must not carry anything else of a
			// machine record across a concurrent change.
			_ = g.cfg.Store.Update(func(st *state.State) error {
				for i := range st.Machines {
					m := &st.Machines[i]
					if m.ID != machineID {
						continue
					}
					if matched && m.HostKeyStatus == state.HostKeyStatusMismatch {
						return nil
					}
					m.HostKeyStatus = status
					v := seen
					m.ObservedSSHDHostKey = &v
					return nil
				}
				return nil
			})
		}
	}

	if matched {
		// §3.5's dictionary is closed and holds no "the keys agreed" event:
		// agreement is the absence of the mismatch event, and the record says
		// which key was seen.
		return
	}

	observedFP := auth.Fingerprint(presented)
	g.appendEvent(events.Event{
		Type:        events.EventHostKeyMismatch,
		Actor:       person,
		Object:      machineID,
		Result:      "mismatch",
		Fingerprint: observedFP,
		Details: map[string]interface{}{
			"observed": observedFP,
			"pinned":   pinnedFP,
		},
	})
}

// proxyChannelRequests applies the one table sshx owns (PROTOCOL §4.1) to
// every request arriving on src, forwarding to fwdTo on Forward and recording
// pty/window sizes when rec is non-nil. It returns when src's request
// channel closes (i.e. the SSH channel is gone).
func (g *Gateway) proxyChannelRequests(src <-chan *ssh.Request, fwdTo, human ssh.Channel, rec core.Recording, execOnly bool, person, machine, sessionID, sessionGoal string) {
	budget := sshx.NewEnvBudget()
	execOnlyRejected := false // D1(b): one event per session, not per refusal
	for r := range src {
		var d sshx.Disposition
		if r.Type == "env" {
			d = budget.Decide(r.Payload)
		} else {
			d = sshx.LookupChannelRequest(r.Type, r.Payload)
		}
		if execOnly && (r.Type == "pty-req" || r.Type == "shell") {
			_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, sshx.Reject, nil)
			if !execOnlyRejected {
				g.recordSSHRequestReject(person, machine, r.Type, true)
				execOnlyRejected = true
			}
			continue
		}
		// The program was started by the request awaitSessionStart
		// returned - with a pty-req before it or without (IAMT-454) - and
		// was classified there: a second shell or exec is refused.
		if r.Type == "shell" || r.Type == "exec" {
			_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, sshx.Reject, nil)
			g.recordSSHRequestReject(person, machine, r.Type, false)
			continue
		}
		if d == sshx.Reject {
			_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, nil)
			g.recordSSHRequestReject(person, machine, r.Type, false)
			continue
		}
		if r.Type == "pty-req" {
			// IAMT-217: a mid-session pty-req can carry the same 0x0 size a
			// human's pty-req can (see awaitSessionStart/fixPTYSize) - and,
			// IAMT-442, the same oversize one. Fix it here too, before
			// forward captures r.Payload, so the machine gets the same size
			// the .cast "r" event below records.
			if fixedPayload, _, _, changed := fixPTYSize(r.Payload); changed {
				r.Payload = fixedPayload
			}
		}
		if r.Type == "window-change" {
			// IAMT-442: a resize is held to the same bound, again before
			// forward, for the same reason.
			if fixedPayload, changed := fixWindowSize(r.Payload); changed {
				r.Payload = fixedPayload
			}
		}
		forward := func() (bool, error) { return fwdTo.SendRequest(r.Type, r.WantReply, r.Payload) }
		applied := sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, forward)
		if applied != sshx.Forward {
			continue
		}
		if rec == nil {
			continue
		}
		switch r.Type {
		case "pty-req":
			if p, err := sshx.ParsePTY(r.Payload); err == nil && p.Columns > 0 && p.Rows > 0 {
				resizeRecording(rec, int(p.Columns), int(p.Rows))
			}
		case "window-change":
			if w, err := sshx.ParseWindow(r.Payload); err == nil && w.Columns > 0 && w.Rows > 0 {
				resizeRecording(rec, int(w.Columns), int(w.Rows))
			}
			// IAMT-210: no exec case here. The single session.start event
			// was already written by serveHumanSession, with the exec
			// command in Details. Writing another event from this path
			// produced the second "session.start" row sessions.history
			// used to render, with the actor literal "exec" that is
			// neither a person nor a machine — see the canary in
			// iamt210_sessions_history_exec_test.go.
		}
	}
}

// recordSSHRequestReject records an SSH request or channel-open that v1
// explicitly rejects. The event dictionary has no SSH-request-specific type;
// session.drop is the existing type for a refused interactive action, while
// Result preserves the normative E_SSH_* code for an operator's search.
func (g *Gateway) recordSSHRequestReject(person, machine, requestType string, execOnly bool) {
	g.recordSSHRequestRejectCode(person, machine, sshRequestRejectCode(requestType, execOnly), requestType)
}

// recordSSHRequestRejectCode is recordSSHRequestReject for a caller that
// already knows the code the refusal must carry — awaitSessionStart's deny
// branches, whose code must match the denyCode row the session's end
// journals for the same refusal.
func (g *Gateway) recordSSHRequestRejectCode(person, machine, code, requestType string) {
	g.appendEvent(events.Event{
		Type:   events.EventSessionDrop,
		Actor:  person,
		Object: machine,
		Result: code,
		Details: map[string]interface{}{
			"sshRequest": requestType,
		},
	})
}

func sshRequestRejectCode(requestType string, execOnly bool) string {
	if execOnly && (requestType == "pty-req" || requestType == "shell") {
		return "E_SSH_SHELL_FORBIDDEN" // errdict:internal
	}
	switch requestType {
	case "subsystem":
		return "E_SSH_SUBSYSTEM_FORBIDDEN" // errdict:internal
	case "auth-agent-req@openssh.com":
		return "E_SSH_AGENT_FORBIDDEN" // errdict:internal
	case "x11-req":
		return "E_SSH_X11_FORBIDDEN" // errdict:internal
	case "direct-tcpip", "tcpip-forward", "cancel-tcpip-forward":
		return "E_SSH_FORWARD_FORBIDDEN" // errdict:internal
	case "session", "shell", "exec":
		return "E_SSH_SESSION_ALREADY_STARTED" // errdict:internal
	default:
		return "E_SSH_REQUEST_FORBIDDEN" // errdict:internal
	}
}

type sessionStart struct {
	cols, rows int
	// pty is whether the target took a pty-req before the program's
	// request: an exec then runs in a terminal and is recorded as one
	// (IAMT-454).
	pty     bool
	exec    bool
	command string
	request *ssh.Request
	// denyCode is set only when awaitSessionStart itself has already
	// written a refusal to human's stderr and closed human (A2: an
	// exec-only grant's pty-req/shell no longer waits out the rest of
	// SessionSetupTimeout in silence — see the execOnly branch below).
	// ok is still false in that case; the caller must not write to or
	// close human again, only clean up session bookkeeping and journal
	// this code in place of "timeout".
	denyCode string
}

// shellForbiddenMessage is A2's fix for human_role.go's own former
// silence: with an exec grant, pty-req and shell used to be refused
// without a single word to the person, who waited until timeout. PROTOCOL §5.2's
// pty-req/shell table rows both read "refuse with
// E_SSH_SHELL_FORBIDDEN at caps:[\"exec\"]" — this is that code, put where a person
// actually reads it: human's own stderr channel. internal/client's
// Connect drains that channel into its caller's Out
// during setup specifically so this line is not lost the way it used
// to be — there is no separate wording for "client connect" to repeat;
// it is the same bytes. It also names the way out, so a person is not
// left to guess "iamtunnel client exec" exists at all.
func shellForbiddenMessage() []byte {
	return []byte("[iamtunnel] E_SSH_SHELL_FORBIDDEN: this grant allows individual commands only — an interactive terminal (shell) cannot be opened with it.\r\nRun the command like this: iamtunnel client exec <machine> -- <command>.\r\n")
}

// shellNeedsTerminalMessage is the refusal of a shell that asked for no
// terminal (IAMT-464), in the same shape as shellForbiddenMessage: what
// happened, why, and the two ways that do work.
func shellNeedsTerminalMessage() []byte {
	return []byte("[iamtunnel] E_SSH_SHELL_NO_PTY: a shell is opened only in a terminal — without one, what the program writes to stderr could be neither shown to you nor recorded.\r\nAsk for a terminal (ssh -t), or run one command: iamtunnel client exec <machine> -- <command>.\r\n")
}

// execStdinForbiddenMessage is F-03's line for the person whose bytes the
// gateway refused to carry, in the same shape as shellForbiddenMessage:
// what happened, why, and the way that does work. execStdinGuard writes it
// to human's stderr before failing the copy, so it reaches the terminal
// even though the session is being torn down around it.
func execStdinForbiddenMessage() []byte {
	return []byte("[iamtunnel] E_SSH_STDIN_FORBIDDEN: this grant allows individual commands only — the gateway does not carry stdin to them, so what you typed did not reach the machine.\r\nRun the command like this: iamtunnel client exec <machine> -- <command>.\r\n")
}

// defaultPTYColumns/defaultPTYRows are substituted for a pty-req's 0x0 size
// (RFC 4254 §6.2 permits it; OpenSSH's client sends exactly this when stdin
// is not a terminal - IAMT-217's live probe). They MUST be the one pair used
// both for the .cast header/VT parser size and for what actually reaches the
// machine (fixPTYSize below): a mismatch there is exactly IAMT-217 - the
// machine picks its own ConPTY size while the recording assumes this one,
// and the transcript is parsed in the wrong geometry.
const (
	defaultPTYColumns = 80
	defaultPTYRows    = 24
)

// fixPTYSize makes a pty-req's size one the gateway will really use, and
// makes the payload say so, byte-for-byte preserving every other field
// (term, pixel size, modes) via a parse/re-marshal round trip:
//
//   - a zero column or row count becomes defaultPTYColumns/defaultPTYRows
//     (IAMT-217);
//   - a count past record.MaxCols/record.MaxRows becomes that bound
//     (IAMT-442). The count is whatever uint32 the person's client chose,
//     and the recording allocates rows*cols cells for it at once.
//
// It reports whether it changed anything, and the payload to use either way
// - callers forward the returned payload rather than the original when ok,
// so the machine gets the size the recording parses in.
func fixPTYSize(payload []byte) (fixed []byte, cols, rows int, ok bool) {
	p, err := sshx.ParsePTY(payload)
	if err != nil {
		return payload, 0, 0, false
	}
	c := boundPTYDimension(p.Columns, defaultPTYColumns, record.MaxCols)
	r := boundPTYDimension(p.Rows, defaultPTYRows, record.MaxRows)
	if c == p.Columns && r == p.Rows {
		return payload, int(c), int(r), false
	}
	p.Columns, p.Rows = c, r
	return sshx.MarshalPTY(p), int(c), int(r), true
}

// fixWindowSize holds a window-change to record.MaxCols/record.MaxRows
// (IAMT-442) in the payload the machine gets, and so in the size the
// recording resizes to. A zero count is left as it was: the recording
// already ignores one, and what a machine makes of it is its own affair.
func fixWindowSize(payload []byte) (fixed []byte, changed bool) {
	w, err := sshx.ParseWindow(payload)
	if err != nil {
		return payload, false
	}
	c := boundPTYDimension(w.Columns, 0, record.MaxCols)
	r := boundPTYDimension(w.Rows, 0, record.MaxRows)
	if c == w.Columns && r == w.Rows {
		return payload, false
	}
	w.Columns, w.Rows = c, r
	return sshx.MarshalWindow(w), true
}

// boundPTYDimension is one dimension of the rule above: zero is def, and
// anything past limit is limit.
func boundPTYDimension(n, def, limit uint32) uint32 {
	if n == 0 {
		return def
	}
	if n > limit {
		return limit
	}
	return n
}

// awaitSessionStart consumes setup requests until a shell or an exec - the
// request that starts a program - has arrived. The recorder is deliberately
// opened only after this decision, while the target program still cannot
// deliver a byte to the human channel.
//
// A pty-req starts nothing (IAMT-454). It used to end the setup: the timer
// stopped - PROTOCOL §1.4 gives the setup until a successful shell or exec -
// so a pty-req and then silence held the session and its door open with no
// program ever run; and the session's shape was settled before its program
// was known, so the exec of "ssh -t gw command" arrived after the start,
// out of reach of everything that records a command. Now a pty-req is
// forwarded as it comes - the person's client may wait for its answer
// before it sends the rest - and remembered, together with any resize that
// follows it, and the setup goes on until the shell or the exec.
//
// onReject journals a refused request: the branches that end the session
// pass the deny code they are about to return (the journal then says the
// same thing whoever reads it, and however the two rows of one refusal
// land in events.jsonl), the branches that refuse and keep waiting pass
// the generic sshRequestRejectCode mapping.
func awaitSessionStart(reqs <-chan *ssh.Request, target, human ssh.Channel, timeout time.Duration, execOnly bool, onReject func(code, requestType string)) (sessionStart, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	budget := sshx.NewEnvBudget()
	// The terminal the program will start in, once the target has taken a
	// pty-req.
	cols, rows, pty := defaultPTYColumns, defaultPTYRows, false
	// forward hands r to the target, answers the person with the target's
	// answer, and reports whether the target took it. A request that wants
	// no answer is taken as sent.
	forward := func(r *ssh.Request, d sshx.Disposition) bool {
		if d != sshx.Forward {
			_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, nil)
			return false
		}
		taken := !r.WantReply
		_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, func() (bool, error) {
			ok, err := target.SendRequest(r.Type, r.WantReply, r.Payload)
			if r.WantReply {
				taken = err == nil && ok
			}
			return ok, err
		})
		return taken
	}
	for {
		select {
		case <-timer.C:
			return sessionStart{}, false
		case r, ok := <-reqs:
			if !ok {
				return sessionStart{}, false
			}
			d := sshx.LookupChannelRequest(r.Type, r.Payload)
			if r.Type == "env" {
				d = budget.Decide(r.Payload)
			}
			if execOnly && (r.Type == "pty-req" || r.Type == "shell") {
				_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, sshx.Reject, nil)
				if onReject != nil {
					onReject("E_SSH_SHELL_FORBIDDEN", r.Type) // errdict:internal
				}
				// A2: say so now and end the session, instead of
				// leaving the person sitting through the rest of the
				// setup timeout for an answer that already exists.
				_, _ = human.Stderr().Write(shellForbiddenMessage())
				_ = human.Close()
				return sessionStart{denyCode: "E_SSH_SHELL_FORBIDDEN"}, false // errdict:internal
			}
			if r.Type == "exec" {
				exec, err := sshx.ParseExec(r.Payload)
				if err != nil {
					_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, sshx.Reject, nil)
					if onReject != nil {
						onReject(sshRequestRejectCode(r.Type, false), r.Type)
					}
					continue
				}
				return sessionStart{cols: cols, rows: rows, pty: pty, exec: true, command: exec.Command, request: r}, true
			}
			if r.Type == "shell" {
				if !pty {
					// IAMT-464: a shell with no terminal is refused. The
					// machine keeps such a program's stderr apart, and a
					// terminal session carries and records only the output
					// stream: its stderr would reach neither the person nor
					// the recording. The product never offered this mode.
					_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, sshx.Reject, nil)
					if onReject != nil {
						// The journal row of the wire refusal says the same
						// thing the denial itself does. It used to go through
						// the generic mapping, which filed "shell" under
						// E_SSH_SESSION_ALREADY_STARTED - a sentence about a
						// session that had started, when nothing had: the
						// shell is refused for the missing terminal, and the
						// denyCode row written moments later said exactly
						// that. An operator searching events.jsonl by
						// E_SSH_SHELL_NO_PTY found one row of the refusal and
						// a second row contradicting it (MAC, 24.09.2026).
						onReject("E_SSH_SHELL_NO_PTY", r.Type) // errdict:internal
					}
					_, _ = human.Stderr().Write(shellNeedsTerminalMessage())
					_ = human.Close()
					return sessionStart{denyCode: "E_SSH_SHELL_NO_PTY"}, false // errdict:internal
				}
				return sessionStart{cols: cols, rows: rows, pty: pty, request: r}, true
			}
			if r.Type == "pty-req" {
				if _, err := sshx.ParsePTY(r.Payload); err != nil {
					_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, sshx.Reject, nil)
					if onReject != nil {
						onReject(sshRequestRejectCode(r.Type, false), r.Type)
					}
					continue
				}
				// IAMT-217: a pty-req with cols=0 or rows=0 (RFC 4254 §6.2;
				// OpenSSH's client sends exactly this when stdin is not a
				// terminal) must not diverge between what the .cast
				// header/VT parser assume and what actually reaches the
				// machine - fixPTYSize substitutes the same
				// default*80x24* in both, byte-for-byte preserving term/
				// pixel size/modes, and (IAMT-442) holds an oversized one
				// to the bound. r.Payload is fixed before it is forwarded.
				fixedPayload, c, rw, _ := fixPTYSize(r.Payload)
				r.Payload = fixedPayload
				if forward(r, d) {
					cols, rows, pty = c, rw, true
				}
				continue
			}
			if r.Type == "window-change" {
				// A resize before the program starts is the recording's
				// starting size, and held to the same bound (IAMT-442).
				if fixedPayload, changed := fixWindowSize(r.Payload); changed {
					r.Payload = fixedPayload
				}
				if forward(r, d) && pty {
					if w, err := sshx.ParseWindow(r.Payload); err == nil && w.Columns > 0 && w.Rows > 0 {
						cols, rows = int(w.Columns), int(w.Rows)
					}
				}
				continue
			}
			if d == sshx.Reject {
				_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, nil)
				if onReject != nil {
					onReject(sshRequestRejectCode(r.Type, false), r.Type)
				}
				continue
			}
			_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, func() (bool, error) {
				return target.SendRequest(r.Type, r.WantReply, r.Payload)
			})
		}
	}
}

func forwardSessionStart(start sessionStart, target ssh.Channel) bool {
	if start.request == nil {
		return false
	}
	d := sshx.LookupChannelRequest(start.request.Type, start.request.Payload)
	return sshx.ApplyDisposition(start.request.Type, start.request.WantReply, start.request.Reply, d, func() (bool, error) {
		return target.SendRequest(start.request.Type, start.request.WantReply, start.request.Payload)
	}) == sshx.Forward
}

func (g *Gateway) riskAction(level risk.Level) RiskAction {
	mode := g.currentRiskMode().mode
	switch mode {
	case RiskActionAsk:
		if level == risk.Red {
			return RiskActionAsk
		}
		return RiskActionWarn
	case RiskActionBlock:
		if level == risk.Red {
			return RiskActionBlock
		}
		return RiskActionWarn
	default:
		return mode
	}
}

func riskEventDetails(sessionID, command string, verdict risk.Verdict, action RiskAction) map[string]interface{} {
	return map[string]interface{}{
		"sessionId": sessionID,
		"command":   risk.ScrubCommand(command),
		"rule":      verdict.Rule,
		"reason":    verdict.Reason,
		"action":    string(action),
	}
}

// riskWarning is what the person reads when the classifier had something
// to say about their command (IAMT-395).
//
// Three properties, each of them learned the hard way on 20.09.2026 when
// a red command was stopped under "block" and the answer did not make
// clear whether it had run:
//
//  1. The outcome comes FIRST, in words, before any code or rule name.
//     The line this replaced opened with "risk=red rule=… action=block
//     E_COMMAND_BLOCKED", which reads as a journal entry and never once
//     says the thing that matters: nothing ran.
//
//  2. Every line carries the "[iamtunnel] " prefix. This text shares one
//     stderr with the machine's own output, and the prefix is the only
//     thing that tells the two apart -- for a person reading, for the
//     window colouring the gateway's words (IAMT-392), and for anything
//     that ever parses this. A sentence that starts with prose and hides
//     the prefix at the end of the line loses that.
//
//  3. The tense is honest. This is written BEFORE the command is
//     forwarded (see the call site), so under "warn" it cannot claim the
//     command "was executed" -- at that instant it has not been, and if
//     the machine refuses it never will be. It says what the gateway is
//     about to do, which is the only thing the gateway knows yet.
func riskWarning(verdict risk.Verdict, action RiskAction, pty bool) []byte {
	return riskWarningWithApproval(verdict, action, "", pty)
}

func riskWarningWithApproval(verdict risk.Verdict, action RiskAction, approvalID string, pty bool) []byte {
	return riskWarningWithClassifier(verdict, action, approvalID, "", nil, pty)
}

const riskClassifierFailureCode = "E_RISK_CLASSIFIER_UNAVAILABLE" // errdict:internal

// riskClassifierFailurePolicy keeps the owner's explicit emergency escape
// meaningful. Enabling ai remains fail-closed for the configured/default
// policy; only a live admin switch to log or warn deliberately removes that
// guarantee for the next retry. A config value alone is not treated as the
// emergency acknowledgement because the human-facing recovery commands are
// specifically the live risk-mode commands printed below.
func (g *Gateway) riskClassifierFailurePolicy(classification riskClassification) (RiskAction, bool) {
	if !classification.failsClosed() {
		return RiskActionWarn, false
	}
	mode := g.currentRiskMode()
	if mode.source == "live" && (mode.mode == RiskActionLog || mode.mode == RiskActionWarn) {
		return mode.mode, false
	}
	// Never a pass. Which of the two refusals depends on what the gateway
	// was told to do with dangerous commands in general.
	//
	// It was always the hard stop, exit 126, which left the person nothing
	// to do about it but edit the gateway's live risk mode. The other shape
	// was asked for on 21.09.2026 -- a request must not go through
	// without a confirmation -- and by then the approval popup existed, so the
	// command can wait for a yes or a no like any other red one.
	//
	// A gateway set to block is the exception, and deliberately so: block
	// means "do not offer me the choice", and a command nobody could judge
	// is not the moment to start offering it. That is stricter than what
	// was asked for, never looser.
	if mode.mode == RiskActionBlock {
		return RiskActionBlock, true
	}
	return RiskActionAsk, false
}

// failedClassifierVerdict replaces the verdict when the classifier that was
// supposed to judge this command never answered AND the policy wants a human
// to decide.
//
// It lives here, after riskClassifierFailurePolicy, and not inside the
// classifier, for one reason: only the policy knows whether the owner has
// deliberately escaped to a live warn/log mode. Written a layer earlier, it
// made the failure look red even on that escape, so the notice explaining
// that the bypass was deliberate became unreachable and the agent was told
// its command had been "classified red" by something that never saw it.
func failedClassifierVerdict(classification riskClassification, failureAction RiskAction, verdict risk.Verdict) risk.Verdict {
	if !classification.failsClosed() || failureAction != RiskActionAsk {
		return verdict
	}
	return riskClassifierFailureVerdict(classification.ExternalError)
}

// riskClassifierFailureRule is the rule name a classifier failure wears so
// that the journal, the popup and the agent's stderr can all tell it apart
// from a command that was judged and found dangerous. Nothing was judged.
const riskClassifierFailureRule = "risk-classifier-unavailable"

// riskClassifierFailureVerdict turns "the service did not answer" into a
// first-class red verdict.
//
// The point is the REASON: this
// reason must be shouted about, and handed to the agent that actually
// receives the answer. An agent that is told only "confirmation required"
// learns nothing and will retry forever. An agent told "the classifier did
// not answer within 1s, so every command now needs a human" knows to stop
// and say so. The categories already exist in riskClassifierFailureReason;
// this is what puts them on the path the agent actually reads.
func riskClassifierFailureVerdict(err error) risk.Verdict {
	return risk.Verdict{
		Level:   risk.Red,
		Matched: true,
		Rule:    riskClassifierFailureRule,
		Reason:  riskClassifierFailureReason(err),
	}
}

func riskClassifierFailureReason(err error) string {
	kind := risk.ExternalFailureKindOf(err)
	status := risk.ExternalFailureStatusCode(err)
	switch kind {
	case risk.ExternalFailureAuthentication:
		if status != 0 {
			return fmt.Sprintf("the external classifier rejected its key; the key is invalid or expired (HTTP %d)", status)
		}
		return "the external classifier rejected its key; the key is invalid or expired"
	case risk.ExternalFailureConfiguration:
		return "risk_classifier=ai is enabled but the external classifier key is not configured; fix the gateway configuration and restart"
	default:
		if risk.ExternalFailureTimedOut(err) {
			return fmt.Sprintf("the external classifier did not answer within its %s budget, so this command was never judged; "+
				"every command needs a human decision until it answers again", risk.ExternalClassifierTimeout)
		}
		switch status {
		case http.StatusPaymentRequired:
			return "the external classifier refused the request for payment (HTTP 402) — the account behind the key is out of funds; " +
				"every command needs a human decision until it is topped up"
		case http.StatusTooManyRequests:
			return "the external classifier is rate limiting or the plan's quota is exhausted (HTTP 429); " +
				"every command needs a human decision until it answers again"
		}
		if status != 0 {
			return fmt.Sprintf("the external classifier service is unavailable (HTTP %d); "+
				"every command needs a human decision until it answers again", status)
		}
		safeError := strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
		return "the external classifier service is unavailable; cause: " + safeError
	}
}

func classifierFailureEventDetails(sessionID, command string, classification riskClassification) map[string]interface{} {
	details := map[string]interface{}{
		"sessionId":     sessionID,
		"command":       risk.ScrubCommand(command),
		"goal":          classification.Goal,
		"goalApplied":   classification.GoalApplied,
		"classifier":    string(classification.Classifier),
		"failureKind":   string(risk.ExternalFailureKindOf(classification.ExternalError)),
		"failureReason": riskClassifierFailureReason(classification.ExternalError),
	}
	if classification.ExternalError != nil {
		details["externalError"] = classification.ExternalError.Error()
	}
	if status := risk.ExternalFailureStatusCode(classification.ExternalError); status != 0 {
		details["status"] = status
	}
	return details
}

func riskClassifierFailureStop(classifier RiskClassifier, err error, pty bool) []byte {
	lines := []string{
		"STOPPED — this command was not run. Not a byte of it reached the machine.",
		"Reason: " + riskClassifierFailureReason(err),
		"To continue, set risk_classifier to \"rules\" or \"both\" in gateway configuration and restart, or explicitly disable protection with:",
		"iamtunnel admin risk mode log",
		"iamtunnel admin risk mode warn",
		"Then retry the command.",
		"risk=unavailable rule=external-classifier action=fail-closed " + riskClassifierFailureCode + " classifier=" + string(classifier),
	}
	return formatGatewayNotice(lines, "\x1b[31m", "[iamtunnel] ", pty)
}

// riskStoppedBy names WHO made this decision, in a sentence.
//
// The owner asked for it after watching an agent relay a refusal: it is
// very important who initiated the current prohibition -- our own static
// rules, or the AI that reads every command. The distinction is real and
// it changes what a person should do next.
//
// A RULE is a pattern somebody wrote once. It knows nothing about the
// situation, it cannot be argued with, and when it fires on something
// harmless the answer is to look at the rule.
//
// The CLASSIFIER judged this command against the goal declared for this
// access. It can be wrong in the other direction -- it can be talked
// round by a differently worded command, and it can miss what a rule
// would have caught. When it fires, the useful question is whether the
// declared goal actually covers what is being asked.
//
// The name arrives here as the verdict's rule id, which is
// "external-classifier" for the AI and a rule's own id otherwise. That is
// the gateway's own vocabulary and it is not going to be readable by
// somebody who has never seen the rule list, so it is spelled out.
// riskDeciderShort is the same answer in the two or three words that can
// survive being relayed.
//
// The long sentence riskStoppedBy produces is correct and was being
// dropped: an AI agent reads the whole notice, writes its own summary for
// the person, and a separate explanatory line is exactly what a summary
// leaves out. The owner watched that happen and asked for the obvious
// remedy -- it only needs to add a couple of words to its own warning.
//
// So the decider goes INSIDE the sentence the agent is told to pass on
// word for word. A relay instruction that carries the fact cannot relay
// the instruction and lose the fact.
func riskDeciderShort(rule string) string {
	switch {
	case rule == "":
		return "the gateway"
	case rule == riskClassifierFailureRule:
		return "the AI classifier being unreachable — nothing judged this command"
	case strings.Contains(rule, "external"):
		return "the AI classifier (not a fixed rule)"
	default:
		return "a fixed rule of the gateway, " + rule + " (not the AI classifier)"
	}
}

func riskStoppedBy(rule string) string {
	switch {
	case rule == "":
		return "Decided by: the gateway, without naming a rule."
	case rule == riskClassifierFailureRule:
		// Deliberately not phrased as a decision about the command,
		// because none was made. An agent told "the AI judged this
		// dangerous" argues with the judgement; an agent told "the AI
		// never saw it" learns the useful thing instead.
		return "Decided by: NOBODY — the AI classifier could not be reached, so this command was never judged at all. " +
			"The gateway is configured to have every command checked by the AI, so while it is silent every command waits for a person."
	case strings.Contains(rule, "external"):
		return "Decided by: the AI classifier, which read this command against the goal declared for this access. " +
			"Not a fixed rule -- a judgement about this command in this situation."
	default:
		return "Decided by: a built-in rule of the gateway (" + rule + "). " +
			"A fixed pattern, written in advance; it knows nothing about why you are doing this."
	}
}

// riskApprovedNotice is what a command says when it goes through BECAUSE
// somebody approved it (21.09.2026).
//
// Until now it said nothing. A run that consumed an approval looked
// exactly like a run that was never stopped, so an AI agent drew the only
// conclusion available to it: that the classifier had
// flagged the command once and waved the same command through a minute
// later, unreproducible. The journal said otherwise -- a person had pressed
// Allow, twice, and each approval was consumed by its own command -- but
// nothing on the wire told the agent that, so it reported a defect that
// did not exist and hid the thing that did happen.
//
// The agent relays what it is told. Told nothing, it invents.
func riskApprovedNotice(verdict risk.Verdict, approvalID string, pty bool) []byte {
	const prefix = "[iamtunnel] "
	lines := []string{
		"ALLOWED — this command was stopped for review and a person approved it. It is running now.",
		"It was classified " + verdict.Level.String() + ": " + verdict.Reason,
		riskStoppedBy(verdict.Rule),
		"Tell whoever asked you to do this: \"Your approval came through and the command ran.\" " +
			"The approval was for this exact command and is now spent; the next attempt will be judged afresh.",
		"risk=" + verdict.Level.String() + " rule=" + verdict.Rule + " action=approved approval-id=" + approvalID,
	}
	return formatGatewayNotice(lines, "\x1b[32m", prefix, pty)
}

func riskWarningWithClassifier(verdict risk.Verdict, action RiskAction, approvalID string, classifier RiskClassifier, externalErr error, pty bool) []byte {
	const prefix = "[iamtunnel] "
	color, level := "\x1b[33m", "yellow"
	if verdict.Level == risk.Red {
		color, level = "\x1b[31m", "red"
	}
	diagnostic := fmt.Sprintf("risk=%s rule=%s action=%s", verdict.Level.String(), verdict.Rule, action)

	var lines []string
	switch action {
	case RiskActionAsk:
		// What to TELL THE PERSON, in the words to tell them.
		//
		// This text is read by an AI agent, and the agent repeats it to
		// whoever asked. Until 21.09.2026 it named a terminal command,
		// which sent people out of the conversation to open a shell and
		// paste an id -- precisely what a refusal of this kind must
		// never demand.
		//
		// The instruction now names the window, because the window is
		// where a person can answer without copying anything. The
		// wording is aimed past the agent at the human: an agent asked
		// to relay "tell whoever asked" passes on an instruction, while
		// one handed a command tends to look for a way to run it.
		//
		// The limits line (22.09.2026) says what the pause does NOT do:
		// approval travels under the same key as the command, so the
		// gateway cannot tell a person's Allow from an agent's. Saying
		// so in the refusal itself keeps the boundary honest where the
		// agent reads it, without turning it into an invitation.
		lines = []string{
			"APPROVAL REQUIRED — this command was not run. Not a byte of it reached the machine.",
			"Reason (" + level + "): " + verdict.Reason,
			riskStoppedBy(verdict.Rule),
			"Tell whoever asked you to do this, and say who stopped it: \"This was stopped by " +
				riskDeciderShort(verdict.Rule) + ". To let it through, open the iamtunnel window, press the " +
				"button at the top right that says something is held, and press Allow on this command.\" " +
				"Then ask me to try again.",
			"They do not need to type anything, and you must not approve this yourself.",
			"This pause cannot prove a person did the allowing: your approval and this command travel " +
				"under the same key, and the gateway cannot tell one key-press from another. What it " +
				"guarantees is only that nothing runs until a separate deliberate action happens -- " +
				"which is why the person, not the program, must be the one to act.",
			diagnostic + " approval-id=" + approvalID + " E_APPROVAL_REQUIRED",
		}
	case RiskActionBlock:
		lines = []string{
			"STOPPED — this command was not run. Not a byte of it reached the machine.",
			"Reason (" + level + "): " + verdict.Reason,
			riskStoppedBy(verdict.Rule),
			`The gateway is in "block" mode. An administrator can change that: "iamtunnel admin risk mode warn", or Admin → Live in the window.`,
			diagnostic + " E_COMMAND_BLOCKED",
		}
	default:
		lines = []string{
			"WARNING — this command is classified " + level + ", and it is being run anyway.",
			"Reason (" + level + "): " + verdict.Reason,
			riskStoppedBy(verdict.Rule),
			`The gateway is allowing this warning to proceed. An administrator can choose a stricter mode with "iamtunnel admin risk mode ask" or "block", or Admin → Live in the window.`,
			diagnostic,
		}
	}
	if externalErr != nil {
		// Two different situations wore one sentence until 21.09.2026,
		// and it was the sentence for the situation that no longer
		// happens by default: "running without AI risk protection".
		// Once a silent classifier means the command WAITS, saying it
		// is running is false — and false in the direction that stops
		// an agent from looking for the cause.
		var message string
		switch {
		case action == RiskActionAsk || action == RiskActionBlock:
			message = "This is NOT a judgement about your command: the external classifier never answered, " +
				"so nothing examined it. That is why a person has to decide."
		case classifier == RiskClassifierBoth:
			message = "The external classifier is unavailable; local rules are still deciding this command."
		default:
			message = "The external classifier is unavailable; this command is running without AI risk protection."
		}
		safeError := strings.NewReplacer("\r", " ", "\n", " ").Replace(externalErr.Error())
		lines = append(lines[:len(lines)-1], message, "Reason: "+safeError, lines[len(lines)-1])
	}
	if classifier != "" {
		lines[len(lines)-1] += " classifier=" + string(classifier)
	}
	if externalErr != nil {
		lines[len(lines)-1] += " external=unavailable"
	}
	return formatGatewayNotice(lines, color, prefix, pty)
}

func riskClassifierFailureWarning(classifier RiskClassifier, err error, pty bool) []byte {
	message := "WARNING — the external classifier is unavailable; this command is running without AI risk protection."
	if classifier == RiskClassifierBoth {
		message = "WARNING — the external classifier is unavailable; local rules are still deciding this command."
	}
	safeError := strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
	lines := []string{
		message,
		"Reason: " + safeError,
		"risk=green rule=external-classifier action=warn classifier=" + string(classifier) + " external=unavailable",
	}
	return formatGatewayNotice(lines, "\x1b[33m", "[iamtunnel] ", pty)
}

func riskClassifierFailureWarningWithAction(classifier RiskClassifier, err error, action RiskAction, pty bool) []byte {
	message := "WARNING — the external classifier is unavailable; this command is running without AI risk protection."
	if classifier == RiskClassifierBoth {
		message = "WARNING — the external classifier is unavailable; local rules are still deciding this command."
	}
	safeError := strings.NewReplacer("\r", " ", "\n", " ").Replace(err.Error())
	lines := []string{
		message,
		"Reason: " + safeError,
		"risk=unavailable rule=external-classifier action=" + string(action) + " classifier=" + string(classifier) + " external=unavailable",
	}
	return formatGatewayNotice(lines, "\x1b[33m", "[iamtunnel] ", pty)
}

func formatGatewayNotice(lines []string, color, prefix string, pty bool) []byte {

	eol := "\n"
	if pty {
		eol = "\r\n"
	}
	var b strings.Builder
	for _, line := range lines {
		if pty {
			b.WriteString(color + prefix + line + "\x1b[0m" + eol)
			continue
		}
		b.WriteString(prefix + line + eol)
	}
	return []byte(b.String())
}

type execExitRecorder interface {
	ExitStatus(uint32) error
	ExitSignal(string) error
}

// proxyMachineRequests commits terminal status requests before forwarding
// them. exit-status and exit-signal travel on this function's own request
// stream (mreqs), a different Go channel from the one the target -> human
// data copy in core.Bridge reads (the channel's regular data stream) - two
// independent goroutines racing two independent buffers. The underlying SSH
// mux dispatches both in the wire order the machine actually sent them (data
// before exit-status, always), but that only fixes when each byte is
// *enqueued*; it says nothing about which goroutine's consumer gets
// *scheduled* first, and that race is exactly what IAMT-306 caught live: a
// completed exec's .exec.jsonl had sequence 3 (exit-status) before sequence 4
// (the command's own last stdout chunk) - a transcript that finishes the
// command before its own last line. outputDrained is what actually
// serializes the two: it closes only once Bridge's target -> human copy (and,
// for an exec recording, the separate stderr copy next to it in
// serveHumanSession) has committed every byte, so waiting on it here before
// touching exitRec guarantees every stdout/stderr chunk is on disk first.
//
// onExit (IAMT-409) fires once a machine-reported outcome has been parsed and
// recorded: a decimal exit status, or "signal <NAME>". It becomes the Exit
// field of the pair's recent-command entry; the caller hands the value to a
// variable its teardown reads only after this function has returned, so no
// further synchronization is needed.
func (g *Gateway) proxyMachineRequests(src <-chan *ssh.Request, human ssh.Channel, rec core.Recording, outputDrained <-chan struct{}, onFailure func(), onExit func(string)) {
	exitRec, recordsExit := rec.(execExitRecorder)
	for r := range src {
		if recordsExit && (r.Type == "exit-status" || r.Type == "exit-signal") && outputDrained != nil {
			<-outputDrained
		}
		if recordsExit && r.Type == "exit-status" {
			status, err := sshx.ParseExitStatus(r.Payload)
			if err != nil || exitRec.ExitStatus(status.Status) != nil {
				onFailure()
				return
			}
			if onExit != nil {
				onExit(strconv.FormatUint(uint64(status.Status), 10))
			}
		}
		if recordsExit && r.Type == "exit-signal" {
			signal, err := sshx.ParseExitSignal(r.Payload)
			if err != nil || exitRec.ExitSignal(signal.Signal) != nil {
				onFailure()
				return
			}
			if onExit != nil {
				onExit("signal " + signal.Signal)
			}
		}
		d := sshx.LookupChannelRequest(r.Type, r.Payload)
		_ = sshx.ApplyDisposition(r.Type, r.WantReply, r.Reply, d, func() (bool, error) {
			return human.SendRequest(r.Type, r.WantReply, r.Payload)
		})
	}
}

type execRecordingWriter struct {
	rec *record.ExecRecorder
	dst io.Writer
}

func (w execRecordingWriter) Write(p []byte) (int, error) {
	n, err := w.rec.WriteStderr(p)
	if err != nil || n != len(p) {
		if err == nil {
			err = io.ErrShortWrite
		}
		return n, err
	}
	return w.dst.Write(p)
}

// drainedAfter wraps a core.Stream so its Read never reports the
// underlying stream's own io.EOF until an out-of-band signal — drained —
// has also fired.
//
// Why this exists: SSH's channel EOF is directional but NOT per stream
// type (core/bridge.go's own Stream doc comment: "CloseWrite is kept
// separate because EOF is directional in SSH" — directional, not
// per-stream). golang.org/x/crypto/ssh's channel therefore shares one
// sentEOF flag between a channel's regular data and its extended data
// (stderr): once CloseWrite has been sent, WriteExtended on the SAME
// channel returns a bare io.EOF (channel.go: "if ch.sentEOF { return 0,
// io.EOF }"), silently, with no distinguishing error.
//
// serveHumanSession runs two independent writers to the human channel for
// an exec session: core.Bridge's own target -> human copy (regular data),
// and this file's own stderr-forwarder goroutine (nestedSession.Stderr()
// -> human.Stderr()). core.Bridge calls human.CloseWrite() the instant
// its own copy sees the target end (core/bridge.go, by design — see its
// doc comment on why closing is the caller's job on a clean end, IAMT-108).
// A real sshd ends an exec channel's regular and extended data at the
// same instant (one EOF for the whole channel, not two), so on the
// ordinary path both goroutines race for that same sentEOF flag: if
// core.Bridge's CloseWrite wins, the stderr-forwarder's very next
// WriteExtended (which may be carrying the exec's own last stderr bytes,
// or A2's risk warning, or E_COMMAND_BLOCKED) gets a bare io.EOF, which
// the forwarder treats as a hard failure and force-closes the whole
// session — discarding whatever it had not yet written and, since that
// happens before proxyMachineRequests's outputDrained-gated forward, the
// exit-status the person was owed.
//
// This was found, not theorized: internal/client's own exec canary
// (execrun_test.go) failed intermittently — roughly one run in
// three — with a nil ExitStatus on an otherwise-successful command, purely
// from this timing. Wrapping the Stream core.Bridge reads from so its EOF
// is held back until the stderr-forwarder has also drained closes the
// window: CloseWrite can then only ever happen after every writer to
// human is done, so WriteExtended never sees a live channel go EOF out
// from under it. Only the terminal, EOF-signaling Read is delayed — every
// ordinary data Read passes straight through — so this adds no latency
// to the session's actual output.
type drainedAfter struct {
	core.Stream
	drained <-chan struct{}
}

func (d drainedAfter) Read(p []byte) (int, error) {
	n, err := d.Stream.Read(p)
	if err == io.EOF {
		<-d.drained
	}
	return n, err
}

// errExecStdinForbidden is the bridging fault execStdinGuard reports (R4
// F-03). Its text is the journal's Result for the drop it causes.
var errExecStdinForbidden = errors.New("E_SSH_STDIN_FORBIDDEN") // errdict:internal

// execStdinGuard is the F-03 enforcement half for exec-only grants: it
// wraps the target side of the bridge so the first byte the person writes
// to the command's stdin is refused before it can reach the machine.
//
// Why a Write error rather than trusting the CloseWrite above: CloseWrite
// is sent the moment the exec is forwarded, but bytes already in flight can
// cross it on the wire, and x/crypto would surface a post-close Write as a
// bare EOF — which core.Bridge, by design (IAMT-108), reads as a CLEAN end:
// the payload would be silently gone and the session would stay up. A typed
// error instead breaks the copy the same way any bridging fault does —
// stop() closes both sides, the recording aborts, and the switch below
// journals session.drop with the error's own text as Result. countWriter
// never calls AddBytesIn for a failed Write (n == 0), so refused bytes are
// absent from the recording's byte count and hash too, which is the honest
// number: they never became part of the session.
type execStdinGuard struct {
	core.Stream
	stderr io.Writer
	once   sync.Once
}

func (s *execStdinGuard) Write(p []byte) (int, error) {
	s.once.Do(func() {
		if s.stderr != nil {
			_, _ = s.stderr.Write(execStdinForbiddenMessage())
		}
	})
	return 0, errExecStdinForbidden
}

// resizeRecording calls Resize on rec if it offers one. core.Recording does
// not declare Resize (it only needs Write/Close/Abort to bridge bytes), but
// record.Recorder - the only real implementation - does; this is an optional
// capability, not a second recording contract.
func resizeRecording(rec core.Recording, cols, rows int) {
	if r, ok := rec.(interface{ Resize(int, int) error }); ok {
		_ = r.Resize(cols, rows)
	}
}

func (g *Gateway) denyHuman(human ssh.Channel, person, machine string, reason acl.DenyReason) {
	g.appendEvent(events.Event{Type: events.EventSessionDrop, Actor: person, Object: machine, Result: reason.String()})
	g.writeAndClose(human, "Access to this machine is currently unavailable.\r\n")
}

// hostKeyMismatchMessage is the one line a person is given when access is
// refused because the machine's sshd presented a host key that does not match
// the pinned one. It keeps the established refusal phrase - the e2e acceptance
// scenario pins the word "unavailable" - and it adds the reason: "machine is not
// verified" would leave an operator guessing at which precondition failed, and
// the remedy is not on their side at all.
const hostKeyMismatchMessage = "Access to this machine is currently unavailable: its sshd presented a key that does not match the pinned key.\r\n"

// denyHumanHostKeyMismatch refuses a person whose target machine is recorded as
// host-key mismatch - the state the door rule of SPEC §4.3 forbids - or has
// just presented a foreign key during this very handshake. For the person both
// are one fact, and in the journal both are one typed reason; the difference
// between them is only which line of the preconditions caught it.
func (g *Gateway) denyHumanHostKeyMismatch(human ssh.Channel, person, machine string) {
	g.appendEvent(events.Event{
		Type:   events.EventSessionDrop,
		Actor:  person,
		Object: machine,
		Result: acl.DenyMachineHostKeyMismatch.String(),
	})
	g.writeAndClose(human, hostKeyMismatchMessage)
}

// sshdUnreachableMessage is the one line a person is given when access is
// refused because the machine's target sshd does not answer or refused connection.
// It keeps the established refusal phrase ("unavailable") and adds the specific
// reason so the person knows to fix the service rather than network or access.
const sshdUnreachableMessage = "Access to this machine is currently unavailable: the target machine's sshd service is not responding.\r\n"

func (g *Gateway) denyHumanSSHDUnreachable(human ssh.Channel, person, machine string) {
	g.appendEvent(events.Event{
		Type:   events.EventSessionDrop,
		Actor:  person,
		Object: machine,
		Result: acl.DenyMachineSSHDUnreachable.String(),
	})
	g.writeAndClose(human, sshdUnreachableMessage)
}

// sshdAuthFailedMessage is shown when the target sshd responded to TCP and
// completed SSH key exchange, but rejected the door public key (e.g. key line
// not reloaded, wrong account, or permissions).
const sshdAuthFailedMessage = "Access to this machine is currently unavailable: the target machine's sshd service rejected the door key.\r\n"

func (g *Gateway) denyHumanSSHAuthFailed(human ssh.Channel, person, machine string) {
	g.appendEvent(events.Event{
		Type:   events.EventSessionDrop,
		Actor:  person,
		Object: machine,
		Result: acl.DenyMachineSSHAuthFailed.String(),
	})
	g.writeAndClose(human, sshdAuthFailedMessage)
}

func isSSHAuthFailed(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "unable to authenticate")
}

// revokeNoticeTimeout is the longest a revoked session's connection
// outlives the revoke (IAMT-448): the time its client is given to take the
// one line that says why and to answer the channel's close. A client that
// reads does both at once; one that has stopped reading would never do
// either.
const revokeNoticeTimeout = time.Second

// endRevokedSession ends a session the ACL engine has just killed
// (revocation or expiry, SPEC §6.4).
//
// The machine side goes first and waits for nothing: closing the nested
// connection ends the program on the machine and cuts off every byte
// still on its way there. Then the person is told why and the channel is
// closed - which takes the client's part - and the connection is closed
// revokeNoticeTimeout later, whatever the client has done by then. A
// client that takes part has answered the close long before, the session
// has ended and handleHuman has closed the connection itself (a
// connection carries one session, IAMT-189), so the late close finds
// nothing in use. A client that has stopped reading would otherwise hold
// all of it: the line waits for a receive window that never opens, the
// close behind it for a connection nobody reads, and the bridge for an
// answer to that close - with the session counted and its door open.
//
// It used to be one Write and then the Close, and nothing else. A client
// that had stopped reading has a full receive window, so the Write waited
// for a window that never opened, the Close behind it never ran, and the
// session kept its door open and kept passing the person's keystrokes to
// the machine long after the grant was gone (IAMT-448).
func (g *Gateway) endRevokedSession(human ssh.Channel, nested, transport io.Closer, msg string) {
	_ = nested.Close()
	time.AfterFunc(revokeNoticeTimeout, func() { _ = transport.Close() })
	_, _ = human.Write([]byte(msg))
	_ = human.Close()
}

// revocableHuman is the person's channel as the bridge sees it. Once the
// session is revoked its CloseWrite does nothing: the revoke closes the
// machine side first, the bridge answers the machine's end with an EOF to
// the person, and after that EOF the line saying why could no longer be
// written. The channel is closed by endRevokedSession in any case.
type revocableHuman struct {
	ssh.Channel
	revoked *atomic.Bool
}

func (h revocableHuman) CloseWrite() error {
	if h.revoked.Load() {
		return nil
	}
	return h.Channel.CloseWrite()
}

func (g *Gateway) writeAndClose(human ssh.Channel, msg string) {
	_, _ = human.Write([]byte(msg))
	_ = human.Close()
}

// sessionClosedMessage deliberately separates expiry from revocation. The
// exact typed reason remains in the audit event; this is the concise line a
// person sees before their recorded channel closes.
func sessionClosedMessage(reason acl.DenyReason) string {
	switch reason {
	case acl.DenyGrantExpired:
		return "Session closed: the grant expired.\r\n"
	case acl.DenyKeyRemoved:
		return "Session closed: the key it was opened with was removed.\r\n"
	case acl.DenyAdminKilled:
		// sessions.kill ends this one session and leaves the grant as it
		// is; "revoked" sent the person to ask for access they still had
		// (IAMT-440).
		return "Session closed: an administrator ended this session. Your access is unchanged.\r\n"
	case acl.DenyGrantChanged:
		// The grant was narrowed or shortened, not taken away: the
		// person can log in again on its new terms (IAMT-440).
		return "Session closed: an administrator changed your access to this machine. Log in again to continue on the new terms.\r\n"
	case acl.DenyPersonRenamed:
		return "Session closed: an administrator renamed you on this gateway. Your access moved to the new name; log in again with it.\r\n"
	case acl.DenyMachineUnverified:
		// machines.set-user: the account the gateway logs into on the
		// machine changed and is being checked.
		return "Session closed: an administrator changed the account the gateway uses on this machine. It is being checked now; your access is unchanged.\r\n"
	}
	return "Session closed: the grant was revoked.\r\n"
}

func discardRequests(reqs <-chan *ssh.Request) {
	for r := range reqs {
		if r.WantReply {
			_ = r.Reply(false, nil)
		}
	}
}
