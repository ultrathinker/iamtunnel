package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// riskApprovalTTL is deliberately short. An approval is a human's one-time
// continuation of the command that just stopped, not a grant that should
// survive a work break or a gateway restart.
const riskApprovalTTL = 5 * time.Minute

const (
	riskApprovalPending  = "pending"
	riskApprovalApproved = "approved"
	riskApprovalConsumed = "consumed"
	riskApprovalExpired  = "expired"
	riskApprovalDenied   = "denied"
)

// riskApproval is kept only in the live gateway. Command is intentionally the
// exact SSH exec string; the journal receives only its scrubbed presentation.
type riskApproval struct {
	ID                 string
	Person             string
	Machine            string
	Command            string
	Verdict            risk.Verdict
	RequestedAt        time.Time
	RequestedSessionID string
	Expires            time.Time
	ApprovedAt         time.Time
}

func riskApprovalIDValid(id string) bool {
	if len(id) != len("apr-")+16 || !strings.HasPrefix(id, "apr-") {
		return false
	}
	_, err := hex.DecodeString(id[len("apr-"):])
	return err == nil
}

func (g *Gateway) nextRiskApprovalID(now time.Time) string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return "apr-" + hex.EncodeToString(raw[:])
	}
	// crypto/rand failure is not permission to let a red command through. The
	// sequence fallback still gives this live gateway a unique, shape-valid id
	// and the exact owner/machine/command checks remain the security boundary.
	seq := g.riskApprovalSeq.Add(1)
	return fmt.Sprintf("apr-%016x", uint64(now.UnixNano())^seq)
}

func (g *Gateway) createRiskApproval(person, machine, sessionID, command string, verdict risk.Verdict, now time.Time) riskApproval {
	g.riskApprovalMu.Lock()
	defer g.riskApprovalMu.Unlock()
	if g.riskApprovals == nil {
		g.riskApprovals = make(map[string]*riskApproval)
	}
	// The SAME command held again reuses the record it already has.
	//
	// It minted a fresh id per attempt until 21.09.2026, and the owner
	// paid for it: his agent, watching the id change under it, concluded
	// that retrying destroyed the approval and stopped retrying, so he
	// waited on a gate that was never going to lift. The agent was wrong
	// -- consumeRiskApproval matches on person+machine+command, never on
	// the id -- but a mechanism whose observable behaviour teaches a
	// careful reader the wrong lesson is the mechanism's fault.
	//
	// Now the id is stable while the request is alive, which is also what
	// makes a list of held commands worth showing: a person looking at
	// one wants to see one entry per held command, not one per attempt.
	for id, a := range g.riskApprovals {
		if a.Person == person && a.Machine == machine && a.Command == command &&
			now.Before(a.Expires) && a.ApprovedAt.IsZero() {
			// Keep the original request time -- the wait started then --
			// but let the window run from the newest attempt, or a person
			// who reached the list late would find it already gone.
			a.Expires = now.Add(riskApprovalTTL)
			a.RequestedSessionID = sessionID
			_ = id
			return *a
		}
	}
	for {
		id := g.nextRiskApprovalID(now)
		if _, exists := g.riskApprovals[id]; exists {
			continue
		}
		a := riskApproval{
			ID:                 id,
			Person:             person,
			Machine:            machine,
			Command:            command,
			Verdict:            verdict,
			RequestedAt:        now,
			RequestedSessionID: sessionID,
			Expires:            now.Add(riskApprovalTTL),
		}
		g.riskApprovals[id] = &a
		return a
	}
}

// approveRiskApproval marks an approval for its owner. It does not consume
// it: the subsequent exact command consumes it once. changed is false for a
// repeated approval of the same still-live record.
func (g *Gateway) approveRiskApproval(person, id string, now time.Time) (riskApproval, string, bool) {
	g.riskApprovalMu.Lock()
	defer g.riskApprovalMu.Unlock()
	a, ok := g.riskApprovals[id]
	if !ok {
		return riskApproval{}, "missing", false
	}
	copy := *a
	if !now.Before(a.Expires) {
		delete(g.riskApprovals, id)
		return copy, riskApprovalExpired, false
	}
	if a.Person != person {
		return copy, riskApprovalDenied, false
	}
	if a.ApprovedAt.IsZero() {
		a.ApprovedAt = now
		copy = *a
		return copy, riskApprovalApproved, true
	}
	return copy, riskApprovalApproved, false
}

// consumeRiskApproval removes one approved record only when all three
// identity bindings and the exact SSH command match. Expired records are
// removed while looking, so a long-lived gateway does not retain stale
// approvals indefinitely. The caller journals the returned expirations.
func (g *Gateway) consumeRiskApproval(person, machine, command string, now time.Time) (riskApproval, []riskApproval, bool) {
	g.riskApprovalMu.Lock()
	defer g.riskApprovalMu.Unlock()
	var expired []riskApproval
	for id, a := range g.riskApprovals {
		if !now.Before(a.Expires) {
			expired = append(expired, *a)
			delete(g.riskApprovals, id)
		}
	}
	var found riskApproval
	for id, a := range g.riskApprovals {
		if a.Person != person || a.Machine != machine || a.Command != command || a.ApprovedAt.IsZero() {
			continue
		}
		found = *a
		delete(g.riskApprovals, id)
		return found, expired, true
	}
	return riskApproval{}, expired, false
}

// pendingRiskApprovals lists what is held for one person, newest request
// last, dropping anything that has expired on the way past.
//
// Nothing could read this until 21.09.2026: an approval could be created
// and approved by id, and the id arrived only in the refusal the agent
// got. A person wanting to know what was waiting for them had no way to
// ask -- the same hole the window had around removing people, and the
// same answer.
func (g *Gateway) pendingRiskApprovals(person string, now time.Time) []riskApproval {
	g.riskApprovalMu.Lock()
	defer g.riskApprovalMu.Unlock()
	var out []riskApproval
	for id, a := range g.riskApprovals {
		if !now.Before(a.Expires) {
			delete(g.riskApprovals, id)
			continue
		}
		if a.Person != person || !a.ApprovedAt.IsZero() {
			continue
		}
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RequestedAt.Before(out[j].RequestedAt) })
	return out
}

// denyRiskApproval throws one held request away. Refusing is not the same
// as letting it expire: the person said no, and the record must not sit
// there looking like something still under consideration.
func (g *Gateway) denyRiskApproval(person, id string, now time.Time) (riskApproval, string) {
	g.riskApprovalMu.Lock()
	defer g.riskApprovalMu.Unlock()
	a, ok := g.riskApprovals[id]
	if !ok {
		return riskApproval{}, "missing"
	}
	if !now.Before(a.Expires) {
		copy := *a
		delete(g.riskApprovals, id)
		return copy, riskApprovalExpired
	}
	if a.Person != person {
		return *a, riskApprovalDenied
	}
	copy := *a
	delete(g.riskApprovals, id)
	return copy, "ok"
}

func (g *Gateway) appendRiskApprovalEvent(a riskApproval, actor, result, sessionID string) {
	details := map[string]interface{}{
		"approvalId":  a.ID,
		"command":     risk.ScrubCommand(a.Command),
		"rule":        a.Verdict.Rule,
		"reason":      a.Verdict.Reason,
		"level":       a.Verdict.Level.String(),
		"requestedAt": a.RequestedAt.UTC().Format(time.RFC3339),
		"expiresAt":   a.Expires.UTC().Format(time.RFC3339),
	}
	if a.RequestedSessionID != "" {
		details["requestedSessionId"] = a.RequestedSessionID
	}
	if sessionID != "" {
		details["sessionId"] = sessionID
	}
	if !a.ApprovedAt.IsZero() {
		details["approvedAt"] = a.ApprovedAt.UTC().Format(time.RFC3339)
	}
	if actor != a.Person {
		details["requestedBy"] = a.Person
	}
	g.appendEvent(events.Event{
		Type:    events.EventRiskApproval,
		Actor:   actor,
		Object:  a.Machine,
		Result:  result,
		Details: details,
	})
}

// prepareRiskAction applies the ask-mode continuation. The policy action is
// returned separately from the effective action so session.risk can say that
// the gateway was in ask mode even when an already-approved exact command is
// allowed through as a one-time log-equivalent execution.
func (g *Gateway) prepareRiskAction(person, machine, sessionID, command string, verdict risk.Verdict) (policy, effective RiskAction, approvalID string) {
	return g.prepareRiskActionWithPolicy(g.riskAction(verdict.Level), person, machine, sessionID, command, verdict)
}

// prepareRiskActionWithPolicy is prepareRiskAction with the policy handed in
// instead of read from the gateway's risk mode.
//
// One caller needs that: a classifier that never answered (21.09.2026). The
// ordinary risk mode answers the question "how strict are we with commands
// we have judged", and a gateway sitting in warn would wave the failure
// through on exactly that answer -- which is how the first version of this
// change still let the command reach the machine. A command nobody judged is
// a different question, and its answer is fixed: a person decides. The
// owner's deliberate live escape is honoured earlier, in
// riskClassifierFailurePolicy, and never reaches here.
func (g *Gateway) prepareRiskActionWithPolicy(policy RiskAction, person, machine, sessionID, command string, verdict risk.Verdict) (_, effective RiskAction, approvalID string) {
	effective = policy
	if policy != RiskActionAsk {
		return policy, effective, ""
	}
	now := g.cfg.Now()
	approved, expired, ok := g.consumeRiskApproval(person, machine, command, now)
	for _, a := range expired {
		g.appendRiskApprovalEvent(a, a.Person, riskApprovalExpired, "")
	}
	if ok {
		g.appendRiskApprovalEvent(approved, person, riskApprovalConsumed, sessionID)
		return policy, RiskActionLog, approved.ID
	}
	pending := g.createRiskApproval(person, machine, sessionID, command, verdict, now)
	g.appendRiskApprovalEvent(pending, person, riskApprovalPending, sessionID)
	return policy, effective, pending.ID
}

// cmdRiskApprove is intentionally available to any known person, not just an
// administrator. The person who launched the red command is the issuer and
// is the only identity allowed to approve its exact continuation.
//
// cmdRiskPending answers "what is being held for me" and cmdRiskDeny
// throws one away. Both are bound to the caller the same way approve is:
// a person sees and settles their OWN held commands and nobody else's.
// The command string is returned whole, not scrubbed -- the person is
// about to decide whether it may run, and deciding on a redacted command
// is deciding on a different command. The journal still receives only the
// scrubbed form.
func cmdRiskPending(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto int `json:"proto"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	held := g.pendingRiskApprovals(person, now)
	out := make([]map[string]any, 0, len(held))
	for _, a := range held {
		out = append(out, map[string]any{
			"approvalId":  a.ID,
			"machine":     a.Machine,
			"command":     a.Command,
			"rule":        a.Verdict.Rule,
			"reason":      a.Verdict.Reason,
			"level":       a.Verdict.Level.String(),
			"requestedAt": a.RequestedAt.UTC().Format(time.RFC3339),
			"expiresAt":   a.Expires.UTC().Format(time.RFC3339),
		})
	}
	return map[string]any{"pending": out}, nil
}

func cmdRiskDeny(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto      int    `json:"proto"`
		ApprovalID string `json:"approvalId"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if !riskApprovalIDValid(req.ApprovalID) {
		return nil, errf("E_JSON_INVALID", 3, "approvalId must have the form apr- followed by 16 lowercase hexadecimal characters")
	}
	a, status := g.denyRiskApproval(person, req.ApprovalID, now)
	switch status {
	case "missing", riskApprovalExpired:
		return nil, errf("E_APPROVAL_NOT_FOUND", 2, "approval %q is unknown or expired", req.ApprovalID) // errdict:internal
	case riskApprovalDenied:
		return nil, errf("E_APPROVAL_FORBIDDEN", 2, "approval %q belongs to another person", req.ApprovalID) // errdict:internal
	}
	g.appendRiskApprovalEvent(a, person, riskApprovalDenied, "")
	// The command's own record, in the shape every command's record has
	// (F-02, round-3 review 24.09.2026): the typed event says what was
	// decided and in which risk context, and this line is what the verdict
	// on a LOST record is matched against. Without it the loss of a
	// denial is nobody's, and risk.deny answers "ok" for a decision the
	// journal does not hold.
	g.logAdminOp(person, "risk.deny", a.Machine, "ok", map[string]interface{}{"approvalId": a.ID})
	return map[string]any{"denied": a.ID}, nil
}

func cmdRiskApprove(g *Gateway, person string, now time.Time, body []byte) (any, *cmdError) {
	var req struct {
		Proto      int    `json:"proto"`
		ApprovalID string `json:"approvalId"`
	}
	if cerr := decodeStrict(body, &req); cerr != nil {
		return nil, cerr
	}
	if cerr := checkProto(req.Proto); cerr != nil {
		return nil, cerr
	}
	if !riskApprovalIDValid(req.ApprovalID) {
		return nil, errf("E_JSON_INVALID", 3, "approvalId must have the form apr- followed by 16 lowercase hexadecimal characters")
	}
	a, status, changed := g.approveRiskApproval(person, req.ApprovalID, now)
	switch status {
	case "missing":
		return nil, errf("E_APPROVAL_NOT_FOUND", 2, "approval %q is unknown or expired", req.ApprovalID) // errdict:internal
	case riskApprovalExpired:
		g.appendRiskApprovalEvent(a, person, riskApprovalExpired, "")
		return nil, errf("E_APPROVAL_NOT_FOUND", 2, "approval %q is unknown or expired", req.ApprovalID) // errdict:internal
	case riskApprovalDenied:
		g.appendRiskApprovalEvent(a, person, riskApprovalDenied, "")
		return nil, errf("E_APPROVAL_FORBIDDEN", 2, "approval %q belongs to another person", req.ApprovalID) // errdict:internal
	case riskApprovalApproved:
		if changed {
			g.appendRiskApprovalEvent(a, person, riskApprovalApproved, "")
			// Same line, same reason as risk.deny above: the approval is
			// granted in memory and is spent by the next matching command,
			// so "approved: true" without a line saying who approved it is
			// the one loss nobody could reconstruct afterwards.
			g.logAdminOp(person, "risk.approve", a.Machine, "ok", map[string]interface{}{"approvalId": a.ID})
		}
		return map[string]interface{}{
			"approvalId": a.ID,
			"approved":   true,
			"changed":    changed,
			"expiresAt":  a.Expires.UTC().Format(time.RFC3339),
		}, nil
	default:
		return nil, errf("E_INTERNAL", 70, "unknown risk approval state %q", status)
	}
}
