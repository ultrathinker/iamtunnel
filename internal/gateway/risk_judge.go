package gateway

import (
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// riskDecision is one pre-flight judgement of one action: an exec command
// (serveHumanSession) or a mutating SFTP request (sftp_session.go, 1.50).
// Both barriers used to be one inline block in serveHumanSession; 1.50's
// SFTP judgement must apply risk_action "exactly as exec does", and the
// only way to keep that promise through the next edit is for both to run
// the same code.
type riskDecision struct {
	classification riskClassification
	verdict        risk.Verdict
	// action is the effective action; policyAction is what the risk mode
	// asked for before an approval was consumed (ask -> log). Both keep
	// the meaning they always had in serveHumanSession.
	action        RiskAction
	policyAction  RiskAction
	approvalID    string
	failureAction RiskAction
	failureStops  bool
	// stdinRefused is set when forced (an unjudged stdin script) met a
	// policy that would stop or hold it: it is refused, never held.
	stdinRefused bool
}

// judgeRisk classifies text against the pair's goal and history, applies
// the configured risk_action (creating or consuming a one-time approval
// keyed by text), and journals session.risk when the verdict is not green
// or the external classifier failed. eventCommand is what session.risk's
// details.command carries (scrubbed); extra, when non-nil, is merged into
// those details.
//
// forced, when non-nil, is the verdict of a stdin script that could not be
// judged whole. It replaces the judged verdict, and it never reaches an
// approval: an approval could only name the bytes that were seen, and
// would then release whatever followed them (fixup round 2, V-09). Where
// the policy would hold or stop a red command (ask, block, or a failed
// classifier that asks a person), the command is refused instead
// (stdinRefused, action block); under log and warn it passes as any red
// command does.
//
// The approval key is text, not eventCommand, on purpose: an exec whose
// script arrived on stdin (exec_stdin.go) is judged on command+script, and
// an approval given for one script must not let a different script through
// under the same bare `powershell`.
func (g *Gateway) judgeRisk(sessionID, person, machine, text, eventCommand, goal string, history []risk.RecentCommandContext, forced *risk.Verdict, extra map[string]interface{}) riskDecision {
	d := riskDecision{failureAction: RiskActionLog}
	d.classification = g.classifyExec(text, goal, history)
	classification := d.classification
	d.failureAction, d.failureStops = g.riskClassifierFailurePolicy(classification)
	d.verdict = failedClassifierVerdict(classification, d.failureAction, classification.Verdict)
	if forced != nil {
		d.verdict = *forced
	}
	if classification.ExternalAsync {
		g.observeExternalRisk(sessionID, person, machine, text, goal, history, classification.Local, classification.ExternalClient)
	}
	if d.verdict.Level == risk.Green && classification.ExternalError == nil {
		return d
	}
	d.action = RiskActionLog
	switch {
	case forced != nil:
		policy := g.riskAction(risk.Red)
		if d.failureStops || classification.failsClosed() && d.failureAction == RiskActionAsk {
			policy = RiskActionBlock
		}
		if policy == RiskActionAsk || policy == RiskActionBlock {
			d.stdinRefused, d.failureStops = true, false
			policy = RiskActionBlock
		}
		d.policyAction, d.action = policy, policy
	case d.failureStops:
		d.action = RiskActionBlock
	case d.verdict.Level == risk.Green && classification.ExternalError != nil:
		d.action = d.failureAction
	case classification.failsClosed() && d.failureAction == RiskActionAsk:
		d.policyAction, d.action, d.approvalID = g.prepareRiskActionWithPolicy(RiskActionAsk, person, machine, sessionID, text, d.verdict)
	default:
		d.policyAction, d.action, d.approvalID = g.prepareRiskAction(person, machine, sessionID, text, d.verdict)
	}
	eventAction := d.action
	if d.verdict.Level != risk.Green {
		eventAction = d.policyAction
	}
	details := riskEventDetails(sessionID, eventCommand, d.verdict, eventAction)
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
	if d.approvalID != "" {
		details["approvalId"] = d.approvalID
		if d.action == RiskActionLog {
			details["approval"] = "consumed"
		}
	}
	for k, v := range extra {
		details[k] = v
	}
	result := d.verdict.Level.String()
	if d.verdict.Level == risk.Green && classification.ExternalError != nil {
		result = "external-error"
	}
	g.appendEvent(events.Event{
		Type:    events.EventSessionRisk,
		Actor:   person,
		Object:  machine,
		Result:  result,
		Details: details,
	})
	return d
}

// approvalUsed is the one case where a Log action must still be announced:
// the policy was ask, and a person's approval let this exact action through
// (see riskApprovedNotice).
func (d riskDecision) approvalUsed() bool {
	return d.policyAction == RiskActionAsk && d.action == RiskActionLog && d.approvalID != ""
}

// noticeNeeded reports whether the person must be told something about
// this decision before the action proceeds or is refused.
func (d riskDecision) noticeNeeded() bool {
	return d.verdict.Level != risk.Green && d.action != RiskActionLog || d.classification.ExternalError != nil || d.approvalUsed()
}

// refused reports whether the action must not reach the machine: a
// classifier failure under block, a red held for approval, or a block.
func (d riskDecision) refused() bool {
	return d.failureStops || d.policyAction == RiskActionAsk && d.action == RiskActionAsk || d.action == RiskActionBlock
}

// notice is the text the person reads about this decision — the same
// sentences for an exec command and an SFTP request.
func (d riskDecision) notice(pty bool) []byte {
	c := d.classification
	switch {
	case d.stdinRefused:
		return stdinScriptRefusal(d.verdict, pty)
	case d.failureStops:
		return riskClassifierFailureStop(c.Classifier, c.ExternalError, pty)
	case d.verdict.Level == risk.Green && c.ExternalError != nil:
		if c.failsClosed() {
			return riskClassifierFailureWarningWithAction(c.Classifier, c.ExternalError, d.failureAction, pty)
		}
		return riskClassifierFailureWarning(c.Classifier, c.ExternalError, pty)
	case d.approvalUsed():
		return riskApprovedNotice(d.verdict, d.approvalID, pty)
	default:
		return riskWarningWithClassifier(d.verdict, d.policyAction, d.approvalID, c.Classifier, c.ExternalError, pty)
	}
}
