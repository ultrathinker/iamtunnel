package gateway

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// riskClassification is the pre-flight result used by both exec barriers.
// Local is retained for audit and for both-mode fallback; Verdict is the
// source selected by the owner and is the only verdict that reaches policy.
type riskClassification struct {
	Classifier     RiskClassifier
	Local          risk.Verdict
	External       risk.Verdict
	Verdict        risk.Verdict
	ExternalCalled bool
	ExternalAsync  bool
	ExternalError  error
	ExternalWait   time.Duration
	ExternalScores map[string]float64
	ExternalClient risk.ExternalClassifier
	Goal           string
	GoalApplied    bool
}

// failsClosed reports that the external classifier was supposed to speak
// and did not. It covers BOTH modes that consult it, not just ai.
//
// It used to name only ai, and that was a hole with the gateway sitting in
// both: a timeout, an expired key or an exhausted account let the command
// through on the local rules with a warning. The owner settled it on
// 21.09.2026, and named the ranking while he was at it: both is the
// STRICTEST mode -- two filters, and a command passes unhindered only when
// both let it. rules never calls the service and cannot fail this way; ai
// has one filter; both has two. In ai and in both alike, "the service did
// not answer" must not become "allowed".
func (c riskClassification) failsClosed() bool {
	if c.ExternalError == nil {
		return false
	}
	return c.Classifier == RiskClassifierAI || c.Classifier == RiskClassifierBoth
}

func (g *Gateway) classifyExec(command, goal string, history []risk.RecentCommandContext) riskClassification {
	// The LIVE choice, not cfg's: since 21.09.2026 an administrator can
	// change which checkers judge commands without restarting the gateway
	// (risk_source.go), exactly as they have long been able to change what
	// happens to a red one.
	classifier := g.currentRiskSource().classifier
	local := risk.Classify(command)
	result := riskClassification{
		Classifier: classifier,
		Local:      local,
		Verdict:    local,
		Goal:       risk.ScrubCommand(goal),
	}

	switch classifier {
	case RiskClassifierRules:
		return result
	case RiskClassifierAI:
		return g.classifyWithExternal(result, command, goal, history)
	case RiskClassifierBoth:
		// A local red already decides the consequence. Still send the
		// scrubbed command asynchronously for the configured second-source
		// audit, but never make the safety decision wait 800 ms for it.
		if local.Level == risk.Red {
			result.ExternalAsync = true
			result.ExternalClient = g.currentExternalRiskClassifier()
			result.GoalApplied = externalClassifierCanReceiveGoal(result.ExternalClient, goal)
			return result
		}
		return g.classifyWithExternal(result, command, goal, history)
	default:
		// Config validation and Config.setDefaults reject this state. Keep a
		// safe local fallback for tests or a future in-process caller that
		// constructs Config without New.
		return result
	}
}

func externalClassifierCanReceiveGoal(classifier risk.ExternalClassifier, goal string) bool {
	if strings.TrimSpace(goal) == "" {
		return false
	}
	if classifier == nil {
		return false
	}
	_, ok := classifier.(risk.ExternalGoalClassifier)
	return ok
}

func (g *Gateway) classifyWithExternal(result riskClassification, command, goal string, history []risk.RecentCommandContext) riskClassification {
	result.ExternalCalled = true
	started := time.Now()
	classifier := g.currentExternalRiskClassifier()
	result.ExternalClient = classifier
	if classifier == nil {
		result.ExternalError = risk.NewExternalClassifierError(risk.ExternalFailureConfiguration, 0,
			fmt.Errorf("external classifier is not configured"))
		result.ExternalWait = time.Since(started)
		if result.Classifier == RiskClassifierAI {
			result.Verdict = risk.Verdict{Level: risk.Green, Matched: false}
		}
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), risk.ExternalClassifierTimeout)
	assessment, err := risk.ClassifyWithGoal(ctx, classifier, risk.ScrubCommand(command), risk.ScrubCommand(goal), history)
	cancel()
	result.ExternalWait = time.Since(started)
	result.GoalApplied = externalClassifierCanReceiveGoal(classifier, goal)
	if err != nil {
		result.ExternalError = err
		if result.Classifier == RiskClassifierAI {
			result.Verdict = risk.Verdict{Level: risk.Green, Matched: false}
		}
		return result
	}
	result.External = risk.VerdictFromExternalAssessment(assessment)
	result.ExternalScores = assessment.Scores
	if result.Classifier == RiskClassifierAI {
		result.Verdict = result.External
	} else {
		result.Verdict = worseRiskVerdict(result.Local, result.External)
	}
	return result
}

func worseRiskVerdict(local, external risk.Verdict) risk.Verdict {
	if external.Level > local.Level {
		return external
	}
	return local
}

// observeExternalRisk is the deliberately non-blocking both-mode path for a
// local red. It preserves the privacy promise that both sends every exec to
// the external service, while the already decisive local red reaches policy
// immediately. Its result is telemetry only and cannot reopen the session.
func (g *Gateway) observeExternalRisk(sessionID, person, machine, command, goal string, history []risk.RecentCommandContext, local risk.Verdict, classifier risk.ExternalClassifier) {
	g.wg.Add(1)
	go func() {
		defer g.wg.Done()
		started := time.Now()
		details := map[string]interface{}{
			"classifier":     string(RiskClassifierBoth),
			"local":          local.Level.String(),
			"async":          true,
			"latency_ms":     int64(0),
			"threshold":      risk.ExternalRiskThreshold,
			"sessionId":      sessionID,
			"command":        risk.ScrubCommand(command),
			"goal":           risk.ScrubCommand(goal),
			"goalApplied":    externalClassifierCanReceiveGoal(classifier, goal),
			"historyEntries": len(history),
		}
		ctx, cancel := context.WithTimeout(context.Background(), risk.ExternalClassifierTimeout)
		defer cancel()
		if classifier == nil {
			err := risk.NewExternalClassifierError(risk.ExternalFailureConfiguration, 0,
				fmt.Errorf("external classifier is not configured"))
			details["error"] = err.Error()
			details["failureKind"] = string(risk.ExternalFailureKindOf(err))
			g.appendEvent(events.Event{Type: events.EventSessionRisk, Actor: person, Object: machine, Result: "external-error", Details: details})
			return
		}
		assessment, err := risk.ClassifyWithGoal(ctx, classifier, risk.ScrubCommand(command), risk.ScrubCommand(goal), history)
		details["latency_ms"] = time.Since(started).Milliseconds()
		if err != nil {
			details["error"] = err.Error()
			details["failureKind"] = string(risk.ExternalFailureKindOf(err))
			if status := risk.ExternalFailureStatusCode(err); status != 0 {
				details["status"] = status
			}
			g.appendEvent(events.Event{Type: events.EventSessionRisk, Actor: person, Object: machine, Result: "external-error", Details: details})
			return
		}
		external := risk.VerdictFromExternalAssessment(assessment)
		details["external"] = external.Level.String()
		details["rule"] = external.Rule
		details["reason"] = external.Reason
		details["probabilities"] = assessment.Scores
		g.appendEvent(events.Event{Type: events.EventSessionRisk, Actor: person, Object: machine, Result: external.Level.String(), Details: details})
	}()
}
