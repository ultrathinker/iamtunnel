package gateway

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// The IAMT-408 canary: a silent AI check must not let a command through
// in any mode that calls it at all.
//
// On 21.09.2026 the maintainer's gateway ran with risk_classifier=both,
// while the "no answer means stop" protection was written for ai only:
// failsClosed() named a single mode. Any failure of the external
// service in both mode -- a timeout, a stale key, money run out --
// produced a warning, and the command went to the machine on local
// rules alone.
//
// The maintainer named the order of the modes in their own words: if
// the modes work together, that is the strictest mode -- two filters
// must both pass before a command goes through without prohibitions...
// and if the service does not answer, or is broken, or we are out of
// budget, we must not let a request through without a confirmation.
//
// Checked at the decision level, not the text level: the rules mode
// never calls the service and cannot fail that way; ai and both must
// recognize the failure as closed.
func TestCanary_IAMT408_SilentClassifierNeverPasses(t *testing.T) {
	err := errors.New("classifier unavailable")
	for _, tc := range []struct {
		classifier RiskClassifier
		wantClosed bool
	}{
		{RiskClassifierAI, true},
		{RiskClassifierBoth, true},
		{RiskClassifierRules, false},
	} {
		c := riskClassification{Classifier: tc.classifier, ExternalError: err}
		if got := c.failsClosed(); got != tc.wantClosed {
			t.Errorf("failsClosed(%s) = %v, want %v -- a mode that calls the AI must treat silence as a failure, "+
				"otherwise someone else's service going down quietly removes the check", tc.classifier, got, tc.wantClosed)
		}
	}

	// And the refusal must become a verdict that NAMES the reason:
	// the maintainer's order was that this reason must be shouted about.
	v := riskClassifierFailureVerdict(err)
	if v.Level != risk.Red {
		t.Errorf("the refusal verdict = %s, want red", v.Level)
	}
	if v.Rule != riskClassifierFailureRule {
		t.Errorf("the refusal verdict rule = %q, want %q -- the refusal must be distinguishable from a judged command",
			v.Rule, riskClassifierFailureRule)
	}
	if v.Reason == "" {
		t.Error("a refusal verdict without a reason -- the agent learns only \"confirmation needed\" and will keep hammering retries")
	}

	// The budget was named by the maintainer: one second.
	if risk.ExternalClassifierTimeout != time.Second {
		t.Errorf("the external classifier budget = %s, want 1s (the maintainer's decision of 21.09.2026)",
			risk.ExternalClassifierTimeout)
	}

	// The timeout reason must name the BUDGET itself, not a hardcoded
	// number: otherwise, at the next budget change, the agent is told the
	// old one.
	timeoutReason := riskClassifierFailureReason(risk.NewExternalClassifierError(
		risk.ExternalFailureUnavailable, 0, context.DeadlineExceeded))
	if !strings.Contains(timeoutReason, risk.ExternalClassifierTimeout.String()) {
		t.Errorf("the timeout reason = %q, does not name the budget %s", timeoutReason, risk.ExternalClassifierTimeout)
	}
}
