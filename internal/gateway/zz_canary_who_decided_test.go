package gateway

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// The canary: every gateway answer says WHO made the decision.
//
// The maintainer, 21.09.2026: it is very important who initiated the
// current prohibition -- our static rules or the AI that checks every
// request. The difference is not cosmetic: a rule is a template written
// in advance that knows nothing about the situation, while the classifier
// is a judgement about THIS command under THIS declared goal. What to do
// next depends on the answer, and the agent relays this very message to
// the person.
//
// All three outcomes are checked, because forgetting one is exactly how
// things like this get lost.
func TestCanary_NoticeNamesWhoDecided(t *testing.T) {
	cases := []struct {
		name   string
		action RiskAction
		rule   string
		want   string
	}{
		{"ask/ai", RiskActionAsk, "external-classifier", "AI classifier"},
		{"ask/rule", RiskActionAsk, "rm-rf-root", "built-in rule"},
		{"block/ai", RiskActionBlock, "external-classifier", "AI classifier"},
		{"block/rule", RiskActionBlock, "wipe-disk", "built-in rule"},
		{"warn/ai", RiskActionWarn, "external-classifier", "AI classifier"},
		{"warn/rule", RiskActionWarn, "chmod-777", "built-in rule"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := risk.Verdict{Level: risk.Red, Rule: c.rule, Reason: "because"}
			got := string(riskWarningWithApproval(v, c.action, "apr-0123456789abcdef", false))
			if !strings.Contains(got, "Decided by:") {
				t.Fatalf("the answer has no \"Decided by:\" line — the agent will not be able to tell the person who prohibited it:\n%s", got)
			}
			if !strings.Contains(got, c.want) {
				t.Errorf("the rule %q must be named as %q, but the answer says:\n%s", c.rule, c.want, got)
			}
			if c.rule != "external-classifier" && !strings.Contains(got, c.rule) {
				t.Errorf("the rule name %q is not named — the person has nothing to look for in the rule list:\n%s", c.rule, got)
			}
		})
	}
}
