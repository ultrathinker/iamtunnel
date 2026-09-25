package gateway

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// The canary: a command that went through BY APPROVAL says so.
//
// On 21.09.2026 the maintainer pressed Allow twice -- for a picture and
// for a poem -- and the AI agent reported that the second command went
// through without asking for a confirmation and that the classifier's
// decision was unreproducible. The gateway journal showed the opposite:
// two approvals, two consumptions, each by its own command.
//
// The agent did not lie -- it had nothing to tell. Consuming an approval
// looked exactly like an ordinary successful run: the gateway was silent.
// An agent relays what it is told; told nothing, it invents.
//
// The content is checked too: the outcome, who decided, and a direct
// phrase for the person.
func TestCanary_ApprovedCommandSaysSo(t *testing.T) {
	v := risk.Verdict{Level: risk.Red, Rule: "external-classifier", Reason: "writes a file on the desktop"}
	got := string(riskApprovedNotice(v, "apr-0123456789abcdef", false))

	if !strings.Contains(got, "ALLOWED") {
		t.Fatalf("the answer has no ALLOWED word — consuming an approval is indistinguishable from an ordinary run:\n%s", got)
	}
	if !strings.Contains(got, "approved it") {
		t.Errorf("nowhere does it say a person approved the command:\n%s", got)
	}
	if !strings.Contains(got, "Decided by:") {
		t.Errorf("nowhere does it say who stopped it — the person will never learn whether it was a rule or the AI:\n%s", got)
	}
	if !strings.Contains(got, "AI classifier") {
		t.Errorf("the decider is named incorrectly:\n%s", got)
	}
	// The phrase to pass to the person -- otherwise the agent retells it
	// its own way and loses the main thing again.
	if !strings.Contains(got, "Tell whoever asked you to do this") {
		t.Errorf("no direct phrase for passing to the person:\n%s", got)
	}
	if !strings.Contains(got, "apr-0123456789abcdef") {
		t.Errorf("the id of the consumed approval is not named:\n%s", got)
	}
	// And honesty about one-time use: the approval is spent.
	if !strings.Contains(got, "spent") {
		t.Errorf("nowhere does it say the approval is spent — the next attempt will be judged all over again:\n%s", got)
	}
}
