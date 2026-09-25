package gateway

import (
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
)

// The maintainer's canaries for IAMT-401.
//
// Each checks EXACTLY ONE assertion and looks where that assertion is
// actually decided -- on the machine's fake sshd. The executor's
// canaries check several things at once and fall on the first one, so
// they do not prove the very assertion named in the test's name.
//
// The first assertion, the main one and the maintainer's decision of
// 20.09: with the source "ai" and the external classifier unavailable,
// the command does NOT reach the machine. In their words: we cannot
// continue when the AI is switched on but not working. Letting it
// through with a warning means lying: there is no safety net, while
// the person believes there is one.
func TestCanary_IAMT401_AIUnavailableMeansNothingReachesTheMachine(t *testing.T) {
	stub := &iamt354ClassifierStub{err: errors.New("classifier unavailable")}
	// Deliberately warn, not block: under warn an ordinary red command
	// would go through. If it goes through here too, the service refusal
	// stopped nothing -- and that is the defect itself.
	f := iamt401EnabledFixture(t, RiskClassifierAI, stub, RiskActionWarn)
	execSeen := make(chan struct{}, 4)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) { execSeen <- struct{}{} })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	const command = "echo harmless"
	client, hs := iamt353OpenExec(t, f, command)
	defer client.Close()

	select {
	case <-execSeen:
		t.Fatalf("CANARY IAMT-401: classification source \"ai\", the external service unavailable, "+
			"yet command %q STILL reached the machine. The ai mode means \"judge through the AI\"; "+
			"when there is nothing to judge with, letting it through is not allowed -- the person "+
			"believes they are covered, and they are not", command)
	case <-time.After(2 * time.Second):
	}
	_ = hs.ch.Close()
}

// The second assertion, OVERTURNED on 21.09.2026 by the maintainer's
// order.
//
// BEFORE: with the source "both" the service being unavailable did NOT
// stop the work -- the local verdict remained. The reasoning was about
// convenience: otherwise a single failure of someone else's service
// takes down all the work.
//
// AFTER: the maintainer named the order of the modes in their own words:
// if the modes work together, that is the strictest mode -- two filters
// must both pass before a command goes through without prohibitions...
// and if the service does not answer, or is broken, or we are out of
// budget, we must not let a request through without a confirmation.
//
// The command is not discarded -- it waits for a person. The convenience
// the old assertion was written for is preserved by the Allow button,
// not by a silent pass-through.
func TestCanary_IAMT401_BothAsksWhenTheClassifierIsUnavailable(t *testing.T) {
	stub := &iamt354ClassifierStub{err: errors.New("classifier unavailable")}
	f := iamt401EnabledFixture(t, RiskClassifierBoth, stub, RiskActionWarn)
	execSeen := make(chan struct{}, 4)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) { execSeen <- struct{}{} })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	const command = "echo harmless"
	client, hs := iamt353OpenExec(t, f, command)
	defer client.Close()

	select {
	case <-execSeen:
		t.Fatalf("CANARY IAMT-408: source \"both\", the external service unavailable, "+
			"yet command %q STILL reached the machine. both is the strictest mode: "+
			"two filters, and a command passes untouched only when both of them "+
			"let it through. A silent service did not \"let it through\"", command)
	case <-time.After(2 * time.Second):
	}

	// And the reason must be named: an agent told only "confirmation
	// needed" will keep hammering retries instead of telling the person
	// that the AI check is down.
	stderr := readUntil(t, hs.ch.Stderr(), "APPROVAL REQUIRED")
	for _, want := range []string{"never judged at all", riskClassifierFailureRule} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("CANARY IAMT-408: the classifier refusal did not name the reason to the agent: %q does not contain %q",
				stderr, want)
		}
	}
	_ = hs.ch.Close()
}

// The third assertion: with the source "rules" NOTHING leaves outward.
// This is a privacy promise, not a convenience one: a person who chose
// rules is entitled to believe their commands never leave the gateway.
func TestCanary_IAMT401_RulesSendsNothingOutside(t *testing.T) {
	stub := &iamt354ClassifierStub{
		assessment: risk.ExternalAssessment{Scores: map[string]float64{"destroys": 0.99, "access": 0.99}},
		commands:   make(chan string, 4),
	}
	f := iamt401EnabledFixture(t, RiskClassifierRules, stub, RiskActionWarn)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "echo harmless")
	defer client.Close()

	select {
	case sent := <-stub.commands:
		t.Fatalf("CANARY IAMT-401: source \"rules\", yet command %q still went out to the external "+
			"classifier. rules is a promise that commands never leave the gateway", sent)
	case <-time.After(1500 * time.Millisecond):
	}
	_ = hs.ch.Close()
}
