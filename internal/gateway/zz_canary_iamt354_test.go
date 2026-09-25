package gateway

// The maintainer's canaries for IAMT-354 -- two properties the task
// named and the delivered tests do not check.
//
// 1. A switched-off feature makes not a single call. It is checked
//    that the classifier is not called on a RECOGNIZED command, but
//    not that it is not called when the maintainer never switched it
//    on. And that is exactly the default mode: if even one command
//    line leaves outward in it, then a feature nobody switched on
//    sends the contents of other people's sessions to a third-party
//    service.
//
// 2. A slow service does not hold the session longer than its limit.
//    The 800 ms cap is the only thing keeping someone else's service
//    from adding a second to EVERY command. Without a test this is a
//    promise, not a property: the constant exists, but nothing keeps
//    it from stopping to apply.

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// slowClassifier hangs longer than its allotted term and releases the
// call only when the context is cancelled -- like a genuinely
// overloaded service.
type slowClassifier struct {
	called chan struct{}
}

func (s *slowClassifier) Classify(ctx context.Context, command string) (risk.ExternalAssessment, error) {
	select {
	case s.called <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return risk.ExternalAssessment{}, ctx.Err()
}

// TestCanary_IAMT354_DisabledClassifierIsNeverCalled.
//
// The canary: remove `&& g.cfg.ExternalRiskClassifierEnabled` from the
// call condition in serveHumanSession -- the test names the command
// that leaked.
func TestCanary_IAMT354_DisabledClassifierIsNeverCalled(t *testing.T) {
	stub := &iamt354ClassifierStub{commands: make(chan string, 1)}
	// The fixture WITHOUT the switch on: exactly what a maintainer gets
	// after updating the gateway without configuring anything.
	f := newFixture(t, nil)
	f.gw.cfg.externalRiskClassifier = stub
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// A command the local rules do NOT recognize: exactly these go to
	// the second opinion when it is enabled.
	client, hs := iamt353OpenExec(t, f, "Get-WinEvent -LogName System -MaxEvents 5")
	defer client.Close()

	select {
	case command := <-stub.commands:
		t.Fatalf("the classifier is off yet received %q -- the command line would have gone to a third-party service for a maintainer who never enabled this feature", command)
	case <-time.After(200 * time.Millisecond):
	}
	_ = hs.ch.Close()
}

// TestCanary_IAMT354_SlowClassifierDoesNotHoldTheCommand.
//
// The canary: replace risk.ExternalClassifierTimeout with a term
// clearly longer than allotted here (or drop context.WithTimeout
// entirely) -- the test turns red on the overrun.
func TestCanary_IAMT354_SlowClassifierDoesNotHoldTheCommand(t *testing.T) {
	if risk.ExternalClassifierTimeout > 2*time.Second {
		t.Fatalf("the external classifier limit %v: waiting this long before EVERY command is not acceptable -- this limit exists to prevent exactly that", risk.ExternalClassifierTimeout)
	}

	slow := &slowClassifier{called: make(chan struct{}, 1)}
	f := iamt354EnabledFixture(t, slow, nil)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// The bound is deliberately generous: what is checked is not the
	// timeout's precision but that it applies at all. A call hung
	// forever fails the test on this bound, not on the run's overall
	// timeout ten minutes later.
	limit := risk.ExternalClassifierTimeout + 3*time.Second

	done := make(chan struct{})
	go func() {
		client, hs := iamt353OpenExec(t, f, "Get-WinEvent -LogName System -MaxEvents 5")
		_ = hs.ch.Close()
		_ = client.Close()
		close(done)
	}()

	select {
	case <-slow.called:
	case <-time.After(limit):
		t.Fatal("the classifier is enabled but was never called -- the fixture is not about what it claims")
	}

	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("the command did not complete within %v with the classifier hung: the limit %v does not apply, and someone else's service delays every command at its own discretion",
			limit, risk.ExternalClassifierTimeout)
	}
}
