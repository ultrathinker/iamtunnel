package gateway

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

type iamt354ClassifierStub struct {
	assessment risk.ExternalAssessment
	err        error
	commands   chan string
}

type iamt354BlockingClassifier struct {
	started chan struct{}
	release chan struct{}
}

func (s *iamt354BlockingClassifier) Classify(ctx context.Context, command string) (risk.ExternalAssessment, error) {
	select {
	case s.started <- struct{}{}:
	default:
	}
	select {
	case <-s.release:
		return risk.ExternalAssessment{Scores: map[string]float64{"destroys": 0.99, "access": 0.99}}, nil
	case <-ctx.Done():
		return risk.ExternalAssessment{}, ctx.Err()
	}
}

func (s *iamt354ClassifierStub) Classify(ctx context.Context, command string) (risk.ExternalAssessment, error) {
	if s.commands != nil {
		s.commands <- command
	}
	if s.err != nil {
		return risk.ExternalAssessment{}, s.err
	}
	return s.assessment, nil
}

func iamt354EnabledFixture(t *testing.T, stub risk.ExternalClassifier, cfgMod func(*Config)) *fixture {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "typesafe.key")
	if err := os.WriteFile(keyPath, []byte("test-key\n"), 0o600); err != nil {
		t.Fatalf("write classifier key: %v", err)
	}
	f := newFixture(t, func(c *Config) {
		c.RiskClassifier = RiskClassifierBoth
		c.ExternalRiskObservationEnabled = true
		c.ExternalRiskObservationKeyFile = keyPath
		if cfgMod != nil {
			cfgMod(c)
		}
	})
	// The startup path above has already proved that a key file is required.
	// Replacing the constructed client here keeps gateway-path tests local;
	// HTTP request shape and scrubbing have their own httptest coverage in risk.
	f.gw.cfg.externalRiskClassifier = stub
	return f
}

func TestIAMT354_UnknownExecExternalRedBlocks(t *testing.T) {
	stub := &iamt354ClassifierStub{
		assessment: risk.ExternalAssessment{Scores: map[string]float64{
			"destroys": 0.99, "access": 0.99,
		}},
		commands: make(chan string, 1),
	}
	f := iamt354EnabledFixture(t, stub, func(c *Config) { c.RiskAction = RiskActionBlock })
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- struct{}{}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "unlisted-command --password=hunter2")
	defer client.Close()
	select {
	case command := <-stub.commands:
		if command != "unlisted-command --password=<redacted>" {
			t.Fatalf("classifier command = %q, want scrubbed exec command", command)
		}
	case <-time.After(time.Second):
		t.Fatal("unknown command did not ask classifier")
	}
	stderr := readUntil(t, hs.ch.Stderr(), "E_COMMAND_BLOCKED")
	if why := iamt353CheckNotice(stderr, "STOPPED", "risk=red rule=external-classifier action=block E_COMMAND_BLOCKED"); why != "" {
		t.Fatalf("external red stderr = %q: %s", stderr, why)
	}
	select {
	case <-execSeen:
		t.Fatal("external red reached the machine under block")
	case <-time.After(250 * time.Millisecond):
	}
	event := iamt353RiskEvent(t, f)
	if event.Result != "red" || event.Details["classifier"] != "both" || event.Details["external"] != "red" || event.Details["threshold"] != risk.ExternalRiskThreshold || event.Details["sessionId"] == "" || event.Details["command"] != "unlisted-command --password=<redacted>" {
		t.Fatalf("external risk event = %+v, want active external red with metadata", event)
	}
	if _, ok := event.Details["probabilities"]; !ok || event.Details["latency_ms"] == nil {
		t.Fatalf("external risk event lacks raw probabilities or latency: %+v", event)
	}
	_ = hs.ch.Close()
}

func TestIAMT354_ExternalClassificationDelaysExec(t *testing.T) {
	observer := &iamt354BlockingClassifier{started: make(chan struct{}, 1), release: make(chan struct{})}
	f := iamt354EnabledFixture(t, observer, nil)
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- struct{}{}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	opened := make(chan struct {
		client *ssh.Client
		hs     *humanSession
	}, 1)
	go func() {
		client, hs := iamt353OpenExec(t, f, "unlisted-command")
		opened <- struct {
			client *ssh.Client
			hs     *humanSession
		}{client, hs}
	}()
	select {
	case <-observer.started:
	case <-time.After(time.Second):
		t.Fatal("external observer was not started")
	}
	select {
	case <-execSeen:
		t.Fatal("external classification did not hold exec before its verdict")
	case <-time.After(250 * time.Millisecond):
	}
	close(observer.release)
	select {
	case session := <-opened:
		select {
		case <-execSeen:
		case <-time.After(3 * time.Second):
			t.Fatal("external classification released but exec did not reach the machine")
		}
		_ = session.hs.ch.Close()
		_ = session.client.Close()
	case <-time.After(time.Second):
		t.Fatal("exec request did not complete while observation was running")
	}
}

func TestIAMT354_MatchedExecIsSentToExternalWithoutHoldingLocalRed(t *testing.T) {
	stub := &iamt354ClassifierStub{commands: make(chan string, 1)}
	f := iamt354EnabledFixture(t, stub, nil)
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- struct{}{}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "rm -rf /var/lib/postgresql")
	defer client.Close()
	select {
	case command := <-stub.commands:
		if command != "rm -rf /var/lib/postgresql" {
			t.Fatalf("matched command sent to classifier as %q", command)
		}
	case <-time.After(time.Second):
		t.Fatal("both mode did not send the matched command to the classifier")
	}
	select {
	case <-execSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("local red under warn did not reach the machine")
	}
	_ = hs.ch.Close()
}

// Rewritten 21.09.2026. BEFORE: TestIAMT354_ClassifierFailureKeepsLocalVerdict —
// a classifier failure in both mode kept the local verdict, and a locally
// green command went to the machine with a single warning.
//
// The maintainer revoked that rule outright: if the person has the box
// checked that we use the artificial judge for every request, we must not
// just wave it through; and named the order of the modes along the way:
// both is the STRICTEST -- two filters, and a command passes untouched
// only when both of them let it through. The rules mode never calls the
// service and cannot fail anyway.
//
// Now a refusal in both mode is a command that NOBODY judged, and it
// waits for a person.
func TestIAMT354_ClassifierFailureAsksAHuman(t *testing.T) {
	stub := &iamt354ClassifierStub{err: errors.New("classifier unavailable")}
	f := iamt354EnabledFixture(t, stub, nil)
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- struct{}{}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "unlisted-command")
	defer client.Close()
	select {
	case <-execSeen:
		t.Fatal("the command reached the machine although the classifier never judged it")
	case <-time.After(time.Second):
	}
	event := iamt353RiskEvent(t, f)
	if event.Result != "red" || event.Details["classifier"] != "both" || event.Details["externalError"] == "" {
		t.Fatalf("classifier failure event = %+v, want both/red with the external error", event)
	}
	if event.Details["rule"] != riskClassifierFailureRule {
		t.Fatalf("classifier failure rule = %v, want %q — the refusal must be distinguishable from a judged command",
			event.Details["rule"], riskClassifierFailureRule)
	}
	stderr := readUntil(t, hs.ch.Stderr(), "APPROVAL REQUIRED")
	// The reason must be named to the agent, not just "confirmation needed":
	// the maintainer's order was that this reason must be shouted about.
	for _, want := range []string{
		"never judged at all",
		"NOT a judgement about your command",
		riskClassifierFailureRule,
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("classifier failure stderr = %q, does not contain %q", stderr, want)
		}
	}
	_ = hs.ch.Close()
}
