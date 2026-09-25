package gateway

import (
	"encoding/json"
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

func iamt401EnabledFixture(t *testing.T, classifier RiskClassifier, stub risk.ExternalClassifier, action RiskAction) *fixture {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "classifier.key")
	if err := os.WriteFile(keyPath, []byte("test-key\n"), 0o600); err != nil {
		t.Fatalf("write classifier key: %v", err)
	}
	f := newFixture(t, func(c *Config) {
		c.RiskClassifier = classifier
		c.ExternalRiskObservationKeyFile = keyPath
		if action != "" {
			c.RiskAction = action
		}
	})
	f.gw.cfg.externalRiskClassifier = stub
	return f
}

func iamt401OpenAndExit(t *testing.T, f *fixture, command string) (*ssh.Client, *humanSession, chan struct{}) {
	t.Helper()
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- struct{}{}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	client, hs := iamt353OpenExec(t, f, command)
	return client, hs, execSeen
}

func TestIAMT401_BothExternalRedStopsGreenLocalCommand(t *testing.T) {
	stub := &iamt354ClassifierStub{
		assessment: risk.ExternalAssessment{Scores: map[string]float64{"destroys": 0.99, "access": 0.1}},
		commands:   make(chan string, 1),
	}
	f := iamt401EnabledFixture(t, RiskClassifierBoth, stub, RiskActionBlock)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, hs, execSeen := iamt401OpenAndExit(t, f, "status --password=hunter2")
	defer client.Close()
	select {
	case command := <-stub.commands:
		if command != "status --password=<redacted>" {
			t.Fatalf("external command = %q, want scrubbed command", command)
		}
	case <-time.After(time.Second):
		t.Fatal("both classifier was not called")
	}
	stderr := readUntil(t, hs.ch.Stderr(), "E_COMMAND_BLOCKED")
	if why := iamt353CheckNotice(stderr, "STOPPED", "risk=red rule=external-classifier action=block E_COMMAND_BLOCKED"); why != "" {
		t.Fatalf("both external red notice = %q: %s", stderr, why)
	}
	select {
	case status := <-hs.exits:
		if status != 126 {
			t.Fatalf("external red exit status = %d, want 126", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("external red did not return exit-status 126")
	}
	select {
	case <-execSeen:
		t.Fatal("external red reached the machine")
	case <-time.After(250 * time.Millisecond):
	}
}

func TestIAMT401_BothLocalRedStaysRedWithGreenExternal(t *testing.T) {
	stub := &iamt354ClassifierStub{
		assessment: risk.ExternalAssessment{Scores: map[string]float64{"destroys": 0.1, "access": 0.1}},
		commands:   make(chan string, 1),
	}
	f := iamt401EnabledFixture(t, RiskClassifierBoth, stub, RiskActionBlock)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, hs, execSeen := iamt401OpenAndExit(t, f, "rm -rf /var/lib/postgresql")
	defer client.Close()
	stderr := readUntil(t, hs.ch.Stderr(), "E_COMMAND_BLOCKED")
	if why := iamt353CheckNotice(stderr, "STOPPED", "risk=red rule=rm-recursive-outside-temp action=block E_COMMAND_BLOCKED"); why != "" {
		t.Fatalf("both local red notice = %q: %s", stderr, why)
	}
	select {
	case <-execSeen:
		t.Fatal("local red reached the machine")
	case <-time.After(250 * time.Millisecond):
	}
}

func TestIAMT401_RulesNeverCallsExternalClassifier(t *testing.T) {
	stub := &iamt354ClassifierStub{commands: make(chan string, 1)}
	f := iamt401EnabledFixture(t, RiskClassifierRules, stub, RiskActionWarn)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, hs, execSeen := iamt401OpenAndExit(t, f, "unlisted-command")
	defer client.Close()
	select {
	case <-execSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("rules command did not reach the machine")
	}
	select {
	case command := <-stub.commands:
		t.Fatalf("rules source called external classifier with %q", command)
	case <-time.After(250 * time.Millisecond):
	}
	_ = hs.ch.Close()
}

func TestIAMT401_AIIgnoresLocalRedWhenExternalIsGreen(t *testing.T) {
	stub := &iamt354ClassifierStub{
		assessment: risk.ExternalAssessment{Scores: map[string]float64{"destroys": 0.1, "access": 0.1}},
		commands:   make(chan string, 1),
	}
	f := iamt401EnabledFixture(t, RiskClassifierAI, stub, RiskActionBlock)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, hs, execSeen := iamt401OpenAndExit(t, f, "rm -rf /var/lib/postgresql")
	defer client.Close()
	select {
	case command := <-stub.commands:
		if command != "rm -rf /var/lib/postgresql" {
			t.Fatalf("AI command = %q, want command without local-rule rewrite", command)
		}
	case <-time.After(time.Second):
		t.Fatal("AI classifier was not called")
	}
	select {
	case <-execSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("AI green verdict did not reach the machine")
	}
	_ = hs.ch.Close()
}

func TestIAMT401_RiskCheckUsesSelectedClassifier(t *testing.T) {
	stub := &iamt354ClassifierStub{
		assessment: risk.ExternalAssessment{Scores: map[string]float64{"destroys": 0.1, "access": 0.1}},
		commands:   make(chan string, 1),
	}
	f := iamt401EnabledFixture(t, RiskClassifierAI, stub, RiskActionBlock)
	rootKey := genSigner(t)
	addPerson(t, f, "root", "admin", rootKey)
	root := dialAdmin(t, f, "root", rootKey)
	raw, err := root.Exec("risk.check", map[string]any{"proto": 1, "command": "rm -rf /var/lib/postgresql"})
	if err != nil {
		t.Fatalf("risk.check: %v", err)
	}
	var result struct {
		Level      string `json:"level"`
		Classifier string `json:"classifier"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatalf("risk.check response: %v", err)
	}
	if result.Level != "green" || result.Classifier != "ai" {
		t.Fatalf("risk.check result = %+v, want AI green verdict", result)
	}
	select {
	case command := <-stub.commands:
		if command != "rm -rf /var/lib/postgresql" {
			t.Fatalf("risk.check classifier command = %q", command)
		}
	case <-time.After(time.Second):
		t.Fatal("risk.check did not call selected external classifier")
	}
}

func TestIAMT401_AIUnavailableAsksInsteadOfPassing(t *testing.T) {
	stub := &iamt354ClassifierStub{err: errors.New("classifier unavailable")}
	f := iamt401EnabledFixture(t, RiskClassifierAI, stub, RiskActionWarn)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, hs, execSeen := iamt401OpenAndExit(t, f, "unlisted-command")
	defer client.Close()
	// 21.09.2026: a refusal no longer cuts the session with code 126 but
	// asks for confirmation -- the maintainer's point: a request must not
	// go through without a confirmation. What stayed unchanged is the main
	// thing: nothing reached the machine, and the reason was named.
	stderr := readUntil(t, hs.ch.Stderr(), "E_APPROVAL_REQUIRED")
	for _, want := range []string{
		"APPROVAL REQUIRED — this command was not run. Not a byte of it reached the machine.",
		"external classifier service is unavailable",
		"never judged at all",
		"NOT a judgement about your command",
		riskClassifierFailureRule,
		"classifier=ai",
	} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("AI failure notice = %q, missing %q", stderr, want)
		}
	}
	select {
	case <-execSeen:
		t.Fatal("AI failure reached the machine")
	case <-time.After(250 * time.Millisecond):
	}
	select {
	case status := <-hs.exits:
		if status != 126 {
			t.Fatalf("AI failure exit status = %d, want 126", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("AI failure did not return exit-status 126")
	}
	if got := f.lastSessionDropResult(f.person, f.machineID); got != riskClassifierFailureCode {
		t.Fatalf("AI failure session.drop = %q, want %s", got, riskClassifierFailureCode)
	}
}

func TestIAMT401_AIUnavailableCanBeExplicitlyDisabledWithLiveWarn(t *testing.T) {
	stub := &iamt354ClassifierStub{err: errors.New("classifier unavailable")}
	f := iamt401EnabledFixture(t, RiskClassifierAI, stub, RiskActionBlock)
	f.gw.riskLive.Store(&riskModeState{mode: RiskActionWarn, source: "live"})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, hs, execSeen := iamt401OpenAndExit(t, f, "unlisted-command")
	defer client.Close()
	stderr := readUntil(t, hs.ch.Stderr(), "external=unavailable")
	if !strings.Contains(stderr, "risk=unavailable rule=external-classifier action=warn classifier=ai") {
		t.Fatalf("live warn AI failure notice = %q, want explicit bypass diagnostic", stderr)
	}
	select {
	case <-execSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("live risk mode warn did not allow the retry")
	}
	_ = hs.ch.Close()
}

func TestIAMT401_BothLocalRedDoesNotWaitForExternal(t *testing.T) {
	stub := &iamt354BlockingClassifier{started: make(chan struct{}, 1), release: make(chan struct{})}
	f := iamt401EnabledFixture(t, RiskClassifierBoth, stub, RiskActionBlock)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)
	client, hs := iamt353OpenExec(t, f, "rm -rf /var/lib/postgresql")
	defer client.Close()
	select {
	case <-stub.started:
	case <-time.After(time.Second):
		t.Fatal("both local red did not start its asynchronous external observation")
	}
	stderr := readUntil(t, hs.ch.Stderr(), "E_COMMAND_BLOCKED")
	if !strings.Contains(stderr, "risk=red rule=rm-recursive-outside-temp action=block") {
		t.Fatalf("local red notice = %q", stderr)
	}
	select {
	case status := <-hs.exits:
		if status != 126 {
			t.Fatalf("local red exit status = %d, want 126", status)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("local red waited for the external classifier")
	}
	close(stub.release)
}
