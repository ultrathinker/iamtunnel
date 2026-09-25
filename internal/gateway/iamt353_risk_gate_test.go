package gateway

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/risk"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func iamt353OpenExec(t *testing.T, f *fixture, command string) (*ssh.Client, *humanSession) {
	t.Helper()
	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	hs := openHumanSession(t, client, f)
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: command}))
	if err != nil || !ok {
		_ = client.Close()
		t.Fatalf("exec %q: ok=%v err=%v", command, ok, err)
	}
	return client, hs
}

func iamt353RiskEvent(t *testing.T, f *fixture) events.Event {
	t.Helper()
	var result events.Event
	waitUntil(t, "IAMT-353: session.risk was not journaled", func() bool {
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionRisk}, Actor: f.person, Object: f.machineID})
		if err != nil {
			t.Fatalf("read risk events: %v", err)
		}
		if len(evs) == 0 {
			return false
		}
		result = evs[len(evs)-1]
		return true
	})
	return result
}

func iamt353NoRiskEvent(t *testing.T, f *fixture) {
	t.Helper()
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionRisk}, Actor: f.person, Object: f.machineID})
	if err != nil {
		t.Fatalf("read risk events: %v", err)
	}
	if len(evs) != 0 {
		t.Fatalf("unexpected session.risk events: %+v", evs)
	}
}

func TestIAMT353_GreenExecPassesSilently(t *testing.T) {
	f := newFixture(t, nil)
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- struct{}{}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "echo harmless")
	defer client.Close()
	select {
	case <-execSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("green exec did not reach the machine")
	}
	iamt353NoRiskEvent(t, f)
	if stderr := readAll(t, hs.ch.Stderr(), time.Second); strings.Contains(stderr, "[iamtunnel]") {
		t.Fatalf("green stderr = %q, want no risk warning", stderr)
	}
	_ = hs.ch.Close()
}

func TestIAMT353_YellowWarnsAndJournals(t *testing.T) {
	f := newFixture(t, nil)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "git push --force origin main")
	defer client.Close()
	stderr := readUntil(t, hs.ch.Stderr(), "action=warn")
	if why := iamt353CheckNotice(stderr, "WARNING", "risk=yellow rule=git-push-force action=warn"); why != "" {
		t.Fatalf("yellow stderr = %q: %s", stderr, why)
	}
	event := iamt353RiskEvent(t, f)
	if event.Result != "yellow" || event.Details["action"] != "warn" || event.Details["reason"] == "" || event.Details["sessionId"] == "" || event.Details["command"] != "git push --force origin main" {
		t.Fatalf("yellow risk event = %+v, want yellow/warn with reason", event)
	}
	_ = hs.ch.Close()
}

func TestIAMT353_RedBlockNeverReachesMachine(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionBlock })
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) { execSeen <- struct{}{} })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "rm -rf /var/lib/postgresql")
	defer client.Close()
	stderr := readUntil(t, hs.ch.Stderr(), "E_COMMAND_BLOCKED")
	if why := iamt353CheckNotice(stderr, "STOPPED", "risk=red rule=rm-recursive-outside-temp action=block E_COMMAND_BLOCKED"); why != "" {
		t.Fatalf("red stderr = %q: %s", stderr, why)
	}
	select {
	case status := <-hs.exits:
		if status != 126 {
			t.Fatalf("blocked exec exit status = %d, want 126", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("blocked exec did not return exit-status 126")
	}
	select {
	case <-execSeen:
		t.Fatal("blocked exec reached the machine")
	default:
	}
	event := iamt353RiskEvent(t, f)
	if event.Result != "red" || event.Details["action"] != "block" {
		t.Fatalf("red risk event = %+v, want red/block", event)
	}
	if got := f.lastSessionDropResult(f.person, f.machineID); got != "E_COMMAND_BLOCKED" {
		t.Fatalf("blocked exec session.drop = %q, want E_COMMAND_BLOCKED", got)
	}
}

func TestIAMT353_RedDefaultsToWarn(t *testing.T) {
	f := newFixture(t, nil)
	execSeen := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- struct{}{}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "rm -rf /var/lib/postgresql")
	defer client.Close()
	if stderr := readUntil(t, hs.ch.Stderr(), "action=warn"); iamt353CheckNotice(stderr, "WARNING", "risk=red rule=rm-recursive-outside-temp action=warn") != "" {
		t.Fatalf("red default stderr = %q, want a warning that says the command is being run anyway", stderr)
	}
	select {
	case <-execSeen:
	case <-time.After(3 * time.Second):
		t.Fatal("red exec with default action did not reach the machine")
	}
	event := iamt353RiskEvent(t, f)
	if event.Details["action"] != "warn" {
		t.Fatalf("red default action = %v, want warn", event.Details["action"])
	}
	_ = hs.ch.Close()
}

func TestIAMT353_InteractiveShellIsNotClassified(t *testing.T) {
	f := newFixture(t, func(c *Config) {
		c.RiskAction = RiskActionBlock
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)
	hs.shell(t)
	iamt353NoRiskEvent(t, f)
	_ = hs.ch.Close()
}

func TestIAMT353_BlockKeepsYellowAtWarn(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionBlock })
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "git push --force origin main")
	defer client.Close()
	if stderr := readUntil(t, hs.ch.Stderr(), "[iamtunnel]"); !strings.Contains(stderr, "action=warn") {
		t.Fatalf("yellow under block = %q, want warning rather than block", stderr)
	}
	event := iamt353RiskEvent(t, f)
	if event.Details["action"] != "warn" {
		t.Fatalf("yellow action under block = %v, want warn", event.Details["action"])
	}
	_ = hs.ch.Close()
}

func TestIAMT353_RiskWarningUsesTerminalFormattingOnlyForPTY(t *testing.T) {
	verdict := risk.Verdict{Level: risk.Red, Rule: "rm-recursive-outside-temp", Reason: "data would be lost"}
	plain := string(riskWarning(verdict, RiskActionBlock, false))
	if strings.Contains(plain, "\x1b[") || strings.Contains(plain, "\r") || !strings.Contains(plain, "E_COMMAND_BLOCKED") {
		t.Fatalf("non-PTY warning = %q, want plain E_COMMAND_BLOCKED line", plain)
	}
	terminal := string(riskWarning(verdict, RiskActionBlock, true))
	if !strings.Contains(terminal, "\x1b[31m") || !strings.HasSuffix(terminal, "\x1b[0m\r\n") {
		t.Fatalf("PTY warning = %q, want coloured CRLF line", terminal)
	}
}

// iamt353CheckNotice pins the SHAPE of the gateway's risk notice, not its
// prose (IAMT-395): the wording is meant to be improved, the shape is a
// contract.
//
//   - Every line carries the "[iamtunnel] " prefix. This text shares one
//     stderr with the machine's own output, and the prefix is the only
//     thing that tells the two apart — for a person reading it, and for
//     the window that colours the gateway's words (IAMT-392).
//   - The FIRST line states the outcome in words. The notice this
//     replaced opened with "risk=red rule=… action=block
//     E_COMMAND_BLOCKED" and nowhere said that nothing had run, which is
//     exactly what the owner could not work out on 20.09.2026.
//   - The machine-readable diagnostic is still there, for the journal and
//     for gate 14.
//   - No ANSI and no CR on a non-pty channel.
//
// Returns "" when the notice holds, or the reason it does not.
func iamt353CheckNotice(stderr, wantFirstWord, wantDiagnostic string) string {
	if strings.Contains(stderr, "\x1b[") {
		return "notice carries ANSI colour on a non-pty channel"
	}
	if strings.Contains(stderr, "\r") {
		return "notice carries CR on a non-pty channel"
	}
	lines := strings.Split(strings.TrimRight(stderr, "\n"), "\n")
	if len(lines) < 2 {
		return fmt.Sprintf("notice is %d line(s); want the outcome, the reason and the diagnostic each on their own line", len(lines))
	}
	for i, line := range lines {
		if !strings.HasPrefix(line, "[iamtunnel] ") {
			return fmt.Sprintf("line %d %q carries no [iamtunnel] prefix; the window cannot tell it from the machine's own output", i+1, line)
		}
	}
	if first := strings.TrimPrefix(lines[0], "[iamtunnel] "); !strings.HasPrefix(first, wantFirstWord) {
		return fmt.Sprintf("first line is %q; it must open with %q and say the outcome in words before any code", first, wantFirstWord)
	}
	if !strings.Contains(stderr, wantDiagnostic) {
		return fmt.Sprintf("diagnostic %q missing", wantDiagnostic)
	}
	return ""
}
