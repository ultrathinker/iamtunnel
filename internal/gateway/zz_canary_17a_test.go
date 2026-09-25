package gateway

// The maintainer's canaries for wave 1.7-A.
//
// The ladder has three positions, but the delivered tests check only
// two: warn (the default) and block. The log position is checked by
// nothing -- and it is exactly the mode a maintainer picks to "first
// see what this would catch, touching nobody". If log does write to
// stderr, it fails at the one thing it exists for, and the maintainer
// will learn about it from the specialist who asks what those lines
// raining into their logs are.

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

// TestCanary_17A_LogIsSilentButStillJournals.
//
// The canary: make log behave like warn (for example, remove the
// position check before writing to stderr) -- the test names the line
// that must not have appeared.
func TestCanary_17A_LogIsSilentButStillJournals(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionLog })
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// A red command: if the warning breaks out anywhere, it is here.
	client, hs := iamt353OpenExec(t, f, "rm -rf /var/lib/postgresql")
	defer client.Close()

	// The journal must remember: "journal only" is about the person, not
	// about the audit.
	ev := iamt353RiskEvent(t, f)
	if ev.Result != "red" {
		t.Fatalf("in log mode the session.risk event = %q, want red -- the mode dims the warning, not the classification", ev.Result)
	}

	if stderr := readAll(t, hs.ch.Stderr(), time.Second); strings.Contains(stderr, "[iamtunnel]") {
		t.Fatalf("in log mode stderr received %q -- the log position exists exactly so that the maintainer can look at what would be caught without troubling anyone; if it writes to the specialist, it does not differ from warn", stderr)
	}
	_ = hs.ch.Close()
}

// TestCanary_17A_LogNeverBlocks: log is softer than warn,
// and warn does not block -- so log cannot either. Checked separately,
// because the ladder rests on every position being strictly softer
// than the next, and no test about block catches a violation of that
// order.
func TestCanary_17A_LogNeverBlocks(t *testing.T) {
	reached := make(chan struct{}, 1)
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionLog })
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		select {
		case reached <- struct{}{}:
		default:
		}
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, "rm -rf /var/lib/postgresql")
	defer client.Close()

	select {
	case <-reached:
	case <-time.After(3 * time.Second):
		t.Fatal("in log mode the red command did not reach the machine -- log is softer than warn, and warn lets through; the ladder stopped being a ladder")
	}
	_ = hs.ch.Close()
}

// TestCanary_17A_BlockedCommandIsRecoverableFromTheJournalAlone.
//
// The sessionId and command item was made for exactly this: for a
// blocked command session.start is not written at all, and before this
// fix the command text was not preserved in the journal anywhere. The
// test demands that ONE journal line be enough for the question "what
// exactly was stopped", without reading the recording files.
//
// The canary: drop command (or sessionId) from details -- the test
// names what was missing.
func TestCanary_17A_BlockedCommandIsRecoverableFromTheJournalAlone(t *testing.T) {
	const command = "rm -rf /var/lib/postgresql"

	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionBlock })
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		_, _ = ch.SendRequest("exit-status", false, sshx.MarshalExitStatus(sshx.ExitStatus{Status: 0}))
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, hs := iamt353OpenExec(t, f, command)
	defer client.Close()

	ev := iamt353RiskEvent(t, f)
	if ev.Result != "red" {
		t.Fatalf("level in the event = %q, want red", ev.Result)
	}
	got, _ := ev.Details["command"].(string)
	if got != command {
		t.Errorf("session.risk.details.command = %q, want %q -- for a blocked command session.start is not written, and without this field the text of what was stopped is not preserved in the journal ANYWHERE",
			got, command)
	}
	if sid, _ := ev.Details["sessionId"].(string); sid == "" {
		t.Error("session.risk.details.sessionId is empty -- the event cannot be tied to the session.drop carrying the same incident")
	}

	// The "one line is enough" check: the rule and the action are in
	// place too.
	if rule, _ := ev.Details["rule"].(string); rule == "" {
		t.Error("session.risk.details.rule is empty -- the journal reader has nothing to explain WHY it was stopped")
	}
	if action, _ := ev.Details["action"].(string); action != "block" {
		t.Errorf("session.risk.details.action = %q, want block", action)
	}

	_ = hs.ch.Close()
	_ = events.EventSessionRisk
}
