package gateway

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The maintainer's canary for IAMT-394.
//
// The executor's canary (TestIAMT394_AskRedNeverReachesMachine) carries
// the right name but checks the wrong thing first: it calls the helper
// iamt394RefusedRed, which fails the test on the return code 126 before
// the question "did the machine see the exec" is even reached. Removing
// the ask barrier in human_role.go does make it turn red on the
// exit-status line. That proves the barrier does something but does NOT
// prove the main thing: that the red command never arrived.
//
// Exactly one assertion and nothing else is checked here: under the ask
// mode the machine's fake sshd must not see the exec. No return code,
// no text, no journal -- for this canary to turn red, its own reason is
// the only way.
func TestCanary_IAMT394_AskRedDoesNotReachTheMachineAtAll(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionAsk })
	execSeen := make(chan string, 4)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) { execSeen <- "exec" })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	const command = "rm -rf /var/lib/postgresql"
	client, hs := iamt353OpenExec(t, f, command)
	defer client.Close()

	// Give the gateway as much time as it would need to pass the command
	// through: the silence must be a decision, not a race.
	select {
	case <-execSeen:
		t.Fatalf("CANARY IAMT-394: under the ask mode the red command %q REACHED the machine -- "+
			"the fake sshd got the exec. The whole point of the mode is that before a person's "+
			"approval not a single byte reaches the machine", command)
	case <-time.After(2 * time.Second):
	}
	_ = hs.ch.Close()
}

// The other side: after the approval the very same command must arrive.
// A mode that still does not let it through after a "yes" is block
// under another name, and this canary catches that swap.
func TestCanary_IAMT394_ApprovedCommandDoesReachTheMachine(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionAsk })
	execSeen := make(chan string, 4)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		execSeen <- "exec"
		_, _ = ch.SendRequest("exit-status", false, nil)
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	const command = "rm -rf /var/lib/postgresql"
	id := iamt394RefusedRed(t, f, command)
	iamt394Approve(t, f, f.person, id)

	client, hs := iamt353OpenExec(t, f, command)
	defer client.Close()
	select {
	case <-execSeen:
	case <-time.After(3 * time.Second):
		t.Fatalf("CANARY IAMT-394: approval %q granted, yet the same command %q still "+
			"never reached the machine -- the ask mode behaves like block", id, command)
	}
	_ = hs.ch.Close()
}
