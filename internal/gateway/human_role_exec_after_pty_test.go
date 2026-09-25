package gateway

// human_role_exec_after_pty_test.go covers the exec-only surface's third
// claim: an exec
// after pty-req (the second barrier, human_role.go's proxyChannelRequests)
// must be classified too: PROTOCOL §4.1 promises the classification of
// every exec, and the code skipped it there.
//
// The real-world shape this closes is "ssh -t gw command" (pty-req, then
// exec, never shell — a normal, common OpenSSH invocation, not a crafted
// client): before this fix, an exec request arriving after an earlier
// pty-req was accepted skipped risk.Classify entirely and went straight
// to the machine, silently, for ANY command — including a red one.
//
// Canary: TestClassifyAndGateExecBlocksRedCommandAfterPTYReq. Broken on
// purpose during development (commented out the
// "if r.Type == \"exec\" && !programStarted" branch in
// proxyChannelRequests, restoring exactly the pre-fix pass-through): the
// test went red on its own "the red command reached the machine" fatal,
// not on setup. Reverted from this file's own saved copy of
// human_role.go, not `git checkout`.
//
// IAMT-454: there is no second barrier any more. awaitSessionStart no
// longer ends the setup at pty-req - it forwards the pty-req and waits
// for the exec - so the exec of "ssh -t gw command" is the session's
// start request and goes through the one classification every exec gets.
// The tests below pin the same behaviour over the wire and stay as they
// are.

import (
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestClassifyAndGateExecBlocksRedCommandAfterPTYReq(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionBlock })

	reachedMachine := make(chan struct{}, 1)
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		// The canary itself: this must never run for a red command. If
		// the second barrier's classification is skipped (the pre-fix
		// behavior), the exec sails straight through to here.
		reachedMachine <- struct{}{}
		_ = ch.Close()
	})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)

	// pty-req, never "shell" — the "ssh -t gw command" shape. The default
	// fixture grant carries "shell" (not exec-only), so this is allowed;
	// since IAMT-454 awaitSessionStart forwards the pty-req and goes on
	// waiting for the exec that follows.
	ok, err := hs.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err != nil || !ok {
		t.Fatalf("pty-req: ok=%v err=%v", ok, err)
	}

	ok, err = hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "rm -rf /"}))
	if err != nil || !ok {
		t.Fatalf("exec (second barrier): ok=%v err=%v", ok, err)
	}

	select {
	case status := <-hs.exits:
		if status != 126 {
			t.Fatalf("exit-status = %d, want 126 (E_COMMAND_BLOCKED)", status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no exit-status arrived — the blocked command was never answered")
	}

	select {
	case <-reachedMachine:
		t.Fatal("the red command reached the machine — the second barrier (proxyChannelRequests) did not classify it before forwarding")
	case <-time.After(300 * time.Millisecond):
	}

	if got := lastSessionDropResult(f.log, f.person, f.machineID); got != "E_COMMAND_BLOCKED" {
		t.Fatalf("last session.drop Result = %q, want E_COMMAND_BLOCKED", got)
	}
}

// TestClassifyAndGateExecForwardsGreenCommandAfterPTYReq is the other half
// of the same claim: an ordinary, green command arriving the same way
// (pty-req then exec) must still reach the machine — the second barrier's
// new classification must not turn into a second, accidental exec-only
// wall for every "ssh -t" session.
func TestClassifyAndGateExecForwardsGreenCommandAfterPTYReq(t *testing.T) {
	f := newFixture(t, func(c *Config) { c.RiskAction = RiskActionBlock })
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	client, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)

	ok, err := hs.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err != nil || !ok {
		t.Fatalf("pty-req: ok=%v err=%v", ok, err)
	}
	ok, err = hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "cmd /c echo iamt-a2-green"}))
	if err != nil || !ok {
		t.Fatalf("exec (second barrier): ok=%v err=%v", ok, err)
	}

	const marker = "iamt-a2-green-echo"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Fatalf("write exec stdin: %v", err)
	}
	if got := readUntil(t, hs.ch, marker); got == "" {
		t.Fatalf("a green command after pty-req produced no echoed output: %q", got)
	}
}
