package gateway

// R4 F-03 (round-4 review): "an exec grant = an interactive interpreter
// without classification". An exec-only grant forwards `exec "powershell"` (a bare
// interpreter) to the machine, and then core.Bridge happily carries
// everything the person types next — bytes the classifier never saw,
// because no second exec request ever happens. The live scenario:
// `ssh -p 2222 agent:m@gw powershell` and then
// `Remove-Item -Recure C:\Data` straight into the same channel.
//
// The fix under test has two halves, both pinned here:
//
//   - the gateway closes the machine side's stdin (CloseWrite) the moment
//     the exec command has been forwarded, so a bare interpreter gets EOF
//     instead of a silent, unclassified command channel (iamtunnel's own
//     client has always done exactly this — internal/client/execrun.go);
//   - bytes the person writes anyway do not reach the machine: the first
//     one ends the session with session.drop Result E_SSH_STDIN_FORBIDDEN
//     and the same code goes to the person's stderr with the "client exec"
//     hint, in the shape A2 already established for E_SSH_SHELL_FORBIDDEN.
//
// Canary: drop the CloseWrite or the guard, and the payload below reaches
// the machine (the fake interpreter echoes it back) while no drop with the
// code is ever journaled — this test goes red on both counts.

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestF03_ExecOnlyGrantRefusesStdin(t *testing.T) {
	f := newFixture(t, nil)
	iamt351SetGrantCaps(t, f, []string{"exec"})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// The machine side of the scenario: an interpreter that is
	// only ever given stdin. Count every byte that reaches it and echo it
	// back — the echo is what makes "bytes reached the machine" observable.
	// On stdin EOF the interpreter would exit; here it parks on release
	// instead, so the session's lifetime is decided by the gateway's
	// enforcement alone and the test stays deterministic (no race between
	// the machine's own exit and the person's stdin write). release is
	// closed in t.Cleanup, so the parked goroutine always leaves.
	var reached atomic.Int64
	release := make(chan struct{})
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		buf := make([]byte, 4096)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				reached.Add(int64(n))
				_, _ = ch.Write(buf[:n])
			}
			if err != nil {
				<-release
				return
			}
		}
	})
	t.Cleanup(func() { close(release) })

	hc, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer hc.Close()
	hs := openHumanSession(t, hc, f)

	// The scenario's command: an interactive interpreter by name, no
	// payload for the classifier to look at. The exec itself is legal on
	// this grant — what must not happen is the stdin flow that follows.
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "powershell"}))
	if err != nil || !ok {
		t.Fatalf("exec with exec-only grant: ok=%v err=%v", ok, err)
	}

	// The command that would have been typed into that interpreter.
	const payload = "Remove-Item -Recurse C:\\Data\r\n"
	if _, err := hs.ch.Write([]byte(payload)); err != nil {
		t.Logf("stdin write failed (%v) — the transport may already be refusing it", err)
	}

	waitUntil(t, "F-03: stdin bytes on an exec-only grant must end the session as E_SSH_STDIN_FORBIDDEN", func() bool {
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
		if err != nil {
			t.Fatalf("read events: %v", err)
		}
		for _, ev := range evs {
			if ev.Actor == f.person && ev.Object == f.machineID && ev.Result == "E_SSH_STDIN_FORBIDDEN" {
				return true
			}
		}
		return false
	})

	if got := reached.Load(); got != 0 {
		t.Fatalf("stdin payload reached the machine (%d bytes) on an exec-only grant — the classifier never saw it", got)
	}
	if stderrText := iamt351ReadStderr(hs.ch, time.Second); !strings.Contains(stderrText, "E_SSH_STDIN_FORBIDDEN") || !strings.Contains(stderrText, "client exec") {
		t.Fatalf("F-03: stdin refusal did not reach stderr with the E_SSH_STDIN_FORBIDDEN code and the \"client exec\" hint: %q", stderrText)
	}
}
