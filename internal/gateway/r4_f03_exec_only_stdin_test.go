package gateway

// R4 F-03 forbade all stdin on an exec-only grant because a bare
// interpreter (`powershell`, `bash`, ...) turned into an unmonitored
// shell: the classifier only ever saw the exec command line, never what
// arrived on stdin next. The 1.50 security model removed that
// prohibition (no bans in advance — the classifier judges instead) and
// replaced it with exec_stdin.go's peek: for exactly that interpreter
// shape, the gateway folds the start of stdin into what the classifier
// judges before forwarding the exec, then lets every byte through.
//
// This test pins the new shape: stdin now reaches the machine on an
// exec-only grant, and the piped script text is what the classifier saw.

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestR150_ExecOnlyGrantForwardsStdin(t *testing.T) {
	f := newFixture(t, nil)
	iamt351SetGrantCaps(t, f, []string{"exec"})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// The machine side: an interpreter that only ever reads stdin. It
	// echoes back what it received so "the bytes reached the machine" is
	// observable, and it exits on stdin EOF like a real interpreter would.
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		buf := make([]byte, 4096)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				_, _ = ch.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	})

	hc, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer hc.Close()
	hs := openHumanSession(t, hc, f)

	// A bare interpreter by name: nothing on the command line for the
	// classifier to read, and the exact shape exec_stdin.go's peek
	// targets.
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "powershell"}))
	if err != nil || !ok {
		t.Fatalf("exec with exec-only grant: ok=%v err=%v", ok, err)
	}

	const payload = "Get-Date\r\n"
	if _, err := hs.ch.Write([]byte(payload)); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	if err := hs.ch.CloseWrite(); err != nil {
		t.Fatalf("close stdin: %v", err)
	}

	got := readUntil(t, hs.ch, payload)
	if !strings.Contains(got, payload) {
		t.Fatalf("stdin payload did not reach the machine and echo back: got %q", got)
	}

	// No E_SSH_STDIN_FORBIDDEN drop exists any more — the session ends
	// cleanly once the interpreter exits on stdin EOF.
	evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	for _, ev := range evs {
		if ev.Result == "E_SSH_STDIN_FORBIDDEN" {
			t.Fatalf("stdin was refused on an exec-only grant, but 1.50 forwards it: %+v", ev)
		}
	}

	_ = hs.ch.Close()
}
