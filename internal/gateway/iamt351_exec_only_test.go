package gateway

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ultrathinker/iamtunnel/internal/gateway/acl"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
	"github.com/ultrathinker/iamtunnel/internal/gateway/state"
	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func iamt351SetGrantCaps(t *testing.T, f *fixture, caps []string) {
	t.Helper()
	found := false
	if err := f.store.Update(func(st *state.State) error {
		for i := range st.Grants {
			if st.Grants[i].Person == f.person && st.Grants[i].Machine == f.machineID {
				st.Grants[i].Caps = append([]string(nil), caps...)
				found = true
				return nil
			}
		}
		return errors.New("fixture grant is missing")
	}); err != nil {
		t.Fatalf("set fixture grant caps: %v", err)
	}
	if !found {
		t.Fatal("set fixture grant caps: grant was not found")
	}
	until := f.clock.Now().Add(time.Hour)
	if err := f.gw.aclE.AddGrant(acl.Grant{
		Person: f.person, Machine: f.machineID, Until: &until, Caps: append([]string(nil), caps...),
	}, f.clock.Now()); err != nil {
		t.Fatalf("activate fixture grant caps: %v", err)
	}
}

func iamt351ExpectSSHReject(t *testing.T, f *fixture, ch ssh.Channel, request string, payload []byte) {
	t.Helper()
	ok, err := ch.SendRequest(request, true, payload)
	if err != nil || ok {
		t.Fatalf("%s with exec-only grant: ok=%v err=%v, want request failure", request, ok, err)
	}
	waitUntil(t, "IAMT-351: missing exec-only SSH refusal for "+request, func() bool {
		evs, _, err := f.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}})
		if err != nil {
			t.Fatalf("read events: %v", err)
		}
		for _, ev := range evs {
			if ev.Actor == f.person && ev.Object == f.machineID &&
				ev.Result == "E_SSH_SHELL_FORBIDDEN" && ev.Details["sshRequest"] == request {
				return true
			}
		}
		return false
	})
}

// iamt351ReadStderr reads whatever the gateway wrote to ch's extended data
// (stream 1) within deadline, then stops — used to check the human-facing
// A2 refusal text, not just the internal event journal.
func iamt351ReadStderr(ch ssh.Channel, deadline time.Duration) string {
	done := make(chan string, 1)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := ch.Stderr().Read(buf)
			if n > 0 {
				sb.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	select {
	case s := <-done:
		return s
	case <-time.After(deadline):
		return ""
	}
}

// TestIAMT351_ExecOnlyRejectsInteractiveRequestsAndAllowsExec covers
// PROTOCOL §4.1's exec-only rule from three angles: a bare "shell", a bare
// "pty-req", and a "pty-req" arriving mid-session through the second
// barrier (proxyChannelRequests, after an exec has already started) — each
// on its own connection, because the 1.8 exec-only change altered the first
// two
// from "refused, then the channel stays open for more setup requests" to
// "refused, told why on stderr, and the channel ends right there" — a
// second SendRequest on the very same (now closed) channel would see EOF,
// not another orderly refusal, which is the whole point of the fix (see
// human_role.go's awaitSessionStart execOnly branch).
func TestIAMT351_ExecOnlyRejectsInteractiveRequestsAndAllowsExec(t *testing.T) {
	f := newFixture(t, nil)
	iamt351SetGrantCaps(t, f, []string{"exec"})
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// "shell" alone: refused, and the channel ends there (A2).
	shellClient, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	shellSession := openHumanSession(t, shellClient, f)
	iamt351ExpectSSHReject(t, f, shellSession.ch, "shell", nil)
	if stderrText := iamt351ReadStderr(shellSession.ch, time.Second); !strings.Contains(stderrText, "E_SSH_SHELL_FORBIDDEN") || !strings.Contains(stderrText, "client exec") {
		t.Fatalf("A2: shell refusal did not reach stderr with the E_SSH_SHELL_FORBIDDEN code and the \"client exec\" hint: %q", stderrText)
	}
	_ = shellClient.Close()

	// "pty-req" alone, on a fresh connection: the same refusal, independent
	// of which setup request the person happened to send first.
	ptyClient, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	ptySession := openHumanSession(t, ptyClient, f)
	iamt351ExpectSSHReject(t, f, ptySession.ch, "pty-req", sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	_ = ptyClient.Close()

	// exec still works on this grant, and a pty-req arriving AFTER exec has
	// already started (the second barrier, proxyChannelRequests) is refused
	// too — on its own, third connection, since the first two channels are
	// already gone. The fake machine side is an interpreter-shaped handler
	// (like the real sshd running a bare command): it drains stdin and, once
	// the gateway's F-03 CloseWrite arrives, parks instead of exiting, so
	// the session's only possible exit is the gateway's own stdin refusal —
	// the wait below is therefore deterministic, not a race with the
	// machine's own EOF.
	release := make(chan struct{})
	f.sshd.setOnExecImmediate(func(ch ssh.Channel) {
		buf := make([]byte, 4096)
		for {
			if _, err := ch.Read(buf); err != nil {
				<-release
				return
			}
		}
	})
	t.Cleanup(func() { close(release) })
	execClient, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial human: %v", err)
	}
	defer execClient.Close()
	hs := openHumanSession(t, execClient, f)
	ok, err := hs.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "cmd /c echo iamt351"}))
	if err != nil || !ok {
		t.Fatalf("exec with exec-only grant: ok=%v err=%v", ok, err)
	}
	iamt351ExpectSSHReject(t, f, hs.ch, "pty-req", sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 120, Rows: 35}))

	// R4 F-03: exec on this grant starts with the machine's stdin already
	// closed by the gateway, and a byte written anyway ends the session as
	// E_SSH_STDIN_FORBIDDEN (TestF03_ExecOnlyGrantRefusesStdin pins that
	// refusal itself; here the coarser half is pinned: what used to be
	// echoed back by the machine must now stay unheard).
	const marker = "iamt351-exec-still-runs"
	if _, err := hs.ch.Write([]byte(marker)); err != nil {
		t.Logf("stdin write refused (%v) — the exec-only enforcement is holding", err)
	}
	waitUntil(t, "F-03: exec-only session must end after stdin is refused", func() bool {
		evs, _, err := f.log.Read(events.Filter{
			Types: []events.EventType{events.EventSessionDrop},
			Actor: f.person, Object: f.machineID,
		})
		if err != nil {
			return false
		}
		for _, ev := range evs {
			if ev.Result == "E_SSH_STDIN_FORBIDDEN" {
				return true
			}
		}
		return false
	})
	if got := readUntil(t, hs.ch, marker); strings.Contains(got, marker) {
		t.Fatalf("exec-only grant echoed stdin to the machine and back: %q", got)
	}
	_ = hs.ch.Close()
}

func TestIAMT351_ShellGrantKeepsShellAndExecCompatibility(t *testing.T) {
	f := newFixture(t, nil)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	shellClient, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial shell client: %v", err)
	}
	hs := openHumanSession(t, shellClient, f)
	hs.shell(t)
	_ = hs.ch.Close()
	_ = shellClient.Close()
	waitUntil(t, "shell session did not close", func() bool {
		mc, ok := f.gw.reg.get(f.machineID)
		return ok && mc.doorMachine.Snapshot().Sessions == 0
	})

	execClient, err := dialHuman(t, f.addr, f.person, f.machineID, f.personKey)
	if err != nil {
		t.Fatalf("dial exec client: %v", err)
	}
	defer execClient.Close()
	execSession := openHumanSession(t, execClient, f)
	ok, err := execSession.ch.SendRequest("exec", true, sshx.MarshalExec(sshx.Exec{Command: "cmd /c echo iamt351-shell-compat"}))
	if err != nil || !ok {
		t.Fatalf("exec with shell grant: ok=%v err=%v", ok, err)
	}
	_ = execSession.ch.Close()
}

func TestIAMT351_GrantsGrantAcceptsExactlyOneKnownCapability(t *testing.T) {
	for _, tc := range []struct {
		name string
		caps []string
		code string
	}{
		{name: "exec", caps: []string{"exec"}},
		{name: "shell", caps: []string{"shell"}},
		{name: "two capabilities", caps: []string{"shell", "exec"}, code: "E_CAP_UNSUPPORTED"},
		{name: "empty", caps: []string{}, code: "E_CAP_UNSUPPORTED"},
		{name: "unknown", caps: []string{"ports"}, code: "E_CAP_UNSUPPORTED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, nil)
			if tc.code == "" {
				if err := f.store.Update(func(st *state.State) error {
					if !st.RevokeAccess(f.person, f.machineID) {
						return errors.New("fixture grant is missing")
					}
					return nil
				}); err != nil {
					t.Fatalf("remove fixture grant: %v", err)
				}
				if _, err := f.gw.aclE.Revoke(f.person, f.machineID, f.clock.Now()); err != nil {
					t.Fatalf("deactivate fixture grant: %v", err)
				}
			}
			body, err := json.Marshal(map[string]any{
				"proto": 1, "person": f.person, "machine": f.machineID, "until": "", "caps": tc.caps,
			})
			if err != nil {
				t.Fatalf("marshal grants.grant body: %v", err)
			}
			result, cerr := cmdGrantsGrant(f.gw, "admin", f.clock.Now(), body)
			if tc.code != "" {
				if cerr == nil || cerr.code != tc.code {
					t.Fatalf("grants.grant caps=%v: error=%v, want %s", tc.caps, cerr, tc.code)
				}
				return
			}
			if cerr != nil {
				t.Fatalf("grants.grant caps=%v: %v", tc.caps, cerr)
			}
			grant := result.(map[string]any)["grant"].(grantView)
			if len(grant.Caps) != 1 || grant.Caps[0] != tc.caps[0] {
				t.Fatalf("grants.grant caps=%v: returned %+v", tc.caps, grant)
			}
		})
	}
}
