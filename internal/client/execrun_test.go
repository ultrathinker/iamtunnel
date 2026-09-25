// execrun_test.go proves, end to end against the real
// internal/gateway.Gateway (gatewayfixture_test.go), that an exec-only
// grant can run exactly one command, without ever attempting the
// interactive setup an exec-only grant refuses (PROTOCOL §4.1's pty-
// req/shell row), with stdout and stderr kept apart, and with the
// machine's own exit-status forwarded byte for byte.
//
// Canary: TestExecRunsOverExecOnlyGrantWithoutTouchingInteractiveSetup.
// Before this package had client.Exec at all, the only way to reach a
// machine was Connect, and Connect always sends "pty-req" then "shell"
// (connect.go) — which an exec-only grant's gateway rejects outright
// (internal/gateway/human_role.go's awaitSessionStart, execOnly branch):
// the function everything was done for had never once been used by
// anyone and could not be used. This
// test's second half checks the gateway's own event journal for exactly
// that rejection (Result "E_SSH_SHELL_FORBIDDEN", sshRequest "pty-req" or
// "shell") and fails if it is there — i.e. it fails if Exec ever sent
// either request. Broken on purpose during development (adding a
// ch.SendRequest("pty-req", ...) call ahead of the "exec" request inside
// Exec, exactly the old Connect-only bug): the test went red on this
// file's own "unexpected interactive-setup rejection" assertion, not on
// setup.
package client_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/client"
	"github.com/ultrathinker/iamtunnel/internal/gateway/events"
)

// execRetrying is connectRetrying's counterpart for Exec: a freshly
// connected fake machine needs the same short real round trip with the
// gateway before a human session can succeed.
func execRetrying(t *testing.T, newOpts func() client.ExecOptions) (client.ExecOutcome, error) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last client.ExecOutcome
	var lastErr error
	for time.Now().Before(deadline) {
		outcome, err := client.Exec(context.Background(), newOpts())
		if err == nil && outcome.Started {
			return outcome, nil
		}
		last, lastErr = outcome, err
		time.Sleep(20 * time.Millisecond)
	}
	return last, lastErr
}

func TestExecRunsOverExecOnlyGrantWithoutTouchingInteractiveSetup(t *testing.T) {
	gf := newGWFixture(t)
	signer := testSigner(t)
	until := time.Now().Add(time.Hour)
	gf.addPersonWithCap(t, "alice", signer, &until, "exec")
	gf.start(t)
	gf.connectMachine(t)

	dir := t.TempDir()
	const command = "cmd /c echo iamt-a1-exec"
	stdout, stderr := &syncBuffer{}, &syncBuffer{}
	outcome, err := execRetrying(t, func() client.ExecOptions {
		stdout, stderr = &syncBuffer{}, &syncBuffer{}
		return client.ExecOptions{
			Conn:           gf.connString("alice"),
			Machine:        gf.machineID,
			Command:        command,
			Signer:         signer,
			KnownHostsPath: client.KnownHostsPath(dir),
			Stdout:         stdout,
			Stderr:         stderr,
			DialTimeout:    2 * time.Second,
		}
	})
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if !outcome.Started {
		t.Fatal("gateway never accepted the exec request — an exec-only grant could not run its one allowed command")
	}
	if outcome.ExitStatus == nil || *outcome.ExitStatus != 0 {
		t.Fatalf("exit status = %v, want 0", outcome.ExitStatus)
	}

	// stdout/stderr separation.
	if !strings.Contains(stdout.String(), "exec-stdout:"+command) {
		t.Fatalf("stdout did not carry the target's own stdout: %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "exec-stderr:") {
		t.Fatalf("stderr text leaked into stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "exec-stderr:"+command) {
		t.Fatalf("stderr did not carry the target's own stderr: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "exec-stdout:") {
		t.Fatalf("stdout text leaked into stderr: %q", stderr.String())
	}

	// The canary: an exec-only grant's whole point is that Exec never
	// attempts the interactive setup the gateway would refuse. If it
	// ever did, the gateway's own journal would carry exactly this
	// rejection — see this file's header comment for how this was
	// proven red.
	evs, _, err := gf.log.Read(events.Filter{Types: []events.EventType{events.EventSessionDrop}, Actor: "alice", Object: gf.machineID})
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	for _, ev := range evs {
		if ev.Result == "E_SSH_SHELL_FORBIDDEN" {
			t.Fatalf("unexpected interactive-setup rejection in the journal: %+v — Exec must never send pty-req/shell", ev)
		}
	}
}
