package client_test

// IAMT-383: on an offline machine the gateway refuses a session before
// any channel request lands (serveHumanSession's preconditions run ahead
// of everything), writes its refusal line into the channel and closes
// it. client.Exec only looked at the exec request's own fate, so the
// person read "cannot send the command to the gateway: EOF" - a dead
// wire, when the gateway had actually said why: the machine is not
// reachable. The refusal line beats the close on the wire and survives
// in the channel; the client must read it and show it.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/client"
)

func TestIAMT383_ExecShowsTheGatewayRefusalForAnOfflineMachine(t *testing.T) {
	gf := newGWFixture(t)
	signer := testSigner(t)
	until := time.Now().Add(time.Hour)
	// The grant is real; the machine is never connected - exactly the
	// precondition order the gateway refuses in.
	gf.addPersonWithCap(t, "alice", signer, &until, "exec")
	gf.start(t)

	dir := t.TempDir()
	var stderr, stdout syncBuffer
	_, err := client.Exec(context.Background(), client.ExecOptions{
		Conn:           gf.connString("alice"),
		Machine:        gf.machineID,
		Command:        "cmd /c echo never",
		Signer:         signer,
		KnownHostsPath: client.KnownHostsPath(dir),
		Stdout:         &stdout,
		Stderr:         &stderr,
		DialTimeout:    2 * time.Second,
	})
	if err == nil {
		t.Fatal("Exec ran against an offline machine")
	}
	msg := err.Error()
	if !strings.Contains(msg, "Access to this machine is currently unavailable") {
		t.Fatalf("Exec reported %q - the gateway refused in words before the exec request could land, and the client threw those words away (IAMT-383)", msg)
	}
	if strings.Contains(msg, "EOF") {
		t.Errorf("the refusal still reads as a dead wire: %q - the reason must win over the transport noise", msg)
	}
}
