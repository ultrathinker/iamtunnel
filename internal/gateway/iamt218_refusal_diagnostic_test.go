package gateway

// iamt218_refusal_diagnostic_test.go — the canary of the IAMT-218
// diagnostics.
//
// The diagnostics live in humanSession.refusalDiagnostic
// (harness_test.go): when the gateway closes a person's channel
// without answering the pty-req, shell() dies not with a bare
// "pty-req: ok=false err=EOF" but with a message that names the
// refusal line the gateway has already written into the channel and the
// Result of the last session.drop from events.jsonl -- only the
// journal distinguishes the refusal branches of human_role.go that
// share the same refusal text.
//
// This test checks the MESSAGE, not the gateway's behavior: a person
// without a grant receives a lawful refusal, and the formatter must
// name both the refusal line and the typical reason from the journal.
// The formatter is a pure function (no t.Fatalf inside), so the canary
// compares the content directly and does not fail in a green suite.

import (
	"strings"
	"testing"

	"github.com/ultrathinker/iamtunnel/internal/sshx"
)

func TestIAMT218_RefusalDiagnosticNamesTheRefusalAndDropResult(t *testing.T) {
	f := newFixture(t, nil)

	// carol is in people but has no grant for the machine -- exactly the
	// setup TestAdmin_GrantActuallyControlsAccess checks gate 1 with. The
	// machine is deliberately not connected: the ACL check in
	// serveHumanSession fires before reg.get, that is, the earliest
	// refusal branch of human_role.go (denyHuman).
	carolKey := genSigner(t)
	addPerson(t, f, "carol", "user", carolKey)

	client, err := dialHuman(t, f.addr, "carol", f.machineID, carolKey)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	hs := openHumanSession(t, client, f)

	// shell() is no good here: it ends the test via t.Fatalf, and the
	// canary needs the message itself. We send the pty-req by hand -- the
	// gateway answers with a refusal (first session.drop into the
	// journal, then the refusal line into the channel and the close),
	// and refusalDiagnostic must name both parts.
	ok, err := hs.ch.SendRequest("pty-req", true, sshx.MarshalPTY(sshx.PTYRequest{Term: "xterm", Columns: 80, Rows: 24}))
	if err == nil && ok {
		t.Fatal("gateway granted pty-req to a person without a grant")
	}
	msg := hs.refusalDiagnostic(ok, err)

	// Assertion 1 (the refusal line): the verbatim prefix of the constant
	// from denyHuman. CANARY (maintainer's): corrupt the literal
	// "Access to this machine is currently unavailable.\r\n" in
	// internal/gateway/human_role.go:2164 (denyHuman) -- for example,
	// replace "currently" with "curently"; the test fails here with the
	// words
	// "IAMT-218 canary: the refusal diagnostic lost the gateway's refusal line".
	if !strings.Contains(msg, "Access to this machine is currently unavailable") {
		t.Fatalf("IAMT-218 canary: the refusal diagnostic lost the gateway's refusal line; want the message to contain %q, got:\n%s",
			"Access to this machine is currently unavailable", msg)
	}

	// Assertion 2 (the Result from the journal): denyHuman writes
	// session.drop with Result = acl.DenyNoGrant.String(). CANARY
	// (maintainer's): delete or break the appendEvent session.drop call
	// in denyHuman (internal/gateway/human_role.go:2163) -- the test
	// fails here with the words
	// "IAMT-218 canary: the refusal diagnostic lost the session.drop Result".
	const wantResult = "no permission for this machine" // acl.DenyNoGrant.String()
	if !strings.Contains(msg, "sessionDrop=\""+wantResult+"\"") {
		t.Fatalf("IAMT-218 canary: the refusal diagnostic lost the session.drop Result; want the message to contain sessionDrop=%q, got:\n%s",
			wantResult, msg)
	}
}
