package client_test

// connect_execonly_test.go proves end to end:
// "iamtunnel client connect on an exec grant prints the same thing and
// suggests client exec." Before this, human_role.go's awaitSessionStart
// rejected an exec-only grant's pty-req with no explanation at all
// (execOnly branch, no stderr write) and Connect never read the gateway's
// stderr channel during setup in the first place — so even if the gateway
// HAD written something there, nobody would have seen it. A person ran
// "client connect", got silence for the full SessionSetupTimeout, and
// then a generic "no shell" line with nothing above it to explain why.
//
// Canary: TestConnectOnExecOnlyGrantExplainsAndSuggestsExec. It asserts
// two things a pre-A2 build cannot both satisfy: the refusal text
// (E_SSH_SHELL_FORBIDDEN, the "client exec" hint) actually reaches Out,
// and Connect returns quickly — well under the fixture's
// SessionSetupTimeout (3s) — rather than sitting through it in silence.
import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/client"
)

func TestConnectOnExecOnlyGrantExplainsAndSuggestsExec(t *testing.T) {
	gf := newGWFixture(t)
	signer := testSigner(t)
	until := time.Now().Add(time.Hour)
	gf.addPersonWithCap(t, "alice", signer, &until, "exec")
	gf.start(t)
	gf.connectMachine(t)

	dir := t.TempDir()
	deadline := time.Now().Add(5 * time.Second)
	var outcome client.ConnectOutcome
	var out *syncBuffer
	var err error
	var elapsed time.Duration
	for time.Now().Before(deadline) {
		out = &syncBuffer{}
		callStart := time.Now()
		outcome, err = client.Connect(context.Background(), client.ConnectOptions{
			Conn:           gf.connString("alice"),
			Machine:        gf.machineID,
			Signer:         signer,
			KnownHostsPath: client.KnownHostsPath(dir),
			In:             strings.NewReader(""),
			Out:            out,
			DialTimeout:    2 * time.Second,
		})
		elapsed = time.Since(callStart)
		// Wait for the answer this test is about, not merely for a
		// transport that did not error.
		//
		// The loop used to stop at err == nil, and err is nil for the
		// generic "Access to this machine is currently unavailable"
		// refusal too -- the one the gateway gives while the machine is
		// not online YET. Under a full parallel suite the machine takes
		// longer to come up, so the loop kept stopping on that refusal
		// and the assertion below read it as a missing
		// E_SSH_SHELL_FORBIDDEN. That is the whole of the "flaky UI/
		// client canary" seen on 20.09.2026: not a race in the product,
		// but a test whose exit condition did not match what it was
		// waiting for.
		//
		// A real regression still fails here; it just spends the whole
		// deadline first, and the message below prints what did arrive.
		if err == nil && strings.Contains(out.String(), "E_SSH_SHELL_FORBIDDEN") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if outcome.ShellGranted {
		t.Fatal("an exec-only grant was handed a shell")
	}
	if !strings.Contains(out.String(), "E_SSH_SHELL_FORBIDDEN") {
		t.Fatalf("Out lacks the E_SSH_SHELL_FORBIDDEN refusal text: %q", out.String())
	}
	if !strings.Contains(out.String(), "client exec") {
		t.Fatalf("Out lacks the \"client exec\" hint: %q", out.String())
	}
	// The fixture's SessionSetupTimeout is 3s (gatewayfixture_test.go); a
	// silent pre-A2 rejection would have this call return only once that
	// full timeout elapsed. 1s is generous slack above "immediately" while
	// still being decisively short of the timeout it used to sit through.
	if elapsed > time.Second {
		t.Fatalf("Connect on an exec-only grant took %s — A2 requires an immediate refusal, not a wait for SessionSetupTimeout", elapsed)
	}
}
