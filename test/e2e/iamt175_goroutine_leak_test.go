package e2e

// iamt175_goroutine_leak_test.go is the IAMT-175 broad leak check for
// the e2e fixture, built exactly like
// internal/gateway/iamt175_goroutine_leak_test.go (see that file for
// why the round-3 count-inside-the-test-body shape was unreliable):
//
//   - the stack snapshot is taken BEFORE any fixture work;
//   - the check runs in the test's FIRST-registered t.Cleanup, so
//     (cleanups run LIFO) it executes after the fixture has closed the
//     gateway, the store, the event log, the fake sshd and the fake
//     machine;
//   - only goroutines NEW relative to the snapshot are flagged;
//   - a goroutine counts as gateway work only if the first frame that
//     says who owns it is a production frame of package
//     github.com/ultrathinker/iamtunnel/internal/gateway (not *_test.go, not testing, not a
//     subpackage);
//   - the wait is bounded decay protection after Close, not the
//     assertion.
//
// The test body repeats the steps of the live TestE2E_EnrolSuccessPath
// (enrol_admin_test.go) exactly — seeded admin, enrol-code, machine
// enrol with the ephemeral key, then the fake machine connecting with
// the SAME long-term key that was registered — so the gateway's
// machine path (handler goroutines, sshd probe under probesWG, drain
// goroutines) is exercised before Close.

import (
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ultrathinker/iamtunnel/internal/admin"
	"github.com/ultrathinker/iamtunnel/internal/config"
)

// e2eGatewayPkgQualifier / e2eGatewayFileRe: the same package
// qualifier and file-line pattern the internal/gateway leak check
// uses. The qualifier is a substring check (the character right after
// it is "(" for every pointer-receiver method); subpackage frames
// (gateway/acl, gateway/state, ...) carry "gateway/" and never match.
const e2eGatewayPkgQualifier = "github.com/ultrathinker/iamtunnel/internal/gateway."

var e2eGatewayFileRe = regexp.MustCompile(`internal[/\\]gateway[/\\][A-Za-z0-9_]+\.go:`)

// isE2EGatewayProductionGoroutine mirrors
// gateway.isGatewayProductionGoroutine: walk frames top down, skip
// runtime plumbing, and let the first owner frame decide — testing or
// *_test.go means harness, a production gateway frame means product.
func isE2EGatewayProductionGoroutine(block string) bool {
	lines := strings.Split(block, "\n")
	for i := 1; i+1 < len(lines); i += 2 {
		fn, file := lines[i], lines[i+1]
		switch {
		case strings.HasPrefix(fn, "runtime."):
			continue
		case strings.HasPrefix(fn, "testing."):
			return false
		case strings.Contains(fn, e2eGatewayPkgQualifier):
			if strings.Contains(file, "_test.go:") {
				return false
			}
			return true
		case strings.Contains(file, "_test.go:"):
			return false
		case e2eGatewayFileRe.MatchString(file):
			return true
		}
	}
	return false
}

// e2eNormalizeStack strips the goroutine header, argument lists and
// code offsets so two snapshots of the same parked goroutine diff to
// the same key. The argument list opens at the LAST "(" of a function
// line — the method receiver's own parentheses come first. Mirrors
// gateway.normalizeStack.
func e2eNormalizeStack(block string) string {
	lines := strings.Split(block, "\n")
	var sb strings.Builder
	for i, line := range lines {
		if i == 0 {
			continue
		}
		if strings.HasPrefix(line, "\t") {
			if idx := strings.Index(line, " +0x"); idx >= 0 {
				line = line[:idx]
			}
		} else {
			if idx := strings.LastIndex(line, "("); idx >= 0 {
				line = line[:idx]
			}
		}
		sb.WriteString(strings.TrimSpace(line))
		sb.WriteByte('\n')
	}
	return sb.String()
}

func e2eProductionGatewayBlocks(t *testing.T) []string {
	t.Helper()
	const fourMiB = 4 << 20
	buf := make([]byte, fourMiB)
	n := runtime.Stack(buf, true)
	if n == len(buf) {
		t.Fatalf("runtime.Stack buffer full; cannot reliably diff gateway goroutines")
	}
	var out []string
	for _, block := range strings.Split(string(buf[:n]), "\n\n") {
		if isE2EGatewayProductionGoroutine(block) {
			out = append(out, block)
		}
	}
	return out
}

// e2eNewGatewayProductionStacks returns the production gateway
// goroutines whose normalized stack is not in the pre-fixture
// snapshot.
func e2eNewGatewayProductionStacks(t *testing.T, before map[string]bool) []string {
	t.Helper()
	var out []string
	for _, block := range e2eProductionGatewayBlocks(t) {
		if before[e2eNormalizeStack(block)] {
			continue
		}
		out = append(out, block)
	}
	return out
}

// TestIAMT175_E2E_CloseDoesNotLeakGatewayGoroutines is the broad e2e
// leak check. The assertion lives in the cleanup registered first, so
// it observes the process after Close and after every other cleanup of
// this fixture has completed.
func TestIAMT175_E2E_CloseDoesNotLeakGatewayGoroutines(t *testing.T) {
	before := make(map[string]bool)
	for _, block := range e2eProductionGatewayBlocks(t) {
		before[e2eNormalizeStack(block)] = true
	}
	t.Cleanup(func() {
		deadline := time.Now().Add(time.Second)
		var leaked []string
		for {
			leaked = e2eNewGatewayProductionStacks(t, before)
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Errorf("CANARY (IAMT-175 e2e): %d new gateway-package goroutine(s) still alive after Close and every fixture cleanup; "+
			"this is the broad leak check (diff against the pre-fixture snapshot, production frames only). "+
			"First leaked stack:\n%s", len(leaked), leaked[0])
	})

	f := newFixture(t, nil)

	// The exact step shape of TestE2E_EnrolSuccessPath: seed the first
	// admin, dial, issue an enrol-code.
	rootKey := genSigner(t)
	addPersonForE2E(t, f, "root", "admin", rootKey)
	root, err := admin.Dial(admin.Peer{Addr: f.addr, Fingerprint: gatewayFingerprintE2E(f)},
		"root", rootKey, 5*time.Second)
	if err != nil {
		t.Fatalf("admin dial: %v", err)
	}
	defer root.Close()
	// The fake machine below connects as f.machineID, so that is the
	// name this registration has to carry — and a name already in use
	// is refused when the invitation is MINTED, so the fixture's own
	// seeded record goes before it is asked for.
	forgetSeededMachine(t, f)

	code, _, err := root.MachinesInvite(f.machineID)
	if err != nil {
		t.Fatalf("enrol-code: %v", err)
	}
	parsed, err := config.ParseEnrolCode(code)
	if err != nil {
		t.Fatalf("parse enrol code: %v", err)
	}

	// The machine's long-term key is generated HERE and used for BOTH
	// halves: the pubkey line enrolled through the enrol exec, and the
	// signer the fake machine presents. The round-3 version enrolled one
	// random key and connected the fake machine with a different random
	// one, so the handshake died during preparation ("unable to
	// authenticate, attempted methods [none publickey]") before any leak
	// check could run.
	machineKey := genSigner(t)
	ephemeral, err := config.DeriveEphemeralSigner(parsed.Secret, config.EnrolKeySalt)
	if err != nil {
		t.Fatalf("derive ephemeral: %v", err)
	}
	enrolResp := doEnrol(t, f, ephemeral, parsed.Secret, "", `MACHINE\svc`,
		authorizedLine(machineKey.PublicKey()))
	if !strings.Contains(enrolResp, `"state":"enrolled"`) {
		t.Fatalf("enrol response missing state=enrolled: %q", enrolResp)
	}

	// The fake machine connects with the just-enrolled long-term key and
	// reaches online; the gateway opens the control channel and the sshd
	// probe path (IAMT-161's tracked writer) runs against the fixture's
	// fake sshd. connectMachineWithKey already waits for the machine's
	// own view of online; waitForMachineOnline is the registry-side
	// confirmation TestE2E_EnrolSuccessPath also does.
	f.runFakeMachineAs(t, machineKey)
	waitForMachineOnline(t, f, 3*time.Second)

	// Close in the body: the checker above must observe the state after
	// Close (which waited for g.wg and probesWG), not race it. The
	// fixture's own cleanup Close is a no-op second call.
	if err := f.gw.Close(); err != nil {
		t.Fatalf("gateway Close: %v", err)
	}
}
