package gateway

// iamt175_goroutine_leak_test.go is the IAMT-175 broad leak check.
//
// Round 4: counting goroutines across
// the whole process from inside one test body is nondeterministic —
// the package runs hundreds of tests, and fixtures and t.Cleanup
// chains outlive any single assertion. The round-3 shape (count
// gateway-referencing stacks right after Close, inside the test)
// went red on a healthy product: its "production-only" filter never
// matched (a top-frame file line ends in ":<line> +0x<offset>", so a
// "_test.go" suffix check is always false), and the count saw the
// fixture's own harness goroutines, which the cleanups had not torn
// down yet, plus leftovers of neighbouring tests. This file implements
// the prescribed reliable shape:
//
//   - the stack snapshot is taken BEFORE any fixture work;
//   - the check runs in the test's FIRST-registered t.Cleanup, so
//     (cleanups run LIFO) it executes after the fixture has closed the
//     gateway, the store, the event log, the fake sshd and the fake
//     machine;
//   - only goroutines NEW relative to the snapshot are flagged (diff by
//     normalized stack), so whatever predated this test cannot fire it;
//   - a goroutine counts as this package's production work only if the
//     first frame that says who owns it — walking top down, skipping
//     runtime plumbing and stdlib/transport frames — is a function of
//     package github.com/ultrathinker/iamtunnel/internal/gateway (the "." excludes
//     subpackages) in a non-test file, or sits in a production file
//     directly in internal/gateway. Test functions in this package
//     carry the same package qualifier, so the file line is what
//     separates them: their first qualifying frame is in a *_test.go
//     file or in testing;
//   - the wait after Close is bounded decay protection, not the
//     assertion: a goroutine that exits within the window is scheduler
//     latency after the transports were cut, not a leak.
//
// What is deliberately NOT here: the round-3 stack-scraping canary for
// the sshd probe. That regression is covered deterministically by
// TestIAMT161_CloseWaitsForSSHDProbeToFinish (probesInFlight) and by
// the counter-based IAMT-172 canaries for the g.wg writers; restating
// it through runtime.Stack would only re-introduce the
// nondeterminism removed above. The goroutine table in
// REPORT_IAMT-161.md (Round 3) stays the documentation of every
// goroutine in this package.

import (
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"
)

// gatewayPkgQualifier is what a function frame of the gateway package
// itself starts with: github.com/ultrathinker/iamtunnel/internal/gateway.(*Gateway).Close,
// github.com/ultrathinker/iamtunnel/internal/gateway.discardRequests. It is a substring check,
// not a regex, because the character right after the qualifier is "("
// for every pointer-receiver method. Subpackage frames
// (github.com/ultrathinker/iamtunnel/internal/gateway/acl.(*Engine).Check) carry "gateway/"
// instead of "gateway." and therefore never contain the qualifier.
const gatewayPkgQualifier = "github.com/ultrathinker/iamtunnel/internal/gateway."

// gatewayFileRe matches frame file lines whose file sits directly in
// internal/gateway (either path flavour), e.g.
// .../internal/gateway/human_role.go:448. Subpackage files
// (internal/gateway/acl/acl.go) do not match, and *_test.go files are
// excluded by the frame walk before this regex is consulted.
var gatewayFileRe = regexp.MustCompile(`internal[/\\]gateway[/\\][A-Za-z0-9_]+\.go:`)

// isGatewayProductionGoroutine reports whether the first frame of
// block that characterizes the goroutine's owner belongs to this
// package's production code. The walk is top down: runtime plumbing
// (gopark, chanrecv, netpoll, ...) and every stdlib/transport frame
// below the owner is skipped, because a product goroutine parked in a
// network read shows only poll/net/x-ssh above its own frames.
func isGatewayProductionGoroutine(block string) bool {
	lines := strings.Split(block, "\n")
	// lines[0] is the "goroutine N [state]:" header; then
	// (function line, file line) pairs follow.
	for i := 1; i+1 < len(lines); i += 2 {
		fn, file := lines[i], lines[i+1]
		switch {
		case strings.HasPrefix(fn, "runtime."):
			continue // scheduler plumbing, not an owner
		case strings.HasPrefix(fn, "testing."):
			return false // the test runtime owns this goroutine
		case strings.Contains(fn, gatewayPkgQualifier):
			// Same-package function frame. Test functions and harness
			// methods in this package carry the same qualifier, so the
			// file decides.
			if strings.Contains(file, "_test.go:") {
				return false
			}
			return true
		case strings.Contains(file, "_test.go:"):
			return false // test harness owns this goroutine
		case gatewayFileRe.MatchString(file):
			return true
		}
		// Any other frame (net, bufio, x/ssh, io, sync, ...) does not
		// say who owns the goroutine — keep walking down.
	}
	return false
}

// normalizeStack reduces a goroutine block to its frame lines with the
// identity header, the argument lists and the code offsets stripped,
// so two snapshots of the same parked goroutine produce the same diff
// key even if a pointer argument changed between snapshots. The
// argument list opens at the LAST "(" of a function line: the method
// receiver's own parentheses — gateway.(*Gateway).Close — come first.
func normalizeStack(block string) string {
	lines := strings.Split(block, "\n")
	var sb strings.Builder
	for i, line := range lines {
		if i == 0 {
			continue // "goroutine N [state]:" — identity and scheduler state
		}
		if strings.HasPrefix(line, "\t") {
			// File line: "\t<path>.go:<line> +0x<offset>"
			if idx := strings.Index(line, " +0x"); idx >= 0 {
				line = line[:idx]
			}
		} else {
			// Function line: cut the argument list.
			if idx := strings.LastIndex(line, "("); idx >= 0 {
				line = line[:idx]
			}
		}
		sb.WriteString(strings.TrimSpace(line))
		sb.WriteByte('\n')
	}
	return sb.String()
}

// productionGatewayBlocks snapshots the whole process and returns the
// goroutine blocks that count as this package's production work.
func productionGatewayBlocks(t *testing.T) []string {
	t.Helper()
	const fourMiB = 4 << 20
	buf := make([]byte, fourMiB)
	n := runtime.Stack(buf, true)
	if n == len(buf) {
		t.Fatalf("runtime.Stack buffer full; cannot reliably diff gateway goroutines")
	}
	var out []string
	for _, block := range strings.Split(string(buf[:n]), "\n\n") {
		if isGatewayProductionGoroutine(block) {
			out = append(out, block)
		}
	}
	return out
}

// newGatewayProductionStacks snapshots the process and returns the
// production gateway goroutines whose normalized stack is not in the
// pre-fixture snapshot.
func newGatewayProductionStacks(t *testing.T, before map[string]bool) []string {
	t.Helper()
	var out []string
	for _, block := range productionGatewayBlocks(t) {
		if before[normalizeStack(block)] {
			continue
		}
		out = append(out, block)
	}
	return out
}

// TestIAMT175_CloseDoesNotLeakGatewayGoroutines is the broad leak
// check. The fixture exercises every writer the round-3 goroutine table
// lists for this package: the sweep goroutines and the connection
// handlers under g.wg, the sshd probe under g.probesWG
// (prepareSSHDProbe makes it fire), and the drain goroutines that die
// with the transports. The assertion itself lives in the cleanup
// registered first, so it observes the process after Close and after
// every other cleanup of this fixture has completed.
func TestIAMT175_CloseDoesNotLeakGatewayGoroutines(t *testing.T) {
	before := make(map[string]bool)
	for _, block := range productionGatewayBlocks(t) {
		before[normalizeStack(block)] = true
	}
	t.Cleanup(func() {
		// Bounded decay: Close and the cleanups cut every transport, and
		// goroutines scheduled to exit may need a few scheduler ticks to
		// actually disappear. One that survives the whole window is a
		// leak, not latency.
		deadline := time.Now().Add(time.Second)
		var leaked []string
		for {
			leaked = newGatewayProductionStacks(t, before)
			if len(leaked) == 0 {
				return
			}
			if time.Now().After(deadline) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Errorf("CANARY (IAMT-175): %d new gateway-package goroutine(s) still alive after Close and every fixture cleanup; "+
			"this is the broad leak check (diff against the pre-fixture snapshot, production frames only). "+
			"First leaked stack:\n%s", len(leaked), leaked[0])
	})

	f := newFixture(t, nil)
	prepareSSHDProbe(t, f)
	f.connectMachine(fakeMachineBehavior{})
	f.waitMachineOnline(t)

	// Close in the body: the checker above must observe the state after
	// Close (which waited for g.wg and probesWG), not race it. The
	// fixture's own cleanup Close is a no-op second call.
	if err := f.gw.Close(); err != nil {
		t.Fatalf("gateway Close: %v", err)
	}
}
